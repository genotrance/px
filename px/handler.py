"Px proxy request handler - asyncio connection handler with h11 HTTP parsing"

import asyncio
import contextlib
import io
import os
import socket
import sys
import time

# External dependencies
import h11
import keyring
import mcurl

from . import config, wproxy
from .config import CLIENT_REALM, STATE
from .debug import dprint, pprint

try:
    import spnego._ntlm
    import spnego._ntlm_raw.messages
    from spnego._ntlm_raw.crypto import lmowfv1, ntowfv1
except ImportError:
    pprint("Requires module pyspnego")
    sys.exit(config.ERROR_IMPORT)

###
# spnego _ntlm monkey patching


def _get_credential(store, domain, username):
    "Get credentials for domain\\username for NTLM authentication"
    domainuser = username
    if domain is not None and len(domain) != 0:
        domainuser = f"{domain}\\{username}"

    password = get_client_password(domainuser)
    if password is not None:
        lmhash = lmowfv1(password)
        nthash = ntowfv1(password)
        return domain, username, lmhash, nthash

    raise spnego.exceptions.SpnegoError(spnego.exceptions.ErrorCode.failure, "Bad credentials")  # type: ignore[arg-type]


spnego._ntlm._get_credential = _get_credential  # type: ignore[assignment]


def _get_credential_file():
    "Not using a credential file"
    return True


spnego._ntlm._get_credential_file = _get_credential_file

import spnego


def get_client_password(username):
    "Get client password from environment variables or keyring"
    password = None
    if username is None or len(username) == 0:
        # Blank username - failure
        dprint("Blank username")
    elif len(STATE.client_username) == 0:
        # No client_username configured - directly check keyring for password
        dprint("No client_username configured - checking keyring")
        password = keyring.get_password(CLIENT_REALM, username)
    elif username == STATE.client_username:
        # Username matches client_username - return password from env var or keyring
        dprint("Username matches client_username")
        if "PX_CLIENT_PASSWORD" in os.environ:
            dprint("Using PX_CLIENT_PASSWORD")
            password = os.environ.get("PX_CLIENT_PASSWORD", "")
        else:
            dprint("Using keyring")
            password = keyring.get_password(CLIENT_REALM, username)
    else:
        # Username does not match client_username
        dprint("Username does not match client_username")

    # Blank password = failure
    return password or None


def set_curl_auth(curl, auth):
    "Set proxy authentication info for curl object"
    if auth != "NONE":
        # Connecting to proxy and authenticating
        key = ""
        pwd = None
        if STATE.kerberos:
            # Kerberos managed by px — use GSS-API with ticket from ccache
            features = STATE.curl_features
            if "SSPI" in features or "GSS-API" in features:
                dprint(curl.easyhash + ": Using managed Kerberos ticket via GSS-API")
                key = ":"
            else:
                dprint("Kerberos enabled but GSS-API not available in libcurl")
                return
        elif len(STATE.username) != 0:
            key = STATE.username
            if "PX_PASSWORD" in os.environ:  # noqa: SIM108
                # Use environment variable PX_PASSWORD
                pwd = os.environ["PX_PASSWORD"]
            else:
                # Use keyring to get password
                pwd = keyring.get_password("Px", key)
        if len(key) == 0:
            # No username, try SSPI / GSS-API
            features = STATE.curl_features
            if "SSPI" in features or "GSS-API" in features:
                dprint(curl.easyhash + ": Using SSPI/GSS-API to login")
                key = ":"
            else:
                dprint("SSPI/GSS-API not available and no username configured - no auth")
                return
        curl.set_auth(user=key, password=pwd, auth=auth)
    else:
        # Explicitly deferring proxy authentication to the client
        dprint(curl.easyhash + ": Skipping proxy authentication")

        # Use easy interface to maintain a persistent connection
        # for NTLM auth, multi interface does not guarantee this
        curl.is_easy = True


###
# Thread-safe I/O wrappers for mcurl bridge

# Timeout for idle connections that haven't sent a complete request (slowloris protection)
REQUEST_TIMEOUT = 30

# Buffer size for socket reads
RECV_SIZE = 65536


class BridgeWriter:
    """Thread-safe writer that forwards data from the mcurl thread to the asyncio transport.

    mcurl callbacks call write() from the thread pool. Each call schedules a
    transport.write() on the event loop via call_soon_threadsafe, preserving
    ordering and streaming.
    """

    def __init__(self, loop, transport):
        self._loop = loop
        self._transport = transport
        self._closed = False

    def write(self, data):
        if self._closed or self._transport.is_closing():
            return 0
        self._loop.call_soon_threadsafe(self._transport.write, bytes(data))
        return len(data)

    def flush(self):
        pass

    def close(self):
        self._closed = True


class BodyReader:
    """BytesIO wrapper providing rfile-like interface for an already-read request body."""

    def __init__(self, body_bytes):
        self._buf = io.BytesIO(body_bytes)

    def read(self, n=-1):
        return self._buf.read(n)

    def readline(self, limit=-1):
        return self._buf.readline(limit)


###
# Tunnel relay for CONNECT


class TunnelRelay:
    """Bidirectional relay between client socket and upstream socket using event loop FD watchers.

    Eliminates the need for a thread per tunnel: the event loop multiplexes
    all active tunnels with zero threads.
    """

    def __init__(self, loop, client_fd, upstream_fd, idle_timeout, done_future, easyhash):
        self._loop = loop
        self._client_fd = client_fd
        self._upstream_fd = upstream_fd
        self._idle_timeout = idle_timeout
        self._done_future = done_future
        self._easyhash = easyhash
        self._closed = False
        self._last_activity = time.monotonic()

        # Buffers for data that couldn't be written immediately
        self._to_client = bytearray()
        self._to_upstream = bytearray()

        # Set non-blocking
        os.set_blocking(client_fd, False)
        os.set_blocking(upstream_fd, False)

        # Start reading from both sides
        self._loop.add_reader(client_fd, self._on_client_readable)
        self._loop.add_reader(upstream_fd, self._on_upstream_readable)

        # Idle timeout check
        self._timeout_handle = self._loop.call_later(idle_timeout, self._check_idle)

        self._cl = 0
        self._cs = 0

    def _on_client_readable(self):
        try:
            data = os.read(self._client_fd, RECV_SIZE)
        except OSError:
            self._close()
            return
        if data:
            self._last_activity = time.monotonic()
            self._cl += len(data)
            # If buffer already has pending data, append to preserve ordering
            if self._to_upstream:
                self._to_upstream.extend(data)
                return
            try:
                sent = os.write(self._upstream_fd, data)
                if sent < len(data):
                    self._to_upstream.extend(data[sent:])
                    self._loop.add_writer(self._upstream_fd, self._drain_upstream)
            except BlockingIOError:
                self._to_upstream.extend(data)
                self._loop.add_writer(self._upstream_fd, self._drain_upstream)
            except OSError:
                self._close()
        else:
            dprint(self._easyhash + ": Connection closed by client")
            self._close()

    def _on_upstream_readable(self):
        try:
            data = os.read(self._upstream_fd, RECV_SIZE)
        except OSError:
            self._close()
            return
        if data:
            self._last_activity = time.monotonic()
            self._cs += len(data)
            # If buffer already has pending data, append to preserve ordering
            if self._to_client:
                self._to_client.extend(data)
                return
            try:
                sent = os.write(self._client_fd, data)
                if sent < len(data):
                    self._to_client.extend(data[sent:])
                    self._loop.add_writer(self._client_fd, self._drain_client)
            except BlockingIOError:
                self._to_client.extend(data)
                self._loop.add_writer(self._client_fd, self._drain_client)
            except OSError:
                self._close()
        else:
            dprint(self._easyhash + ": Connection closed by server")
            self._close()

    def _drain_upstream(self):
        if not self._to_upstream:
            self._loop.remove_writer(self._upstream_fd)
            return
        try:
            sent = os.write(self._upstream_fd, self._to_upstream)
            if sent > 0:
                del self._to_upstream[:sent]
                self._last_activity = time.monotonic()
            if not self._to_upstream:
                self._loop.remove_writer(self._upstream_fd)
        except (BlockingIOError, OSError):
            pass

    def _drain_client(self):
        if not self._to_client:
            self._loop.remove_writer(self._client_fd)
            return
        try:
            sent = os.write(self._client_fd, self._to_client)
            if sent > 0:
                del self._to_client[:sent]
                self._last_activity = time.monotonic()
            if not self._to_client:
                self._loop.remove_writer(self._client_fd)
        except (BlockingIOError, OSError):
            pass

    def _check_idle(self):
        if self._closed:
            return
        if time.monotonic() - self._last_activity > self._idle_timeout:
            dprint(self._easyhash + ": Server connection timeout")
            self._close()
        else:
            self._timeout_handle = self._loop.call_later(1, self._check_idle)

    def _close(self):
        if self._closed:
            return
        self._closed = True

        self._timeout_handle.cancel()

        # Remove all FD watchers
        for fd in (self._client_fd, self._upstream_fd):
            with contextlib.suppress(Exception):
                self._loop.remove_reader(fd)
            with contextlib.suppress(Exception):
                self._loop.remove_writer(fd)

        dprint(f"{self._easyhash}: {self._cl} bytes read, {self._cs} bytes written")

        if not self._done_future.done():
            self._done_future.set_result(True)


async def _async_tunnel_relay(reader, writer, upstream_sock, idle_timeout, easyhash):
    """Zero-thread bidirectional relay for Windows ProactorEventLoop.

    Uses asyncio StreamReader/StreamWriter for the client side so the transport
    keeps ownership of the client socket and its IOCP registration.  The upstream
    (libcurl) side uses raw sock_recv/sock_sendall since it has no asyncio
    transport.  No additional threads needed.
    """
    loop = asyncio.get_event_loop()
    upstream_sock.setblocking(False)

    cl = 0  # bytes client -> upstream
    cs = 0  # bytes upstream -> client
    last_activity = time.monotonic()

    async def client_to_upstream():
        nonlocal cl, last_activity
        try:
            while True:
                data = await reader.read(RECV_SIZE)
                if not data:
                    dprint(easyhash + ": Connection closed by client")
                    return
                last_activity = time.monotonic()
                cl += len(data)
                await loop.sock_sendall(upstream_sock, data)
        except (OSError, ConnectionError) as exc:
            dprint(f"{easyhash}: from client: {exc}")

    async def upstream_to_client():
        nonlocal cs, last_activity
        try:
            while True:
                data = await loop.sock_recv(upstream_sock, RECV_SIZE)
                if not data:
                    dprint(easyhash + ": Connection closed by server")
                    return
                last_activity = time.monotonic()
                cs += len(data)
                writer.write(data)
                await writer.drain()
        except (OSError, ConnectionError) as exc:
            dprint(f"{easyhash}: from server: {exc}")

    c2s = asyncio.create_task(client_to_upstream())
    s2c = asyncio.create_task(upstream_to_client())

    # Idle timeout watchdog
    async def watchdog():
        while True:
            await asyncio.sleep(1)
            if time.monotonic() - last_activity > idle_timeout:
                dprint(easyhash + ": Server connection timeout")
                return

    wd = asyncio.create_task(watchdog())

    _done, pending = await asyncio.wait([c2s, s2c, wd], return_when=asyncio.FIRST_COMPLETED)
    for t in pending:
        t.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await t

    dprint(f"{easyhash}: {cl} bytes read, {cs} bytes written")


###
# HTTP response helpers

STATUS_PHRASES = {
    200: "OK",
    400: "Bad Request",
    401: "Unauthorized",
    403: "Forbidden",
    407: "Proxy Authentication Required",
    500: "Internal Server Error",
    501: "Not Implemented",
    502: "Bad Gateway",
    503: "Service Unavailable",
    504: "Gateway Timeout",
}


def format_error_body(code, message):
    "Format an HTML error page"
    import html as html_mod

    phrase = STATUS_PHRASES.get(code, "Error")
    content = (
        f"<html><head><title>Error response</title></head>"
        f"<body><h1>Error response</h1>"
        f"<p>Error code: {code}</p>"
        f"<p>Message: {html_mod.escape(message, quote=False)}</p>"
        f"<p>Error code explanation: {code} - {phrase}.</p></body></html>"
    )
    return content.encode("UTF-8", "replace")


###
# Connection handler


class ConnectionHandler:
    """Handles a single client connection using h11 for HTTP/1.1 request parsing.

    h11 is used ONLY for parsing incoming requests. All responses are sent as
    raw bytes because curl's bridge writes responses directly to the transport,
    bypassing h11's state machine. A fresh h11.Connection is created for each
    request to avoid state conflicts.

    Connection-scoped state (client_authed, client_ctxt, curl) persists
    across keep-alive requests on the same TCP connection.
    """

    def __init__(self, reader, writer):
        self.reader = reader
        self.writer = writer
        self.transport = writer.transport

        # Connection-scoped state
        self.client_authed = False
        self.client_ctxt = None
        self.curl = None
        self.proxy_servers = []
        self._close_after_response = False
        self._tunnel_established = False

        # Client address
        peername = writer.get_extra_info("peername")
        self.client_address = peername if peername else ("0.0.0.0", 0)

        # Leftover bytes from h11's receive buffer carried between requests
        self._recv_buf = b""

    async def handle(self):
        "Main connection loop - handles keep-alive requests"
        try:
            while True:
                # Fresh h11 connection per request (avoids state machine conflicts
                # since curl writes responses directly, bypassing h11)
                h11_conn = h11.Connection(h11.SERVER)
                if self._recv_buf:
                    h11_conn.receive_data(self._recv_buf)
                    self._recv_buf = b""

                request = await self._read_request(h11_conn)
                if request is None:
                    break

                method, target, headers, body, request_version = request

                # Save any data h11 buffered beyond this request (pipelined)
                trailing = h11_conn.trailing_data
                if trailing[0]:
                    self._recv_buf = bytes(trailing[0])

                # Process the request
                self._close_after_response = False
                self._tunnel_established = False
                await self._handle_request(method, target, headers, body, request_version)

                # CONNECT tunnels consume the connection (only when actually established)
                if method == "CONNECT" and self._tunnel_established:
                    break

                # Check keep-alive
                if self._close_after_response or not self._should_keep_alive(request_version, headers):
                    break
        except Exception as exc:
            easyhash = ""
            if self.curl is not None:
                easyhash = self.curl.easyhash + ": "
                STATE.mcurl.stop(self.curl)
                self.curl = None
            dprint(easyhash + "Connection error: " + str(exc))
        finally:
            try:
                self.writer.close()
                await self.writer.wait_closed()
            except Exception:
                pass

    @staticmethod
    def _should_keep_alive(request_version, headers):
        "Check if the connection should be kept alive based on request"
        conn = headers.get("connection", "").lower()
        proxy_conn = headers.get("proxy-connection", "").lower()
        if "close" in conn or "close" in proxy_conn:
            return False
        if request_version == "HTTP/1.0" and "keep-alive" not in conn and "keep-alive" not in proxy_conn:
            return False
        return True

    async def _read_request(self, h11_conn):
        """Read and parse one HTTP request using h11.

        Returns (method, target, headers, body, request_version) or None on connection close.
        """
        while True:
            event = h11_conn.next_event()

            if event is h11.NEED_DATA:
                try:
                    data = await asyncio.wait_for(self.reader.read(RECV_SIZE), timeout=REQUEST_TIMEOUT)
                except (TimeoutError, asyncio.TimeoutError):
                    dprint("Request timeout - closing connection")
                    return None
                except (OSError, ConnectionError):
                    return None
                if not data:
                    return None
                h11_conn.receive_data(data)
                continue

            if isinstance(event, h11.Request):
                method = event.method.decode("ascii")
                target = event.target.decode("ascii")
                request_version = "HTTP/" + event.http_version.decode("ascii")

                # Build headers dict (h11 normalizes names to lowercase)
                headers: dict[str, str] = {}
                for name, value in event.headers:
                    hname = name.decode("ascii")
                    hvalue = value.decode("ascii")
                    if hname in headers:
                        headers[hname] = headers[hname] + ", " + hvalue
                    else:
                        headers[hname] = hvalue

                # Read body if present (not for CONNECT)
                body = b""
                if method != "CONNECT":
                    while True:
                        bevt = h11_conn.next_event()
                        if bevt is h11.NEED_DATA:
                            try:
                                data = await asyncio.wait_for(self.reader.read(RECV_SIZE), timeout=REQUEST_TIMEOUT)
                            except (TimeoutError, asyncio.TimeoutError, OSError, ConnectionError):
                                return None
                            if not data:
                                return None
                            h11_conn.receive_data(data)
                            continue
                        if isinstance(bevt, h11.Data):
                            body += bytes(bevt.data)
                        elif isinstance(bevt, h11.EndOfMessage):
                            break
                        elif isinstance(bevt, (h11.ConnectionClosed, h11.RemoteProtocolError)):
                            return None
                        else:
                            break

                return method, target, headers, body, request_version

            if isinstance(event, (h11.ConnectionClosed, h11.RemoteProtocolError)):
                return None

            # h11.PAUSED or unknown event
            return None

    def _send_raw(self, data):
        "Write raw bytes to the client transport"
        if not self.transport.is_closing():
            self.transport.write(data)

    def _send_response(self, status_code, headers, body=b""):
        "Send a complete HTTP response as raw bytes"
        phrase = STATUS_PHRASES.get(status_code, "Error")
        parts = [f"HTTP/1.1 {status_code} {phrase}\r\n"]
        for name, value in headers:
            parts.append(f"{name}: {value}\r\n")
        parts.append("\r\n")
        raw = "".join(parts).encode("ascii")
        if body:
            raw += body
        self._send_raw(raw)

    def _send_error(self, code, message=""):
        "Send an HTTP error response and mark connection for close"
        body = format_error_body(code, message)
        headers = [
            ("Content-Type", "text/html;charset=utf-8"),
            ("Content-Length", str(len(body))),
            ("Connection", "close"),
        ]
        self._send_response(code, headers, body)
        self._close_after_response = True

    def _send_auth_response(self, auth_headers):
        "Send a 407 Proxy Authentication Required response (keep-alive for auth handshake)"
        body = format_error_body(407, "Proxy authentication required")
        headers = list(auth_headers)
        headers.append(("Content-Type", "text/html;charset=utf-8"))
        headers.append(("Content-Length", str(len(body))))
        headers.append(("Proxy-Connection", "Keep-Alive"))
        self._send_response(407, headers, body)

    ###
    # Client authentication

    def _do_client_auth(self, method, headers):
        "Handle authentication of clients - returns True if authenticated"
        if len(STATE.client_auth) != 0:
            auth_header = headers.get("proxy-authorization")
            if auth_header is None:
                if not self.client_authed:
                    dprint("No auth header")
                    self._send_auth_challenge()
                    return False
                elif method in ("POST", "PUT", "PATCH"):
                    content_length = headers.get("content-length")
                    if content_length is not None and content_length == "0":
                        dprint("POST/PUT expects to receive auth headers")
                        self._send_auth_challenge()
                        return False
                else:
                    dprint("Client already authenticated")
            else:
                authtype = auth_header.split(" ", 1)[0].upper()
                if authtype not in STATE.client_auth:
                    self._send_auth_challenge()
                    dprint("Unsupported client auth type: " + authtype)
                    return False

                dprint("Auth type: " + authtype)
                if authtype in ("NEGOTIATE", "NTLM"):
                    if not self._do_spnego_auth(auth_header, authtype):
                        return False
                elif authtype == "DIGEST":
                    if not self._do_digest_auth(auth_header, method, headers):
                        return False
                elif authtype == "BASIC" and not self._do_basic_auth(auth_header):
                    return False
        else:
            dprint("No client authentication required")

        return True

    def _send_auth_challenge(self, authtype="", challenge=""):
        "Send 407 with authentication challenge headers"
        auth_headers = []
        if len(authtype) != 0 and len(challenge) != 0:
            auth_headers.append(("Proxy-Authenticate", authtype + " " + challenge))
        else:
            if "NEGOTIATE" in STATE.client_auth:
                auth_headers.append(("Proxy-Authenticate", "Negotiate"))
            if "NTLM" in STATE.client_auth:
                auth_headers.append(("Proxy-Authenticate", "NTLM"))
            if "DIGEST" in STATE.client_auth:
                import os as _os

                nonce = self._get_digest_nonce()
                opaque = _os.urandom(16).hex()
                digest_header = f'Digest realm="{CLIENT_REALM}", qop="auth", algorithm="MD5"'
                digest_header += f', nonce="{nonce}", opaque="{opaque}"'
                auth_headers.append(("Proxy-Authenticate", digest_header))
            if "BASIC" in STATE.client_auth:
                auth_headers.append(("Proxy-Authenticate", f'Basic realm="{CLIENT_REALM}"'))

        self.client_authed = False
        self._send_auth_response(auth_headers)

    def _do_spnego_auth(self, auth_header, authtype):
        "NEGOTIATE/NTLM auth using pyspnego"
        import base64

        encoded_credentials = auth_header[len(authtype + " ") :]
        if self.client_ctxt is None:
            if authtype == "NEGOTIATE":
                authtype = "Negotiate"
                options = spnego.NegotiateOptions.use_negotiate
            else:
                options = spnego.NegotiateOptions.use_ntlm
            if sys.platform == "win32" and not STATE.client_nosspi:
                options = spnego.NegotiateOptions.use_sspi
            self.client_ctxt = spnego.auth.server(protocol=authtype.lower(), options=options)
        try:
            outok = self.client_ctxt.step(base64.b64decode(encoded_credentials))
        except (spnego.exceptions.InvalidTokenError, spnego.exceptions.SpnegoError, ValueError) as exc:
            dprint("Authentication failed: " + str(exc))
            self._send_error(401, "Authentication failed")
            return False
        if outok is not None:
            import base64 as b64

            dprint(f"Sending {authtype} challenge")
            self._send_auth_challenge(authtype=authtype, challenge=b64.b64encode(outok).decode("utf-8"))
            return False
        else:
            dprint(f"Authenticated {authtype} client")
            self.client_authed = True
            self.client_ctxt = None
            return True

    def _do_digest_auth(self, auth_header, method, headers):
        "Digest auth verification"
        import hashlib

        encoded_credentials = auth_header[len("Digest ") :]
        params = {}
        for param in encoded_credentials.split(","):
            key, value = param.strip().split("=", 1)
            params[key] = value.strip('"').replace("\\\\", "\\")

        nonce = params.get("nonce", "")
        if len(nonce) == 0:
            dprint("Authentication failed: No nonce")
            self._send_error(401, "Authentication failed")
            return False
        if not self._verify_digest_nonce(nonce):
            dprint("Authentication failed: Invalid nonce")
            self._send_error(401, "Authentication failed")
            return False

        client_username = params.get("username", "")
        client_password = get_client_password(client_username)
        if client_password is None:
            dprint("Authentication failed: Bad username")
            self._send_error(401, "Authentication failed")
            return False

        A1 = f"{client_username}:{CLIENT_REALM}:{client_password}"
        HA1 = hashlib.md5(A1.encode("utf-8")).hexdigest()
        A2 = f"{method}:{params['uri']}"
        HA2 = hashlib.md5(A2.encode("utf-8")).hexdigest()
        A3 = f"{HA1}:{params['nonce']}:{params['nc']}:{params['cnonce']}:{params['qop']}:{HA2}"
        response = hashlib.md5(A3.encode("utf-8")).hexdigest()

        if response != params["response"]:
            dprint("Authentication failed: Bad response")
            self._send_error(401, "Authentication failed")
            return False
        else:
            dprint("Authenticated Digest client")
            self.client_authed = True
            return True

    def _do_basic_auth(self, auth_header):
        "Basic auth verification"
        import base64

        encoded_credentials = auth_header[len("Basic ") :]
        credentials = base64.b64decode(encoded_credentials).decode("utf-8")
        username, password = credentials.split(":", 1)

        client_password = get_client_password(username)
        if client_password is None or client_password != password:
            dprint("Authentication failed")
            self._send_error(401, "Authentication failed")
            return False

        dprint("Authenticated Basic client")
        self.client_authed = True
        return True

    def _get_digest_nonce(self):
        "Generate a new nonce for Digest authentication"
        import base64
        import hashlib

        timestamp = int(time.time())
        key = f"{timestamp}:{self.client_address[0]}:{CLIENT_REALM}"
        keyhash = hashlib.sha256(key.encode("utf-8")).hexdigest()
        nonce_dec = f"{timestamp}:{keyhash}"
        return base64.b64encode(nonce_dec.encode("utf-8")).decode("utf-8")

    def _verify_digest_nonce(self, nonce):
        "Verify a nonce received from the client"
        import base64
        import hashlib

        nonce_dec = base64.b64decode(nonce.encode("utf-8")).decode("utf-8")
        try:
            timestamp_str, keyhash = nonce_dec.split(":", 1)
            timestamp = int(timestamp_str)
        except ValueError:
            dprint("Invalid nonce format")
            return False

        if time.time() - timestamp > 120:
            dprint("Nonce has expired")
            return False

        key = f"{timestamp}:{self.client_address[0]}:{CLIENT_REALM}"
        keyhash_new = hashlib.sha256(key.encode("utf-8")).hexdigest()
        if keyhash != keyhash_new:
            dprint("Invalid nonce hash")
            return False

        return True

    ###
    # Core request handling

    async def _handle_request(self, method, target, headers, body, request_version):
        "Handle one proxy request"
        # Handle quit request
        if method == "GET" and target == "/PxQuit":
            await self._handle_quit()
            return

        # Client authentication
        strip_proxy_headers = False
        if not self._do_client_auth(method, headers):
            return

        # If client auth succeeded and was performed, strip proxy headers
        if len(STATE.client_auth) != 0 and self.client_authed:
            strip_proxy_headers = True

        # Create or reset curl handle using the client's HTTP version
        if self.curl is None:
            self.curl = mcurl.Curl(target, method, request_version, STATE.socktimeout)
        else:
            self.curl.reset(target, method, request_version, STATE.socktimeout)

        dprint(self.curl.easyhash + ": Path = " + target)

        # Get destination (proxy or direct)
        ipport = await self._get_destination(target)
        if ipport is None:
            dprint(self.curl.easyhash + ": Configuring proxy settings")
            server = self.proxy_servers[0][0]
            port = self.proxy_servers[0][1]
            noproxy_hosts = STATE.wproxy.noproxy_hosts_str
            ret = self.curl.set_proxy(proxy=server, port=port, noproxy=noproxy_hosts)
            if ret:
                STATE.note_proxy_attempt(server)
            elif STATE.retry_auth_failure(server):
                dprint(self.curl.easyhash + f": Retrying proxy blocked after auth failures: {server}:{port}")
                ret = self.curl.set_proxy(proxy=server, port=port, noproxy=noproxy_hosts)
            if not ret:
                self._send_error(401, f"Proxy server authentication failed: {server}:{port}")
                STATE.mcurl.remove(self.curl)
                return

            set_curl_auth(self.curl, STATE.auth)
        else:
            dprint(self.curl.easyhash + ": Skipping auth proxying")

        # Set debug mode
        self.curl.set_debug(STATE.debug is not None)

        # Build headers dict for curl, stripping proxy headers if needed
        curl_headers = {}
        for hname, hvalue in headers.items():
            if strip_proxy_headers and hname.lower().startswith("proxy-"):
                continue
            curl_headers[hname] = hvalue

        # Plain HTTP: bridge request body and response
        if not self.curl.is_connect:
            loop = asyncio.get_event_loop()
            body_reader = BodyReader(body)
            response_writer = BridgeWriter(loop, self.transport)
            self.curl.bridge(body_reader, response_writer, response_writer)

            # Support NTLM auth from http client in auth=NONE mode with upstream proxy
            if ipport is None and STATE.auth == "NONE" and method in ("POST", "PUT", "PATCH"):
                content_length = headers.get("content-length")
                if content_length is not None and content_length == "0":
                    dprint(self.curl.easyhash + ": Setting CURLOPT_KEEP_SENDING_ON_ERROR")
                    mcurl.libcurl.curl_easy_setopt(
                        self.curl.easy, mcurl.libcurl.CURLOPT_KEEP_SENDING_ON_ERROR, mcurl.py2cbool(True)
                    )

        # Set headers for request
        self.curl.set_headers(curl_headers)

        # Turn off transfer decoding
        self.curl.set_transfer_decoding(False)

        # Set user agent if configured
        self.curl.set_useragent(STATE.useragent)

        # Execute via thread pool (mcurl.do is blocking)
        success = await asyncio.to_thread(STATE.mcurl.do, self.curl)

        if not success:
            dprint(self.curl.easyhash + ": Connection failed: " + self.curl.errstr)

            # If SSO auth failure or mechanism error, force Kerberos ticket check
            if (self.curl.resp == 401 and "single sign-on failed" in self.curl.errstr) or (
                self.curl.resp == 407 and "auth mechanism error" in self.curl.errstr
            ):
                STATE.reload_kerberos(force=True)

            self._send_error(self.curl.resp, self.curl.errstr)
        elif self.curl.is_connect:
            await self._handle_connect_tunnel(h11_trailing=self._recv_buf)
            self._recv_buf = b""  # Consumed by tunnel

        STATE.mcurl.remove(self.curl)

    async def _get_destination(self, target):
        "Get destination - returns netloc for DIRECT or None for proxy"
        # Reload proxy info if timeout exceeded — fast path is a timestamp
        # check; only the actual PAC reload (re-fetching URL, re-parsing JS)
        # blocks and that is rare (proxyreload interval)
        STATE.reload_proxy()

        # Check Kerberos ticket validity — fast path is a timestamp check;
        # only subprocess calls (klist/kinit) block and those are rare
        STATE.reload_kerberos()

        # Find proxy — async_find_proxy_for_url offloads to thread pool when
        # noproxy or PAC evaluation would block (getaddrinfo / quickjs)
        url = ("https://" if "://" not in target else "") + target
        servers, netloc, _path = await STATE.wproxy.async_find_proxy_for_url(url)
        if len(servers) == 0 or servers[0] == wproxy.DIRECT:
            dprint(self.curl.easyhash + ": Direct connection")
            return netloc
        else:
            dprint(self.curl.easyhash + ": Proxy = " + str(servers))
            self.proxy_servers = servers
            return None

    async def _handle_connect_tunnel(self, h11_trailing=b""):
        "Handle CONNECT tunnel after upstream connection is established"
        self._tunnel_established = True
        ret, used_proxy = self.curl.get_used_proxy()
        if ret != 0:
            dprint(self.curl.easyhash + ": Failed to get used proxy: " + str(ret))
        elif self.curl.is_tunnel or not used_proxy:
            # Inform client that SSL connection has been established
            dprint(self.curl.easyhash + ": SSL connected")
            self._send_raw(b"HTTP/1.1 200 Connection established\r\nProxy-Agent: Px\r\n\r\n")

        # Get upstream socket FD
        if self.curl.sock_fd is None:
            dprint(self.curl.easyhash + ": No active socket for tunnel")
            return

        # Ensure any pending writes (e.g. the 200 response) are flushed
        await self.writer.drain()

        if sys.platform != "win32":
            # Linux: pause asyncio reads and dup the client fd so asyncio
            # doesn't complain about FD ownership (asyncio checks _transports[fd]).
            # On Windows the relay reads through the StreamReader so the
            # transport keeps its IOCP ownership — no pause needed.
            self.reader._transport.pause_reading()
            client_sock = self.transport.get_extra_info("socket")
            if client_sock is None:
                dprint(self.curl.easyhash + ": Cannot get client socket")
                return
            relay_client_fd = os.dup(client_sock.fileno())

        curl_sock = socket.fromfd(self.curl.sock_fd, socket.AF_INET, socket.SOCK_STREAM)

        try:
            # auth=NONE passthrough: send original client headers to upstream proxy
            if self.curl.is_connect and (not self.curl.is_tunnel and used_proxy):
                dprint(self.curl.easyhash + ": Sending original client headers")
                curl_sock.sendall((f"{self.curl.method} {self.curl.url} {self.curl.request_version}\r\n").encode())
                if self.curl.xheaders is not None:
                    for header in self.curl.xheaders:
                        curl_sock.sendall(f"{header}: {self.curl.xheaders[header]}\r\n".encode())
                curl_sock.sendall(b"\r\n")

            # Send any data that was buffered beyond the CONNECT request
            if h11_trailing:
                curl_sock.sendall(h11_trailing)

            if sys.platform == "win32":
                # Windows: zero-thread async relay using StreamReader/Writer
                # for the client side (avoids stealing the socket from the
                # transport's IOCP registration) and sock_recv/sock_sendall
                # for the upstream libcurl socket
                await _async_tunnel_relay(self.reader, self.writer, curl_sock, STATE.idle, self.curl.easyhash)
            else:
                # Linux: zero-thread relay using epoll-backed add_reader/add_writer
                loop = asyncio.get_event_loop()
                done_future = loop.create_future()
                relay = TunnelRelay(
                    loop, relay_client_fd, curl_sock.fileno(), STATE.idle, done_future, self.curl.easyhash
                )
                try:
                    await done_future
                except asyncio.CancelledError:
                    relay._close()
        finally:
            curl_sock.close()
            if sys.platform != "win32":
                os.close(relay_client_fd)

    async def _handle_quit(self):
        "Handle /PxQuit request"
        hostips = config.get_host_ips()
        for listen in STATE.listen:
            if (len(listen) == 0 and self.client_address[0] in hostips) or (self.client_address[0] == listen):
                self._send_response(200, [("Content-Length", "0")])
                STATE.cleanup_kerberos()
                # Give time for the response to be sent
                await asyncio.sleep(0.1)
                os._exit(config.ERROR_SUCCESS)

        self._send_error(403)
