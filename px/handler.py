"Px proxy request handler - asyncio connection handler with h11 HTTP parsing"

import asyncio
import contextlib
import os
import socket
import sys
import threading
import time

# External dependencies
import h11
import keyring
import mcurl

from . import config, wproxy
from .config import CLIENT_REALM, STATE
from .debug import dprint, missing_module_message, pprint

try:
    import spnego._ntlm
    import spnego._ntlm_raw.messages
    from spnego._ntlm_raw.crypto import lmowfv1, ntowfv1
except ImportError as error:
    pprint(missing_module_message("pyspnego", error))
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

_client_password_cache: dict[str, str] = {}


def get_client_password(username):
    "Get client password from environment variables or keyring, cached per username"
    if username in _client_password_cache:
        return _client_password_cache[username]

    password = _lookup_client_password(username)
    if password is not None:
        # NTLM/Digest validate credentials synchronously on the event loop thread
        # (pyspnego's credential callback and the hash checks are not run via
        # asyncio.to_thread like mcurl transfers are), so a slow keyring backend
        # would otherwise stall every connection on every handshake.
        _client_password_cache[username] = password
    return password


def _lookup_client_password(username):
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

# Interim response sent when a client waits for "Expect: 100-continue"
CONTINUE_RESPONSE = b"HTTP/1.1 100 Continue\r\n\r\n"

# Headers that apply to the client connection only and are never forwarded
# upstream, together with the headers named by the client's Connection header
HOP_BY_HOP_HEADERS = frozenset(("connection", "proxy-connection", "keep-alive", "te", "trailer", "upgrade"))

REWIND_MESSAGE = (
    "The request body could not be sent through the upstream proxy: its authentication method was not "
    "known yet and the proxy ignored 'Expect: 100-continue', so the body went out before the proxy asked "
    "for credentials and Px cannot resend a streamed body. The method is now cached; retry the request."
)


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


class HeaderBridgeWriter(BridgeWriter):
    """Forward upstream headers except its 100 response, which Px has already answered."""

    def __init__(self, loop, transport):
        super().__init__(loop, transport)
        self._dropping_continue = False

    def write(self, data):
        data = bytes(data)
        if data.startswith(b"HTTP/"):
            self._dropping_continue = data.split(None, 2)[1:2] == [b"100"]
        if self._dropping_continue:
            if data in (b"\r\n", b"\n"):
                self._dropping_continue = False
            return len(data)
        return super().write(data)


class RequestBody:
    """Streaming, non-seekable reader over the client's request body.

    Handed to Curl.bridge() as the read source. Content-Length bodies are read
    lazily (exactly that many bytes) and chunked bodies are de-chunked lazily,
    with trailers consumed and read() returning b"" at the terminating chunk.
    h11 does the framing. read() runs on mcurl's thread, never the event loop:
    it never blocks: when the client has not sent more yet it returns None, which
    pauses mcurl's upload, while one RECV_SIZE read runs on the loop and then
    resumes it. So a stalled client delays nothing else, only one chunk is held
    here (asyncio's StreamReader applies backpressure to the client socket) and
    no size limit applies.

    complete is True once h11 reported the end of the body, failed after a
    client error, timeout or disconnect. A client "Expect: 100-continue" is
    answered with "100 Continue" the first time the body is needed, so the
    client sends the body only once the upstream wants it; held_back is True
    until then.
    """

    def __init__(self, h11_conn=None, stream=None, loop=None, transport=None, expect_continue=False):
        self._h11 = h11_conn
        self._stream = stream
        self._loop = loop
        self._transport = transport
        self._expect_continue = expect_continue
        self._pending = b""
        self._lock = threading.Lock()
        self._fetching = False
        self._task = None
        self.resume = lambda: None
        self.blocking = False
        self.complete = h11_conn is None
        self.failed = False
        if not self.complete:
            self._step()

    def seekable(self):
        "A client socket cannot rewind; mcurl relies on this to avoid resending the body"
        return False

    def _step(self):
        "Advance over events h11 already holds; False when it needs more client data"
        try:
            event = self._h11.next_event()
        except h11.ProtocolError:
            self.failed = True
            return True
        if event is h11.NEED_DATA:
            return False
        if isinstance(event, h11.Data):
            self._pending = bytes(event.data)
        elif isinstance(event, h11.EndOfMessage):
            self.complete = True
        else:
            self.failed = True
        return True

    async def _recv(self):
        try:
            return await asyncio.wait_for(self._stream.read(RECV_SIZE), timeout=REQUEST_TIMEOUT)
        except (TimeoutError, asyncio.TimeoutError, OSError, ConnectionError):
            return b""

    def _receive(self, data):
        if data:
            self._h11.receive_data(data)
        else:
            self.failed = True

    def _write_continue(self):
        if not self._transport.is_closing():
            self._transport.write(CONTINUE_RESPONSE)

    def _send_continue(self):
        if self._expect_continue:
            self._expect_continue = False
            self._loop.call_soon_threadsafe(self._write_continue)

    def _fetch_done(self, data):
        "On the event loop: feed what the client sent to h11, then wake the paused upload"
        with self._lock:
            try:
                self._receive(data)
                self._step()
            except Exception as exc:
                dprint("Error reading request body: " + str(exc))
                self.failed = True
            self._fetching = False
        try:
            self.resume()
        except Exception as exc:
            dprint("Error resuming upload: " + str(exc))

    async def _fetch(self):
        self._fetch_done(await self._recv())

    def _start_fetch(self):
        self._task = self._loop.create_task(self._fetch())

    def read(self, n=-1):
        """Return up to n bytes (at most one chunk), b'' at the end of the body or when the client fails.

        Never blocks mcurl's thread: when the client has not sent more yet it returns None, which
        mcurl turns into a paused upload, and a single event loop read resumes it via resume().
        """
        with self._lock:
            if not self._pending:
                if self._fetching:
                    return None
                self._send_continue()
                try:
                    while not (self._pending or self.complete or self.failed):
                        if self._step():
                            continue
                        if self.blocking:
                            self._receive(asyncio.run_coroutine_threadsafe(self._recv(), self._loop).result())
                        else:
                            self._fetching = True
                            self._loop.call_soon_threadsafe(self._start_fetch)
                            return None
                except Exception as exc:
                    dprint("Error reading request body: " + str(exc))
                    self.failed = True
            if n is None or n < 0:
                n = len(self._pending)
            data, self._pending = self._pending[:n], self._pending[n:]
            if not (self._pending or self.blocking or self.complete or self.failed):
                self._read_ahead()
            return data

    def _read_ahead(self):
        "While mcurl sends the chunk just handed over, fetch the next one so read() rarely has to pause"
        try:
            if not self._step():
                self._fetching = True
                self._loop.call_soon_threadsafe(self._start_fetch)
        except Exception as exc:
            dprint("Error reading request body: " + str(exc))
            self.failed = True

    @property
    def held_back(self):
        "True while the client waits for 100 Continue and no body byte has arrived"
        return self._expect_continue and not self._pending and not self.complete

    def finish(self):
        "After the transfer, on the event loop: True if the whole body was consumed (connection reusable)"
        if self._fetching:
            return False
        if not (self.complete or self.failed or self._pending):
            self._step()
        return self.complete

    async def drain(self):
        "Discard the rest of the body without storing it so the connection can be reused"
        if self._task is not None:
            await asyncio.wait([self._task])
        self._pending = b""
        while not (self.complete or self.failed):
            if self._step():
                self._pending = b""
            else:
                self._receive(await self._recv())
        return self.complete


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
        self.client_ctxt_scheme = None
        self.curl = None
        self.proxy_servers = []
        self._close_after_response = False
        self._drain_body = False
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

                if body is None:
                    # CONNECT: save any data h11 buffered beyond the request (tunnel data)
                    trailing = h11_conn.trailing_data
                    if trailing[0]:
                        self._recv_buf = bytes(trailing[0])

                # Process the request
                self._close_after_response = False
                self._drain_body = False
                self._tunnel_established = False
                await self._handle_request(method, target, headers, body, request_version)

                # CONNECT tunnels consume the connection (only when actually established)
                if method == "CONNECT" and self._tunnel_established:
                    break

                if self._close_after_response:
                    break

                # The body streams straight from the client, so it must be fully consumed
                # (or discarded after a reply that did not need it) before the next
                # request can be read from this connection; otherwise close it
                if body is not None:
                    trailing = h11_conn.trailing_data
                    if self._drain_body and body.held_back and not trailing[0]:
                        # The 407 was sent as the final response to the client's Expect, so the
                        # client holds the body back and there is nothing to discard
                        pass
                    else:
                        if self._drain_body:
                            await body.drain()
                        if not body.finish():
                            break
                        # Save any data h11 buffered beyond this request (pipelined)
                        trailing = h11_conn.trailing_data
                        if trailing[0]:
                            self._recv_buf = bytes(trailing[0])

                # Check keep-alive
                if self._close_after_response or not self._should_keep_alive(request_version, headers):
                    break
        except Exception as exc:
            easyhash = ""
            if self.curl is not None:
                easyhash = self.curl.easyhash + ": "
                # mcurl's lock can be held by a transfer waiting for this loop to read a body
                await asyncio.to_thread(STATE.mcurl.stop, self.curl)
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
        body is a RequestBody for everything but CONNECT, which has none.
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

                # The body is not read here: CONNECT has none and for other
                # methods it streams lazily to mcurl as upstream needs it
                body = None
                if method != "CONNECT":
                    expect = headers.get("expect", "").lower() == "100-continue" and request_version == "HTTP/1.1"
                    body = RequestBody(h11_conn, self.reader, asyncio.get_running_loop(), self.transport, expect)

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

    def _reset_client_auth_context(self):
        "Discard an incomplete connection-oriented authentication context"
        self.client_ctxt = None
        self.client_ctxt_scheme = None

    def _fail_client_auth(self):
        "Restart client authentication after a failed credential or token"
        self._reset_client_auth_context()
        self._send_auth_challenge()

    @staticmethod
    def _is_spnego_new_handshake(credentials, authtype):
        "Return whether credentials begin a fresh NTLM or Negotiate exchange"
        if authtype == "NTLM":
            return credentials.startswith(b"NTLMSSP\x00\x01\x00\x00\x00")
        return credentials.startswith(b"\x60")

    def _do_spnego_auth(self, auth_header, authtype):
        "NEGOTIATE/NTLM auth using pyspnego"
        import base64
        import binascii

        encoded_credentials = auth_header[len(authtype + " ") :]
        try:
            credentials = base64.b64decode(encoded_credentials, validate=True)
        except (binascii.Error, ValueError) as exc:
            dprint("Authentication failed: " + str(exc))
            self._fail_client_auth()
            return False

        if self.client_ctxt_scheme != authtype or self._is_spnego_new_handshake(credentials, authtype):
            self._reset_client_auth_context()

        challenge_authtype = "Negotiate" if authtype == "NEGOTIATE" else "NTLM"
        if self.client_ctxt is None:
            if authtype == "NEGOTIATE":
                options = spnego.NegotiateOptions.use_negotiate
            else:
                options = spnego.NegotiateOptions.use_ntlm
            if sys.platform == "win32" and not STATE.client_nosspi:
                options = spnego.NegotiateOptions.use_sspi
            self.client_ctxt = spnego.auth.server(protocol=challenge_authtype.lower(), options=options)
            self.client_ctxt_scheme = authtype
        try:
            outok = self.client_ctxt.step(credentials)
        except (spnego.exceptions.InvalidTokenError, spnego.exceptions.SpnegoError, ValueError) as exc:
            dprint("Authentication failed: " + str(exc))
            self._fail_client_auth()
            return False
        if outok is not None:
            import base64 as b64

            dprint(f"Sending {challenge_authtype} challenge")
            self._send_auth_challenge(authtype=challenge_authtype, challenge=b64.b64encode(outok).decode("utf-8"))
            return False
        else:
            dprint(f"Authenticated {challenge_authtype} client")
            self.client_authed = True
            self._reset_client_auth_context()
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
            self._fail_client_auth()
            return False
        if not self._verify_digest_nonce(nonce):
            dprint("Authentication failed: Invalid nonce")
            self._fail_client_auth()
            return False

        client_username = params.get("username", "")
        client_password = get_client_password(client_username)
        if client_password is None:
            dprint("Authentication failed: Bad username")
            self._fail_client_auth()
            return False

        A1 = f"{client_username}:{CLIENT_REALM}:{client_password}"
        HA1 = hashlib.md5(A1.encode("utf-8")).hexdigest()
        A2 = f"{method}:{params['uri']}"
        HA2 = hashlib.md5(A2.encode("utf-8")).hexdigest()
        A3 = f"{HA1}:{params['nonce']}:{params['nc']}:{params['cnonce']}:{params['qop']}:{HA2}"
        response = hashlib.md5(A3.encode("utf-8")).hexdigest()

        if response != params["response"]:
            dprint("Authentication failed: Bad response")
            self._fail_client_auth()
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
            self._fail_client_auth()
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
            # The client resends the request on this connection, so discard its body
            self._drain_body = True
            return

        # If client auth succeeded and was performed, strip proxy headers
        if len(STATE.client_auth) != 0 and self.client_authed:
            strip_proxy_headers = True

        # Create or reset curl handle using the client's HTTP version
        if self.curl is None:
            self.curl = mcurl.Curl(target, method, request_version, STATE.socktimeout)
        else:
            self.curl.reset(target, method, request_version, STATE.socktimeout)

        if method != "CONNECT":
            self.curl.set_low_speed(1, STATE.idle)

        dprint(self.curl.easyhash + ": Path = " + target)

        # Get destination (proxy or direct)
        ipport = await self._get_destination(target)
        if ipport is None:
            dprint(self.curl.easyhash + ": Configuring proxy settings")
            server = self.proxy_servers[0][0]
            port = self.proxy_servers[0][1]
            noproxy_hosts = STATE.wproxy.noproxy_hosts_str
            ret = self.curl.set_proxy(proxy=server, port=port, noproxy=noproxy_hosts)
            if not ret:
                self._send_error(401, f"Proxy server authentication failed: {server}:{port}")
                await asyncio.to_thread(STATE.mcurl.remove, self.curl)
                return

            set_curl_auth(self.curl, STATE.auth)
            proxy_resolve = await self._set_proxy_resolve(server, port)
        else:
            proxy_resolve = None
            dprint(self.curl.easyhash + ": Skipping auth proxying")

        # Set debug mode
        self.curl.set_debug(STATE.debug is not None)

        # Build headers dict for curl, stripping hop-by-hop and proxy headers
        strip_proxy_auth = strip_proxy_headers or (ipport is None and STATE.auth != "NONE")
        curl_headers = self._upstream_headers(headers, strip_proxy_headers, strip_proxy_auth)

        # Plain HTTP: bridge request body and response
        if not self.curl.is_connect:
            loop = asyncio.get_event_loop()
            body_reader = body if body is not None else RequestBody()
            response_writer = BridgeWriter(loop, self.transport)
            header_writer = HeaderBridgeWriter(loop, self.transport)
            if hasattr(self.curl, "resume_upload") and not self.curl.is_easy:
                body_reader.resume = self.curl.resume_upload
            else:
                # The easy interface (--auth=NONE) has no loop to apply a resume, and pymcurl without
                # pause/resume cannot pause: block mcurl's thread instead (an easy transfer owns its
                # thread, so a stalled client delays nobody else)
                body_reader.blocking = True
            self.curl.bridge(body_reader, response_writer, header_writer)

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
        try:
            success = await asyncio.to_thread(STATE.mcurl.do, self.curl)
        finally:
            if proxy_resolve is not None:
                # CURLOPT_RESOLVE retains the slist pointer, so clear it before
                # releasing the request-scoped DNS override.
                self.curl.unsetopt(mcurl.libcurl.CURLOPT_RESOLVE)
                mcurl.libcurl.curl_slist_free_all(proxy_resolve)

        if not success:
            dprint(self.curl.easyhash + ": Connection failed: " + self.curl.errstr)

            # If SSO auth failure or mechanism error, force Kerberos ticket check
            if (self.curl.resp == 401 and "single sign-on failed" in self.curl.errstr) or (
                self.curl.resp == 407 and "auth mechanism error" in self.curl.errstr
            ):
                STATE.reload_kerberos(force=True)

            if self.curl.resp == 503 and self._is_rewind_error(self.curl.errstr):
                dprint(self.curl.easyhash + ": " + REWIND_MESSAGE)
                self._send_error(503, REWIND_MESSAGE)
            else:
                self._send_error(self.curl.resp, self.curl.errstr)
        elif self.curl.is_connect:
            await self._handle_connect_tunnel(h11_trailing=self._recv_buf)
            self._recv_buf = b""  # Consumed by tunnel

        await asyncio.to_thread(STATE.mcurl.remove, self.curl)

    async def _set_proxy_resolve(self, host, port):
        """Seed libcurl's DNS cache with Px's shared proxy lookup.

        A burst of new handles otherwise starts one resolver request per
        handle.  Sharing the existing Wproxy resolver keeps a busy local DNS
        service from exhausting the connection timeout before uploads begin.
        """
        address = await asyncio.to_thread(STATE.wproxy._get_resolver().lookup, host)
        if address is None or address == host:
            return None

        entry = f"{host}:{port}:{address}"
        resolve = mcurl.libcurl.curl_slist_append(mcurl.ffi.NULL, mcurl.py2cstr(entry))
        if resolve == mcurl.ffi.NULL:
            dprint(self.curl.easyhash + ": Could not allocate proxy DNS override")
            return None
        self.curl.setopt(mcurl.libcurl.CURLOPT_RESOLVE, resolve)
        return resolve

    @staticmethod
    def _upstream_headers(headers, strip_proxy_headers=False, strip_proxy_auth=False):
        """Client headers to forward upstream.

        Drops hop-by-hop headers (Connection and the headers it names, Proxy-Connection,
        Keep-Alive, TE, Trailer, Upgrade) since they describe the client connection and
        e.g. a forwarded "Connection: close" makes a proxy drop an NTLM handshake. Expect
        is dropped too: Px answers the client itself and mcurl picks the upstream Expect.
        Content-Length is dropped when the body is chunked (Transfer-Encoding wins), and
        Proxy-Authorization when Px authenticates to the upstream proxy itself.
        """
        named = {t.strip().lower() for t in headers.get("connection", "").split(",") if t.strip()}
        drop = (named | HOP_BY_HOP_HEADERS | {"expect"}) - {"content-length", "transfer-encoding", "host"}
        if "chunked" in headers.get("transfer-encoding", "").lower():
            drop.add("content-length")
        if strip_proxy_auth:
            drop.add("proxy-authorization")
        return {
            name: value
            for name, value in headers.items()
            if name.lower() not in drop and not (strip_proxy_headers and name.lower().startswith("proxy-"))
        }

    @staticmethod
    def _is_rewind_error(errstr):
        "True if mcurl could not resend a streamed body (REWIND_ERROR, or libcurl's own text on older mcurl)"
        rewind = getattr(mcurl, "REWIND_ERROR", None)
        return bool(rewind and rewind in errstr) or "rewinding of the data stream failed" in errstr

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
                # os._exit() bypasses the loop's normal transport cleanup.  Drain
                # first so frozen event loops deliver the successful quit response.
                await self.writer.drain()
                STATE.cleanup_kerberos()
                # Give time for the response to be sent
                await asyncio.sleep(0.1)
                os._exit(config.ERROR_SUCCESS)

        self._send_error(403)
