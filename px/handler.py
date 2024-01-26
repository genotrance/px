"Px proxy handler for incoming requests"

import base64
import hashlib
import html
import http.server
import os
import socket
import sys
import time

from .config import STATE, CLIENT_REALM
from .debug import pprint, dprint

from . import config
from . import mcurl
from . import wproxy

# External dependencies
import keyring

try:
    import spnego._ntlm

    from spnego._ntlm_raw.crypto import (
        lmowfv1,
        ntowfv1,
        ntowfv2
    )
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
    if password is not  None:
        lmhash = lmowfv1(password)
        nthash = ntowfv1(password)
        return domain, username, lmhash, nthash

    raise spnego.exceptions.SpnegoError(
        spnego.exceptions.ErrorCode.failure, "Bad credentials")
spnego._ntlm._get_credential = _get_credential

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
        if len(STATE.username) != 0:
            key = STATE.username
            if "PX_PASSWORD" in os.environ:
                # Use environment variable PX_PASSWORD
                pwd = os.environ["PX_PASSWORD"]
            else:
                # Use keyring to get password
                pwd = keyring.get_password("Px", key)
        if len(key) == 0:
            if sys.platform == "win32":
                dprint(curl.easyhash + ": Using SSPI to login")
                key = ":"
            else:
                dprint("SSPI not available and no username configured - no auth")
                return
        curl.set_auth(user = key, password = pwd, auth = auth)
    else:
        # Explicitly deferring proxy authentication to the client
        dprint(curl.easyhash + ": Skipping proxy authentication")
        curl.is_easy = True

###
# Proxy handler

class PxHandler(http.server.BaseHTTPRequestHandler):
    "Handler for each proxy connection - unique instance for each thread in each process"

    protocol_version = "HTTP/1.1"

    # Contains the proxy servers responsible for the url this Proxy instance
    # (aka thread) serves
    proxy_servers = []
    curl = None

    def handle_one_request(self):
        try:
            http.server.BaseHTTPRequestHandler.handle_one_request(self)
        except socket.error as error:
            self.close_connection = True
            easyhash = ""
            if self.curl is not None:
                easyhash = self.curl.easyhash + ": "
                STATE.mcurl.stop(self.curl)
                self.curl = None
            dprint(easyhash + str(error))
        except ConnectionError:
            pass

    def address_string(self):
        host, port = self.client_address[:2]
        #return socket.getfqdn(host)
        return host

    def log_message(self, format, *args):
        dprint(format % args)

    def do_curl(self):
        "Handle incoming request using libcurl"
        if not self.do_client_auth():
            return

        if self.curl is None:
            self.curl = mcurl.Curl(self.path, self.command, self.request_version, STATE.socktimeout)
        else:
            self.curl.reset(self.path, self.command, self.request_version, STATE.socktimeout)

        dprint(self.curl.easyhash + ": Path = " + self.path)
        ipport = self.get_destination()
        if ipport is None:
            dprint(self.curl.easyhash + ": Configuring proxy settings")
            server = self.proxy_servers[0][0]
            port = self.proxy_servers[0][1]
            # libcurl handles noproxy domains only. IP addresses are still handled within wproxy
            # since libcurl only supports CIDR addresses since v7.86 and does not support wildcards
            # (192.168.0.*) or ranges (192.168.0.1-192.168.0.255)
            noproxy_hosts = ",".join(STATE.wproxy.noproxy_hosts) or None
            ret = self.curl.set_proxy(proxy = server, port = port, noproxy = noproxy_hosts)
            if not ret:
                # Proxy server has had auth issues so returning failure to client
                self.send_error(401, f"Proxy server authentication failed: {server}:{port}")
                return

            # Set proxy authentication
            set_curl_auth(self.curl, STATE.auth)
        else:
            # Directly connecting to the destination
            dprint(self.curl.easyhash + ": Skipping auth proxying")

        # Set debug mode
        self.curl.set_debug(STATE.debug is not None)

        # Plain HTTP can be bridged directly
        if not self.curl.is_connect:
            self.curl.bridge(self.rfile, self.wfile, self.wfile)

        # Set headers for request
        self.curl.set_headers(self.headers)

        # Turn off transfer decoding
        self.curl.set_transfer_decoding(False)

        # Set user agent if configured
        self.curl.set_useragent(STATE.useragent)

        if not STATE.mcurl.do(self.curl):
            dprint(self.curl.easyhash + ": Connection failed: " + self.curl.errstr)
            self.send_error(self.curl.resp, self.curl.errstr)
        elif self.curl.is_connect:
            if self.curl.is_tunnel or not self.curl.is_proxied:
                # Inform client that SSL connection has been established
                dprint(self.curl.easyhash + ": SSL connected")
                self.send_response(200, "Connection established")
                self.send_header("Proxy-Agent", self.version_string())
                self.end_headers()
            STATE.mcurl.select(self.curl, self.connection, STATE.idle)
            self.close_connection = True

        STATE.mcurl.remove(self.curl)

    def do_quit(self):
        "Handle quit request - client has to be host"
        hostips = config.get_host_ips()
        for listen in STATE.listen:
            if ((len(listen) == 0 and self.client_address[0] in hostips) or
                # client address matches any hostip since --hostonly or --gateway
                (self.client_address[0] == listen)):
                # client address matches --listen
                    # Quit request from same host
                    self.send_response(200)
                    self.end_headers()
                    os._exit(config.ERROR_SUCCESS)

        self.send_error(403)

    def do_GET(self):
        if self.path == "/PxQuit":
            self.do_quit()
        else:
            self.do_curl()

    def do_HEAD(self):
        self.do_curl()

    def do_POST(self):
        self.do_curl()

    def do_PUT(self):
        self.do_curl()

    def do_DELETE(self):
        self.do_curl()

    def do_PATCH(self):
        self.do_curl()

    def do_CONNECT(self):
        self.do_curl()

    def get_destination(self):
        # Reload proxy info if timeout exceeded
        STATE.reload_proxy()

        # Find proxy
        servers, netloc, path = STATE.wproxy.find_proxy_for_url(
            ("https://" if "://" not in self.path else "") + self.path)
        if servers[0] == wproxy.DIRECT:
            dprint(self.curl.easyhash + ": Direct connection")
            return netloc
        else:
            dprint(self.curl.easyhash + ": Proxy = " + str(servers))
            self.proxy_servers = servers
            return None

    # Client authentication

    def get_digest_nonce(self):
        "Get a new nonce for Digest authentication"

        # Timestamp in seconds
        timestamp = int(time.time())

        # key = timestamp:clientIP:CLIENT_REALM
        key = f"{timestamp}:{self.client_address[0]}:{CLIENT_REALM}"

        # Compute the SHA-256 hash of the key
        keyhash = hashlib.sha256(key.encode("utf-8")).hexdigest()

        # Combine with timestamp
        nonce_dec = f"{timestamp}:{keyhash}"

        # Base64 encode the nonce
        nonce = base64.b64encode(nonce_dec.encode("utf-8")).decode("utf-8")
        return nonce

    def verify_digest_nonce(self, nonce):
        "Verify the nonce received from the client"

        # Base64 decode the nonce
        nonce_dec = base64.b64decode(nonce.encode("utf-8")).decode("utf-8")

        # Split the nonce by colons
        try:
            # Should be timestamp:keyhash
            timestamp_str, keyhash = nonce_dec.split(":", 1)

            # Convert the timestamp to an integer
            timestamp = int(timestamp_str)
        except ValueError:
            dprint("Invalid nonce format")
            return False

        # Check if the timestamp is not more than 2 minutes old
        if time.time() - timestamp > 120:
            dprint("Nonce has expired")
            return False

        # Regenerate key
        key = f"{timestamp}:{self.client_address[0]}:{CLIENT_REALM}"

        # Compute the SHA-256 hash of the key
        keyhash_new = hashlib.sha256(key.encode("utf-8")).hexdigest()

        # Check if the keyhash matches
        if keyhash != keyhash_new:
            dprint("Invalid nonce hash")
            return False

        # Nonce is valid
        return True

    def send_html(self, code, message):
        "Send HTML error page - from BaseHTTPRequestHandler.send_error()"
        content = (self.error_message_format % {
                'code': code,
                'message': html.escape(message, quote=False),
                'explain': self.responses[code]
            })
        body = content.encode('UTF-8', 'replace')
        self.send_header("Content-Type", self.error_content_type)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()

        if self.command != 'HEAD' and body:
            self.wfile.write(body)

    def send_auth_headers(self, authtype="", challenge=""):
        "Send authentication headers to client"
        self.send_response(407, "Proxy authentication required")

        self.client_authed = False
        if len(authtype) != 0 and len(challenge) != 0:
            # Send authentication challenge
            self.send_header("Proxy-Authenticate", authtype + " " + challenge)
        else:
            # Send supported authentication types
            if "NEGOTIATE" in STATE.client_auth:
                self.send_header("Proxy-Authenticate", "Negotiate")

            if "NTLM" in STATE.client_auth:
                self.send_header("Proxy-Authenticate", "NTLM")

            if "DIGEST" in STATE.client_auth:
                digest_header = f'Digest realm="{CLIENT_REALM}", qop="auth", algorithm="MD5"'
                digest_header += f', nonce="{self.get_digest_nonce()}", opaque="{os.urandom(16).hex()}"'
                self.send_header("Proxy-Authenticate", digest_header)

            if "BASIC" in STATE.client_auth:
                self.send_header("Proxy-Authenticate", f'Basic realm="{CLIENT_REALM}"')

        self.send_header("Proxy-Connection", "Keep-Alive")
        self.send_html(407, "Proxy authentication required")

    def do_spnego_auth(self, auth_header, authtype):
        "Verify client login using pyspnego for authentication - NEGOTIATE, NTLM"
        encoded_credentials = auth_header[len(authtype + " "):]
        if not hasattr(self, "client_ctxt"):
            # Create new context for this client:port combo
            if authtype == "NEGOTIATE":
                authtype = "Negotiate"
                options = spnego.NegotiateOptions.use_negotiate
            else:
                options = spnego.NegotiateOptions.use_ntlm
            if sys.platform == "win32" and not STATE.client_nosspi:
                options = spnego.NegotiateOptions.use_sspi
            self.client_ctxt = spnego.auth.server(
                protocol=authtype.lower(), options=options)
        try:
            outok = self.client_ctxt.step(base64.b64decode(encoded_credentials))
        except (spnego.exceptions.InvalidTokenError,
                spnego.exceptions.SpnegoError,
                ValueError) as exc:
            # Invalid token = bad login or auth issues
            dprint("Authentication failed: " + str(exc))
            self.send_error(401, "Authentication failed")
            return False
        if outok is not None:
            # Send challenge = client needs to send response
            dprint(f"Sending {authtype} challenge")
            self.send_auth_headers(
                authtype = authtype, challenge = base64.b64encode(outok).decode("utf-8"))
            return False
        else:
            # Authentication complete
            dprint(f"Authenticated {authtype} client")
            self.client_authed = True
            del self.client_ctxt
            for key in list(self.headers.keys()):
                # Remove any proxy headers
                if key.startswith("Proxy-"):
                    del self.headers[key]
            return True

    def do_digest_auth(self, auth_header):
        "Verify client login using Digest authentication"
        encoded_credentials = auth_header[len("Digest "):]
        params = {}
        for param in encoded_credentials.split(","):
            key, value = param.strip().split("=", 1)
            params[key] = value.strip('"').replace("\\\\", "\\")

        # Check if nonce is present and valid
        nonce = params.get("nonce", "")
        if len(nonce) == 0:
            dprint("Authentication failed: No nonce")
            self.send_error(401, "Authentication failed")
            return False
        if not self.verify_digest_nonce(nonce):
            dprint("Authentication failed: Invalid nonce")
            self.send_error(401, "Authentication failed")
            return False

        client_username = params.get("username", "")
        client_password = get_client_password(client_username)
        if client_password is None:
            dprint("Authentication failed: Bad username")
            self.send_error(401, "Authentication failed")
            return False

        # Check if digest response matches
        A1 = f"{client_username}:{CLIENT_REALM}:{client_password}"
        HA1 = hashlib.md5(A1.encode("utf-8")).hexdigest()
        A2 = f'{self.command}:{params["uri"]}'
        HA2 = hashlib.md5(A2.encode("utf-8")).hexdigest()
        A3 = f'{HA1}:{params["nonce"]}:{params["nc"]}:{params["cnonce"]}:{params["qop"]}:{HA2}'
        response = hashlib.md5(A3.encode("utf-8")).hexdigest()

        if response != params["response"]:
            dprint("Authentication failed: Bad response")
            self.send_error(401, "Authentication failed")
            return False
        else:
            # Username and password matches
            dprint("Authenticated Digest client")
            self.client_authed = True
            for key in list(self.headers.keys()):
                # Remove any proxy headers
                if key.startswith("Proxy-"):
                    del self.headers[key]
            return True

    def do_basic_auth(self, auth_header):
        "Verify client login using Basic authentication"
        encoded_credentials = auth_header[len("Basic "):]
        credentials = base64.b64decode(encoded_credentials).decode("utf-8")
        username, password = credentials.split(":", 1)

        client_password = get_client_password(username)
        if client_password is None or client_password != password:
            dprint("Authentication failed")
            self.send_error(401, "Authentication failed")
            return False

        # Username and password matches
        dprint("Authenticated Basic client")
        self.client_authed = True
        return True

    def do_client_auth(self):
        "Handle authentication of clients"
        if len(STATE.client_auth) != 0:
            # Check for authentication header
            auth_header = self.headers.get("Proxy-Authorization")
            if auth_header is None:
                # No authentication header
                if not hasattr(self, "client_authed") or not self.client_authed:
                    # Not already logged in
                    dprint("No auth header")
                    self.send_auth_headers()
                    return False
                elif self.command in ["POST", "PUT", "PATCH"]:
                    # POST / PUT with Content-Length = 0
                    content_length = self.headers.get("Content-Length")
                    if content_length is not None and content_length == "0":
                        dprint("POST/PUT expects to receive auth headers")
                        self.send_auth_headers()
                        return False
                else:
                    dprint("Client already authenticated")
            else:
                # Check if authentication type is supported
                authtype = auth_header.split(" ", 1)[0].upper()
                if authtype not in STATE.client_auth:
                    self.send_auth_headers()
                    dprint("Unsupported client auth type: " + authtype)
                    return False

                # Authenticate client using the specified authentication type
                dprint("Auth type: " + authtype)
                if authtype in ["NEGOTIATE", "NTLM"]:
                    if not self.do_spnego_auth(auth_header, authtype):
                        return False
                elif authtype == "DIGEST":
                    if not self.do_digest_auth(auth_header):
                        return False
                elif authtype == "BASIC":
                    if not self.do_basic_auth(auth_header):
                        return False
        else:
            dprint("No client authentication required")

        return True