"Px proxy handler for incoming requests"

import http.server
import os
import socket
import sys

from .config import STATE
from .debug import dprint

from . import mcurl
from . import wproxy

# External dependencies
import keyring

###
# Proxy handler

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

    def do_GET(self):
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
