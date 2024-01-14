"Px is an HTTP proxy server to automatically authenticate through an NTLM proxy"

import concurrent.futures
import http.server
import multiprocessing
import os
import signal
import socket
import socketserver
import sys
import threading
import time
import traceback
import warnings

from .config import State
from .debug import pprint
from .version import __version__

from . import config
from . import mcurl
from . import wproxy

if sys.platform == "win32":
    from . import windows

warnings.filterwarnings("ignore")

# External dependencies
import keyring

# Debug shortcut
dprint = lambda x: None

###
# Proxy handler

def set_curl_auth(curl, auth):
    "Set proxy authentication info for curl object"
    if auth != "NONE":
        # Connecting to proxy and authenticating
        key = ""
        pwd = None
        if len(State.username) != 0:
            key = State.username
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

class Proxy(http.server.BaseHTTPRequestHandler):
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
                State.mcurl.stop(self.curl)
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
            self.curl = mcurl.Curl(self.path, self.command, self.request_version, State.socktimeout)
        else:
            self.curl.reset(self.path, self.command, self.request_version, State.socktimeout)

        dprint(self.curl.easyhash + ": Path = " + self.path)
        ipport = self.get_destination()
        if ipport is None:
            dprint(self.curl.easyhash + ": Configuring proxy settings")
            server = self.proxy_servers[0][0]
            port = self.proxy_servers[0][1]
            # libcurl handles noproxy domains only. IP addresses are still handled within wproxy
            # since libcurl only supports CIDR addresses since v7.86 and does not support wildcards
            # (192.168.0.*) or ranges (192.168.0.1-192.168.0.255)
            noproxy_hosts = ",".join(State.wproxy.noproxy_hosts) or None
            ret = self.curl.set_proxy(proxy = server, port = port, noproxy = noproxy_hosts)
            if not ret:
                # Proxy server has had auth issues so returning failure to client
                self.send_error(401, "Proxy server authentication failed: %s:%d" % (server, port))
                return

            # Set proxy authentication
            set_curl_auth(self.curl, State.auth)
        else:
            # Directly connecting to the destination
            dprint(self.curl.easyhash + ": Skipping auth proxying")

        # Set debug mode
        self.curl.set_debug(State.debug is not None)

        # Plain HTTP can be bridged directly
        if not self.curl.is_connect:
            self.curl.bridge(self.rfile, self.wfile, self.wfile)

        # Set headers for request
        self.curl.set_headers(self.headers)

        # Turn off transfer decoding
        self.curl.set_transfer_decoding(False)

        # Set user agent if configured
        self.curl.set_useragent(State.useragent)

        if not State.mcurl.do(self.curl):
            dprint(self.curl.easyhash + ": Connection failed: " + self.curl.errstr)
            self.send_error(self.curl.resp, self.curl.errstr)
        elif self.curl.is_connect:
            if self.curl.is_tunnel or not self.curl.is_proxied:
                # Inform client that SSL connection has been established
                dprint(self.curl.easyhash + ": SSL connected")
                self.send_response(200, "Connection established")
                self.send_header("Proxy-Agent", self.version_string())
                self.end_headers()
            State.mcurl.select(self.curl, self.connection, State.idle)
            self.close_connection = True

        State.mcurl.remove(self.curl)

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
        config.reload_proxy()

        # Find proxy
        servers, netloc, path = State.wproxy.find_proxy_for_url(
            ("https://" if "://" not in self.path else "") + self.path)
        if servers[0] == wproxy.DIRECT:
            dprint(self.curl.easyhash + ": Direct connection")
            return netloc
        else:
            dprint(self.curl.easyhash + ": Proxy = " + str(servers))
            self.proxy_servers = servers
            return None

###
# Multi-processing and multi-threading

class PoolMixIn(socketserver.ThreadingMixIn):
    pool = None

    def process_request(self, request, client_address):
        self.pool.submit(self.process_request_thread, request, client_address)

    def verify_request(self, request, client_address):
        dprint("Client address: %s" % client_address[0])
        if client_address[0] in State.allow:
            return True

        if State.hostonly and client_address[0] in config.get_host_ips():
            dprint("Host-only IP allowed")
            return True

        dprint("Client not allowed: %s" % client_address[0])
        return False

class ThreadedTCPServer(PoolMixIn, socketserver.TCPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, server_address, RequestHandlerClass,
            bind_and_activate=True):
        socketserver.TCPServer.__init__(self, server_address,
            RequestHandlerClass, bind_and_activate)

        try:
            # Workaround bad thread naming code in Python 3.6+, fixed in master
            self.pool = concurrent.futures.ThreadPoolExecutor(
                max_workers=State.config.getint("settings", "threads"),
                thread_name_prefix="Thread")
        except:
            self.pool = concurrent.futures.ThreadPoolExecutor(
                max_workers=State.config.getint("settings", "threads"))

def print_banner(listen, port):
    pprint("Serving at %s:%d proc %s" % (
        listen, port, multiprocessing.current_process().name)
    )

    if sys.platform == "win32":
        if config.is_compiled() or "pythonw.exe" in sys.executable:
            if State.config.getint("settings", "foreground") == 0:
                windows.detach_console(State, dprint)

    for section in State.config.sections():
        for option in State.config.options(section):
            dprint(section + ":" + option + " = " + State.config.get(
                section, option))

def serve_forever(httpd):
    httpd.serve_forever()
    httpd.shutdown()

def start_httpds(httpds):
    for httpd in httpds[:-1]:
        # Start server in a thread for each listen address
        thrd = threading.Thread(target = serve_forever, args = (httpd,))
        thrd.start()

    # Start server in main thread for last listen address
    serve_forever(httpds[-1])

def start_worker(pipeout):
    global dprint

    # CTRL-C should exit the process
    signal.signal(signal.SIGINT, signal.SIG_DFL)

    config.parse_config()
    dprint = State.debug.get_print()

    port = State.config.getint("proxy", "port")
    httpds = []
    for listen in State.listen:
        # Get socket from parent process for each listen address
        mainsock = pipeout.recv()
        if hasattr(socket, "fromshare"):
            mainsock = socket.fromshare(mainsock)

        # Start server but use socket from parent process
        httpd = ThreadedTCPServer((listen, port), Proxy, bind_and_activate=False)
        httpd.socket = mainsock

        httpds.append(httpd)

        print_banner(listen, port)

    start_httpds(httpds)

def run_pool():
    # CTRL-C should exit the process
    signal.signal(signal.SIGINT, signal.SIG_DFL)

    port = State.config.getint("proxy", "port")
    httpds = []
    mainsocks = []
    for listen in State.listen:
        # Setup server for each listen address
        try:
            httpd = ThreadedTCPServer((listen, port), Proxy)
        except OSError as exc:
            if "attempt was made" in str(exc):
                pprint("Px failed to start - port in use")
            else:
                pprint(exc)
            return

        httpds.append(httpd)
        mainsocks.append(httpd.socket)

        print_banner(listen, port)

    if sys.platform != "darwin":
        # Multiprocessing enabled on Windows and Linux, no idea how shared sockets
        # work on MacOSX
        if sys.platform == "linux" or hasattr(socket, "fromshare"):
            # Windows needs Python > 3.3 which added socket.fromshare()- have to
            # explicitly share socket with child processes
            #
            # Linux shares all open FD with children since it uses fork()
            workers = State.config.getint("settings", "workers")
            for i in range(workers-1):
                (pipeout, pipein) = multiprocessing.Pipe()
                p = multiprocessing.Process(target=start_worker, args=(pipeout,))
                p.daemon = True
                p.start()
                while p.pid is None:
                    time.sleep(1)
                for mainsock in mainsocks:
                    # Share socket for each listen address to child process
                    if hasattr(socket, "fromshare"):
                        # Send duplicate socket explicitly shared with child for Windows
                        pipein.send(mainsock.share(p.pid))
                    else:
                        # Send socket as is for Linux
                        pipein.send(mainsock)

    start_httpds(httpds)

###
# Actions

def test(testurl):
    # Get Px configuration
    listen = State.listen[0]
    if len(listen) == 0:
        # Listening on all interfaces - figure out which one is allowed
        hostips = config.get_host_ips()
        if State.gateway:
            # Check allow list
            for ip in hostips:
                if ip in State.allow:
                    listen = str(ip)
                    break
            if len(listen) == 0:
                pprint("Failed: host IP not in --allow to test Px")
                sys.exit()
        elif State.hostonly:
            # Use first host IP
            listen = str(list(hostips)[0])
    port = State.config.getint("proxy", "port")

    # Tweak Px configuration for test - only 1 process required
    State.config.set("settings", "workers", "1")

    if "--test-auth" in sys.argv:
        # Set Px to --auth=NONE
        auth = State.auth
        State.auth = "NONE"
        State.config.set("proxy", "auth", "NONE")
    else:
        auth = "NONE"

    def query(url, method="GET", data = None, quit=True):
        if quit:
            time.sleep(0.1)

        ec = mcurl.Curl(url, method)
        ec.set_proxy(listen, port)
        set_curl_auth(ec, auth)
        ec.set_debug(State.debug is not None)
        if data is not None:
            ec.buffer(data.encode("utf-8"))
            ec.set_headers({"Content-Length": len(data)})
        else:
            ec.buffer()
        ec.set_useragent("mcurl v" + __version__)
        ret = ec.perform()
        pprint(f"\nTesting {method} {url}")
        if ret != 0:
            pprint(f"Failed with error {ret}\n{ec.errstr}")
            os._exit(1)
        else:
            ret_data = ec.get_data()
            pprint(f"\n{ec.get_headers()}Response length: {len(ret_data)}")
            if testurl == "all":
                if url not in ret_data:
                    pprint(f"Failed: response does not contain {url}:\n{ret_data}")
                    os._exit(1)
                if data is not None and data not in ret_data:
                    pprint(f"Failed: response does not match {data}:\n{ret_data}")
                    os._exit(1)

        if quit:
            os._exit(0)

    def queryall():
        import uuid

        url = "://httpbin.org/"
        for method in ["GET", "POST", "PUT", "DELETE", "PATCH"]:
            for protocol in ["http", "https"]:
                testurl = protocol + url + method.lower()
                data = str(uuid.uuid4()) if method in ["POST", "PUT", "PATCH"] else None
                query(testurl, method, data, quit=False)

        os._exit(0)

    # Run testurl query in a thread
    if testurl in ["all", "1"]:
        t = threading.Thread(target = queryall)
    else:
        t = threading.Thread(target = query, args = (testurl,))
    t.daemon = True
    t.start()

    # Run Px to respond to query
    run_pool()

###
# Exit related

def handle_exceptions(extype, value, tb):
    # Create traceback log
    lst = (traceback.format_tb(tb, None) +
        traceback.format_exception_only(extype, value))
    tracelog = '\nTraceback (most recent call last):\n' + "%-20s%s\n" % (
        "".join(lst[:-1]), lst[-1])

    if State.debug is not None:
        pprint(tracelog)
    else:
        sys.stderr.write(tracelog)

        # Save to debug.log in working directory
        dbg = open(config.get_logfile(config.LOG_CWD), 'w')
        dbg.write(tracelog)
        dbg.close()

###
# Startup

def main():
    global dprint
    multiprocessing.freeze_support()
    sys.excepthook = handle_exceptions

    config.parse_config()
    dprint = State.debug.get_print()

    if State.test is not None:
        test(State.test)

    run_pool()

if __name__ == "__main__":
    main()
