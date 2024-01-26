"Px is an HTTP proxy server to automatically authenticate through an NTLM proxy"

import concurrent.futures
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

from .config import STATE
from .debug import pprint, dprint
from .version import __version__

from . import config
from . import handler
from . import mcurl

if sys.platform == "win32":
    from . import windows

warnings.filterwarnings("ignore")

###
# Multi-processing and multi-threading

class PoolMixIn(socketserver.ThreadingMixIn):
    pool = None

    def process_request(self, request, client_address):
        self.pool.submit(self.process_request_thread, request, client_address)

    def verify_request(self, request, client_address):
        dprint("Client address: %s" % client_address[0])
        if client_address[0] in STATE.allow:
            return True

        if STATE.hostonly and client_address[0] in config.get_host_ips():
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
                max_workers=STATE.config.getint("settings", "threads"),
                thread_name_prefix="Thread")
        except:
            self.pool = concurrent.futures.ThreadPoolExecutor(
                max_workers=STATE.config.getint("settings", "threads"))

def print_banner(listen, port):
    pprint(f"Serving at {listen}:{port} proc {multiprocessing.current_process().name}")

    if sys.platform == "win32":
        if config.is_compiled() or "pythonw.exe" in sys.executable:
            if STATE.config.getint("settings", "foreground") == 0:
                windows.detach_console(STATE)

    for section in STATE.config.sections():
        for option in STATE.config.options(section):
            dprint(section + ":" + option + " = " + STATE.config.get(
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
    # CTRL-C should exit the process
    signal.signal(signal.SIGINT, signal.SIG_DFL)

    STATE.parse_config()

    port = STATE.config.getint("proxy", "port")
    httpds = []
    for listen in STATE.listen:
        # Get socket from parent process for each listen address
        mainsock = pipeout.recv()
        if hasattr(socket, "fromshare"):
            mainsock = socket.fromshare(mainsock)

        # Start server but use socket from parent process
        httpd = ThreadedTCPServer((listen, port), handler.PxHandler, bind_and_activate=False)
        httpd.socket = mainsock

        httpds.append(httpd)

        print_banner(listen, port)

    start_httpds(httpds)

def run_pool():
    # CTRL-C should exit the process
    signal.signal(signal.SIGINT, signal.SIG_DFL)

    port = STATE.config.getint("proxy", "port")
    httpds = []
    mainsocks = []
    for listen in STATE.listen:
        # Setup server for each listen address
        try:
            httpd = ThreadedTCPServer((listen, port), handler.PxHandler)
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
            workers = STATE.config.getint("settings", "workers")
            for _ in range(workers-1):
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
    listen = config.get_listen()
    port = STATE.config.getint("proxy", "port")

    if len(listen) == 0:
        pprint("Failed: Px not listening on localhost - cannot run test")
        sys.exit(config.ERROR_TEST)

    # Tweak Px configuration for test - only 1 process required
    STATE.config.set("settings", "workers", "1")

    if "--test-auth" in sys.argv:
        # Set Px to --auth=NONE
        auth = STATE.auth
        STATE.auth = "NONE"
        STATE.config.set("proxy", "auth", "NONE")
    else:
        auth = "NONE"

    def waitforpx():
        count = 0
        while True:
            try:
                socket.create_connection((listen, port), 1)
                break
            except (socket.timeout, ConnectionRefusedError):
                time.sleep(0.1)
                count += 1
                if count == 5:
                    pprint("Failed: Px did not start")
                    os._exit(config.ERROR_TEST)

    def query(url, method="GET", data = None, quit=True, check=False, insecure=False):
        if quit:
            waitforpx()

        ec = mcurl.Curl(url, method)
        ec.set_proxy(listen, port)
        handler.set_curl_auth(ec, auth)
        if url.startswith("https"):
            ec.set_insecure(insecure)
        ec.set_debug(STATE.debug is not None)
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
            os._exit(config.ERROR_TEST)
        else:
            ret_data = ec.get_data()
            pprint(f"\n{ec.get_headers()}Response length: {len(ret_data)}")
            if check:
                # Tests against httpbin
                if url not in ret_data:
                    pprint(f"Failed: response does not contain {url}:\n{ret_data}")
                    os._exit(config.ERROR_TEST)
                if data is not None and data not in ret_data:
                    pprint(f"Failed: response does not match {data}:\n{ret_data}")
                    os._exit(config.ERROR_TEST)

        if quit:
            os._exit(config.ERROR_SUCCESS)

    def queryall(testurl):
        import uuid

        waitforpx()

        insecure = False
        if testurl in ["all", "1"]:
            url = "://httpbin.org/"
        elif testurl.startswith("all:"):
            url = f"://{testurl[4:]}/"
            insecure = True

        for method in ["GET", "POST", "PUT", "DELETE", "PATCH"]:
            for protocol in ["http", "https"]:
                testurl = protocol + url + method.lower()
                data = str(uuid.uuid4()) if method in ["POST", "PUT", "PATCH"] else None
                query(testurl, method, data, quit=False, check=True, insecure=insecure)

        os._exit(config.ERROR_SUCCESS)

    # Run testurl query in a thread
    if testurl in ["all", "1"] or testurl.startswith("all:"):
        t = threading.Thread(target = queryall, args = (testurl,))
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

    if STATE.debug is not None:
        pprint(tracelog)
    else:
        sys.stderr.write(tracelog)

        # Save to debug.log in working directory
        with open(config.get_logfile(config.LOG_CWD), 'w') as dbg:
            dbg.write(tracelog)

###
# Startup

def main():
    multiprocessing.freeze_support()
    sys.excepthook = handle_exceptions

    STATE.parse_config()

    if STATE.test is not None:
        test(STATE.test)

    run_pool()

if __name__ == "__main__":
    main()
