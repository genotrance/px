"Px is an HTTP proxy server to automatically authenticate through an NTLM proxy"

import asyncio
import concurrent.futures
import multiprocessing
import os
import signal
import socket
import sys
import threading
import time
import traceback
import warnings

from . import config, handler
from .config import STATE
from .debug import Debug, dprint, pprint
from .version import __version__

if sys.platform == "win32":
    from . import windows

import mcurl

warnings.filterwarnings("ignore")

###
# Server startup helpers


def create_listen_socket(listen, port):
    "Create a bound, listening TCP socket for the given address and port"
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if hasattr(socket, "SO_REUSEPORT"):
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    try:
        sock.bind((listen, port))
    except OSError:
        sock.close()
        raise
    sock.listen(128)
    sock.setblocking(False)
    return sock


def print_banner(listen, port):
    pprint(f"Serving at {listen}:{port} proc " + multiprocessing.current_process().name)

    if sys.platform == "win32":
        is_background = config.is_compiled() or "pythonw.exe" in sys.executable
        if is_background and STATE.config.getint("settings", "foreground") == 0:
            windows.detach_console(STATE)

    dprint(f"Px v{__version__}")
    for section in STATE.config.sections():
        for option in STATE.config.options(section):
            dprint(section + ":" + option + " = " + STATE.config.get(section, option))


def verify_client(client_address):
    "Check if client is allowed to connect"
    dprint(f"Client address: {client_address}")
    if client_address in STATE.allow:
        return True

    if STATE.hostonly and client_address in config.get_host_ips():
        dprint("Host-only IP allowed")
        return True

    dprint(f"Client not allowed: {client_address}")
    return False


async def handle_connection(reader, writer):
    "Handle a new client connection"
    peername = writer.get_extra_info("peername")
    if peername and not verify_client(peername[0]):
        writer.close()
        return

    conn = handler.ConnectionHandler(reader, writer)
    await conn.handle()


async def start_server(listen, port, sock=None):
    "Start an async proxy server"
    if sock is not None:
        server = await asyncio.start_server(handle_connection, sock=sock, backlog=128)
    else:
        server = await asyncio.start_server(handle_connection, listen, port, backlog=128, reuse_address=True)
    return server


async def run_async_servers(listen_addrs, port, socks=None):
    "Start async proxy servers for all listen addresses and run until stopped"
    # Configure thread pool for blocking mcurl.do() calls
    threads = STATE.config.getint("settings", "threads")
    loop = asyncio.get_event_loop()
    loop.set_default_executor(concurrent.futures.ThreadPoolExecutor(max_workers=threads))

    servers = []
    for i, listen in enumerate(listen_addrs):
        if socks:
            srv = await start_server(listen, port, sock=socks[i])
        else:
            srv = await start_server(listen, port)
        servers.append(srv)

    # Serve forever on all listen addresses
    await asyncio.gather(*[srv.serve_forever() for srv in servers])


###
# Multi-processing


def start_worker():
    # CTRL-C should exit the process
    signal.signal(signal.SIGINT, signal.SIG_DFL)

    STATE.parse_config()

    port = STATE.config.getint("proxy", "port")
    socks = []
    for listen in STATE.listen:
        # Each worker creates its own listening socket with SO_REUSEPORT/SO_REUSEADDR
        # so each process has an independent IOCP registration (Windows) or kernel
        # load-balanced accept (Linux/macOS)
        sock = create_listen_socket(listen, port)
        socks.append(sock)
        print_banner(listen, port)

    asyncio.run(run_async_servers(STATE.listen, port, socks=socks))


def run_pool():
    # CTRL-C should exit the process
    signal.signal(signal.SIGINT, signal.SIG_DFL)

    port = STATE.config.getint("proxy", "port")
    workers = STATE.config.getint("settings", "workers")
    Debug.workers = workers

    mainsocks = []
    for listen in STATE.listen:
        # Create listening socket for each listen address
        try:
            sock = create_listen_socket(listen, port)
        except OSError as exc:
            strexc = str(exc)
            if "attempt was made" in strexc or "already in use" in strexc:
                pprint("Px failed to start - port in use")
                os._exit(config.ERROR_PORTINUSE)
            else:
                pprint(strexc)
            os._exit(config.ERROR_UNKNOWN)

        mainsocks.append(sock)
        print_banner(listen, port)

    # Spawn additional worker processes - each creates its own sockets
    for _ in range(workers - 1):
        p = multiprocessing.Process(target=start_worker)
        p.daemon = True
        p.start()

    asyncio.run(run_async_servers(STATE.listen, port, socks=mainsocks))


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
            except (TimeoutError, ConnectionRefusedError):
                time.sleep(0.01)
                count += 1
                if count == 50:
                    pprint("Failed: Px did not start")
                    os._exit(config.ERROR_TEST)

    def query(url, method="GET", data=None, do_quit=True, check=False, insecure=False):
        if do_quit:
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
                    pprint("Failed: response does not contain " + f"{url}:\n{ret_data}")
                    os._exit(config.ERROR_TEST)
                if data is not None and data not in ret_data:
                    pprint("Failed: response does not match " + f"{data}:\n{ret_data}")
                    os._exit(config.ERROR_TEST)

        if do_quit:
            os._exit(config.ERROR_SUCCESS)

    def queryall(testurl):
        import uuid

        waitforpx()

        insecure = False
        urls = []
        if testurl in ["all", "1"]:
            url = "://httpbin.org/"
            urls.append("http" + url)
            urls.append("https" + url)
        elif testurl.startswith("all:"):
            insecure = True
            url = testurl[4:]
            if "://" not in url:
                url = f"://{url}"
                if url[-1] != "/":
                    url += "/"
                urls.append("http" + url)
                urls.append("https" + url)
            else:
                if url[-1] != "/":
                    url += "/"
                urls.append(url)

        # Run all method queries concurrently for speed
        threads = []
        for method in ["GET", "POST", "PUT", "DELETE", "PATCH"]:
            for url in urls:
                data = str(uuid.uuid4()) if method in ["POST", "PUT", "PATCH"] else None
                t = threading.Thread(
                    target=query,
                    args=(url + method.lower(), method, data),
                    kwargs={"do_quit": False, "check": True, "insecure": insecure},
                )
                t.start()
                threads.append(t)
        for t in threads:
            t.join()

        os._exit(config.ERROR_SUCCESS)

    # Run testurl query in a thread
    if testurl in ["all", "1"] or testurl.startswith("all:"):
        t = threading.Thread(target=queryall, args=(testurl,))
    else:
        t = threading.Thread(target=query, args=(testurl,))
    t.daemon = True
    t.start()

    # Run Px to respond to query
    run_pool()


###
# Exit related


def handle_exceptions(extype, value, tb):
    # Create traceback log
    lst = traceback.format_tb(tb, None) + traceback.format_exception_only(extype, value)
    tracelog = "\nTraceback (most recent call last):\n" + f"{''.join(lst[:-1]):<20}{lst[-1]}\n"

    if STATE.debug is not None:
        pprint(tracelog)
    else:
        sys.stderr.write(tracelog)

        # Save to debug.log in working directory
        with open(config.get_logfile(config.LOG_CWD), "w") as dbg:
            dbg.write(tracelog)


###
# Startup


def main():
    multiprocessing.freeze_support()
    if multiprocessing.get_start_method(allow_none=True) is None:
        multiprocessing.set_start_method("spawn")
    sys.excepthook = handle_exceptions

    STATE.parse_config()

    if STATE.test is not None:
        test(STATE.test)

    run_pool()


if __name__ == "__main__":
    main()
