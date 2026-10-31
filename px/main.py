"Px is an HTTP proxy server to automatically authenticate through an NTLM proxy"

import asyncio
import concurrent.futures
import contextlib
import email.utils
import multiprocessing
import os
import re
import signal
import socket
import sys
import threading
import time
import traceback
import warnings

from . import config, handler, wproxy
from .config import STATE
from .debug import Debug, dprint, pprint
from .version import __version__

if sys.platform == "win32":
    from . import windows
else:
    import resource

import mcurl

# Set after configuration is parsed. Keeping this unset at import time prevents
# importing px.main from loading dotenv files or inspecting command-line flags.
_libuv = None


def _configure_event_loop():
    """Select and initialize the configured libuv event loop implementation."""
    global _libuv

    if STATE.event_loop == "asyncio":
        _libuv = None
        return

    try:
        if sys.platform == "win32":
            import winloop as _libuv
        else:
            import uvloop as _libuv
    except ImportError:
        _libuv = None

    # Python 3.10-3.11 require a global policy. This occurs after each process
    # has parsed its configuration, including spawned workers.
    if _libuv is not None and sys.version_info < (3, 12):
        _libuv.install()


warnings.filterwarnings("ignore")


def _run_async(coro):
    """Run a coroutine with the configured event loop."""
    if _libuv is not None and sys.version_info >= (3, 12):
        asyncio.run(coro, loop_factory=_libuv.new_event_loop)
    else:
        asyncio.run(coro)


# Target soft limit for RLIMIT_NOFILE on Unix systems
_FD_LIMIT_TARGET = 65536

# Step-down values for macOS where kern.maxfilesperproc may reject high limits
_FD_LIMIT_FALLBACKS = (8192, 4096, 2048, 1024)

# Warn if the final soft limit is below this threshold
_FD_LIMIT_WARN = 1024

# Listen backlog; 128 saturates at 200+ concurrent connects (SYN retransmit stalls)
LISTEN_BACKLOG = 2048


def raise_nofile_limit():
    """Raise the RLIMIT_NOFILE soft limit toward the hard limit (Unix only).

    macOS launchd defaults the soft limit to 256 and Linux defaults to 1024,
    both too low for a proxy server handling concurrent CONNECT tunnels (each
    tunnel consumes up to 4 FDs). This function raises the soft limit to
    min(hard, 65536) at startup with a step-down fallback for macOS where
    kern.maxfilesperproc may silently cap setrlimit.
    """
    if sys.platform == "win32":
        return

    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    target = min(hard, _FD_LIMIT_TARGET)

    if soft >= target:
        dprint(f"FD limit already sufficient: soft={soft} hard={hard}")
        return

    try:
        resource.setrlimit(resource.RLIMIT_NOFILE, (target, hard))
        dprint(f"Raised FD limit: {soft} -> {target} (hard={hard})")
    except (ValueError, OSError) as exc:
        dprint(f"Failed to set FD limit to {target}: {exc}")
        # Step-down fallback (needed on macOS)
        for fallback in _FD_LIMIT_FALLBACKS:
            if fallback <= soft:
                break
            try:
                resource.setrlimit(resource.RLIMIT_NOFILE, (fallback, hard))
                dprint(f"Raised FD limit: {soft} -> {fallback} (hard={hard})")
                break
            except (ValueError, OSError) as exc:
                dprint(f"Failed to set FD limit to {fallback}: {exc}")

    new_soft, _ = resource.getrlimit(resource.RLIMIT_NOFILE)
    if new_soft < _FD_LIMIT_WARN:
        pprint(f"Warning: FD soft limit is {new_soft} - proxy may fail under load")


###
# Server startup helpers


def create_listen_socket(listen, port):
    "Create a bound, listening TCP socket for the given address and port"
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if hasattr(socket, "SO_REUSEPORT"):
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    try:
        sock.bind((listen, port))
    except OSError:
        sock.close()
        raise
    sock.listen(LISTEN_BACKLOG)
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
    # asyncio only sets TCP_NODELAY when the accepted socket reports IPPROTO_TCP, which
    # Windows accept() sockets do not, so set it here for every event loop
    sock = writer.get_extra_info("socket")
    if sock is not None and sock.type == socket.SOCK_STREAM:
        with contextlib.suppress(OSError):
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

    peername = writer.get_extra_info("peername")
    if peername and not verify_client(peername[0]):
        writer.close()
        return

    conn = handler.ConnectionHandler(reader, writer)
    await conn.handle()


async def start_server(listen, port, sock=None):
    "Start an async proxy server"
    if sock is not None:
        server = await asyncio.start_server(handle_connection, sock=sock, backlog=LISTEN_BACKLOG)
    else:
        server = await asyncio.start_server(handle_connection, listen, port, backlog=LISTEN_BACKLOG, reuse_address=True)
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

    raise_nofile_limit()

    STATE.parse_config()
    _configure_event_loop()

    port = STATE.config.getint("proxy", "port")
    socks = []
    for listen in STATE.listen:
        # Each worker creates its own listening socket with SO_REUSEPORT/SO_REUSEADDR
        # so each process has an independent IOCP registration (Windows) or kernel
        # load-balanced accept (Linux/macOS)
        sock = create_listen_socket(listen, port)
        socks.append(sock)
        print_banner(listen, port)

    _run_async(run_async_servers(STATE.listen, port, socks=socks))


def run_pool():
    # CTRL-C should exit the process
    signal.signal(signal.SIGINT, signal.SIG_DFL)

    raise_nofile_limit()

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

    _run_async(run_async_servers(STATE.listen, port, socks=mainsocks))


###
# Actions

# HTTP status codes that mean the request never got an authenticated
# response - a --test run must not report these as success.
_TEST_AUTH_FAILURE_CODES = (401, 407)
_TEST_RATE_LIMIT_CODE = 429
_TEST_RATE_LIMIT_RETRIES = 2
_TEST_RATE_LIMIT_MAX_WAIT = 5.0
_TEST_BODY_ECHO_INTERVAL = 0.6


def _retry_after(headers):
    """Return a target's requested rate-limit delay, if its header is valid."""
    match = re.search(r"(?im)^retry-after:\s*([^\r\n]+)", headers)
    if match is None:
        return None
    value = match.group(1).strip()
    try:
        return max(0.0, float(value))
    except ValueError:
        try:
            return max(0.0, email.utils.parsedate_to_datetime(value).timestamp() - time.time())
        except (TypeError, ValueError, IndexError, OverflowError):
            return None


def _negotiate_test_target(wp, listen, port):
    """Pick the host --test-auth's client should address Px as, plus an optional
    CURLOPT_RESOLVE entry to still connect it to Px's listen address.

    Negotiate (Kerberos) derives its SPN from the proxy address passed to
    libcurl. In --test-auth, that address is Px's own listen address, which
    has no SPN registered - only the upstream proxy does. With a single
    explicit upstream --proxy configured, address Px by that upstream
    hostname instead and let CURLOPT_RESOLVE route the connection to Px's
    real listen address, so the SPN libcurl requests matches the upstream
    proxy. PAC configuration or multiple proxies have no single upstream
    hostname to borrow, so Px keeps being addressed by its listen address
    (the pre-existing, SPN-mismatched behaviour); the caller is told so it
    can warn.

    Returns (host, resolve_entry_or_None, single_explicit_proxy).
    """
    single_explicit_proxy = wp is not None and wp.mode == wproxy.MODE_CONFIG and len(wp.servers) == 1
    if single_explicit_proxy:
        upstream_host = wp.servers[0][0]
        if upstream_host != listen:
            return upstream_host, f"{upstream_host}:{port}:{listen}", single_explicit_proxy
        return upstream_host, None, single_explicit_proxy
    return listen, None, single_explicit_proxy


def test(testurl):
    # Get Px configuration
    listen = config.get_listen()
    port = STATE.config.getint("proxy", "port")

    if len(listen) == 0:
        pprint("Failed: Px not listening on localhost - cannot run test")
        sys.exit(config.ERROR_TEST)

    # Tweak Px configuration for test - only 1 process required
    STATE.config.set("settings", "workers", "1")

    test_proxy_host = listen
    test_proxy_resolve = None

    if "--test-auth" in sys.argv:
        # Set Px to --auth=NONE
        auth = STATE.auth
        STATE.auth = "NONE"
        STATE.config.set("proxy", "auth", "NONE")

        test_proxy_host, test_proxy_resolve, single_explicit_proxy = _negotiate_test_target(STATE.wproxy, listen, port)
        if not single_explicit_proxy:
            pprint(
                "Negotiate --test-auth needs a single explicit --proxy to address Px by the "
                "upstream proxy's hostname; with PAC or multiple proxies configured, Px is "
                "addressed by its listen address instead, which Kerberos may not have an SPN for"
            )
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
        success = False
        rate_limited = False
        if do_quit:
            waitforpx()

        pprint(f"\nTesting {method} {url}")
        attempt = 0
        total_wait = 0.0
        while True:
            resolve_list = None
            try:
                ec = mcurl.Curl(url, method)
                ec.set_proxy(test_proxy_host, port)
                if test_proxy_resolve is not None:
                    resolve_list = mcurl.libcurl.curl_slist_append(mcurl.ffi.NULL, mcurl.py2cstr(test_proxy_resolve))
                    ec.setopt(mcurl.libcurl.CURLOPT_RESOLVE, resolve_list)
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
                if ret != 0:
                    pprint(f"Failed with error {ret}\n{ec.errstr}")
                    break

                ret_data = ec.get_data()
                headers = ec.get_headers()
                pprint(f"\n{headers}Response length: {len(ret_data)}")
                code = ec.get_response_code()
                if code == _TEST_RATE_LIMIT_CODE:
                    remaining_wait = _TEST_RATE_LIMIT_MAX_WAIT - total_wait
                    if attempt < _TEST_RATE_LIMIT_RETRIES and remaining_wait > 0:
                        requested_wait = _retry_after(headers)
                        backoff = 0.5 * (2**attempt)
                        delay = min(requested_wait if requested_wait is not None else backoff, remaining_wait)
                        pprint(f"Rate limited by test target; retrying in {delay:g} seconds")
                        if delay:
                            time.sleep(delay)
                        total_wait += delay
                        attempt += 1
                        continue
                    pprint("Rate limited by test target (HTTP 429)")
                    rate_limited = True
                    break

                success = True
                if code in _TEST_AUTH_FAILURE_CODES:
                    pprint(f"Failed: final response status {code} - request was not authenticated")
                    success = False
                if check:
                    # Tests against httpbin
                    if url not in ret_data:
                        pprint("Failed: response does not contain " + f"{url}:\n{ret_data}")
                        success = False
                    if data is not None and data not in ret_data:
                        pprint("Failed: response does not match " + f"{data}:\n{ret_data}")
                        success = False
                break
            except Exception as exc:
                pprint(f"Failed with exception: {exc}")
                break
            finally:
                if resolve_list is not None:
                    mcurl.libcurl.curl_slist_free_all(resolve_list)

        if success:
            pprint("Passed")
        if do_quit:
            if success:
                os._exit(config.ERROR_SUCCESS)
            os._exit(config.ERROR_TEST_RATE_LIMIT if rate_limited else config.ERROR_TEST)
        return success, rate_limited

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

        # GET and DELETE are safe to overlap. Pace body echoes because httpbin
        # limits them to about two requests per second for each client IP.
        threads = []
        results = []

        def run_query(*args, **kwargs):
            results.append(query(*args, **kwargs))

        for method in ["GET", "DELETE"]:
            for url in urls:
                t = threading.Thread(
                    target=run_query,
                    args=(url + method.lower(), method),
                    kwargs={"do_quit": False, "check": True, "insecure": insecure},
                )
                t.start()
                threads.append(t)
        for t in threads:
            t.join()

        last_body_start = None
        for method in ["POST", "PUT", "PATCH"]:
            for url in urls:
                if last_body_start is not None:
                    delay = _TEST_BODY_ECHO_INTERVAL - (time.monotonic() - last_body_start)
                    if delay > 0:
                        time.sleep(delay)
                last_body_start = time.monotonic()
                results.append(
                    query(
                        url + method.lower(),
                        method,
                        str(uuid.uuid4()),
                        do_quit=False,
                        check=True,
                        insecure=insecure,
                    )
                )

        passed = sum(success for success, _rate_limited in results)
        rate_limited = sum(rate_limited for _success, rate_limited in results)
        failed = len(results) - passed - rate_limited
        pprint(f"Summary: {passed} passed, {failed} failed, {rate_limited} rate limited by test target")
        if failed:
            os._exit(config.ERROR_TEST)
        if rate_limited:
            os._exit(config.ERROR_TEST_RATE_LIMIT)
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
    _configure_event_loop()

    if STATE.test is not None:
        test(STATE.test)

    run_pool()


if __name__ == "__main__":
    main()
