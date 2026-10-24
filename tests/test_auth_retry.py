"""Tests for --authretry: mcurl's single-probe retry of a proxy blocked by
repeated 407s, exercised through a real Px process against a fake upstream.
"""

import concurrent.futures
import copy
import http.client
import http.server
import os
import threading
import time

import pytest
from fixtures import *  # noqa: F403
from helpers import *  # noqa: F403

TARGET = "http://auth-retry.test/"
USERNAME = "authretry-test"
PASSWORD = "authretry-pass"


class _FakeUpstream(http.server.ThreadingHTTPServer):
    """A minimal upstream proxy that denies or allows authenticated requests
    and counts how many it actually saw (Proxy-Authorization present)."""

    daemon_threads = True
    request_queue_size = 512  # Bursts of dozens of simultaneous connects

    def __init__(self):
        super().__init__(("127.0.0.1", 0), _Handler)
        self.mode = "deny"  # deny: 407, allow: 200
        self.attempts = 0
        self.lock = threading.Lock()

    @property
    def addr(self):
        return f"127.0.0.1:{self.server_address[1]}"


class _Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def do_GET(self):
        server = self.server
        if self.headers.get("Proxy-Authorization") is not None:
            with server.lock:
                server.attempts += 1
            if server.mode == "allow":
                body = b"ok"
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(body)
                return
        self.send_response(407)
        self.send_header("Proxy-Authenticate", 'Basic realm="fake"')
        self.send_header("Content-Length", "0")
        self.send_header("Connection", "close")
        self.end_headers()


@pytest.fixture
def fake_upstream():
    server = _FakeUpstream()
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield server
    server.shutdown()
    server.server_close()


def _client_request(port):
    "One client request proxied through Px; returns the status code or None on error"
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    try:
        conn.request("GET", TARGET)
        resp = conn.getresponse()
        resp.read()
    except OSError:
        return None
    else:
        return resp.status
    finally:
        conn.close()


def _start_px(name, port, fake_upstream, authretry, event_loop, tmp_path):
    env = copy.deepcopy(os.environ)
    env["PX_PASSWORD"] = PASSWORD
    if event_loop:
        env["PX_EVENT_LOOP"] = event_loop
    else:
        env.pop("PX_EVENT_LOOP", None)

    # Do not let a configuration file outside this per-test directory change
    # the isolated subprocess (notably by enabling Kerberos).
    config_path = tmp_path / "px.ini"
    config_path.touch()
    flags = (
        f"--server={fake_upstream.addr} --auth=BASIC --username={USERNAME}"
        f" --authretry={authretry} --noproxy= --threads=64 --workers=1 --config={config_path}"
    )
    # Auth-retry's burst tests run beside many Px subprocesses under xdist.
    # Poll the listener for long enough to tolerate a saturated test host.
    return run_px(name, port, tmp_path, flags, env, startup_timeout=90)


@pytest.mark.parametrize("event_loop", ["", "asyncio"])
def test_default_disabled_never_retries(fake_upstream, px_port, tmp_path, event_loop):
    "default authretry=0 keeps today's behaviour: blocked proxy stays blocked"
    subp, cmd, buffer = _start_px("AuthRetryDefault", px_port, fake_upstream, 0, event_loop, tmp_path)
    try:
        for _ in range(3):
            _client_request(px_port)
        assert fake_upstream.attempts == 3

        time.sleep(0.5)  # long enough for any retry interval to have elapsed
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as pool:
            list(pool.map(lambda _: _client_request(px_port), range(50)))
        assert fake_upstream.attempts == 3
    finally:
        print_buffer(buffer)
        quit_px("AuthRetryDefault", subp, cmd, strict=False)


@pytest.mark.parametrize("event_loop", ["", "asyncio"])
def test_single_probe_per_interval_under_burst(fake_upstream, px_port, tmp_path, event_loop):
    "After blocking, a burst of concurrent clients yields exactly one upstream probe"
    interval = 0.3
    subp, cmd, buffer = _start_px("AuthRetryBurst", px_port, fake_upstream, interval, event_loop, tmp_path)
    try:
        for _ in range(3):
            _client_request(px_port)
        assert fake_upstream.attempts == 3

        time.sleep(interval + 0.3)
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as pool:
            list(pool.map(lambda _: _client_request(px_port), range(50)))
        assert fake_upstream.attempts == 4
    finally:
        print_buffer(buffer)
        quit_px("AuthRetryBurst", subp, cmd, strict=False)


@pytest.mark.parametrize("event_loop", ["", "asyncio"])
def test_recovery_after_probe_succeeds(fake_upstream, px_port, tmp_path, event_loop):
    "A successful probe unblocks the proxy for subsequent requests"
    interval = 0.3
    subp, cmd, buffer = _start_px("AuthRetryRecover", px_port, fake_upstream, interval, event_loop, tmp_path)
    try:
        for _ in range(3):
            _client_request(px_port)
        assert fake_upstream.attempts == 3

        time.sleep(interval + 0.3)
        fake_upstream.mode = "allow"
        assert _client_request(px_port) == 200
        assert fake_upstream.attempts == 4

        # Px's do() detects completion via polling, so clearing the probe's
        # auth-failure state can lag a few ms behind the client seeing the
        # response — give it a moment before confirming the proxy stayed
        # unblocked, rather than requiring an immediate following request.
        time.sleep(0.2)
        statuses = [_client_request(px_port) for _ in range(5)]
        assert statuses == [200] * 5
        assert fake_upstream.attempts == 9
    finally:
        print_buffer(buffer)
        quit_px("AuthRetryRecover", subp, cmd, strict=False)
