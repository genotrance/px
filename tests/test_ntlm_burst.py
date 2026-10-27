"""Regression coverage for concurrent requests through an NTLM upstream."""

import base64
import concurrent.futures
import copy
import http.client
import http.server
import os
import threading

import pytest
from fixtures import *  # noqa: F403
from helpers import *  # noqa: F403

TARGET = "http://ntlm-burst.test/"
USERNAME = "ntlm-burst-test"
PASSWORD = "ntlm-burst-pass"
BURST_SIZE = 64

# A minimal Type 2 message is enough for libcurl to emit its Type 3 response.
# The fake proxy deliberately accepts any Type 3 because credentials are not
# what this regression test covers.
NTLM_TYPE_2 = base64.b64encode(
    b"NTLMSSP\x00"
    + (2).to_bytes(4, "little")
    + b"\x00" * 8
    + (0x00088205).to_bytes(4, "little")
    + b"pxntlm01"
    + b"\x00" * 8
    + b"\x00" * 8
).decode("ascii")


class _FakeNtlmUpstream(http.server.ThreadingHTTPServer):
    """A tiny upstream proxy that completes an NTLM handshake per request."""

    daemon_threads = True
    request_queue_size = 512

    def __init__(self):
        super().__init__(("127.0.0.1", 0), _NtlmHandler)
        self.completed = 0
        self.lock = threading.Lock()

    @property
    def addr(self):
        return f"127.0.0.1:{self.server_address[1]}"


class _NtlmHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def _challenge(self, token=None):
        self.send_response(407)
        header = "NTLM" if token is None else f"NTLM {token}"
        self.send_header("Proxy-Authenticate", header)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):
        auth = self.headers.get("Proxy-Authorization", "")
        if not auth.startswith("NTLM "):
            self._challenge()
            return

        message = base64.b64decode(auth[5:])
        message_type = int.from_bytes(message[8:12], "little")
        if message_type != 3:
            self._challenge(NTLM_TYPE_2)
            return

        with self.server.lock:
            self.server.completed += 1
        body = b"ok"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture
def fake_ntlm_upstream():
    server = _FakeNtlmUpstream()
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield server
    server.shutdown()
    server.server_close()


def _client_request(port, barrier):
    """Start one client with the rest of the burst and return its status."""
    barrier.wait()
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=15)
    try:
        conn.request("GET", TARGET)
        response = conn.getresponse()
        response.read()
    except OSError:
        return None
    else:
        return response.status
    finally:
        conn.close()


def _start_px(name, port, fake_ntlm_upstream, event_loop, tmp_path):
    env = copy.deepcopy(os.environ)
    env["PX_PASSWORD"] = PASSWORD
    if event_loop:
        env["PX_EVENT_LOOP"] = event_loop
    else:
        env.pop("PX_EVENT_LOOP", None)

    config_path = tmp_path / "px.ini"
    config_path.touch()
    flags = (
        f"--server={fake_ntlm_upstream.addr} --auth=NTLM --username={USERNAME}"
        f" --noproxy= --threads={BURST_SIZE} --workers=1 --config={config_path}"
    )
    return run_px(name, port, tmp_path, flags, env, startup_timeout=90)


@pytest.mark.parametrize("event_loop", ["", "asyncio"])
def test_ntlm_upstream_burst(fake_ntlm_upstream, px_port, tmp_path, event_loop):
    """Every concurrent client completes an NTLM handshake with the upstream."""
    subp, cmd, buffer = _start_px("NtlmBurst", px_port, fake_ntlm_upstream, event_loop, tmp_path)
    try:
        barrier = threading.Barrier(BURST_SIZE)
        with concurrent.futures.ThreadPoolExecutor(max_workers=BURST_SIZE) as pool:
            statuses = list(pool.map(lambda _: _client_request(px_port, barrier), range(BURST_SIZE)))

        assert statuses == [200] * BURST_SIZE
        assert fake_ntlm_upstream.completed == BURST_SIZE
    finally:
        print_buffer(buffer)
        quit_px("NtlmBurst", subp, cmd, strict=False)
