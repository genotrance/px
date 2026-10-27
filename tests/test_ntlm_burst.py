"""Regression coverage for concurrent requests through an NTLM upstream."""

import base64
import concurrent.futures
import copy
import http.client
import os
import socketserver
import struct
import threading

import mcurl
import pytest
from fixtures import *  # noqa: F403
from helpers import *  # noqa: F403

HAS_NTLM = bool(mcurl.get_curl_vinfo().features & mcurl.libcurl.CURL_VERSION_NTLM)
pytestmark = pytest.mark.skipif(not HAS_NTLM, reason="libcurl was built without NTLM support")

USERNAME = "ntlm-burst-test"
PASSWORD = "ntlm-burst-pass"
BURST_SIZE = 15
# Interrupt the complete first burst so no successful concurrent handshake can
# clear the old mcurl's accumulated failures before the second burst begins.
INTERRUPTED_HANDSHAKES = BURST_SIZE
RESPONSE_BODY = b"ntlm upstream ok"
# TEMPORARY until pymcurl 8.23.0.3 is on PyPI (docs/build.md): mcurl added
# Curl.get_os_errno while fixing px#268, so older installations skip the
# interrupted-CONNECT test. CI sets PX_REQUIRE_MCURL_FIX=1 so it always runs
# there and fails instead of being skipped silently.
MCURL_HAS_CONNECT_FIX = hasattr(mcurl.Curl, "get_os_errno")
REQUIRE_MCURL_FIX = os.environ.get("PX_REQUIRE_MCURL_FIX") == "1"


def _type_2():
    """Return a structurally valid Type 2 challenge for libcurl's NTLM SSPI."""
    flags = 0x00000001 | 0x00000200
    return (
        b"NTLMSSP\x00" + struct.pack("<IHHII", 2, 0, 0, 40, flags) + b"\x01\x02\x03\x04\x05\x06\x07\x08" + b"\x00" * 8
    )


class _FakeNtlmUpstream(socketserver.ThreadingTCPServer):
    """A tiny NTLM proxy which can drop CONNECT handshakes after Type 1."""

    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 512

    def __init__(self):
        super().__init__(("127.0.0.1", 0), _NtlmHandler)
        self.completed = 0
        self.interrupted = 0
        self.drop_type_2 = 0
        self.lock = threading.Lock()

    @property
    def addr(self):
        return f"127.0.0.1:{self.server_address[1]}"


class _NtlmHandler(socketserver.StreamRequestHandler):
    def _read_request(self):
        line = self.rfile.readline()
        if not line.strip():
            return None, {}
        headers = {}
        while True:
            header = self.rfile.readline()
            if header in (b"\r\n", b"\n", b""):
                break
            name, _, value = header.decode("latin-1").partition(":")
            headers[name.strip().lower()] = value.strip()
        return line.decode("latin-1").split()[0], headers

    def _send(self, status, headers=(), body=b""):
        reason = {200: "OK", 407: "Proxy Authentication Required"}[status]
        lines = [f"HTTP/1.1 {status} {reason}", *headers]
        if status != 200 or body:
            lines.append(f"Content-Length: {len(body)}")
        self.wfile.write(("\r\n".join(lines) + "\r\n\r\n").encode() + body)
        self.wfile.flush()

    def _challenge(self, headers):
        self._send(407, headers, b"auth required")

    def _authenticate(self, headers, interrupt_connect=False):
        scheme, _, token = headers.get("proxy-authorization", "").partition(" ")
        try:
            message = base64.b64decode(token) if scheme.upper() == "NTLM" and token else b""
        except ValueError:
            message = b""
        message_type = struct.unpack("<I", message[8:12])[0] if len(message) >= 12 else 0
        if message_type == 1:
            with self.server.lock:
                should_interrupt = interrupt_connect and self.server.drop_type_2 > 0
                if should_interrupt:
                    self.server.drop_type_2 -= 1
                    self.server.interrupted += 1
            if should_interrupt:
                # This is the failure mode from px#268: libcurl remembers the
                # preceding 407 while the proxy drops the Type 1 connection.
                return None
            self._challenge(["Proxy-Authenticate: NTLM " + base64.b64encode(_type_2()).decode()])
            return False

        if message_type != 3:
            self._challenge(["Proxy-Authenticate: NTLM"])
            return False

        with self.server.lock:
            self.server.completed += 1
        return True

    def handle(self):
        authenticated = False
        while True:
            method, headers = self._read_request()
            if method is None:
                return
            if not authenticated:
                authenticated = self._authenticate(headers, interrupt_connect=method == "CONNECT")
                if authenticated is None:
                    return
                if not authenticated:
                    continue
            if method == "CONNECT":
                self._send(200, ["Proxy-Agent: fake-ntlm"])
                # Px takes ownership of the tunnel socket after this response.
                while self.rfile.read(4096):
                    pass
                return
            self._send(200, (), RESPONSE_BODY)


@pytest.fixture
def fake_ntlm_upstream():
    upstream = _FakeNtlmUpstream()
    threading.Thread(target=upstream.serve_forever, daemon=True).start()
    yield upstream
    upstream.shutdown()
    upstream.server_close()


def _plain_request(port, barrier):
    """Start one HTTP client with the rest of the burst."""
    barrier.wait()
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=15)
    try:
        conn.request("GET", "http://ntlm-burst.test/")
        response = conn.getresponse()
        body = response.read()
    except OSError:
        return None, b""
    else:
        return response.status, body
    finally:
        conn.close()


def _connect_request(port, target, barrier):
    """Open one CONNECT tunnel through Px."""
    barrier.wait()
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=15)
    try:
        conn.request("CONNECT", target)
        response = conn.getresponse()
        if response.status != 200:
            return response.status, response.read()
        else:
            return response.status, b""
    except OSError:
        return None, b""
    finally:
        conn.close()


def _burst(client, *args):
    barrier = threading.Barrier(BURST_SIZE)
    with concurrent.futures.ThreadPoolExecutor(max_workers=BURST_SIZE) as pool:
        return list(pool.map(lambda _: client(*args, barrier), range(BURST_SIZE)))


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
        f"--server={fake_ntlm_upstream.addr} --auth=ANY --username={USERNAME}"
        f" --authretry=0 --noproxy= --threads={BURST_SIZE} --workers=1 --config={config_path}"
    )
    return run_px(name, port, tmp_path, flags, env, startup_timeout=90)


@pytest.mark.parametrize("event_loop", ["", "asyncio"])
def test_ntlm_upstream_plain_http_burst(fake_ntlm_upstream, px_port, tmp_path, event_loop):
    """Every concurrent client completes an NTLM handshake with the upstream."""
    subp, cmd, buffer = _start_px("NtlmBurst", px_port, fake_ntlm_upstream, event_loop, tmp_path)
    try:
        responses = _burst(_plain_request, px_port)
        assert responses == [(200, RESPONSE_BODY)] * BURST_SIZE
        assert fake_ntlm_upstream.completed > 0
    finally:
        print_buffer(buffer)
        quit_px("NtlmBurst", subp, cmd, strict=False)


@pytest.mark.parametrize("event_loop", ["", "asyncio"])
@pytest.mark.skipif(
    not MCURL_HAS_CONNECT_FIX and not REQUIRE_MCURL_FIX,
    reason="needs pymcurl>=8.23.0.3 (px#268)",
)
def test_ntlm_upstream_interrupted_connect_burst(fake_ntlm_upstream, px_port, tmp_path, event_loop):
    """Dropped Type 1 CONNECT handshakes must not block later NTLM tunnels."""
    subp, cmd, buffer = _start_px("NtlmConnectBurst", px_port, fake_ntlm_upstream, event_loop, tmp_path)
    try:
        fake_ntlm_upstream.drop_type_2 = INTERRUPTED_HANDSHAKES
        first_burst = _burst(_connect_request, px_port, "127.0.0.1:443")
        assert fake_ntlm_upstream.interrupted >= 3

        # The interrupted requests can legitimately fail with a network error,
        # but they must never be converted into Px's latched-auth 401 response.
        assert all(status != 401 and b"Proxy server authentication failed" not in body for status, body in first_burst)

        second_burst = _burst(_connect_request, px_port, "127.0.0.1:443")
        assert second_burst == [(200, b"")] * BURST_SIZE
    finally:
        print_buffer(buffer)
        quit_px("NtlmConnectBurst", subp, cmd, strict=False)
