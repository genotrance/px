import copy
import http.client
import os
import socket
import socketserver
import threading
import time

import pytest
from fixtures import *  # noqa: F403
from helpers import *  # noqa: F403

from px.handler import _is_connect_passthrough

##
# Tests


def test_proxy(px_basic_cli, tmp_path):
    # Px (test) -> Px -> httpbin
    # px basic cli = 6
    # 6 combinations
    run_in_temp(px_basic_cli, tmp_path)


def test_proxy_auth(px_basic_cli, px_auth, px_username, px_password, tmp_path):
    # Px (test) -> Px (auth unused) -> httpbin
    # px basic cli = 6
    # px auth = 6
    # 36 combinations
    cmd = f"{px_basic_cli} {px_auth} {px_username} {px_password}"
    run_in_temp(cmd, tmp_path)


@pytest.mark.slow
@pytest.mark.skipif(os.getenv("PX_CI_MINIMAL") == "1", reason="Skip slow chain tests in minimal CI mode")
def test_proxy_auth_upstream(
    px_upstream, px_basic_cli, px_port, px_auth, px_username, px_password, px_test_auth, tmp_path
):
    # Px (test?auth) -> Px (auth?) -> Px upstream (client auth) -> httpbin
    # px basic cli = 6
    # px auth = 6
    # px test-auth = 2
    # 72 combinations
    cmd = f"{px_basic_cli} {px_auth} {px_username} {px_password}" + f" --proxy=127.0.0.1:{px_port + 1} {px_test_auth}"
    run_in_temp(cmd, tmp_path, px_upstream)


@pytest.mark.slow
@pytest.mark.skipif(os.getenv("PX_CI_MINIMAL") == "1", reason="Skip slow chain tests in minimal CI mode")
def test_proxy_auth_chain(
    px_upstream, px_chain, px_basic_cli, px_port, px_auth, px_username, px_password, px_test_auth, tmp_path
):
    # Px (test?auth) -> Px (auth?) -> Px chain (no auth) -> Px upstream (client auth) -> httpbin
    # px basic cli = 6
    # px auth = 6
    # px test-auth = 2
    # 72 combinations
    cmd = f"{px_basic_cli} {px_auth} {px_username} {px_password}" + f" --proxy=127.0.0.1:{px_port + 2} {px_test_auth}"
    run_in_temp(cmd, tmp_path, px_upstream, px_chain)


def test_auth_none_connect_passthrough_uses_configured_proxy_not_curl_transfer_info():
    "CONNECT_ONLY's proxy transfer info must not cause Px to send a duplicate 200 response"
    curl = type("CurlState", (), {"is_connect": True, "is_tunnel": False, "proxy": "corp-proxy.example"})()
    assert _is_connect_passthrough(curl, used_proxy=False)


class _HeaderRecorder(socketserver.ThreadingTCPServer):
    "A fake upstream proxy that records each request's raw header lines and accepts it"

    allow_reuse_address = True
    daemon_threads = True

    def __init__(self):
        super().__init__(("127.0.0.1", 0), _HeaderRecorderHandler)
        self.requests = []

    @property
    def addr(self):
        return f"127.0.0.1:{self.server_address[1]}"


class _HeaderRecorderHandler(socketserver.StreamRequestHandler):
    def handle(self):
        request_line = self.rfile.readline().decode("latin-1").rstrip("\r\n")
        head = [request_line]
        while (line := self.rfile.readline()) not in (b"\r\n", b"\n", b""):
            head.append(line.decode("latin-1").rstrip("\r\n"))
        self.server.requests.append(head)
        if request_line.startswith("CONNECT"):
            self.wfile.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
            self.wfile.flush()
            self.rfile.read(1)
        else:
            body = b"ok"
            self.wfile.write(
                b"HTTP/1.1 200 OK\r\nContent-Length: " + str(len(body)).encode("ascii") + b"\r\n\r\n" + body
            )
            self.wfile.flush()


class _ConnectTunnelProxy(_HeaderRecorder):
    "A fake upstream proxy that sends a realistic CONNECT response and raw tunnel bytes"

    def __init__(self, chunked):
        self.chunked = chunked
        socketserver.ThreadingTCPServer.__init__(self, ("127.0.0.1", 0), _ConnectTunnelProxyHandler)
        self.requests = []


class _ConnectTunnelProxyHandler(_HeaderRecorderHandler):
    def handle(self):
        request_line = self.rfile.readline().decode("latin-1").rstrip("\r\n")
        head = [request_line]
        while (line := self.rfile.readline()) not in (b"\r\n", b"\n", b""):
            head.append(line.decode("latin-1").rstrip("\r\n"))
        self.server.requests.append(head)

        response = (
            b"HTTP/1.1 200 Connection established\r\n"
            b"Content-Length: 0\r\n"
            b"Connection: keep-alive\r\n"
            b"Proxy-Connection: keep-alive\r\n"
            b"Proxy-Authenticate: Negotiate bXV0dWFsLWF1dGg=\r\n\r\n"
        )
        tunnel_data = b"\x16\x03\x03raw-tunnel-server-data"
        if self.server.chunked:
            for offset in range(0, len(response), 7):
                self.wfile.write(response[offset : offset + 7])
                self.wfile.flush()
                time.sleep(0.001)
            self.wfile.write(tunnel_data)
        else:
            self.wfile.write(response + tunnel_data)
        self.wfile.flush()
        assert self.rfile.read(len(b"raw-tunnel-client-data")) == b"raw-tunnel-client-data"


def _read_through(sock, marker):
    data = b""
    while marker not in data:
        chunk = sock.recv(4096)
        assert chunk
        data += chunk
    return data


@pytest.mark.parametrize("event_loop", ["", "asyncio"])
@pytest.mark.parametrize("chunked", [False, True], ids=["coalesced", "chunked"])
def test_auth_none_connect_relays_one_response_then_raw_tunnel_data(px_port, tmp_path, event_loop, chunked):
    "The upstream CONNECT response is relayed once and followed only by raw tunnel bytes"
    upstream = _ConnectTunnelProxy(chunked)
    threading.Thread(target=upstream.serve_forever, daemon=True).start()
    env = copy.deepcopy(os.environ)
    if event_loop:
        env["PX_EVENT_LOOP"] = event_loop
    else:
        env.pop("PX_EVENT_LOOP", None)
    subp, cmd, buffer = run_px(
        "AuthNoneConnectTunnel",
        px_port,
        tmp_path,
        f"--proxy={upstream.addr} --auth=NONE --noproxy= --workers=1",
        env,
    )
    try:
        with socket.create_connection(("127.0.0.1", px_port), timeout=15) as client:
            client.sendall(
                b"CONNECT origin.test:443 HTTP/1.1\r\n"
                b"Host: origin.test:443\r\n"
                b"Proxy-Authorization: Negotiate dGVzdA==\r\n\r\n"
            )
            received = _read_through(client, b"raw-tunnel-server-data")
            response_end = received.index(b"\r\n\r\n") + 4
            assert received[:response_end].startswith(b"HTTP/1.1 200 ")
            assert received[response_end:] == b"\x16\x03\x03raw-tunnel-server-data"
            client.sendall(b"raw-tunnel-client-data")
    finally:
        print_buffer(buffer)
        quit_px("AuthNoneConnectTunnel", subp, cmd, strict=False)
        upstream.shutdown()
        upstream.server_close()


@pytest.mark.parametrize("event_loop", ["", "asyncio"])
def test_auth_none_connect_forwards_client_target(px_port, tmp_path, event_loop):
    "With --auth=NONE, CONNECT reaches the upstream proxy with the client's own request target"
    upstream = _HeaderRecorder()
    threading.Thread(target=upstream.serve_forever, daemon=True).start()
    env = copy.deepcopy(os.environ)
    if event_loop:
        env["PX_EVENT_LOOP"] = event_loop
    else:
        env.pop("PX_EVENT_LOOP", None)
    subp, cmd, buffer = run_px(
        "AuthNoneConnect", px_port, tmp_path, f"--proxy={upstream.addr} --auth=NONE --noproxy= --workers=1", env
    )
    try:
        conn = http.client.HTTPConnection("127.0.0.1", px_port, timeout=15)
        conn.request("CONNECT", "origin.test:443", headers={"Proxy-Authorization": "Negotiate dGVzdA=="})
        assert conn.getresponse().status == 200
        conn.close()
        assert upstream.requests, "the upstream proxy saw no CONNECT"
        head = upstream.requests[0]
        assert head[0] == "CONNECT origin.test:443 HTTP/1.1", head
        assert "Proxy-Authorization: Negotiate dGVzdA==" in head, head
    finally:
        print_buffer(buffer)
        quit_px("AuthNoneConnect", subp, cmd, strict=False)
        upstream.shutdown()
        upstream.server_close()


@pytest.mark.parametrize("event_loop", ["", "asyncio"])
def test_auth_none_connect_preserves_header_case(px_port, tmp_path, event_loop):
    "With --auth=NONE, CONNECT pass-through forwards headers with the client's own header-name case"
    upstream = _HeaderRecorder()
    threading.Thread(target=upstream.serve_forever, daemon=True).start()
    env = copy.deepcopy(os.environ)
    if event_loop:
        env["PX_EVENT_LOOP"] = event_loop
    else:
        env.pop("PX_EVENT_LOOP", None)
    subp, cmd, buffer = run_px(
        "AuthNoneConnectCase", px_port, tmp_path, f"--proxy={upstream.addr} --auth=NONE --noproxy= --workers=1", env
    )
    try:
        conn = http.client.HTTPConnection("127.0.0.1", px_port, timeout=15)
        conn.request(
            "CONNECT",
            "origin.test:443",
            headers={"Proxy-Authorization": "Negotiate dGVzdA==", "X-MyCustomHeader": "value1"},
        )
        assert conn.getresponse().status == 200
        conn.close()
        assert upstream.requests, "the upstream proxy saw no CONNECT"
        head = upstream.requests[0]
        assert "Proxy-Authorization: Negotiate dGVzdA==" in head, head
        assert "X-MyCustomHeader: value1" in head, head
    finally:
        print_buffer(buffer)
        quit_px("AuthNoneConnectCase", subp, cmd, strict=False)
        upstream.shutdown()
        upstream.server_close()


@pytest.mark.parametrize("event_loop", ["", "asyncio"])
def test_auth_none_plain_http_preserves_header_case(px_port, tmp_path, event_loop):
    "With --auth=NONE, plain HTTP requests forward headers with the client's own header-name case"
    upstream = _HeaderRecorder()
    threading.Thread(target=upstream.serve_forever, daemon=True).start()
    env = copy.deepcopy(os.environ)
    if event_loop:
        env["PX_EVENT_LOOP"] = event_loop
    else:
        env.pop("PX_EVENT_LOOP", None)
    subp, cmd, buffer = run_px(
        "AuthNonePlainCase", px_port, tmp_path, f"--proxy={upstream.addr} --auth=NONE --noproxy= --workers=1", env
    )
    try:
        conn = http.client.HTTPConnection("127.0.0.1", px_port, timeout=15)
        conn.request(
            "GET",
            "http://origin.test/",
            headers={"Proxy-Authorization": "Negotiate dGVzdA==", "X-MyCustomHeader": "value1"},
        )
        resp = conn.getresponse()
        resp.read()
        assert resp.status == 200
        conn.close()
        assert upstream.requests, "the upstream proxy saw no request"
        head = upstream.requests[0]
        assert "Proxy-Authorization: Negotiate dGVzdA==" in head, head
        assert "X-MyCustomHeader: value1" in head, head
    finally:
        print_buffer(buffer)
        quit_px("AuthNonePlainCase", subp, cmd, strict=False)
        upstream.shutdown()
        upstream.server_close()
