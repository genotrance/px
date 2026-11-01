import copy
import http.client
import os
import socketserver
import threading

import pytest
from fixtures import *  # noqa: F403
from helpers import *  # noqa: F403

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
