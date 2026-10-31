"""Client request bodies are streamed to the upstream without buffering.

Covers px's RequestBody reader (Content-Length and chunked bodies, trailers,
Expect: 100-continue), hop-by-hop header stripping, and uploads through plain
HTTP origins and an NTLM proxy with unknown auth, on both event loops.
"""

import asyncio
import base64
import contextlib
import copy
import hashlib
import json
import os
import socket
import socketserver
import struct
import threading
import time

import h11
import mcurl
import psutil
import pytest
from fixtures import *  # noqa: F403
from helpers import print_buffer, quit_px, run_px

from px import handler

HAS_NTLM = bool(mcurl.get_curl_vinfo().features & mcurl.libcurl.CURL_VERSION_NTLM)

needs_ntlm = pytest.mark.skipif(not HAS_NTLM, reason="libcurl was built without NTLM support")

EVENT_LOOPS = ["", "asyncio"]
USERNAME = "stream-test"
PASSWORD = "stream-pass"
BLOCK = 65536
BODY_SIZE = 3 * BLOCK + 12345
BIG_SIZE = 100 * 1024 * 1024
# px's RSS may grow by far less than the body; the real growth is a few MiB
RSS_CEILING = 40 * 1024 * 1024
PATTERN = hashlib.sha256(b"px stream upload").digest() * (BLOCK // 32)


def body_blocks(size):
    "Deterministic body of exactly size bytes, generated block by block"
    index = 0
    while size > 0:
        block = (index.to_bytes(8, "big") + PATTERN[8:])[: min(size, BLOCK)]
        yield block
        size -= len(block)
        index += 1


def body_sha256(size):
    digest = hashlib.sha256()
    for block in body_blocks(size):
        digest.update(block)
    return digest.hexdigest()


###
# Fake servers


def read_head(rfile):
    "Read a request line and headers; returns (method, target, headers) or None at EOF"
    line = rfile.readline()
    if not line.strip():
        return None
    method, target, _ = line.decode("latin-1").split()
    headers = {}
    while True:
        header = rfile.readline()
        if header in (b"\r\n", b"\n", b""):
            break
        name, _, value = header.decode("latin-1").partition(":")
        headers[name.strip().lower()] = value.strip()
    return method, target, headers


def read_body(rfile, headers):
    "Consume a Content-Length or chunked body; returns (sha256, length, trailers)"
    digest, length, trailers = hashlib.sha256(), 0, {}
    if "chunked" in headers.get("transfer-encoding", "").lower():
        while True:
            size = int(rfile.readline().split(b";")[0].strip() or b"0", 16)
            if size == 0:
                break
            data = rfile.read(size)
            rfile.readline()
            digest.update(data)
            length += len(data)
        while True:
            trailer = rfile.readline()
            if trailer in (b"\r\n", b"\n", b""):
                break
            name, _, value = trailer.decode("latin-1").partition(":")
            trailers[name.strip().lower()] = value.strip()
    else:
        remaining = int(headers.get("content-length", "0"))
        while remaining:
            data = rfile.read(min(remaining, BLOCK))
            if not data:
                break
            digest.update(data)
            length += len(data)
            remaining -= len(data)
    return digest.hexdigest(), length, trailers


def respond(wfile, status, headers=(), body=b""):
    reason = {200: "OK", 407: "Proxy Authentication Required"}[status]
    lines = [f"HTTP/1.1 {status} {reason}", *headers, f"Content-Length: {len(body)}"]
    wfile.write(("\r\n".join(lines) + "\r\n\r\n").encode() + body)
    wfile.flush()


class _Server(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 64

    def __init__(self, handler_class):
        super().__init__(("127.0.0.1", 0), handler_class)
        self.requests = []
        self.lock = threading.Lock()
        threading.Thread(target=self.serve_forever, daemon=True).start()

    @property
    def addr(self):
        return f"127.0.0.1:{self.server_address[1]}"

    def record(self, **fields):
        with self.lock:
            self.requests.append(fields)

    def stop(self):
        self.shutdown()
        self.server_close()


class _OriginHandler(socketserver.StreamRequestHandler):
    "Plain HTTP origin: hashes every request body and reports what it saw"

    def handle(self):
        while True:
            head = read_head(self.rfile)
            if head is None:
                return
            method, target, headers = head
            if headers.get("expect", "").lower() == "100-continue":
                self.wfile.write(b"HTTP/1.1 100 Continue\r\n\r\n")
                self.wfile.flush()
            sha, length, _ = read_body(self.rfile, headers)
            self.server.record(method=method, target=target, headers=headers, sha256=sha, length=length)
            respond(
                self.wfile,
                200,
                ["Content-Type: application/json"],
                json.dumps({"sha256": sha, "length": length}).encode(),
            )


def _type_2():
    flags = 0x00000001 | 0x00000200
    return (
        b"NTLMSSP\x00" + struct.pack("<IHHII", 2, 0, 0, 40, flags) + b"\x01\x02\x03\x04\x05\x06\x07\x08" + b"\x00" * 8
    )


class _NtlmProxyHandler(socketserver.StreamRequestHandler):
    """NTLM proxy answering uploads itself.

    A request without credentials is the unknown-auth probe. When it carries
    Expect: 100-continue the 407 comes before any body byte (and the connection
    is closed, as libcurl abandons it); with ignore_expect the body is read first.
    """

    def handle(self):
        authenticated = False
        while True:
            head = read_head(self.rfile)
            if head is None:
                return
            method, target, headers = head
            expect = headers.get("expect", "").lower() == "100-continue"
            token = headers.get("proxy-authorization", "")
            scheme, _, data = token.partition(" ")
            message = base64.b64decode(data) if scheme.upper() == "NTLM" and data else b""
            stage = struct.unpack("<I", message[8:12])[0] if len(message) >= 12 else 0
            leg = {"method": method, "target": target, "headers": headers, "stage": stage}
            close = "close" in headers.get("connection", "").lower() and self.server.close_honored
            if stage == 0 and not authenticated and expect and not self.server.ignore_expect:
                self.server.record(**leg, probe_before_body=True)
                respond(self.wfile, 407, ["Proxy-Authenticate: NTLM", "Connection: close"], b"auth required")
                return
            if expect and (authenticated or stage == 3):
                self.wfile.write(b"HTTP/1.1 100 Continue\r\n\r\n")
                self.wfile.flush()
            sha, length, _ = read_body(self.rfile, headers)
            if stage == 3:
                authenticated = True
            if not authenticated:
                challenge = "Proxy-Authenticate: NTLM" + (
                    " " + base64.b64encode(_type_2()).decode() if stage == 1 else ""
                )
                self.server.record(**leg, length=length)
                respond(self.wfile, 407, [challenge], b"auth required")
            else:
                self.server.record(**leg, sha256=sha, length=length, final=True)
                body = json.dumps({"sha256": sha, "length": length}).encode()
                respond(self.wfile, 200, ["Content-Type: application/json"], body)
            if close:
                return


class _NtlmProxy(_Server):
    def __init__(self, ignore_expect=False, close_honored=False):
        self.ignore_expect = ignore_expect
        self.close_honored = close_honored
        super().__init__(_NtlmProxyHandler)


@pytest.fixture
def origin():
    server = _Server(_OriginHandler)
    yield server
    server.stop()


@pytest.fixture
def make_ntlm_proxy():
    servers = []

    def make(**kwargs):
        servers.append(_NtlmProxy(**kwargs))
        return servers[-1]

    yield make
    for server in servers:
        server.stop()


###
# Client


class Response:
    def __init__(self, status, headers, body, interim):
        self.status, self.headers, self.body, self.interim = status, headers, body, interim

    def json(self):
        return json.loads(self.body)


class Client:
    "Raw HTTP/1.1 client for px with a generated, streamed request body"

    def __init__(self, port, timeout=60):
        self.sock = socket.create_connection(("127.0.0.1", port), timeout=timeout)
        self.rfile = self.sock.makefile("rb")

    def close(self):
        self.rfile.close()
        self.sock.close()

    def send(self, method, url, size=0, chunked=False, trailers=(), headers=(), expect=False, sender=None):
        lines = [f"{method} {url} HTTP/1.1", "Host: stream.test", *headers]
        if chunked:
            lines.append("Transfer-Encoding: chunked")
            if trailers:
                lines.append("Trailer: " + ", ".join(t.partition(":")[0] for t in trailers))
        elif size or method in ("POST", "PUT", "PATCH"):
            lines.append(f"Content-Length: {size}")
        if expect:
            lines.append("Expect: 100-continue")
        self.sock.sendall(("\r\n".join(lines) + "\r\n\r\n").encode())
        interim = []
        if expect:
            # px must answer 100 so a client that holds back the body does not deadlock
            interim.append(self.read_response().status)
        for block in body_blocks(size):
            self.sock.sendall(f"{len(block):x}\r\n".encode() + block + b"\r\n" if chunked else block)
        if chunked:
            self.sock.sendall(b"0\r\n" + "".join(t + "\r\n" for t in trailers).encode() + b"\r\n")
        response = self.read_response()
        while response.status == 100:
            interim.append(response.status)
            response = self.read_response()
        response.interim = interim
        return response

    def read_response(self):
        status = int(self.rfile.readline().split()[1])
        headers = {}
        while True:
            line = self.rfile.readline()
            if line in (b"\r\n", b""):
                break
            name, _, value = line.decode("latin-1").partition(":")
            headers[name.strip().lower()] = value.strip()
        body = self.rfile.read(int(headers.get("content-length", "0")))
        return Response(status, headers, body, [])


###
# px


def start_px(name, port, tmp_path, flags, loop_kind, extra_env=None):
    env = copy.deepcopy(os.environ)
    env["PX_PASSWORD"] = PASSWORD
    env.pop("PX_EVENT_LOOP", None)
    if loop_kind:
        env["PX_EVENT_LOOP"] = loop_kind
    env.update(extra_env or {})
    return run_px(name, port, tmp_path, flags, env, startup_timeout=90)


@pytest.fixture(params=EVENT_LOOPS, ids=["auto-loop", "asyncio"])
def loop_kind(request):
    return request.param


@pytest.fixture
def direct_px(px_port, tmp_path, loop_kind):
    subp, cmd, buffer = start_px("StreamDirect", px_port, tmp_path, "--noproxy=127.0.0.1 --workers=1", loop_kind)
    yield px_port, subp
    print_buffer(buffer)
    quit_px("StreamDirect", subp, cmd, strict=False)


@pytest.fixture
def client_auth_px(px_port, tmp_path, loop_kind):
    flags = "--noproxy=127.0.0.1 --workers=1 --client-auth=BASIC"
    env = {"PX_CLIENT_USERNAME": USERNAME, "PX_CLIENT_PASSWORD": PASSWORD}
    subp, cmd, buffer = start_px("StreamClientAuth", px_port, tmp_path, flags, loop_kind, env)
    yield px_port
    print_buffer(buffer)
    quit_px("StreamClientAuth", subp, cmd, strict=False)


@pytest.fixture
def ntlm_px(px_port, tmp_path, loop_kind, make_ntlm_proxy):
    "Start px in front of a fake NTLM proxy; returns a factory so tests choose the proxy behaviour"
    started = []

    def start(**proxy_options):
        proxy = make_ntlm_proxy(**proxy_options)
        flags = f"--server={proxy.addr} --auth=ANY --username={USERNAME} --authretry=0 --noproxy= --workers=1"
        started.append(start_px("StreamNtlm", px_port, tmp_path, flags, loop_kind))
        return px_port, proxy

    yield start
    for subp, cmd, buffer in started:
        print_buffer(buffer)
        quit_px("StreamNtlm", subp, cmd, strict=False)


def px_rss(subp):
    "Resident memory of px and its child processes"
    root = psutil.Process(subp.pid)
    return sum(p.memory_info().rss for p in [root, *root.children(recursive=True)])


###
# RequestBody unit tests (in process, on each event loop implementation)


def loop_factories():
    factories = [asyncio.new_event_loop]
    try:
        import uvloop

        factories.append(uvloop.new_event_loop)
    except ImportError:
        try:
            import winloop

            factories.append(winloop.new_event_loop)
        except ImportError:
            pass
    return factories


def consume_body(body, woken):
    "Read a RequestBody to the end; None means paused until body.resume (woken) fires"
    data = b""
    while True:
        woken.clear()
        part = body.read(11)
        if part is None:
            assert woken.wait(10)
        elif not part:
            return data
        else:
            data += part


def run_reader(wire, factory, pipelined=b"", chunk=7):
    """Feed wire bytes to a RequestBody in small pieces and read it all from another thread.

    pipelined bytes ride along with the last piece. Returns (data, body, h11 conn, interim writes)"""
    result = {}

    async def main():
        loop = asyncio.get_running_loop()
        stream = asyncio.StreamReader()
        conn = h11.Connection(h11.SERVER)
        head, _, rest = wire.partition(b"\r\n\r\n")
        conn.receive_data(head + b"\r\n\r\n")
        assert isinstance(conn.next_event(), h11.Request)

        class Transport:
            def __init__(self):
                self.written = []

            def is_closing(self):
                return False

            def write(self, data):
                self.written.append(data)

        transport = Transport()
        body = handler.RequestBody(conn, stream, loop, transport, expect_continue=b"Expect" in head)

        def feed():
            pieces = [rest[i : i + chunk] for i in range(0, len(rest), chunk)] or [b""]
            pieces[-1] += pipelined
            for piece in pieces:
                loop.call_soon_threadsafe(stream.feed_data, piece)
                time.sleep(0.0005)
            loop.call_soon_threadsafe(stream.feed_eof)

        woken = threading.Event()
        body.resume = woken.set

        feeder = threading.Thread(target=feed, daemon=True)
        feeder.start()
        result["data"] = await asyncio.to_thread(consume_body, body, woken)
        await asyncio.to_thread(feeder.join)
        result["body"], result["conn"], result["written"] = body, conn, transport.written

    loop = factory()
    try:
        loop.run_until_complete(main())
    finally:
        loop.close()
    return result["data"], result["body"], result["conn"], result["written"]


@pytest.mark.parametrize("factory", loop_factories())
def test_reader_content_length(factory):
    data, body, conn, _ = run_reader(
        b"POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 20\r\n\r\n0123456789abcdefghij", factory, b"GET /next"
    )
    assert data == b"0123456789abcdefghij"
    assert not body.seekable() and not hasattr(body, "seek")
    assert body.finish() and not body.failed
    assert bytes(conn.trailing_data[0]) == b"GET /next"


@pytest.mark.parametrize("factory", loop_factories())
def test_reader_chunked_with_trailers(factory):
    wire = (
        b"POST / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\nTrailer: X-Sum\r\n\r\n"
        b"5\r\nhello\r\n6;ext=1\r\n world\r\n0\r\nX-Sum: 1\r\n\r\n"
    )
    data, body, conn, _ = run_reader(wire, factory, b"GET /next")
    assert data == b"hello world"
    assert body.finish()
    assert bytes(conn.trailing_data[0]) == b"GET /next"


@pytest.mark.parametrize("factory", loop_factories())
def test_reader_client_disconnect(factory):
    data, body, _, _ = run_reader(b"POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 50\r\n\r\nshort", factory)
    assert data == b"short"
    assert body.failed and not body.finish()


@pytest.mark.parametrize("factory", loop_factories())
def test_reader_expect_continue_sent_on_first_read(factory):
    wire = b"POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 3\r\nExpect: 100-continue\r\n\r\nabc"
    data, body, _, written = run_reader(wire, factory)
    assert data == b"abc" and body.finish()
    assert written == [handler.CONTINUE_RESPONSE]


@pytest.mark.parametrize("factory", loop_factories())
@pytest.mark.parametrize(
    "final_status",
    [b"HTTP/1.1 200 OK\r\n", b"HTTP/1.1 407 Proxy Authentication Required\r\n"],
)
def test_header_writer_suppresses_upstream_continue(factory, final_status):
    """Px owns the downstream 100 response, so bridge relays only the real response.

    A client that did not send its own Expect still reaches an upstream that answers
    with 100 Continue before its real status (200 or 407); the real status and every
    one of its headers must come through unmodified and in order.
    """

    class Transport:
        def __init__(self):
            self.written = []

        def is_closing(self):
            return False

        def write(self, data):
            self.written.append(data)

    async def run():
        transport = Transport()
        writer = handler.HeaderBridgeWriter(asyncio.get_running_loop(), transport)
        for line in (
            b"HTTP/1.1 100 Continue\r\n",
            b"Header: ignored\r\n",
            b"\r\n",
            final_status,
            b"Proxy-Authenticate: Negotiate\r\n",
            b"Content-Length: 0\r\n",
            b"\r\n",
        ):
            writer.write(line)
        await asyncio.sleep(0)
        return transport.written

    loop = factory()
    try:
        assert loop.run_until_complete(run()) == [
            final_status,
            b"Proxy-Authenticate: Negotiate\r\n",
            b"Content-Length: 0\r\n",
            b"\r\n",
        ]
    finally:
        loop.close()


def test_reader_without_body_is_complete():
    conn = h11.Connection(h11.SERVER)
    conn.receive_data(b"GET / HTTP/1.1\r\nHost: h\r\n\r\n")
    conn.next_event()
    body = handler.RequestBody(conn, None, None, None)
    assert body.complete and body.read(10) == b"" and body.finish()
    assert handler.RequestBody().read() == b""


class FakeCurl:
    """Mimics mcurl.Curl's resume_upload()/transfer_id contract (mcurl commit 3318186, pymcurl
    8.23.0.3) without any real transfer: transfer_id is absent on a stand-in for older pymcurl."""

    def __init__(self, has_transfer_id=True):
        if has_transfer_id:
            self.transfer_id = 0
        self.calls = []

    def resume_upload(self, transfer_id=None):
        self.calls.append(transfer_id)
        if not hasattr(self, "transfer_id"):
            return True
        if transfer_id is None and self.transfer_id != 0:
            raise ValueError("resume() of a reused Curl needs its transfer_id")  # noqa: TRY003
        return transfer_id is None or transfer_id == self.transfer_id


def test_bind_upload_resume_scopes_to_current_transfer():
    "A resume bound before curl is reused for a later transfer is stale and becomes a no-op, not an error"
    curl = FakeCurl()
    body = handler.RequestBody()
    handler.bind_upload_resume(curl, body)
    assert body.resume() is True and curl.calls == [0]

    stale_resume = body.resume  # captured the transfer_id of the handle's first transfer (0)
    curl.transfer_id = 1  # curl.reset() reused the handle for a second transfer
    handler.bind_upload_resume(curl, body)
    assert body.resume() is True and curl.calls[-1] == 1

    assert stale_resume() is False  # discarded, not raised, and does not touch transfer 1
    assert curl.calls[-1] == 0


def test_bind_upload_resume_without_transfer_id_uses_plain_call():
    "pymcurl with resume_upload but no transfer_id (pre-8.23.0.3): fall back to the no-argument call"
    curl = FakeCurl(has_transfer_id=False)
    body = handler.RequestBody()
    handler.bind_upload_resume(curl, body)
    assert body.resume() is True and curl.calls == [None]


def test_upstream_headers_strip_hop_by_hop():
    headers = {
        "host": "origin.test",
        "connection": "close, X-Hop",
        "x-hop": "1",
        "proxy-connection": "keep-alive",
        "keep-alive": "timeout=5",
        "te": "trailers",
        "trailer": "X-Sum",
        "upgrade": "websocket",
        "expect": "100-continue",
        "proxy-authorization": "Basic Zm9vOmJhcg==",
        "content-length": "5",
        "transfer-encoding": "chunked",
        "x-keep": "yes",
    }
    kept = handler.ConnectionHandler._upstream_headers(headers)
    assert kept == {
        "host": "origin.test",
        "proxy-authorization": "Basic Zm9vOmJhcg==",
        "transfer-encoding": "chunked",
        "x-keep": "yes",
    }
    assert "proxy-authorization" not in handler.ConnectionHandler._upstream_headers(headers, strip_proxy_auth=True)
    sized = {"content-length": "5", "connection": "Content-Length"}
    assert handler.ConnectionHandler._upstream_headers(sized) == {"content-length": "5"}


def test_rewind_error_detection():
    detect = handler.ConnectionHandler._is_rewind_error
    assert detect("Send failed since rewinding of the data stream failed; ")
    assert not detect("Connection refused")
    assert detect(mcurl.REWIND_ERROR)


###
# Direct (no upstream proxy) uploads through px


@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH"])
@pytest.mark.parametrize("chunked", [False, True], ids=["content-length", "chunked"])
def test_body_reaches_origin_intact(direct_px, origin, method, chunked):
    port, _ = direct_px
    client = Client(port)
    try:
        response = client.send(method, f"http://{origin.addr}/up", BODY_SIZE, chunked=chunked)
    finally:
        client.close()
    assert response.status == 200
    assert response.json() == {"sha256": body_sha256(BODY_SIZE), "length": BODY_SIZE}
    seen = origin.requests[-1]
    assert seen["method"] == method and seen["sha256"] == body_sha256(BODY_SIZE)
    if chunked:
        assert "chunked" in seen["headers"]["transfer-encoding"] and "content-length" not in seen["headers"]
    else:
        assert seen["headers"]["content-length"] == str(BODY_SIZE)
        assert "transfer-encoding" not in seen["headers"]


def test_chunked_trailers_and_keep_alive(direct_px, origin):
    "Trailers are consumed and the connection stays usable for the next request"
    port, _ = direct_px
    client = Client(port)
    try:
        url = f"http://{origin.addr}/up"
        first = client.send("POST", url, 1000, chunked=True, trailers=["X-Checksum: abc"])
        second = client.send("POST", url, 2000)
        third = client.send("GET", url)
        fourth = client.send("PUT", url, 70000, chunked=True)
    finally:
        client.close()
    assert [first.status, second.status, third.status, fourth.status] == [200] * 4
    assert [r["length"] for r in origin.requests] == [1000, 2000, 0, 70000]
    assert origin.requests[0]["sha256"] == body_sha256(1000)
    assert "x-checksum" not in origin.requests[0]["headers"]


def test_empty_post_and_zero_length_chunked(direct_px, origin):
    port, _ = direct_px
    client = Client(port)
    try:
        url = f"http://{origin.addr}/up"
        assert client.send("POST", url, 0).status == 200
        assert client.send("POST", url, 0, chunked=True).status == 200
    finally:
        client.close()
    assert [r["length"] for r in origin.requests] == [0, 0]


def test_expect_continue_does_not_deadlock(direct_px, origin):
    "px answers 100 Continue itself, so a client waiting for it sends the body"
    port, _ = direct_px
    client = Client(port, timeout=20)
    try:
        url = f"http://{origin.addr}/up"
        response = client.send("POST", url, BODY_SIZE, expect=True)
        chunked = client.send("POST", url, BODY_SIZE, chunked=True, expect=True)
    finally:
        client.close()
    assert response.status == 200 and response.interim == [100]
    assert chunked.status == 200 and chunked.interim == [100]
    assert [r["sha256"] for r in origin.requests] == [body_sha256(BODY_SIZE)] * 2
    assert all("expect" not in r["headers"] for r in origin.requests)


def test_hop_by_hop_headers_not_forwarded(direct_px, origin):
    port, _ = direct_px
    client = Client(port)
    headers = [
        "Connection: close, X-Hop",
        "X-Hop: 1",
        "Proxy-Connection: close",
        "Keep-Alive: timeout=5",
        "TE: trailers",
        "Trailer: X-Sum",
        "Upgrade: foo",
        "X-Keep: yes",
    ]
    try:
        response = client.send("POST", f"http://{origin.addr}/up", 100, headers=headers)
    finally:
        client.close()
    assert response.status == 200
    seen = origin.requests[-1]["headers"]
    for name in ("connection", "x-hop", "proxy-connection", "keep-alive", "te", "trailer", "upgrade"):
        assert name not in seen, name
    assert seen["x-keep"] == "yes" and seen["content-length"] == "100"


CLIENT_CREDENTIALS = "Proxy-Authorization: Basic " + base64.b64encode(f"{USERNAME}:{PASSWORD}".encode()).decode()


@pytest.mark.parametrize("chunked", [False, True], ids=["content-length", "chunked"])
def test_client_auth_discards_body_and_keeps_connection(client_auth_px, origin, chunked):
    "Px's own 407 discards the unread body (without storing it) so the client can authenticate on the same connection"
    client = Client(client_auth_px)
    url = f"http://{origin.addr}/up"
    try:
        denied = client.send("POST", url, BODY_SIZE, chunked=chunked)
        allowed = client.send("POST", url, BODY_SIZE, chunked=chunked, headers=[CLIENT_CREDENTIALS])
    finally:
        client.close()
    assert denied.status == 407 and allowed.status == 200
    assert [r["sha256"] for r in origin.requests] == [body_sha256(BODY_SIZE)]
    assert "proxy-authorization" not in origin.requests[0]["headers"]


def test_client_auth_with_expect_closes_connection(client_auth_px, origin):
    "A 407 answering a held-back Expect closes the connection so a late body is never parsed as the next request"
    client = Client(client_auth_px, timeout=20)
    url = f"http://{origin.addr}/up"
    try:
        head = f"POST {url} HTTP/1.1\r\nHost: x\r\nContent-Length: {BODY_SIZE}\r\nExpect: 100-continue\r\n\r\n"
        client.sock.sendall(head.encode())
        denied = client.read_response()
        assert denied.status == 407 and denied.headers["connection"] == "close"
        assert client.rfile.read() == b""
    finally:
        client.close()
    client = Client(client_auth_px, timeout=20)
    try:
        allowed = client.send("POST", url, BODY_SIZE, headers=[CLIENT_CREDENTIALS])
    finally:
        client.close()
    assert allowed.status == 200
    assert [r["sha256"] for r in origin.requests] == [body_sha256(BODY_SIZE)]


@pytest.mark.parametrize("chunked", [False, True], ids=["content-length", "chunked"])
def test_client_auth_late_body_is_not_parsed_as_request(client_auth_px, origin, chunked):
    "A body sent after its Expect timeout, even one shaped like an authenticated request, never reaches the origin"
    smuggled = f"GET http://{origin.addr}/smuggled HTTP/1.1\r\nHost: x\r\n{CLIENT_CREDENTIALS}\r\n\r\n".encode()
    framing = "Transfer-Encoding: chunked" if chunked else f"Content-Length: {len(smuggled)}"
    body = f"{len(smuggled):x}\r\n".encode() + smuggled + b"\r\n0\r\n\r\n" if chunked else smuggled
    client = Client(client_auth_px, timeout=20)
    try:
        head = f"POST http://{origin.addr}/up HTTP/1.1\r\nHost: x\r\n{framing}\r\nExpect: 100-continue\r\n\r\n"
        client.sock.sendall(head.encode())
        assert client.read_response().status == 407
        with contextlib.suppress(OSError):
            client.sock.sendall(body)
        with contextlib.suppress(ConnectionError):
            assert client.rfile.read() == b""
    finally:
        client.close()
    assert origin.requests == []


@pytest.mark.parametrize("chunked", [False, True], ids=["content-length", "chunked"])
def test_large_upload_bounded_memory(direct_px, origin, loop_kind, chunked):
    "A 100 MB body streams through px with RSS far below the body size"
    if chunked and loop_kind:
        pytest.skip("100 MB chunked is covered on the default event loop; the transfer takes ~30 s")
    port, subp = direct_px
    baseline = px_rss(subp)
    peak = [baseline]
    done = threading.Event()

    def sample():
        while not done.wait(0.02):
            peak.append(px_rss(subp))

    sampler = threading.Thread(target=sample, daemon=True)
    sampler.start()
    client = Client(port, timeout=120)
    try:
        response = client.send("POST", f"http://{origin.addr}/big", BIG_SIZE, chunked=chunked)
    finally:
        client.close()
        done.set()
        sampler.join()
    assert response.status == 200
    assert response.json() == {"sha256": body_sha256(BIG_SIZE), "length": BIG_SIZE}
    growth = max(peak) - baseline
    print(f"px RSS baseline {baseline >> 20} MiB, peak growth {growth >> 20} MiB for a {BIG_SIZE >> 20} MiB body")
    assert growth < RSS_CEILING


###
# Uploads through an NTLM proxy with unknown auth


@needs_ntlm
@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH"])
@pytest.mark.parametrize("chunked", [False, True], ids=["content-length", "chunked"])
def test_upload_through_ntlm_proxy_first_request(ntlm_px, method, chunked):
    "The first upload succeeds: the probe leg gets its 407 before any body byte, the body goes on the final leg"
    port, proxy = ntlm_px()
    client = Client(port)
    try:
        response = client.send(method, "http://ntlm-upload.test/up", BODY_SIZE, chunked=chunked)
        again = client.send(method, "http://ntlm-upload.test/up", BODY_SIZE, chunked=chunked)
    finally:
        client.close()
    assert response.status == 200, response.body
    assert response.json() == {"sha256": body_sha256(BODY_SIZE), "length": BODY_SIZE}
    assert again.status == 200
    assert any(leg.get("probe_before_body") for leg in proxy.requests)
    finals = [leg for leg in proxy.requests if leg.get("final")]
    assert [leg["sha256"] for leg in finals] == [body_sha256(BODY_SIZE)] * 2
    assert all(leg["length"] == 0 for leg in proxy.requests if not leg.get("final") and "length" in leg)


@needs_ntlm
def test_upload_through_ntlm_proxy_with_client_expect(ntlm_px):
    port, _proxy = ntlm_px()
    client = Client(port, timeout=30)
    try:
        response = client.send("POST", "http://ntlm-upload.test/up", BODY_SIZE, expect=True)
    finally:
        client.close()
    assert response.status == 200 and response.interim == [100]
    assert response.json()["sha256"] == body_sha256(BODY_SIZE)


@needs_ntlm
def test_proxy_ignoring_expect_reports_rewind_error(ntlm_px):
    "A proxy that ignores Expect with unknown auth gets a clear 503; the retry works as the method is cached"
    port, _proxy = ntlm_px(ignore_expect=True)
    client = Client(port, timeout=30)
    try:
        failed = client.send("POST", "http://ntlm-upload.test/up", BODY_SIZE)
    finally:
        client.close()
    assert failed.status == 503
    assert b"ignored" in failed.body and b"Expect: 100-continue" in failed.body and b"retry" in failed.body
    client = Client(port, timeout=30)
    try:
        retry = client.send("POST", "http://ntlm-upload.test/up", BODY_SIZE)
    finally:
        client.close()
    assert retry.status == 200
    assert retry.json()["sha256"] == body_sha256(BODY_SIZE)


@needs_ntlm
def test_client_connection_close_does_not_break_ntlm(ntlm_px):
    "Connection: close from the client is not forwarded, so the proxy keeps the NTLM connection open"
    port, proxy = ntlm_px(close_honored=True)
    client = Client(port)
    try:
        response = client.send(
            "GET", "http://ntlm-upload.test/", headers=["Connection: close", "Proxy-Authorization: Basic Zm9vOmJhcg=="]
        )
    finally:
        client.close()
    assert response.status == 200, response.body
    assert all("close" not in leg["headers"].get("connection", "").lower() for leg in proxy.requests)
    assert all("basic" not in leg["headers"].get("proxy-authorization", "").lower() for leg in proxy.requests)


###
# A stalled or slow uploader must not delay other requests on the same worker

STALL_SECONDS = 5
# Normal latency of a small request through px on loopback is a few ms; far below the stall
FAST_LATENCY = 2.0
PARALLEL_UPLOADS = 60


def send_stalled_on(client, url, stall, size=BODY_SIZE, first=1000):
    "Send headers and the first bytes of a body on an existing (possibly keep-alive) client, stall, then finish"
    client.sock.sendall(f"POST {url} HTTP/1.1\r\nHost: stall.test\r\nContent-Length: {size}\r\n\r\n".encode())
    data = b"".join(body_blocks(size))
    client.sock.sendall(data[:first])
    stall.wait(STALL_SECONDS)
    client.sock.sendall(data[first:])
    return client.read_response()


def send_stalled(port, url, stall, size=BODY_SIZE, first=1000):
    "Send headers and the first bytes of a body, stall, then finish; returns the response"
    client = Client(port, timeout=60)
    try:
        return send_stalled_on(client, url, stall, size, first)
    finally:
        client.close()


def timed(fn, *args, **kwargs):
    start = time.monotonic()
    result = fn(*args, **kwargs)
    return result, time.monotonic() - start


def check_stalled_does_not_delay(port, url, other_url):
    release = threading.Event()
    stalled = {}
    thread = threading.Thread(target=lambda: stalled.update(r=send_stalled(port, url, release)), daemon=True)
    thread.start()
    time.sleep(1)
    started = time.monotonic()
    latencies = []
    for _ in range(3):
        client = Client(port, timeout=30)
        try:
            response, took = timed(client.send, "GET", other_url)
            assert response.status == 200
            latencies.append(took)
            response, took = timed(client.send, "POST", other_url, BODY_SIZE)
            assert response.status == 200
            assert response.json() == {"sha256": body_sha256(BODY_SIZE), "length": BODY_SIZE}
            latencies.append(took)
        finally:
            client.close()
    elapsed = time.monotonic() - started
    assert thread.is_alive(), "the stalled upload must still be stalled while the others complete"
    print(f"stalled upload, others' latencies: {[round(t, 3) for t in latencies]}")
    assert max(latencies) < FAST_LATENCY and elapsed < STALL_SECONDS - 1
    release.set()
    thread.join(30)
    assert stalled["r"].status == 200
    assert stalled["r"].json() == {"sha256": body_sha256(BODY_SIZE), "length": BODY_SIZE}


def test_stalled_upload_does_not_delay_others_direct(direct_px, origin):
    port, _ = direct_px
    url = f"http://{origin.addr}/x"
    check_stalled_does_not_delay(port, url, url)


@needs_ntlm
def test_stalled_upload_does_not_delay_others_ntlm(ntlm_px):
    port, _proxy = ntlm_px()
    url = "http://ntlm-upload.test/x"
    check_stalled_does_not_delay(port, url, url)


def test_stalled_uploads_on_reused_keep_alive_handle(direct_px, origin):
    """Two sequential paused uploads on one keep-alive connection reuse px's Curl handle (reset()).

    Resuming the second upload must use the reused handle's own transfer, never the first
    transfer's now-stale one (mcurl commit 3318186, pymcurl 8.23.0.3's Curl.transfer_id)."""
    port, _ = direct_px
    url = f"http://{origin.addr}/x"
    client = Client(port, timeout=30)
    try:
        first = send_stalled_on(client, url, threading.Event())
        second = send_stalled_on(client, url, threading.Event())
        third = send_stalled_on(client, url, threading.Event())
    finally:
        client.close()
    expected = {"sha256": body_sha256(BODY_SIZE), "length": BODY_SIZE}
    assert [r.status for r in (first, second, third)] == [200, 200, 200]
    assert [r.json() for r in (first, second, third)] == [expected] * 3


def test_stalled_upload_through_auth_none_proxy_completes(origin, px_port, tmp_path, loop_kind):
    "--auth=NONE runs the easy interface where a paused upload is never resumed: the body must still arrive"
    flags = f"--server={origin.addr} --auth=NONE --noproxy= --workers=1"
    subp, cmd, buffer = start_px("StreamAuthNone", px_port, tmp_path, flags, loop_kind)
    try:
        response, took = timed(send_stalled, px_port, "http://auth-none.test/x", threading.Event())
    finally:
        print_buffer(buffer)
        quit_px("StreamAuthNone", subp, cmd, strict=False)
    assert response.status == 200, response.body
    assert response.json() == {"sha256": body_sha256(BODY_SIZE), "length": BODY_SIZE}
    assert took < STALL_SECONDS + 10


@pytest.mark.parametrize("chunked", [False, True], ids=["content-length", "chunked"])
def test_many_parallel_streamed_uploads_exact(direct_px, origin, chunked):
    port, _ = direct_px
    size = BODY_SIZE + 4321
    results, errors = {}, []

    def upload(i):
        client = Client(port, timeout=120)
        try:
            results[i] = client.send("POST", f"http://{origin.addr}/p{i}", size, chunked=chunked)
        except Exception as exc:
            errors.append(exc)
        finally:
            client.close()

    threads = [threading.Thread(target=upload, args=(i,)) for i in range(PARALLEL_UPLOADS)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(120)
    assert not errors
    assert len(results) == PARALLEL_UPLOADS
    expected = {"sha256": body_sha256(size), "length": size}
    assert all(r.status == 200 and r.json() == expected for r in results.values())
