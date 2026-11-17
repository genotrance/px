"""NTLM/Negotiate server auth passed through px to a DIRECT target (px #290).

Connection-oriented server auth only works if the client's Type 1 and Type 3
messages reach the server on the same upstream connection. px keeps such a
client connection on mcurl's easy interface (one connection cache per handle)
instead of the shared multi pool, for noproxy and PAC DIRECT targets alike.
"""

import base64
import os
import socket
import socketserver
import struct
import threading

import pytest
from fixtures import *  # noqa: F403
from helpers import *  # noqa: F403

TYPE_1 = "NTLM " + base64.b64encode(b"NTLMSSP\x00" + struct.pack("<I", 1) + b"\x00" * 24).decode()
TYPE_3 = "NTLM " + base64.b64encode(b"NTLMSSP\x00" + struct.pack("<I", 3) + b"\x00" * 56).decode()
TYPE_2 = "NTLM " + base64.b64encode(b"NTLMSSP\x00" + struct.pack("<I", 2) + b"\x00" * 24).decode()
RESPONSE_BODY = b"direct ntlm ok"


class _NtlmOrigin(socketserver.ThreadingTCPServer):
    """An origin server which accepts Type 3 only on the connection that got its Type 2."""

    daemon_threads = True
    allow_reuse_address = True

    def __init__(self):
        super().__init__(("127.0.0.1", 0), _NtlmOriginHandler)
        self.lock = threading.Lock()
        self.connections = 0
        self.completed = 0
        self.rejected = 0
        self.bodies = []


class _NtlmOriginHandler(socketserver.StreamRequestHandler):
    def _send(self, status, headers=(), body=b""):
        lines = [f"HTTP/1.1 {status}", *headers, f"Content-Length: {len(body)}", "", ""]
        self.wfile.write("\r\n".join(lines).encode() + body)
        self.wfile.flush()

    def handle(self):
        with self.server.lock:
            self.server.connections += 1
        challenged = False
        while True:
            line = self.rfile.readline()
            if not line.strip():
                return
            headers = {}
            while True:
                hline = self.rfile.readline()
                if hline in (b"\r\n", b"\n", b""):
                    break
                name, _, value = hline.decode("latin-1").partition(":")
                headers[name.strip().lower()] = value.strip()
            body = self.rfile.read(int(headers.get("content-length", "0")))
            auth = headers.get("authorization", "")
            if auth == TYPE_1:
                challenged = True
                self._send("401 Unauthorized", [f"WWW-Authenticate: {TYPE_2}"])
            elif auth == TYPE_3 and challenged:
                challenged = False
                with self.server.lock:
                    self.server.completed += 1
                    self.server.bodies.append(body)
                self._send("200 OK", body=RESPONSE_BODY)
            else:
                if auth == TYPE_3:
                    with self.server.lock:
                        self.server.rejected += 1
                challenged = False
                self._send("401 Unauthorized", ["WWW-Authenticate: NTLM"])


@pytest.fixture
def ntlm_origin():
    server = _NtlmOrigin()
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server
    server.shutdown()
    server.server_close()


class _Client:
    """A raw keep-alive client connection to px."""

    def __init__(self, px_port, origin_port):
        self.sock = socket.create_connection(("127.0.0.1", px_port), timeout=20)
        self.rfile = self.sock.makefile("rb")
        self.url = f"http://127.0.0.1:{origin_port}/"
        self.host = f"127.0.0.1:{origin_port}"

    def request(self, method, auth, body=None):
        lines = [f"{method} {self.url} HTTP/1.1", f"Host: {self.host}", f"Authorization: {auth}"]
        if body is not None:
            lines.append(f"Content-Length: {len(body)}")
        self.sock.sendall(("\r\n".join(lines) + "\r\n\r\n").encode() + (body or b""))
        status = int(self.rfile.readline().split()[1])
        length = 0
        while True:
            hline = self.rfile.readline()
            if hline in (b"\r\n", b"\n", b""):
                break
            name, _, value = hline.decode("latin-1").partition(":")
            if name.strip().lower() == "content-length":
                length = int(value.strip())
        return status, self.rfile.read(length)

    def close(self):
        self.rfile.close()
        self.sock.close()


def _start_px(name, port, tmp_path, flags):
    env = dict(os.environ)
    env.pop("PX_EVENT_LOOP", None)
    return run_px(name, port, tmp_path, f"{flags} --workers=1", env, startup_timeout=90)


def _px_flags(mode, tmp_path):
    if mode == "noproxy":
        return "--noproxy=127.0.0.1"
    pac = tmp_path / "direct.pac"
    pac.write_text('function FindProxyForURL(url, host) { return "DIRECT"; }\n')
    return f"--pac={pac}"


@pytest.mark.parametrize("mode", ["noproxy", "pac"])
@pytest.mark.parametrize("method,body", [("GET", None), ("POST", b"")], ids=["get", "empty-post"])
def test_direct_ntlm_interleaved_clients(ntlm_origin, px_port, tmp_path, mode, method, body):
    """Two client connections interleave NTLM handshakes to a DIRECT server; both complete."""
    subp, cmd, buffer = _start_px("DirectNtlm", px_port, tmp_path, _px_flags(mode, tmp_path))
    port = ntlm_origin.server_address[1]
    first = _Client(px_port, port)
    second = _Client(px_port, port)
    try:
        # Both Type 1 messages leave before either Type 3, so a shared pool would
        # hold two challenged connections and could send a Type 3 on the wrong one
        assert first.request(method, TYPE_1, body)[0] == 401
        assert second.request(method, TYPE_1, body)[0] == 401
        assert second.request(method, TYPE_3, body) == (200, RESPONSE_BODY)
        assert first.request(method, TYPE_3, body) == (200, RESPONSE_BODY)

        # Curl.reset() between requests keeps the easy handle's upstream connection
        assert first.request(method, TYPE_1, body)[0] == 401
        assert first.request(method, TYPE_3, body) == (200, RESPONSE_BODY)

        assert ntlm_origin.completed == 3
        assert ntlm_origin.rejected == 0
        assert ntlm_origin.connections == 2
        if body is not None:
            assert ntlm_origin.bodies == [b""] * 3
    finally:
        first.close()
        second.close()
        print_buffer(buffer)
        quit_px("DirectNtlm", subp, cmd, strict=False)
