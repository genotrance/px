import asyncio
import contextlib
import hashlib
import http.server
import json
import os
import socketserver
import ssl
import subprocess
import threading
import time

ECHO_BODY_MAX = 4096


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        if self._is_echo():
            self._dispatch()
            return
        if self.path == "/large":
            body = b"x" * (4 * 1024 * 1024)
        elif self.path == "/stream":
            self.send_response(200)
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            for _ in range(20):
                self.wfile.write(b"4000\r\n" + b"s" * 16384 + b"\r\n")
                self.wfile.flush()
                time.sleep(0.05)
            self.wfile.write(b"0\r\n\r\n")
            return
        elif self.path == "/slow":
            time.sleep(3)
            body = b"slow response\n"
        elif self.path == "/proxy.pac":
            proxy = os.environ.get("PAC_PROXY", "127.0.0.1:31283")
            body = (
                "function FindProxyForURL(url, host) {\n"
                '  if (dnsDomainIs(host, ".corp.test")) '
                f'return "PROXY {proxy}";\n'
                '  return "DIRECT";\n}\n'
            ).encode()
        else:
            body = b"px scenario origin\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_exact(self, remaining):
        while remaining:
            data = self.rfile.read(min(remaining, 65536))
            if not data:
                raise EOFError
            remaining -= len(data)
            yield data

    def _body_blocks(self):
        """Yield the request body in blocks of at most 64 KiB, de-chunked when it is chunked."""
        if "chunked" not in self.headers.get("Transfer-Encoding", "").lower():
            yield from self._read_exact(int(self.headers.get("Content-Length") or 0))
            return
        while size := int(self.rfile.readline(65537).split(b";")[0].strip() or b"0", 16):
            yield from self._read_exact(size)
            self.rfile.readline(65537)
        while self.rfile.readline(65537) not in (b"\r\n", b"\n", b""):
            pass

    def _echo(self):
        """Hash the request body as it streams in and answer with its method, URL, length and SHA-256.

        Nothing larger than one read block is held in memory, so 100 MB bodies
        cost the origin no more than small ones. Bodies up to ECHO_BODY_MAX are
        also returned, which is what `px --test=all:URL` checks for.
        """
        digest = hashlib.sha256()
        length = 0
        kept = bytearray()
        for data in self._body_blocks():
            digest.update(data)
            length += len(data)
            if length <= ECHO_BODY_MAX:
                kept.extend(data)
        reply = {
            "method": self.command,
            "url": self._full_url(),
            "length": length,
            "sha256": digest.hexdigest(),
            "chunked": "chunked" in self.headers.get("Transfer-Encoding", "").lower(),
            "connection": self.headers.get("Connection", ""),
        }
        if length <= ECHO_BODY_MAX:
            reply["body"] = kept.decode("utf-8", "replace")
        body = json.dumps(reply).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        self._dispatch()

    do_PUT = do_PATCH = do_DELETE = do_POST

    def _full_url(self):
        """The URL as the client addressed it: the proxy sends origin-form paths, so rebuild it from Host."""
        if "://" in self.path:
            return self.path
        scheme = "https" if isinstance(self.server, TLSThreadingServer) else "http"
        return f"{scheme}://{self.headers.get('Host', '')}{self.path}"

    def _is_echo(self):
        path = self.path
        if "://" in path:
            path = "/" + path.split("://", 1)[1].partition("/")[2]
        return path.startswith("/echo")

    def _dispatch(self):
        if self._is_echo():
            try:
                self._echo()
            except (ConnectionError, EOFError, ValueError) as error:
                print(f"echo {self.command} {self.path} failed: {error}", flush=True)
                self.close_connection = True
            return
        body = b"not found\n"
        self.close_connection = True
        self.send_response(404)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        print(f"http {self.address_string()} {fmt % args}", flush=True)


class ThreadingServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    # The default backlog of 5 overflows under the 25-client bursts.
    request_queue_size = 128


class TLSThreadingServer(ThreadingServer):
    """Run each TLS handshake in its connection thread, not in accept().

    Wrapping the listening socket handshakes serially on the serve thread: one
    tunnel whose ClientHello is still in flight stalls every other accept, and
    the burst scenarios then see origin-side resets that are not Px faults.
    """

    def __init__(self, address, handler, context):
        self.context = context
        super().__init__(address, handler)

    def finish_request(self, request, client_address):
        request.settimeout(30)
        try:
            tls = self.context.wrap_socket(request, server_side=True)
        except OSError as error:
            print(f"tls {client_address[0]} handshake failed: {error}", flush=True)
            return
        with tls:
            super().finish_request(tls, client_address)

    def shutdown_request(self, request):
        # wrap_socket() detached the plain socket; the TLS socket is closed above
        with contextlib.suppress(OSError):
            super().shutdown_request(request)


def serve(port, tls=False):
    if tls:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain("/shared/origin.crt", "/shared/origin.key")
        server = TLSThreadingServer(("0.0.0.0", port), Handler, context)  # noqa: S104
    else:
        server = ThreadingServer(("0.0.0.0", port), Handler)  # noqa: S104
    server.serve_forever()


async def echo(reader, writer):
    try:
        while data := await reader.read(65536):
            writer.write(data)
            await writer.drain()
    finally:
        writer.close()
        await writer.wait_closed()


async def main():
    if not os.path.exists("/shared/origin.crt"):
        subprocess.run(
            [
                "/usr/bin/openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-days",
                "7",
                "-subj",
                "/CN=origin.corp.test",
                "-addext",
                "subjectAltName=DNS:origin.corp.test",
                "-keyout",
                "/shared/origin.key",
                "-out",
                "/shared/origin.crt",
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    for port, tls in ((8080, False), (8443, True), (8081, False)):
        threading.Thread(target=serve, args=(port, tls), daemon=True).start()
    server = await asyncio.start_server(echo, "0.0.0.0", 8888)  # noqa: S104
    async with server:
        await server.serve_forever()


asyncio.run(main())
