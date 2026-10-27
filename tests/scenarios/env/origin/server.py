import asyncio
import contextlib
import http.server
import os
import socketserver
import ssl
import subprocess
import threading
import time


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
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
