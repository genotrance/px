"""Tests for listener setup: backlog and TCP_NODELAY on accepted sockets."""

import asyncio
import socket
import unittest.mock

import pytest

from px import main as px_main


def _libuv_factory():
    if px_main._libuv is None:
        pytest.skip("libuv event loop not available")
    return px_main._libuv.new_event_loop


def test_backlog_constant():
    assert px_main.LISTEN_BACKLOG == 2048


def test_create_listen_socket_backlog_and_proto():
    sock = px_main.create_listen_socket("127.0.0.1", 0)
    try:
        assert sock.proto == socket.IPPROTO_TCP
    finally:
        sock.close()

    real = socket.socket
    calls = []

    class Spy(real):
        def listen(self, backlog=None):
            calls.append(backlog)
            return super().listen(backlog)

    with unittest.mock.patch.object(px_main.socket, "socket", Spy):
        s = px_main.create_listen_socket("127.0.0.1", 0)
        s.close()
    assert calls == [px_main.LISTEN_BACKLOG]


def test_start_server_passes_backlog():
    async def run():
        with unittest.mock.patch.object(asyncio, "start_server", unittest.mock.AsyncMock()) as m:
            await px_main.start_server("127.0.0.1", 0)
            await px_main.start_server("127.0.0.1", 0, sock=object())
        return m.call_args_list

    for call in asyncio.run(run()):
        assert call.kwargs["backlog"] == px_main.LISTEN_BACKLOG


async def _accepted_nodelay(use_sock):
    seen = []

    async def handler(reader, writer):
        s = writer.get_extra_info("socket")
        seen.append(s.getsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY))
        writer.close()

    if use_sock:
        sock = px_main.create_listen_socket("127.0.0.1", 0)
        server = await asyncio.start_server(handler, sock=sock, backlog=px_main.LISTEN_BACKLOG)
    else:
        server = await asyncio.start_server(handler, "127.0.0.1", 0, backlog=px_main.LISTEN_BACKLOG)
    port = server.sockets[0].getsockname()[1]
    _, w = await asyncio.open_connection("127.0.0.1", port)
    for _ in range(100):
        if seen:
            break
        await asyncio.sleep(0.02)
    w.close()
    server.close()
    await server.wait_closed()
    return seen


@pytest.mark.parametrize("use_sock", [True, False])
@pytest.mark.parametrize("loop_kind", ["asyncio", "default", "libuv"])
def test_accepted_socket_has_nodelay(loop_kind, use_sock):
    if loop_kind == "asyncio":
        loop = asyncio.SelectorEventLoop()
        try:
            seen = loop.run_until_complete(_accepted_nodelay(use_sock))
        finally:
            loop.close()
    elif loop_kind == "libuv":
        loop = _libuv_factory()()
        try:
            seen = loop.run_until_complete(_accepted_nodelay(use_sock))
        finally:
            loop.close()
    else:
        seen = asyncio.run(_accepted_nodelay(use_sock))
    assert seen and seen[0] != 0
