"""Tests for libuv-based event loop integration (uvloop/winloop)."""

import asyncio
import sys

import pytest


def test_libuv_import():
    """Verify the correct libuv event loop library is importable on this platform."""
    if sys.platform == "win32":
        import winloop

        assert hasattr(winloop, "install")
        assert hasattr(winloop, "new_event_loop")
    else:
        import uvloop

        assert hasattr(uvloop, "install")
        assert hasattr(uvloop, "new_event_loop")


def test_libuv_loop_factory():
    """Verify new_event_loop() creates a libuv-backed event loop."""
    if sys.platform == "win32":
        import winloop

        loop = winloop.new_event_loop()
        assert type(loop).__module__.startswith("winloop")
    else:
        import uvloop

        loop = uvloop.new_event_loop()
        assert type(loop).__module__.startswith("uvloop")
    loop.close()


def test_px_imports_libuv():
    """Verify px.main imports the correct libuv module."""
    from px import main

    assert main._libuv is not None, "libuv module should be imported"
    assert hasattr(main._libuv, "new_event_loop")


def test_run_async():
    """Verify _run_async runs a coroutine with the libuv event loop."""
    from px.main import _run_async

    result = []

    async def coro():
        loop = asyncio.get_running_loop()
        result.append(type(loop).__module__)

    _run_async(coro())

    assert len(result) == 1
    # On 3.12+ with loop_factory, the loop module should be uvloop/winloop
    if sys.version_info >= (3, 12):
        if sys.platform == "win32":
            assert result[0].startswith("winloop")
        else:
            assert result[0].startswith("uvloop")


def test_libuv_basic_server():
    """Verify a basic asyncio server works under the libuv event loop."""
    from px.main import _run_async

    async def _run():
        async def handler(reader, writer):
            data = await reader.read(100)
            writer.write(data)
            await writer.drain()
            writer.close()

        server = await asyncio.start_server(handler, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]

        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(b"hello")
        await writer.drain()
        resp = await reader.read(100)
        assert resp == b"hello"
        writer.close()

        server.close()
        await server.wait_closed()

    _run_async(_run())


@pytest.mark.skipif(sys.platform != "win32", reason="winloop is Windows-only")
def test_winloop_on_windows():
    """On Windows, winloop should be importable."""
    import winloop

    assert winloop is not None


@pytest.mark.skipif(sys.platform == "win32", reason="uvloop is not available on Windows")
def test_uvloop_on_linux():
    """On non-Windows, uvloop should be importable."""
    import uvloop

    assert uvloop is not None
