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
    """Verify px.main imports the correct libuv module and sets loop factory."""
    from px import main

    if sys.platform == "win32":
        assert main.winloop is not None, "winloop should be imported on Windows"
    else:
        assert main.uvloop is not None, "uvloop should be imported on non-Windows"

    assert main._libuv_loop_factory is not None, "loop factory should be set"


def test_asyncio_run_kwargs():
    """Verify _asyncio_run_kwargs returns correct kwargs for this Python version."""
    from px.main import _asyncio_run_kwargs

    kwargs = _asyncio_run_kwargs()

    if sys.version_info >= (3, 12):
        assert "loop_factory" in kwargs
        assert callable(kwargs["loop_factory"])
    else:
        # On 3.10-3.11, install() is called as a side effect and empty dict returned
        assert kwargs == {}


def test_libuv_basic_server():
    """Verify a basic asyncio server works under the libuv event loop."""
    from px.main import _asyncio_run_kwargs

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

    asyncio.run(_run(), **_asyncio_run_kwargs())


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
