"""Tests for the configured asyncio or libuv event loop."""

import asyncio
import sys
import types
import unittest.mock

import pytest


def _configure_px_event_loop(px_event_loop):
    """Configure the imported module without parsing configuration in tests."""
    from px import main

    main.STATE.event_loop = px_event_loop
    main._configure_event_loop()
    return main


def test_libuv_import(px_event_loop):
    """Verify the correct libuv event loop library is importable on this platform."""
    if px_event_loop == "asyncio":
        pytest.skip("plain asyncio selected")
    if sys.platform == "win32":
        import winloop

        assert hasattr(winloop, "install")
        assert hasattr(winloop, "new_event_loop")
    else:
        import uvloop

        assert hasattr(uvloop, "install")
        assert hasattr(uvloop, "new_event_loop")


def test_libuv_loop_factory(px_event_loop):
    """Verify new_event_loop() creates a libuv-backed event loop."""
    if px_event_loop == "asyncio":
        pytest.skip("plain asyncio selected")
    if sys.platform == "win32":
        import winloop

        loop = winloop.new_event_loop()
        assert type(loop).__module__.startswith("winloop")
    else:
        import uvloop

        loop = uvloop.new_event_loop()
        assert type(loop).__module__.startswith("uvloop")
    loop.close()


def test_px_configures_selected_event_loop(px_event_loop):
    """Verify px.main configures the event loop after configuration is available."""
    main = _configure_px_event_loop(px_event_loop)

    if px_event_loop == "asyncio":
        assert main._libuv is None
        return

    assert main._libuv is not None, "libuv module should be imported"
    assert hasattr(main._libuv, "new_event_loop")


def test_configure_event_loop_installs_libuv_on_python_311(monkeypatch):
    """Python 3.10-3.11 need the libuv policy installed after configuration."""
    from px import main

    libuv = types.SimpleNamespace(install=unittest.mock.Mock())
    module_name = "winloop" if sys.platform == "win32" else "uvloop"
    monkeypatch.setitem(sys.modules, module_name, libuv)
    monkeypatch.setattr(sys, "version_info", (3, 11))
    monkeypatch.setattr(main, "_libuv", None)
    monkeypatch.setattr(main.STATE, "event_loop", "auto")

    main._configure_event_loop()

    assert main._libuv is libuv
    libuv.install.assert_called_once_with()


def test_run_async(px_event_loop):
    """Verify _run_async runs a coroutine with the selected event loop."""
    _run_async = _configure_px_event_loop(px_event_loop)._run_async

    result = []

    async def coro():
        loop = asyncio.get_running_loop()
        result.append(type(loop).__module__)

    _run_async(coro())

    assert len(result) == 1
    if px_event_loop == "asyncio":
        assert result[0].startswith("asyncio")
    elif sys.platform == "win32":
        assert result[0].startswith("winloop")
    else:
        assert result[0].startswith("uvloop")


def test_event_loop_basic_server():
    """Verify a basic asyncio server works under the selected event loop."""
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
