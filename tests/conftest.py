import os
import socket
import sys

import pytest

# Add tests directory to path so helpers module can be imported
sys.path.insert(0, os.path.dirname(__file__))

# Set PX_KEYRING_PLAINTEXT so Px uses plaintext keyring backend for tests
# This allows all tests (including proxy auth tests that use keyring for
# server and client credentials) to run in any environment with a shared
# file-based keyring that works across parent and child processes.
os.environ["PX_KEYRING_PLAINTEXT"] = "1"

import keyring
import keyrings.alt.file
from helpers import STARTUP_LIMIT, probe_startup, slow_startup_steps

# Use plaintext keyring for tests on all OS
keyring.set_keyring(keyrings.alt.file.PlaintextKeyring())


# http.server and wsgiref (the fake upstream and pytest-httpbin) name themselves
# with a reverse lookup of the address they bind. Loopback needs none, and on
# macOS 15+ runners it can stall for about 35 seconds in each fixture.
_getfqdn = socket.getfqdn


def _loopback_getfqdn(name=""):
    return name if name in ("127.0.0.1", "::1", "localhost") else _getfqdn(name)


socket.getfqdn = _loopback_getfqdn


def _startup_probe(config):
    "Time px's startup steps once per run on macOS CI, where an affected interpreter stalls them"
    if sys.platform != "darwin" or not os.environ.get("CI") or hasattr(config, "workerinput"):
        return None
    if not hasattr(config, "_px_startup_probe"):
        config._px_startup_probe = probe_startup()
    return config._px_startup_probe


def pytest_sessionstart(session):
    timings = _startup_probe(session.config)
    slow = slow_startup_steps(timings or {})
    if slow:
        steps = ", ".join(f"{name} {seconds:.1f}s" for name, seconds in slow.items())
        pytest.exit(
            f"{sys.executable} takes over {STARTUP_LIMIT:.0f}s for: {steps}. macOS 15+ stalls name lookups for about "
            "35s in Python from setup-python or Homebrew, so every px start would stall. Use uv-managed CPython "
            "(UV_PYTHON_PREFERENCE=only-managed).",
            returncode=3,
        )


def pytest_report_header(config):
    timings = _startup_probe(config)
    if timings:
        return (
            "px startup probe: "
            + ", ".join(f"{name}={seconds:.2f}s" for name, seconds in timings.items())
            + (f" ({sys.executable})")
        )


@pytest.fixture(scope="session")
def px_event_loop():
    """Event loop selection inherited by Px subprocesses."""
    return os.environ.get("PX_EVENT_LOOP", "auto").lower()


def pytest_xdist_auto_num_workers():
    """Compute optimal xdist worker count for `pytest -n auto`.

    Each test spawns 1-3 Px subprocesses, but tests are mostly I/O-bound
    so we can run more workers than CPUs.  The real limits are platform
    connection handling and port space (each worker reserves 3 proxy
    ports + 10 network test ports).

    Windows uses fewer workers because socket/connection limits are
    tighter."""
    import sys

    cpus = os.cpu_count() or 2
    if sys.platform == "win32" and os.environ.get("CI"):
        # Single worker avoids Schannel TLS contention across concurrent
        # Px instances on resource-constrained CI runners.
        return 1
    return max(2, cpus // 4)


MEMORY_ROWS = pytest.StashKey[list[tuple[str, int, int, int]]]()


@pytest.fixture(scope="session")
def memory_report(pytestconfig):
    """Rows of (label, px RSS before MiB, px RSS peak MiB, uploaded MiB) printed in the run summary."""
    return pytestconfig.stash.setdefault(MEMORY_ROWS, [])


def pytest_terminal_summary(terminalreporter, config):
    rows = config.stash.get(MEMORY_ROWS, [])
    if not rows:
        return
    terminalreporter.section("px memory during streamed uploads (RSS of px and all worker processes, MiB)")
    terminalreporter.write_line(f"{'scenario':<72} {'before':>7} {'peak':>7} {'growth':>7} {'uploaded':>9}")
    for label, before, peak, uploaded in rows:
        terminalreporter.write_line(f"{label:<72} {before:>7} {peak:>7} {peak - before:>7} {uploaded:>9}")
    terminalreporter.write_line(f"largest growth: {max(peak - before for _, before, peak, _ in rows)} MiB")
