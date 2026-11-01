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


# Tests whose parametrize product starts one or more Px per case. The fast lane keeps only enough cases for every
# parameter value to run once; the full lane (no slow deselection) runs the whole product.
COVER_FAST = {
    "test_body_reaches_origin_intact",
    "test_client_auth_discards_body_and_keeps_connection",
    "test_client_auth_late_body_is_not_parsed_as_request",
    "test_many_parallel_streamed_uploads_exact",
    "test_multiprocessing_workers_auth",
    "test_proxy",
    "test_proxy_auth",
    "test_upload_through_ntlm_proxy_first_request",
}
LOOP_FIXTURE = "loop_kind"
LOOP_MODULE = "test_stream_upload.py"
# The HTTP method does not change how a body is streamed, so one method per body framing is enough
METHOD_PARAM = "method"


def _cover_keys(item):
    skip = {LOOP_FIXTURE, METHOD_PARAM}
    return {(name, repr(value)) for name, value in item.callspec.params.items() if name not in skip}


@pytest.hookimpl(tryfirst=True)
def pytest_collection_modifyitems(config, items):
    """Keep the fast lane (-m "... and not slow") short without dropping any test from the full lane.

    Stream upload tests run under both event loops: each CI job only runs its own loop in the fast lane (the
    asyncio job sets PX_EVENT_LOOP=asyncio). Parametrized Px tests in COVER_FAST keep a small set of cases that
    runs every parameter value at least once (macOS already pairs auth modes with PX_CI_MINIMAL)."""
    loop = os.environ.get("PX_EVENT_LOOP", "").lower()
    loop = "" if loop == "auto" else loop
    minimal = os.environ.get("PX_CI_MINIMAL") == "1"
    groups = {}
    for item in items:
        callspec = getattr(item, "callspec", None)
        if callspec is None:
            continue
        if item.path.name == LOOP_MODULE and LOOP_FIXTURE in callspec.params and callspec.params[LOOP_FIXTURE] != loop:
            item.add_marker(pytest.mark.slow)
        elif not minimal and item.originalname in COVER_FAST:
            groups.setdefault(item.originalname, []).append(item)
    for group in groups.values():
        keys = {id(item): _cover_keys(item) for item in group}
        uncovered = set().union(*keys.values())
        kept = set()
        while uncovered:
            best = max(group, key=lambda item: len(keys[id(item)] & uncovered))
            kept.add(id(best))
            uncovered -= keys[id(best)]
        for item in group:
            if id(item) not in kept:
                item.add_marker(pytest.mark.slow)


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
