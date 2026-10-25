import sys
import time
import types

import conftest
import pytest
from fixtures import *  # noqa: F403
from helpers import *  # noqa: F403

# The macOS 15+ runner stall these tests guard against lasts about 35 seconds
# per name lookup, so any bound well under that catches it.
BOUND = STARTUP_LIMIT + 5


def test_probe_reports_each_startup_step_within_bound():
    timings = probe_startup()

    assert set(timings) == set(STARTUP_PROBES)
    assert slow_startup_steps(timings) == {}


def test_probe_caps_a_stalled_step(monkeypatch):
    monkeypatch.setattr("helpers.STARTUP_PROBES", {"stall": "import time; time.sleep(30)"})

    start = time.monotonic()
    timings = probe_startup(timeout=1)

    assert timings == {"stall": 1}
    assert time.monotonic() - start < BOUND
    assert slow_startup_steps(timings, limit=0.5) == {"stall": 1}


def test_slow_startup_steps_selects_only_steps_over_the_limit():
    timings = {"fast": 0.2, "slow": STARTUP_LIMIT + 1, "edge": STARTUP_LIMIT}

    assert slow_startup_steps(timings) == {"slow": STARTUP_LIMIT + 1}


def test_loopback_fqdn_needs_no_reverse_lookup(monkeypatch):
    def stalled(*_args):
        pytest.fail("reverse lookup")

    monkeypatch.setattr(conftest.socket, "gethostbyaddr", stalled)

    for name in ("127.0.0.1", "::1", "localhost"):
        assert conftest.socket.getfqdn(name) == name


@pytest.mark.parametrize(
    ("platform", "ci", "timings", "stops"),
    [
        ("darwin", "true", {"parse_config": 36.0}, True),
        ("darwin", "true", {"parse_config": 0.4}, False),
        ("darwin", "", {"parse_config": 36.0}, False),
        ("linux", "true", {"parse_config": 36.0}, False),
    ],
)
def test_session_guard_stops_only_a_slow_macos_ci_run(monkeypatch, platform, ci, timings, stops):
    monkeypatch.setattr(sys, "platform", platform)
    monkeypatch.setenv("CI", ci)
    monkeypatch.setattr(conftest, "probe_startup", lambda: timings)
    session = types.SimpleNamespace(config=types.SimpleNamespace())

    if stops:
        with pytest.raises(pytest.exit.Exception, match=r"parse_config 36\.0s"):
            conftest.pytest_sessionstart(session)
    else:
        conftest.pytest_sessionstart(session)


def test_px_start_and_quit_are_bounded(px_port, tmp_path):
    start = time.monotonic()
    subp, cmd, logfile = run_px("Bounded", px_port, tmp_path, "--noproxy= --workers=1")
    started = time.monotonic() - start

    start = time.monotonic()
    try:
        quit_px("Bounded", subp, cmd)
    finally:
        logfile.close()
    quit_time = time.monotonic() - start

    assert started < BOUND, f"Px took {started:.1f}s to listen"
    assert quit_time < BOUND, f"Px took {quit_time:.1f}s to quit"
