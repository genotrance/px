"""Reporting shared by the corporate-proxy scenario tests."""

from __future__ import annotations

import pytest

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
