import importlib.util
import json
from pathlib import Path

import pytest

_spec = importlib.util.spec_from_file_location("ci_matrix", Path(__file__).parents[1] / "tools" / "ci_matrix.py")
ci_matrix = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ci_matrix)


def jobs(outputs, key):
    return json.loads(outputs[key])["include"]


def key(entry):
    return (entry["os"], entry["python-version"], entry.get("event-loop", "auto"))


@pytest.mark.parametrize(
    ("event", "full_input", "full"),
    [
        ("push", "", False),
        ("pull_request", "", False),
        ("schedule", "", True),
        ("workflow_dispatch", "true", True),
        ("workflow_dispatch", "false", False),
        ("workflow_call", "true", True),
        ("workflow_call", "false", False),
        ("push", "true", True),
    ],
)
def test_resolve_full(event, full_input, full):
    assert ci_matrix.resolve_full(event, full_input) is full


def test_fast_matrix():
    out = ci_matrix.plan("push", "")
    assert out["full"] == "false"
    assert out["marker"] == ci_matrix.FAST_MARKER
    assert "not slow" in out["marker"]
    assert {key(e) for e in jobs(out, "tests")} == {
        ("ubuntu-latest", "3.10", "auto"),
        ("ubuntu-latest", "3.14", "auto"),
        ("ubuntu-latest", "3.14", "asyncio"),
        ("windows-latest", "3.14", "auto"),
        ("windows-latest", "3.14", "asyncio"),
    }
    assert [(e["name"], e["pyver"]) for e in jobs(out, "musl")] == [("musl-x86_64", "314")]
    assert jobs(out, "scenario") == []


def test_full_matrix_keeps_every_configuration():
    out = ci_matrix.plan("schedule", "")
    assert out["full"] == "true"
    assert out["marker"] == ""
    tests = jobs(out, "tests")
    assert len(tests) == 13
    assert {e["python-version"] for e in tests if e["os"] == "ubuntu-latest"} == {
        "3.10",
        "3.11",
        "3.12",
        "3.13",
        "3.14",
    }
    assert {e["os"] for e in tests} == {"ubuntu-latest", "ubuntu-24.04-arm", "macos-latest", "windows-latest"}
    assert {(e["os"], e["python-version"]) for e in tests if e.get("event-loop") == "asyncio"} == {
        ("ubuntu-latest", "3.14"),
        ("windows-latest", "3.14"),
    }
    assert {(e["name"], e["pyver"]) for e in jobs(out, "musl")} == {
        ("musl-x86_64", "310"),
        ("musl-x86_64", "314"),
        ("musl-aarch64", "310"),
        ("musl-aarch64", "314"),
    }
    assert {(e["python-version"], e["event-loop"]) for e in jobs(out, "scenario")} == {
        (pyver, loop) for pyver in ("3.10", "3.11", "3.12", "3.13", "3.14") for loop in ("auto", "asyncio")
    }
    assert {e["os"] for e in jobs(out, "scenario")} == {"ubuntu-latest"}


def test_fast_is_subset_of_full():
    fast, full = ci_matrix.plan("push", ""), ci_matrix.plan("schedule", "")
    for name in ("tests", "musl", "scenario"):
        assert all(e in jobs(full, name) for e in jobs(fast, name))


def test_matrix_entries_have_no_internal_keys():
    for event in ("push", "schedule"):
        out = ci_matrix.plan(event, "")
        for name in ("tests", "musl", "scenario"):
            assert all("fast" not in e for e in jobs(out, name))
