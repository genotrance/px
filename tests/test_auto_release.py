import importlib.util
from pathlib import Path

import pytest

pytest.importorskip("tomllib")

_spec = importlib.util.spec_from_file_location("auto_release", Path(__file__).parents[1] / "tools" / "auto_release.py")
auto_release = importlib.util.module_from_spec(_spec)
assert _spec.loader is not None
_spec.loader.exec_module(auto_release)


def test_bump_patch():
    assert auto_release.bump_patch("0.13.0") == "0.13.1"


def test_replace_requirement():
    text = 'dependencies = ["pymcurl>=8.23.0.2", "quickjs-ng>=0.17.0.1"]'
    assert "pymcurl>=8.23.0.3" in auto_release.replace_requirement(text, "pymcurl", "8.23.0.3")


def test_dependency_changes_lists_updates_additions_and_removals():
    old = {"same": ("1",), "updated": ("1",), "removed": ("1",)}
    new = {"same": ("1",), "updated": ("2",), "added": ("1",)}
    assert auto_release.dependency_changes(old, new) == [
        "`added` not locked -> 1",
        "`removed` 1 -> removed",
        "`updated` 1 -> 2",
    ]


def test_workflow_dispatches_release_build_after_master_push():
    text = (Path(__file__).resolve().parent.parent / ".github/workflows/auto-release.yml").read_text()
    push = text.index("name: Fast-forward master")
    step = text.index("name: Dispatch release build on master")
    assert push < step
    block = text[step : text.index("name: Merge released master into devel")]
    assert "if: steps.publish.outcome == 'success'" in block
    assert "gh workflow run build.yml --ref master" in block
