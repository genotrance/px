import importlib.util
from pathlib import Path

import pytest

pytest.importorskip("tomllib")

_spec = importlib.util.spec_from_file_location("px_tools", Path(__file__).parents[1] / "tools.py")
px_tools = importlib.util.module_from_spec(_spec)
assert _spec.loader is not None
_spec.loader.exec_module(px_tools)


def test_bump_patch():
    assert px_tools.bump_patch("0.13.0") == "0.13.1"


def test_replace_requirement():
    text = 'dependencies = ["pymcurl>=8.23.0.3", "quickjs-ng>=0.17.0.1"]'
    assert "pymcurl>=8.23.0.3" in px_tools.replace_requirement(text, "pymcurl", "8.23.0.3")


def test_dependency_changes_lists_updates_additions_and_removals():
    old = {"same": ("1",), "updated": ("1",), "removed": ("1",)}
    new = {"same": ("1",), "updated": ("2",), "added": ("1",)}
    assert px_tools.dependency_changes(old, new) == [
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


def test_workflow_backmerges_published_release_or_opens_a_pr():
    text = (Path(__file__).resolve().parent.parent / ".github/workflows/auto-release.yml").read_text()
    assert "pull-requests: write" in text

    start = text.index("name: Merge released master into devel")
    end = text.index("name: Close resolved blocked issue")
    block = text[start:end]
    assert "if: steps.publish.outcome == 'success' && env.DRY_RUN != 'true'" in block
    assert "git fetch origin devel master" in block
    assert "git checkout -B auto-release-sync origin/devel" in block
    assert block.count('git merge --no-ff --no-edit "$SHA"') == 2
    assert "git push origin HEAD:devel" in block
    assert "--force" not in block
    assert "git merge --abort" in block
    assert 'git push origin "$SHA:refs/heads/$BRANCH"' in block
    assert 'gh pr list --state open --base devel --head "$BRANCH"' in block
    assert 'gh pr create --base devel --head "$BRANCH"' in block
    assert "::error::" in block
    assert "exit 1" in block
