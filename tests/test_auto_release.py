import importlib.util
import types
from pathlib import Path

import pytest

pytest.importorskip("tomllib")

_spec = importlib.util.spec_from_file_location("px_tools", Path(__file__).parents[1] / "tools.py")
px_tools = importlib.util.module_from_spec(_spec)
assert _spec.loader is not None
_spec.loader.exec_module(px_tools)

CHANGELOG_NO_UNRELEASED = """# Changelog

---

## v0.13.1 — 2026-10-31

### Improvements
- Something released.
"""

CHANGELOG_UNRELEASED_NO_IMPROVEMENTS = """# Changelog

---

## Unreleased

### Bug fixes
- A bug fix.

---

## v0.13.1 — 2026-10-31

### Improvements
- Something released.
"""

CHANGELOG_UNRELEASED_WITH_IMPROVEMENTS = """# Changelog

---

## Unreleased

### Improvements
- An unrelated improvement.

### Bug fixes
- A bug fix.

---

## v0.13.1 — 2026-10-31

### Improvements
- Something released.
"""


def test_dependency_changes_lists_updates_additions_and_removals():
    old = {"same": ("1",), "updated": ("1",), "removed": ("1",)}
    new = {"same": ("1",), "updated": ("2",), "added": ("1",)}
    assert px_tools.dependency_changes(old, new) == [
        "`added` not locked -> 1",
        "`removed` 1 -> removed",
        "`updated` 1 -> 2",
    ]


def test_refresh_summary_line_dependencies_and_python():
    line = px_tools.refresh_summary_line(["`pkg` 1 -> 2"], "3.14.0", "3.14.1")
    assert line == "- Refreshed locked dependencies (`pkg` 1 -> 2) and bundled CPython 3.14.0 -> 3.14.1."


def test_refresh_summary_line_dependencies_only():
    line = px_tools.refresh_summary_line(["`pkg` 1 -> 2"], "3.14.1", "3.14.1")
    assert line == "- Refreshed locked dependencies (`pkg` 1 -> 2)."


def test_refresh_summary_line_python_only():
    line = px_tools.refresh_summary_line([], "3.14.0", "3.14.1")
    assert line == "- Bundled CPython 3.14.0 -> 3.14.1."


def test_refresh_summary_line_nothing_changed():
    assert px_tools.refresh_summary_line([], "3.14.1", "3.14.1") is None


def _insert_changelog(tmp_path, monkeypatch, text, dependencies, old_python, new_python):
    (tmp_path / "docs").mkdir()
    changelog = tmp_path / "docs" / "changelog.md"
    changelog.write_text(text)
    monkeypatch.setattr(px_tools, "AR_ROOT", tmp_path)
    px_tools.insert_changelog(dependencies, old_python, new_python)
    return changelog.read_text()


def test_insert_changelog_creates_missing_unreleased_section(tmp_path, monkeypatch):
    result = _insert_changelog(tmp_path, monkeypatch, CHANGELOG_NO_UNRELEASED, ["`pkg` 1 -> 2"], "3.14.0", "3.14.0")
    assert "## Unreleased\n\n### Improvements\n- Refreshed locked dependencies (`pkg` 1 -> 2).\n\n---" in result
    assert result.index("## Unreleased") < result.index("## v0.13.1")


def test_insert_changelog_adds_missing_improvements_subsection(tmp_path, monkeypatch):
    result = _insert_changelog(
        tmp_path, monkeypatch, CHANGELOG_UNRELEASED_NO_IMPROVEMENTS, ["`pkg` 1 -> 2"], "3.14.0", "3.14.0"
    )
    assert "### Improvements\n- Refreshed locked dependencies (`pkg` 1 -> 2).\n\n### Bug fixes\n- A bug fix." in result


def test_insert_changelog_appends_under_existing_improvements(tmp_path, monkeypatch):
    result = _insert_changelog(
        tmp_path, monkeypatch, CHANGELOG_UNRELEASED_WITH_IMPROVEMENTS, ["`pkg` 1 -> 2"], "3.14.0", "3.14.0"
    )
    assert (
        "### Improvements\n- An unrelated improvement.\n"
        "- Refreshed locked dependencies (`pkg` 1 -> 2).\n\n### Bug fixes"
    ) in result


def test_insert_changelog_replaces_previous_refresh_line(tmp_path, monkeypatch):
    previous = CHANGELOG_UNRELEASED_WITH_IMPROVEMENTS.replace(
        "- An unrelated improvement.",
        "- An unrelated improvement.\n- Refreshed locked dependencies (`pkg` 1 -> 2).",
    )
    result = _insert_changelog(tmp_path, monkeypatch, previous, ["`pkg` 1 -> 3"], "3.14.0", "3.14.0")
    assert result.count("Refreshed locked dependencies") == 1
    assert "- Refreshed locked dependencies (`pkg` 1 -> 3)." in result


def test_insert_changelog_no_changes_leaves_file_untouched(tmp_path, monkeypatch):
    result = _insert_changelog(tmp_path, monkeypatch, CHANGELOG_UNRELEASED_WITH_IMPROVEMENTS, [], "3.14.1", "3.14.1")
    assert result == CHANGELOG_UNRELEASED_WITH_IMPROVEMENTS


def _setup_release_root(tmp_path, monkeypatch, old_python="3.14.0"):
    (tmp_path / ".github").mkdir()
    (tmp_path / "docs").mkdir()
    (tmp_path / ".github" / "bundled-python-version").write_text(old_python + "\n")
    (tmp_path / "docs" / "changelog.md").write_text(CHANGELOG_UNRELEASED_WITH_IMPROVEMENTS)
    (tmp_path / "pyproject.toml").write_text('[project]\nversion = "0.13.1"\n')
    monkeypatch.setattr(px_tools, "AR_ROOT", tmp_path)
    monkeypatch.setattr(px_tools, "PYTHON_VERSION_FILE", tmp_path / ".github" / "bundled-python-version")


def test_auto_release_unchanged(tmp_path, monkeypatch):
    _setup_release_root(tmp_path, monkeypatch)
    lock = b'[[package]]\nname = "pkg"\nversion = "1"\n'
    (tmp_path / "uv.lock").write_bytes(lock)
    monkeypatch.setattr(px_tools, "subprocess", types.SimpleNamespace(run=lambda *a, **k: None))
    monkeypatch.setattr(px_tools, "latest_python", lambda: "3.14.0")

    result = px_tools.auto_release()

    assert result == {"changed": False, "dependencies": [], "python": "3.14.0"}
    assert (tmp_path / "pyproject.toml").read_text() == '[project]\nversion = "0.13.1"\n'
    assert (tmp_path / "docs" / "changelog.md").read_text() == CHANGELOG_UNRELEASED_WITH_IMPROVEMENTS


def test_auto_release_lock_changed(tmp_path, monkeypatch):
    _setup_release_root(tmp_path, monkeypatch)
    (tmp_path / "uv.lock").write_bytes(b'[[package]]\nname = "pkg"\nversion = "1"\n')

    def fake_run(cmd, cwd, check):
        (tmp_path / "uv.lock").write_bytes(b'[[package]]\nname = "pkg"\nversion = "2"\n')

    monkeypatch.setattr(px_tools, "subprocess", types.SimpleNamespace(run=fake_run))
    monkeypatch.setattr(px_tools, "latest_python", lambda: "3.14.0")

    result = px_tools.auto_release()

    assert result["changed"] is True
    assert result["dependencies"] == ["`pkg` 1 -> 2"]
    assert result["python"] == "3.14.0"
    assert result["old_python"] == "3.14.0"
    assert result["branch"].startswith("deps/refresh-")
    assert "version" not in result
    assert (tmp_path / "pyproject.toml").read_text() == '[project]\nversion = "0.13.1"\n'
    assert "Refreshed locked dependencies (`pkg` 1 -> 2)." in (tmp_path / "docs" / "changelog.md").read_text()


def test_auto_release_python_changed(tmp_path, monkeypatch):
    _setup_release_root(tmp_path, monkeypatch, old_python="3.14.0")
    lock = b'[[package]]\nname = "pkg"\nversion = "1"\n'
    (tmp_path / "uv.lock").write_bytes(lock)
    monkeypatch.setattr(px_tools, "subprocess", types.SimpleNamespace(run=lambda *a, **k: None))
    monkeypatch.setattr(px_tools, "latest_python", lambda: "3.14.1")

    result = px_tools.auto_release()

    assert result["changed"] is True
    assert result["dependencies"] == []
    assert result["old_python"] == "3.14.0"
    assert result["python"] == "3.14.1"
    assert (tmp_path / ".github" / "bundled-python-version").read_text() == "3.14.1\n"
    assert (tmp_path / "pyproject.toml").read_text() == '[project]\nversion = "0.13.1"\n'
    assert "Bundled CPython 3.14.0 -> 3.14.1." in (tmp_path / "docs" / "changelog.md").read_text()


def test_workflow_checks_out_devel_only_and_has_no_release_logic():
    text = (Path(__file__).resolve().parent.parent / ".github/workflows/auto-release.yml").read_text()
    assert "ref: devel" in text
    assert "ref: master" not in text
    assert "dry_run" in text
    assert "default: true" in text
    for removed in ("build.yml", "auto-release blocked", "fast-forward", "Fast-forward"):
        assert removed not in text, removed
    assert "gh workflow run ci.yml --ref" in text
    assert "-f full=true" in text
    assert "deps/refresh-" in text
    assert "issues: write" not in text
