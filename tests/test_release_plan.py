import importlib.util
from pathlib import Path

_spec = importlib.util.spec_from_file_location("build_tools", Path(__file__).parents[1] / "tools.py")
tools = importlib.util.module_from_spec(_spec)
assert _spec.loader is not None
_spec.loader.exec_module(tools)


def state(**changes):
    result = {
        "pypi": False,
        "github_release": False,
        "assets": set(),
    }
    result.update(changes)
    return result


def plan(**changes):
    forced = changes.pop("forced", "auto")
    dry_run = changes.pop("dry_run", False)
    return tools.release_plan("0.13.0", forced, dry_run, lambda version: state(**changes))


def test_new_when_nothing_is_published():
    assert plan()["mode"] == "new"


def test_finish_for_every_existing_primary_publication_combination():
    assert plan(pypi=True)["mode"] == "finish"
    assert plan(github_release=True)["mode"] == "finish"
    assert plan(pypi=True, github_release=True)["mode"] == "finish"


def test_complete_requires_pypi_and_every_github_asset():
    assert len(tools.expected_release_assets("0.13.0")) == 26
    result = plan(pypi=True, github_release=True, assets=tools.expected_release_assets("0.13.0"))
    assert result["mode"] == "complete"
    assert result["missing_assets"] == []
    assert plan(pypi=False, github_release=True, assets=tools.expected_release_assets("0.13.0"))["mode"] == "finish"


def test_partial_assets_are_reported():
    assets = tools.expected_release_assets("0.13.0") - {"px-v0.13.0-windows-amd64.zip.sha256"}
    result = plan(pypi=True, github_release=True, assets=assets)
    assert result["mode"] == "finish"
    assert result["missing_assets"] == ["px-v0.13.0-windows-amd64.zip.sha256"]


def test_build_plan_leaves_docker_and_winget_to_publish_workflow():
    result = plan(pypi=True, github_release=True, assets=tools.expected_release_assets("0.13.0"))
    assert "docker_tags" not in result
    assert "winget_exists" not in result


def test_forced_modes_override_automatic_mode():
    complete = {
        "pypi": True,
        "github_release": True,
        "assets": tools.expected_release_assets("0.13.0"),
    }
    assert plan(forced="new", **complete)["mode"] == "new"
    assert plan(forced="finish")["mode"] == "finish"


def test_dry_run_is_part_of_the_plan_without_changing_mode():
    result = plan(dry_run=True)
    assert result["mode"] == "new"
    assert result["dry_run"] is True
