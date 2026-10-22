import importlib.util
from pathlib import Path

import pytest

_spec = importlib.util.spec_from_file_location("build_tools", Path(__file__).parents[1] / "tools.py")
tools = importlib.util.module_from_spec(_spec)
assert _spec.loader is not None
_spec.loader.exec_module(tools)


def test_latest_python_selects_newest_embeddable_release(monkeypatch):
    listings = {
        tools.PY_FTP: """
            <a href="3.13.14/">3.13.14/</a>
            <a href="3.13.17/">3.13.17/</a>
            <a href="3.12.12/">3.12.12/</a>
        """,
        f"{tools.PY_FTP}3.13.14/": '<a href="python-3.13.14-embed-amd64.zip">',
        f"{tools.PY_FTP}3.13.17/": '<a href="python-3.13.17-embed-amd64.zip">',
    }
    monkeypatch.setattr(tools, "fetch_text", listings.__getitem__)

    assert tools.latest_python(asset=tools.PY_EMBED) == "3.13.17"


def test_check_embed_rejects_newest_release_without_embed_zip(monkeypatch):
    def latest_python(_minor=tools.PY_MINOR, asset=None):
        return "3.13.17" if asset is None else "3.13.16"

    monkeypatch.setattr(tools, "latest_python", latest_python)

    with pytest.raises(SystemExit):
        tools.check_embed()


def test_check_bundled_version_rejects_stale_patch(monkeypatch):
    monkeypatch.setattr(tools, "latest_python", lambda: "3.13.17")

    with pytest.raises(SystemExit):
        tools.check_bundled_version("3.13.16", "test image")


def test_embed_rejects_requested_stale_patch(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(tools, "check_embed", lambda: "3.13.17")
    monkeypatch.setattr(tools, "get_argval", lambda _name: "3.13.16")
    _, _, wheels_dir = tools.get_paths("px.dist", "wheels")
    Path(wheels_dir).mkdir(parents=True)

    with pytest.raises(SystemExit):
        tools.embed()


def test_docker_checks_base_and_each_built_image(monkeypatch):
    checked = []
    monkeypatch.setattr(tools, "get_argval", lambda _name: "")
    monkeypatch.setattr(tools, "docker_python", lambda image, _target: checked.append(image))
    monkeypatch.setattr(tools.os, "system", lambda _command: 0)
    monkeypatch.setattr(tools.sys, "argv", ["tools.py", "--docker"])

    tools.docker()

    assert checked == [
        f"python:{tools.PY_MINOR}-alpine",
        f"genotrance/px:{tools.__version__}-mini",
        f"genotrance/px:{tools.__version__}",
    ]
