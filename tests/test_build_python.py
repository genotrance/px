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


MACHO = bytes.fromhex("cffaedfe") + b"\0" * 16

OTOOL_OUTPUT = {
    "good": "good:\n\t/usr/lib/libSystem.B.dylib (compatibility version 1.0.0)\n\t@rpath/libcrypto.3.dylib (compatibility version 3.0.0)\n",
    "bad": "bad:\n\t/usr/lib/libSystem.B.dylib (compatibility version 1.0.0)\n\t/opt/homebrew/Cellar/openssl@3/3.6.4/lib/libcrypto.3.dylib (compatibility version 3.0.0)\n",
    "local": "local:\n\t/usr/local/opt/openssl@3/lib/libssl.3.dylib (compatibility version 3.0.0)\n",
    "_pymcurl.so": "_pymcurl.so:\n\t@rpath/libcurl.4.dylib (compatibility version 4.0.0)\n",
    "_ssl.so": "_ssl.so:\n\t@rpath/libssl.3.dylib (compatibility version 3.0.0)\n",
    "libcurl.4.dylib": "libcurl.4.dylib:\n\t@rpath/libcurl.4.dylib (compatibility version 4.0.0)\n\t/opt/homebrew/opt/openssl@3/lib/libssl.3.dylib (compatibility version 3.0.0)\n",
    "libcrypto.3.dylib": "libcrypto.3.dylib:\n\t/opt/homebrew/opt/openssl@3/lib/libcrypto.3.dylib (compatibility version 3.0.0)\n\t/usr/lib/libSystem.B.dylib (compatibility version 1.0.0)\n",
    "libssl.3.dylib": "libssl.3.dylib:\n\t@rpath/libssl.3.dylib (compatibility version 3.0.0)\n\t/opt/homebrew/Cellar/openssl@3/3.6.4/lib/libcrypto.3.dylib (compatibility version 3.0.0)\n",
}


@pytest.fixture
def fake_otool(monkeypatch):
    monkeypatch.setattr(tools.sys, "platform", "darwin")
    monkeypatch.setattr(tools.subprocess, "check_output", lambda cmd, **_kw: OTOOL_OUTPUT[Path(cmd[-1]).name])


def make_dist(root, names):
    root.mkdir(exist_ok=True)
    for name in names:
        (root / name).write_bytes(MACHO)
    (root / "px.ini").write_text("not mach-o")
    return root


def test_check_portable_accepts_bundled_libraries(fake_otool, tmp_path, capsys):
    dist = make_dist(tmp_path / "dist", ["good"])

    tools.check_portable(str(dist))

    assert "No Homebrew" in capsys.readouterr().out


@pytest.mark.parametrize("name", ["bad", "local"])
def test_check_portable_rejects_host_library_references(fake_otool, tmp_path, capsys, name):
    dist = make_dist(tmp_path / "dist", ["good", name])

    with pytest.raises(SystemExit):
        tools.check_portable(str(dist))

    assert f"{name} links" in capsys.readouterr().out


def test_check_portable_ignores_dylib_own_install_name(fake_otool, tmp_path):
    dist = make_dist(tmp_path / "dist", ["libcrypto.3.dylib"])

    assert tools.host_lib_refs(str(dist / "libcrypto.3.dylib")) == []


def test_relocate_macos_dylibs_rewrites_openssl_and_libcurl_stack(fake_otool, tmp_path, monkeypatch):
    dist = make_dist(
        tmp_path / "dist",
        ["_ssl.so", "_pymcurl.so", "libcrypto.3.dylib", "libssl.3.dylib", "libcurl.4.dylib"],
    )
    commands = []
    monkeypatch.setattr(tools.subprocess, "run", lambda command, **_kw: commands.append(command))

    tools.relocate_macos_dylibs(str(dist))

    assert commands == [
        [
            "install_name_tool",
            "-change",
            "/opt/homebrew/opt/openssl@3/lib/libssl.3.dylib",
            "@loader_path/libssl.3.dylib",
            str(dist / "libcurl.4.dylib"),
        ],
        [
            "install_name_tool",
            "-change",
            "/opt/homebrew/Cellar/openssl@3/3.6.4/lib/libcrypto.3.dylib",
            "@loader_path/libcrypto.3.dylib",
            str(dist / "libssl.3.dylib"),
        ],
    ]


def test_relocate_macos_dylibs_rejects_unbundled_host_library(fake_otool, tmp_path, monkeypatch):
    dist = make_dist(tmp_path / "dist", ["libssl.3.dylib"])
    commands = []
    monkeypatch.setattr(tools.subprocess, "run", lambda command, **_kw: commands.append(command))

    with pytest.raises(SystemExit):
        tools.relocate_macos_dylibs(str(dist))

    assert commands == []


def test_check_portable_rejects_empty_dist(fake_otool, tmp_path):
    with pytest.raises(SystemExit):
        tools.check_portable(str(make_dist(tmp_path / "dist", [])))
