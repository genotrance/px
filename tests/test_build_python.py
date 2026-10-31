import importlib.util
import os
import re
import subprocess
import sys
import types
from pathlib import Path

import pytest

_spec = importlib.util.spec_from_file_location("build_tools", Path(__file__).parents[1] / "tools.py")
tools = importlib.util.module_from_spec(_spec)
assert _spec.loader is not None
_spec.loader.exec_module(tools)


def test_latest_python_selects_newest_release_with_requested_asset(monkeypatch):
    listings = {
        tools.PY_FTP: """
            <a href="3.14.14/">3.14.14/</a>
            <a href="3.14.17/">3.14.17/</a>
            <a href="3.13.12/">3.13.12/</a>
        """,
        f"{tools.PY_FTP}3.14.14/": '<a href="python-3.14.14-embed-amd64.zip">',
        f"{tools.PY_FTP}3.14.17/": '<a href="python-3.14.17-embed-amd64.zip">',
    }
    monkeypatch.setattr(tools, "fetch_text", listings.__getitem__)

    assert tools.latest_python(asset=tools.PY_EMBED) == "3.14.17"


def test_latest_python_skips_release_without_requested_asset_yet(monkeypatch):
    # python.org has published 3.14.17 but the embed zip for it is not up
    # yet; this must not fail, just use the newest release that has one.
    listings = {
        tools.PY_FTP: """
            <a href="3.14.16/">3.14.16/</a>
            <a href="3.14.17/">3.14.17/</a>
        """,
        f"{tools.PY_FTP}3.14.17/": '<a href="Python-3.14.17.tar.xz">',
        f"{tools.PY_FTP}3.14.16/": '<a href="python-3.14.16-embed-amd64.zip">',
    }
    monkeypatch.setattr(tools, "fetch_text", listings.__getitem__)

    assert tools.latest_python(asset=tools.PY_EMBED) == "3.14.16"


def test_check_python_warns_when_upstream_is_newer(monkeypatch, capsys):
    monkeypatch.setattr(tools, "latest_python", lambda: "3.14.18")
    monkeypatch.setattr(tools.platform, "python_version", lambda: "3.14.17")

    tools.check_python()

    assert (
        "WARNING: bundled CPython 3.14.17 is older than newest published 3.14.x release 3.14.18"
        in capsys.readouterr().out
    )


def test_check_python_rejects_wrong_minor(monkeypatch):
    monkeypatch.setattr(tools, "latest_python", lambda: "3.14.18")
    monkeypatch.setattr(tools.platform, "python_version", lambda: "3.12.9")

    with pytest.raises(SystemExit):
        tools.check_python()


def test_check_embed_uses_newest_available_zip_and_warns_when_it_lags(monkeypatch, capsys):
    def latest_python(_minor=tools.PY_MINOR, asset=None):
        return "3.14.18" if asset is None else "3.14.17"

    monkeypatch.setattr(tools, "latest_python", latest_python)

    assert tools.check_embed() == "3.14.17"
    assert (
        "WARNING: python.org has no python-3.14.18-embed-amd64.zip for newest 3.14.x release 3.14.18; bundling available 3.14.17"
        in capsys.readouterr().out
    )


def test_check_bundled_version_warns_when_upstream_is_newer(monkeypatch, capsys):
    monkeypatch.setattr(tools, "latest_python", lambda: "3.14.18")

    tools.check_bundled_version("3.14.17", "test image")

    assert (
        "WARNING: test image CPython 3.14.17 is older than newest published 3.14.x release 3.14.18"
        in capsys.readouterr().out
    )


def test_embed_rejects_requested_version_other_than_newest_available_zip(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(tools, "latest_python", lambda asset=None: "3.14.17")
    monkeypatch.setattr(tools, "get_argval", lambda _name: "3.14.16")
    _, _, wheels_dir = tools.get_paths("px.dist", "wheels")
    Path(wheels_dir).mkdir(parents=True)

    with pytest.raises(SystemExit):
        tools.embed()


def test_docker_python_pulls_base_image_and_warns_when_upstream_is_newer(monkeypatch, capsys):
    commands = []

    def fake_run(cmd, **_kwargs):
        commands.append(cmd)
        if cmd[:2] == ["docker", "pull"]:
            return subprocess.CompletedProcess(cmd, 0)
        return subprocess.CompletedProcess(cmd, 0, stdout="3.14.10\n", stderr="")

    monkeypatch.setattr(tools.subprocess, "run", fake_run)
    monkeypatch.setattr(tools, "latest_python", lambda: "3.14.18")

    tools.docker_python(f"python:{tools.PY_MINOR}-alpine", "Docker base image")

    assert (
        "WARNING: Docker base image CPython 3.14.10 is older than newest published 3.14.x release 3.14.18"
        in capsys.readouterr().out
    )
    assert commands[0] == ["docker", "pull", f"python:{tools.PY_MINOR}-alpine"]


def test_docker_python_checks_local_output_without_pulling(monkeypatch):
    commands = []

    def fake_run(cmd, **_kwargs):
        commands.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, stdout="3.14.17\n", stderr="")

    monkeypatch.setattr(tools.subprocess, "run", fake_run)
    monkeypatch.setattr(tools, "latest_python", lambda: "3.14.17")

    tools.docker_python("genotrance/px:0.13.0-mini", "Docker image", pull=False)

    assert commands == [
        [
            "docker",
            "run",
            "--rm",
            "--entrypoint",
            "python",
            "genotrance/px:0.13.0-mini",
            "-c",
            "import platform;print(platform.python_version())",
        ]
    ]


def test_docker_checks_base_and_each_built_image(monkeypatch):
    checked = []
    monkeypatch.setattr(tools, "get_argval", lambda _name: "")
    monkeypatch.setattr(tools, "docker_python", lambda image, _target, pull=True: checked.append((image, pull)))
    monkeypatch.setattr(tools.os, "system", lambda _command: 0)
    monkeypatch.setattr(tools.sys, "argv", ["tools.py", "--docker"])

    tools.docker()

    assert checked == [
        (f"python:{tools.PY_MINOR}-alpine", True),
        (f"genotrance/px:{tools.__version__}-mini", False),
        (f"genotrance/px:{tools.__version__}", False),
    ]


def test_release_workflow_skips_already_published_release_outputs():
    build = (ROOT / ".github/workflows/build.yml").read_text()

    assert "id: release_exists" in build
    assert "steps.release_exists.outputs.exists != 'true'" in build
    assert "skip-existing: true" in build
    assert "inputs.mode" not in build
    assert "outputs.mode" not in build
    assert "--release-plan" not in build


def test_build_workflow_leaves_docker_and_winget_to_publish_workflow():
    build = (ROOT / ".github/workflows/build.yml").read_text()

    for publishing in ("DOCKERHUB", "WINGET", "docker/login-action", "winget", "--docker", "--push"):
        assert publishing not in build
    assert "workflow_dispatch:\n\nconcurrency:" in build


def test_publish_workflow_follows_master_builds_and_manual_dispatch():
    publish = (ROOT / ".github/workflows/publish.yml").read_text()

    assert "workflows: [Build]" in publish
    assert "github.event.workflow_run.conclusion == 'success'" in publish
    assert "github.event.workflow_run.head_branch == 'master'" in publish
    assert "version:" in publish and "required: true" in publish
    assert "dry_run:" in publish
    assert "permissions: {}" in publish


def test_publish_workflow_uses_release_assets_without_building_or_testing():
    publish = (ROOT / ".github/workflows/publish.yml").read_text()

    for forbidden in ("download-artifact", "build.sh", "pytest", "tox", "uv run", "--wheel", "--nuitka", "--embed"):
        assert forbidden not in publish
    assert '--pattern "$ARCHIVE" --pattern "$ARCHIVE.sha256"' in publish
    assert 'ARCHIVE="px-v$VERSION-linux-musl-x86_64-wheels.tar.gz"' in publish
    assert '"px-v$VERSION-windows-amd64.zip"' in publish


def test_publish_workflow_pushes_only_planned_docker_tags_outside_dry_run():
    publish = (ROOT / ".github/workflows/publish.yml").read_text()

    assert 'TAGS=$(python3 tools.py --docker-plan="$VERSION")' in publish
    assert 'python3 tools.py --docker --push --push-tags="$TAGS"' in publish
    assert publish.count("python3 tools.py --docker --push") == 1
    assert "steps.plan.outputs.tags != '' && env.DRY_RUN != 'true'" in publish
    assert publish.count("secrets.DOCKERHUB_") == 2


def test_publish_workflow_submits_winget_once_outside_dry_run():
    publish = (ROOT / ".github/workflows/publish.yml").read_text()

    assert 'gh api "repos/microsoft/winget-pkgs/contents/$manifest"' in publish
    assert "gh pr list --repo microsoft/winget-pkgs --state open" in publish
    assert "steps.winget.outputs.publish == 'true' && env.DRY_RUN != 'true'" in publish
    assert 'komac update genotrance.px --version "$VERSION" --urls "$URL" --submit' in publish
    assert publish.count("secrets.WINGET_TOKEN") == 1


MACHO = bytes.fromhex("cffaedfe") + b"\0" * 16

OTOOL_OUTPUT = {
    "good": "good:\n\t/usr/lib/libSystem.B.dylib (compatibility version 1.0.0)\n\t@rpath/libcrypto.3.dylib (compatibility version 3.0.0)\n",
    "bad": "bad:\n\t/usr/lib/libSystem.B.dylib (compatibility version 1.0.0)\n\t/opt/homebrew/Cellar/openssl@3/3.6.4/lib/libcrypto.3.dylib (compatibility version 3.0.0)\n",
    "local": "local:\n\t/usr/local/opt/openssl@3/lib/libssl.3.dylib (compatibility version 3.0.0)\n",
    "_pymcurl.so": "_pymcurl.so:\n\t@rpath/libcurl.4.dylib (compatibility version 4.0.0)\n",
    "_ssl.so": "_ssl.so:\n\t@rpath/libssl.3.dylib (compatibility version 3.0.0)\n",
    "libcurl.4.dylib": "libcurl.4.dylib:\n\t@rpath/libcurl.4.dylib (compatibility version 4.0.0)\n\t/opt/homebrew/opt/openssl@3/lib/libssl.3.dylib (compatibility version 3.0.0)\n",
    "libcrypto.3.dylib": "libcrypto.3.dylib:\n\t/opt/homebrew/opt/openssl@3/lib/libcrypto.3.dylib (compatibility version 3.0.0)\n\t/usr/lib/libSystem.B.dylib (compatibility version 1.0.0)\n",
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


def test_check_portable_ignores_non_macho_files(fake_otool, tmp_path, capsys):
    dist = make_dist(tmp_path / "dist", ["good"])

    tools.check_portable(str(dist))

    assert "No Homebrew or /usr/local library references" in capsys.readouterr().out


@pytest.mark.parametrize("name", ["bad", "local"])
def test_check_portable_rejects_host_library_references(fake_otool, tmp_path, capsys, name):
    dist = make_dist(tmp_path / "dist", ["good", name])

    with pytest.raises(SystemExit):
        tools.check_portable(str(dist))

    assert f"{name} links" in capsys.readouterr().out


def test_check_portable_ignores_dylib_own_install_name(fake_otool, tmp_path):
    dist = make_dist(tmp_path / "dist", ["libcrypto.3.dylib"])

    assert tools.host_lib_refs(str(dist / "libcrypto.3.dylib")) == []


def test_portability_check_has_no_dylib_relocation_step():
    assert not hasattr(tools, "relocate_macos_dylibs")


def test_check_portable_rejects_empty_dist(fake_otool, tmp_path):
    with pytest.raises(SystemExit):
        tools.check_portable(str(make_dist(tmp_path / "dist", [])))


ROOT = Path(__file__).parents[1]


def test_macos_test_jobs_use_uv_managed_python():
    action = (ROOT / ".github/actions/setup-python-env/action.yml").read_text()
    assert "UV_PYTHON_PREFERENCE=only-managed" in action
    assert "runner.os == 'macOS' && inputs.managed-python == 'true'" in action

    ci = (ROOT / ".github/workflows/ci.yml").read_text()
    build = (ROOT / ".github/workflows/build.yml").read_text()
    # tests, benchmark and scenario-linux; build, wheels and binary jobs keep setup-python
    assert ci.count('managed-python: "true"') == 3
    assert build.count('managed-python: "true"') == 1
    assert "UV_PYTHON_PREFERENCE=only-managed" in (ROOT / "build.sh").read_text()


def test_binary_is_launched_on_the_test_runner_before_the_suite():
    script = (ROOT / "build.sh").read_text()
    body = script[script.index("test_binary() {") :]

    assert body.index('smoke_binary "$NAME"') < body.index("tox ")


def test_binary_smoke_check_imports_ssl_and_spnego_before_artifact_tests():
    script = (ROOT / "build.sh").read_text()
    smoke = script[script.index("smoke_binary() {") : script.index("# Set up manylinux static libs")]

    assert '"$PXBIN" --help' in smoke
    assert "Smoke check ssl and spnego imports" in smoke
    assert 'grep -q "Requires module"' in smoke


def _plan(images, version="0.13.0"):
    def inspect(tag):
        return images.get(tag, (None, None))[0]

    def run(tag):
        return images[tag][1]

    return tools.docker_plan(version, inspect=inspect, run=run)


def _good(version="0.13.0"):
    out = f"Px v{version}\nusage"
    return {
        version: ("sha:a", out),
        f"{version}-mini": ("sha:b", out),
        "latest": ("sha:a", out),
        "latest-mini": ("sha:b", out),
    }


def test_docker_plan_all_missing():
    assert set(_plan({})) == {"0.13.0", "0.13.0-mini", "latest", "latest-mini"}


def test_docker_plan_all_present_and_correct():
    assert _plan(_good()) == []


def test_docker_plan_latest_stale():
    images = _good()
    images["latest"] = ("sha:old", "Px v0.12.0\n")
    images["latest-mini"] = ("sha:oldmini", "Px v0.12.0\n")
    assert _plan(images) == ["latest-mini", "latest"]


def test_docker_plan_version_tag_wrong_px_version():
    images = _good()
    images["0.13.0"] = ("sha:a", "Px v0.12.0\n")
    assert _plan(images) == ["0.13.0", "latest"]


def test_main_docker_plan_cli_prints_requested_tags(monkeypatch, capsys):
    monkeypatch.setattr(tools, "docker_plan", lambda version: [version, f"{version}-mini", "latest"])
    monkeypatch.setattr(tools.sys, "argv", ["tools.py", "--docker-plan=0.13.0"])

    tools.main()

    assert capsys.readouterr().out == "0.13.0,0.13.0-mini,latest\n"


def test_main_docker_plan_cli_requires_a_version(monkeypatch, capsys):
    monkeypatch.setattr(tools.sys, "argv", ["tools.py", "--docker-plan"])

    with pytest.raises(SystemExit) as exc_info:
        tools.main()

    assert exc_info.value.code == 1
    assert "--docker-plan requires a version" in capsys.readouterr().err


def _binary_job():
    yaml = pytest.importorskip("yaml")
    workflow = yaml.safe_load((ROOT / ".github" / "workflows" / "build.yml").read_text())
    return workflow["jobs"]["binary"]["steps"]


def test_uv_cache_has_no_broad_restore_fallback():
    uv = next(s for s in _binary_job() if s.get("name") == "Restore uv download cache")
    nuitka = next(s for s in _binary_job() if s.get("name") == "Restore Nuitka cache")

    assert "restore-keys" not in uv["with"]
    assert "pyproject.toml" in uv["with"]["key"]
    assert "restore-keys" in nuitka["with"]


def test_binary_builds_install_pymcurl_only_from_a_fresh_pypi_download():
    script = (ROOT / "build.sh").read_text()
    helper = script[script.index("install_released_pymcurl() {") :].split("}", 1)[0]
    body = script[script.index("build_binary() {") : script.index("# --- Archive extraction")]

    assert "--no-cache" in helper and "--reinstall-package pymcurl" in helper
    assert '-f "$WHEELS"' not in helper and "pymcurl>=$PYMCURL_MIN" in helper
    assert not re.search(r"uv pip install [^\n]*pymcurl[^\n]*-f", body[: body.index("        windows)")])
    assert body.count("install_released_pymcurl") == 3
    assert body.count("tools.py --check-mcurl") == 2
    for case in ("linux-musl)", "linux-glibc)"):
        part = body[body.index(case) :]
        assert part.index("--check-mcurl") < part.index("--nuitka")
    assert body.index("smoke_binary") < body.index("--smoke-request")


def test_pymcurl_minimum_is_read_from_pyproject():
    out = subprocess.run(
        ["bash", "-c", ". ./build.sh && echo $PYMCURL_MIN"],  # noqa: S607
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()

    assert out and out in (ROOT / "pyproject.toml").read_text()


def test_check_mcurl_requires_every_api(monkeypatch, capsys):
    full = types.SimpleNamespace(
        Curl=types.SimpleNamespace(resume_upload=1, transfer_id=2, get_os_errno=3), REWIND_ERROR="x", __version__="1"
    )
    monkeypatch.setattr(tools, "mcurl", full)
    monkeypatch.setattr("importlib.metadata.version", lambda name: "8.23.0.3")
    tools.check_mcurl()

    for cls, name in (
        ("Curl", "resume_upload"),
        ("Curl", "transfer_id"),
        ("Curl", "get_os_errno"),
        (None, "REWIND_ERROR"),
    ):
        broken = types.SimpleNamespace(Curl=types.SimpleNamespace(**vars(full.Curl)), REWIND_ERROR="x", __version__="1")
        delattr(broken.Curl if cls else broken, name)
        monkeypatch.setattr(tools, "mcurl", broken)
        with pytest.raises(SystemExit):
            tools.check_mcurl()
        assert name in capsys.readouterr().out

    monkeypatch.setattr(tools, "mcurl", None)
    with pytest.raises(SystemExit):
        tools.check_mcurl()


def test_smoke_request_fails_for_a_binary_that_cannot_serve(tmp_path):
    fake = tmp_path / "px"
    fake.write_text("#!/bin/sh\nexit 1\n")
    fake.chmod(0o755)

    with pytest.raises(SystemExit):
        tools.smoke_request(str(fake))


@pytest.mark.skipif(os.name == "nt", reason="needs a shell launcher")
def test_smoke_request_passes_through_a_working_px(tmp_path):
    pytest.importorskip("mcurl")
    fake = tmp_path / "px"
    fake.write_text(f'#!/bin/sh\nexec {sys.executable} -m px "$@"\n')
    fake.chmod(0o755)

    tools.smoke_request(str(fake))


def test_workflows_use_only_released_dependencies():
    for wf in (ROOT / ".github" / "workflows").glob("*.yml"):
        text = wf.read_text()
        assert not re.search(r"genotrance/mcurl|MCURL_WHEELS|\.whl@|git\+https", text), wf.name
