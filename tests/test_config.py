import configparser
import copy
import os
import shutil
import subprocess
import sys
import unittest.mock

import pytest
from fixtures import *  # noqa: F403
from helpers import *  # noqa: F403

from px import config

# -------------------------------------------------------------------
# Unit tests for utility functions
# -------------------------------------------------------------------


class TestGetLogfile:
    @pytest.mark.parametrize(
        "location, expected",
        [
            (config.LOG_NONE, None),
            (config.LOG_SCRIPTDIR, config.get_script_dir()),
            (config.LOG_CWD, os.getcwd()),
            (config.LOG_UNIQLOG, os.getcwd()),
            (config.LOG_STDOUT, sys.stdout),
        ],
    )
    def test_get_logfile(self, location, expected):
        result = config.get_logfile(location)
        if isinstance(result, str):
            result = os.path.dirname(result)
        assert expected == result


class TestGetConfigDir:
    def test_returns_platform_path(self):
        result = config.get_config_dir()
        assert result.endswith("px")
        assert os.path.isabs(result)

    def test_linux_path(self, monkeypatch):
        if sys.platform == "win32":
            pytest.skip("Linux-only test")
        monkeypatch.setattr(sys, "platform", "linux")
        monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
        result = config.get_config_dir()
        assert ".config/px" in result

    def test_linux_xdg_override(self, monkeypatch, tmp_path):
        if sys.platform == "win32":
            pytest.skip("Linux-only test")
        monkeypatch.setattr(sys, "platform", "linux")
        custom = str(tmp_path / "custom_config")
        monkeypatch.setenv("XDG_CONFIG_HOME", custom)
        result = config.get_config_dir()
        assert result == os.path.join(custom, "px")


class TestFileUrlToLocalPath:
    def test_unix_path(self):
        result = config.file_url_to_local_path("file:///etc/proxy.pac")
        assert result is not None
        assert "proxy.pac" in result

    def test_windows_drive_path(self):
        result = config.file_url_to_local_path("file:///C:/Users/test/proxy.pac")
        assert result is not None
        assert "proxy.pac" in result


class TestGetHostIps:
    def test_returns_non_empty(self):
        ips = config.get_host_ips()
        assert ips.size > 0

    def test_contains_localhost(self):
        ips = config.get_host_ips()
        assert "127.0.0.1" in ips


class TestDefaults:
    def test_defaults_has_required_keys(self):
        required_keys = [
            "server",
            "pac",
            "port",
            "listen",
            "gateway",
            "hostonly",
            "allow",
            "noproxy",
            "username",
            "auth",
            "workers",
            "threads",
            "idle",
            "socktimeout",
            "proxyreload",
            "foreground",
            "log",
        ]
        for key in required_keys:
            assert key in config.DEFAULTS, f"Missing default for {key}"

    def test_default_port(self):
        assert config.DEFAULTS["port"] == "3128"

    def test_default_listen(self):
        assert config.DEFAULTS["listen"] == "127.0.0.1"

    def test_default_workers(self):
        assert config.DEFAULTS["workers"] == "1"

    def test_default_threads(self):
        assert config.DEFAULTS["threads"] == "32"


class TestIsCompiled:
    def test_not_compiled_in_test(self):
        # Running tests from source, should not be compiled
        assert config.is_compiled() is False


class TestGetScriptCmd:
    def test_returns_string(self):
        cmd = config.get_script_cmd()
        assert isinstance(cmd, str)
        assert len(cmd) > 0


# -------------------------------------------------------------------
# Legacy parametrized test (kept as-is)
# -------------------------------------------------------------------


def generate_config():
    values = []
    for key in [
        "allow",
        "auth",
        "client_auth",
        "client_nosspi",
        "client_username",
        "foreground",
        "gateway",
        "hostonly",
        "idle",
        "kerberos",
        "listen",
        "log",
        "noproxy",
        "pac",
        "pac_encoding",
        "port",
        "proxyreload",
        "server",
        "socktimeout",
        "threads",
        "username",
        "useragent",
        "workers",
    ]:
        if key == "port":
            value = 3131
        elif key == "server":
            value = "upstream.proxy.com:55112"
        elif key == "pac":
            value = "http://upstream.proxy.com/PAC.pac"
        elif key == "pac_encoding":
            value = "latin-1"
        elif key == "listen":
            value = "100.0.0.11"
        elif key in ["gateway", "hostonly", "foreground", "client_nosspi", "kerberos"]:
            value = 1
        elif key in ["allow", "noproxy"]:
            value = "127.0.0.1"
        elif key == "useragent":
            value = "Mozilla/5.0"
        elif key in ["username", "client_username"]:
            value = "randomuser"
        elif key in ["auth", "client_auth"]:
            value = "NTLM"
        elif key in ["workers", "threads", "idle", "proxyreload"]:
            value = 100
        elif key == "socktimeout":
            value = 35.5
        elif key == "log":
            value = 4
        else:
            raise ValueError(f"Unknown key: {key}")
        values.append((key, value))
    return values


def config_setup(cmd, px_bin, pxini_location, monkeypatch, tmp_path):
    backup = False
    env = copy.deepcopy(os.environ)

    # Always chdir to tmp_path to avoid parallel test interference
    monkeypatch.chdir(str(tmp_path))

    # cwd, config, script_dir, custom location for px.ini
    if pxini_location == "cwd":
        pxini_path = os.path.join(tmp_path, "px.ini")
    elif pxini_location == "config":
        env["HOME"] = str(tmp_path)
        if sys.platform == "win32":
            env["APPDATA"] = str(tmp_path)
            pxini_path = os.path.join(tmp_path, "px", "px.ini")
        elif sys.platform == "darwin":
            pxini_path = os.path.join(tmp_path, "Library", "Application Support", "px", "px.ini")
        else:
            # Set XDG_CONFIG_HOME explicitly — GH runners may have it set globally
            env["XDG_CONFIG_HOME"] = os.path.join(str(tmp_path), ".config")
            pxini_path = os.path.join(tmp_path, ".config", "px", "px.ini")
    elif pxini_location == "script_dir":
        dirname = os.path.dirname(shutil.which(px_bin))
        pxini_path = os.path.join(dirname, "px.ini")

        # Prevent config dir from shadowing script_dir discovery
        env["HOME"] = str(tmp_path)
        if sys.platform == "win32":
            env["APPDATA"] = str(tmp_path)
        elif sys.platform != "darwin":
            env["XDG_CONFIG_HOME"] = os.path.join(str(tmp_path), ".config")

        # Backup px.ini for binary test
        if px_bin != "px" and os.path.exists(pxini_path):
            os.rename(pxini_path, os.path.join(dirname, "px.ini.bak"))
            backup = True
    elif pxini_location == "custom":
        pxini_path = os.path.join(tmp_path, "custom", "px.ini")
        cmd += f" --config={pxini_path}"

    return backup, cmd, env, pxini_path


def config_cleanup(backup, pxini_path):
    if backup:
        # Restore px.ini for binary test
        dirname = os.path.dirname(pxini_path)
        pxinibak_path = os.path.join(dirname, "px.ini.bak")
        if os.path.exists(pxinibak_path):
            if os.path.exists(pxini_path):
                os.remove(pxini_path)
            os.rename(pxinibak_path, pxini_path)
    elif os.path.exists(pxini_path):
        # Other tests don't have px.ini
        os.remove(pxini_path)


def _test_save(px_bin, pxini_location, monkeypatch, tmp_path):
    cmd = f"{px_bin} --save"
    values = generate_config()

    # Setup config
    backup, cmd, env, pxini_path = config_setup(cmd, px_bin, pxini_location, monkeypatch, tmp_path)

    # File has to exist for --save to use it
    assert not os.path.exists(pxini_path), f"px.ini already exists at {pxini_path}"
    touch(pxini_path)

    # Add all config CLI flags and run
    for name, value in values:
        cmd += f" --{name}={value}"
    with change_dir(tmp_path):
        p = subprocess.run(cmd, shell=True, stdout=None, env=env)
        ret = p.returncode
    assert ret == 0, f"Px exited with {ret}"

    # Load generated file
    assert os.path.exists(pxini_path), f"px.ini not found at {pxini_path}"
    with open(pxini_path) as f:
        ini_content = f.read()
    config = configparser.ConfigParser()
    config.read(pxini_path)

    # Cleanup
    config_cleanup(backup, pxini_path)

    # Check values
    for name, value in values:
        if config.has_section("proxy") and config.has_option("proxy", name):
            # listen gets overridden to empty when gateway or hostonly is set
            if name == "listen":
                assert config.get("proxy", name) == ""
            else:
                assert config.get("proxy", name) == str(value)
        elif config.has_section("client") and config.has_option("client", name):
            assert config.get("client", name) == str(value)
        elif config.has_section("settings") and config.has_option("settings", name):
            assert config.get("settings", name) == str(value)
        else:
            pytest.fail(f"Unknown key: {name} in {pxini_path}\n{ini_content}")


def _px_w_variant(px_bin):
    """Get the windowless variant: px -> pxw, px.exe -> pxw.exe"""
    if px_bin.lower().endswith(".exe"):
        dirname = os.path.dirname(px_bin)
        return os.path.join(dirname, "pxw.exe")
    return px_bin + "w"


def test_save(px_bin, pxini_location, monkeypatch, tmp_path):
    if sys.platform != "win32":
        _test_save(px_bin, pxini_location, monkeypatch, tmp_path)
    else:
        for variant in [px_bin, _px_w_variant(px_bin)]:
            _test_save(variant, pxini_location, monkeypatch, tmp_path)


def _test_install(px_bin, pxini_location, monkeypatch, tmp_path_factory, tmp_path):
    # Setup config
    cmd = ""
    backup, _, _env, pxini_path = config_setup(cmd, px_bin, pxini_location, monkeypatch, tmp_path)

    # Setup mocks
    mock_OpenKey = unittest.mock.Mock(return_value="runkey")
    mock_QueryValueEx = unittest.mock.Mock()
    mock_SetValueEx = unittest.mock.Mock()
    mock_CloseKey = unittest.mock.Mock()
    mock_DeleteValue = unittest.mock.Mock()

    # Patch winreg
    import winreg

    monkeypatch.setattr(winreg, "OpenKey", mock_OpenKey)
    monkeypatch.setattr(winreg, "QueryValueEx", mock_QueryValueEx)
    monkeypatch.setattr(winreg, "SetValueEx", mock_SetValueEx)
    monkeypatch.setattr(winreg, "CloseKey", mock_CloseKey)
    monkeypatch.setattr(winreg, "DeleteValue", mock_DeleteValue)

    # Px not installed
    mock_QueryValueEx.side_effect = FileNotFoundError
    px_bin_full = shutil.which(px_bin)
    dirname = os.path.dirname(px_bin_full)
    try:
        from px import windows

        windows.install(px_bin_full, pxini_path, False)
    except SystemExit:
        pass
    cmd = mock_SetValueEx.call_args.args[-1]
    assert f"{dirname}\\pxw" in cmd, f"Px path incorrect: {cmd} vs {dirname}\\pxw"
    assert f"--config={pxini_path}" in cmd, f"Config path incorrect: {cmd} vs {pxini_path}"

    # Cleanup
    config_cleanup(backup, pxini_path)


def test_install(px_bin, pxini_location, monkeypatch, tmp_path_factory, tmp_path):
    if sys.platform != "win32":
        pytest.skip("Windows only test")

    for variant in [px_bin, _px_w_variant(px_bin)]:
        _test_install(variant, pxini_location, monkeypatch, tmp_path_factory, tmp_path)


# -------------------------------------------------------------------
# Retrying proxies blocked after auth failures (--authretry)
# -------------------------------------------------------------------


class TestAuthRetry:
    @pytest.fixture
    def state(self, monkeypatch):
        # State is a singleton - patch attributes so they are restored afterwards
        state = config.State()
        mcurl = unittest.mock.Mock()
        mcurl.failure_threshold = 3
        mcurl.failed = {"proxy": 3}
        monkeypatch.setattr(state, "mcurl", mcurl)
        monkeypatch.setattr(state, "authretry", 300)
        monkeypatch.setattr(state, "proxy_last_attempt", {})
        return state

    def test_default_disabled(self):
        assert config.DEFAULTS["authretry"] == "0"

    def test_disabled_never_retries(self, state):
        state.authretry = 0
        state.note_proxy_attempt("proxy", now=1_000)
        assert not state.retry_auth_failure("proxy", now=10_000)
        assert state.mcurl.failed == {"proxy": 3}

    def test_no_retry_within_interval_of_last_attempt(self, state):
        state.note_proxy_attempt("proxy", now=1_000)
        assert not state.retry_auth_failure("proxy", now=1_299)
        assert state.mcurl.failed == {"proxy": 3}

    def test_retries_immediately_after_long_idle(self, state):
        state.note_proxy_attempt("proxy", now=1_000)
        assert state.retry_auth_failure("proxy", now=1_000 + 3_600)
        # One more failure brings the proxy straight back to the threshold
        assert state.mcurl.failed == {"proxy": 2}

    def test_retry_counts_as_attempt(self, state):
        state.note_proxy_attempt("proxy", now=1_000)
        assert state.retry_auth_failure("proxy", now=1_300)
        state.mcurl.failed["proxy"] = 3  # the retry failed
        assert not state.retry_auth_failure("proxy", now=1_400)
        assert state.retry_auth_failure("proxy", now=1_600)

    def test_unknown_proxy_starts_interval_now(self, state):
        assert not state.retry_auth_failure("proxy", now=1_000)
        assert state.retry_auth_failure("proxy", now=1_300)

    def test_cfg_init_sets_authretry(self, state, monkeypatch):
        cfg = configparser.ConfigParser()
        cfg.add_section("proxy")
        monkeypatch.setattr(state, "config", cfg)
        state.cfg_init("authretry", "600", override=True)
        assert state.authretry == 600
        assert state.config.get("proxy", "authretry") == "600"
