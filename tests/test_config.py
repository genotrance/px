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
            "authretry",
            "proxyreload",
            "foreground",
            "log",
            "event_loop",
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


class TestEventLoopSelection:
    def test_reads_ini(self, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(sys, "argv", ["px"])
        monkeypatch.delenv("PX_EVENT_LOOP", raising=False)
        (tmp_path / "px.ini").write_text("[settings]\nevent_loop = asyncio\n")

        config.STATE.parse_config()
        assert config.STATE.event_loop == "asyncio"

    def test_ini_configures_asyncio_at_runtime(self, tmp_path):
        (tmp_path / "px.ini").write_text("[settings]\nevent_loop = asyncio\n")
        env = {key: value for key, value in os.environ.items() if not key.startswith("PX_")}

        result = subprocess.run(
            [
                sys.executable,
                "-c",
                "from px import main; main.STATE.parse_config(); "
                "main._configure_event_loop(); assert main._libuv is None",
            ],
            cwd=tmp_path,
            env=env,
        )

        assert result.returncode == 0

    def test_environment_overrides_ini(self, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(sys, "argv", ["px"])
        monkeypatch.setenv("PX_EVENT_LOOP", "asyncio")
        (tmp_path / "px.ini").write_text("[settings]\nevent_loop = auto\n")

        config.STATE.parse_config()
        assert config.STATE.event_loop == "asyncio"

    def test_command_line_overrides_environment(self, monkeypatch):
        monkeypatch.setattr(sys, "argv", ["px", "--event-loop=auto"])
        monkeypatch.setenv("PX_EVENT_LOOP", "asyncio")

        config.STATE.parse_config()
        assert config.STATE.event_loop == "auto"

    def test_import_does_not_load_dotenv(self, tmp_path):
        """Importing px.main must not let a CWD dotenv file alter the process."""
        (tmp_path / ".env").write_text("PX_IMPORT_TEST_SENTINEL=from-dotenv\n")
        env = copy.deepcopy(os.environ)
        env.pop("PX_IMPORT_TEST_SENTINEL", None)

        result = subprocess.run(
            [
                sys.executable,
                "-c",
                "import os; from px import main; assert 'PX_IMPORT_TEST_SENTINEL' not in os.environ",
            ],
            cwd=tmp_path,
            env=env,
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0, result.stderr

    @pytest.mark.parametrize(
        ("ini_event_loop", "env_event_loop", "cli_event_loop", "expected"),
        [
            ("asyncio", None, None, "asyncio"),
            ("asyncio", "auto", None, "auto"),
            ("asyncio", "asyncio", "auto", "auto"),
        ],
    )
    def test_configures_event_loop_with_documented_precedence(
        self, tmp_path, ini_event_loop, env_event_loop, cli_event_loop, expected
    ):
        (tmp_path / "px.ini").write_text(f"[settings]\nevent_loop = {ini_event_loop}\n")
        env = {key: value for key, value in os.environ.items() if not key.startswith("PX_")}
        if env_event_loop is not None:
            env["PX_EVENT_LOOP"] = env_event_loop
        args = [sys.executable, "-c"]
        code = (
            "from px import main; "
            "main.STATE.parse_config(); "
            "main._configure_event_loop(); "
            f"assert main.STATE.event_loop == {expected!r}; "
            f"assert (main._libuv is None) is {expected == 'asyncio'!r}"
        )
        args.extend([code, "px"])
        if cli_event_loop is not None:
            args.append(f"--event-loop={cli_event_loop}")

        result = subprocess.run(  # noqa: S603
            args, cwd=tmp_path, env=env, capture_output=True, text=True
        )

        assert result.returncode == 0, result.stderr


class TestAuthRetry:
    """--authretry wiring: default, parsing, and mcurl configuration."""

    def test_default_disabled(self, monkeypatch):
        monkeypatch.setattr(sys, "argv", ["px"])
        monkeypatch.delenv("PX_AUTHRETRY", raising=False)
        config.STATE.parse_config()
        assert config.STATE.authretry == 0.0

    def test_command_line_sets_value(self, monkeypatch):
        monkeypatch.setattr(sys, "argv", ["px", "--authretry=5.5"])
        monkeypatch.delenv("PX_AUTHRETRY", raising=False)
        config.STATE.parse_config()
        assert config.STATE.authretry == 5.5

    def test_environment_sets_value(self, monkeypatch):
        monkeypatch.setattr(sys, "argv", ["px"])
        monkeypatch.setenv("PX_AUTHRETRY", "2.5")
        config.STATE.parse_config()
        assert config.STATE.authretry == 2.5

    def test_set_auth_retry_called(self, monkeypatch):
        monkeypatch.setattr(sys, "argv", ["px", "--authretry=3"])
        monkeypatch.delenv("PX_AUTHRETRY", raising=False)

        class FakeMCurl:
            def __init__(self, debug_print=None):
                self.retry_calls = []

            def set_auth_retry(self, interval):
                self.retry_calls.append(interval)

            def setopt(self, *args, **kwargs):
                pass

        monkeypatch.setattr(config.mcurl, "MCurl", FakeMCurl)
        config.STATE.parse_config()
        assert config.STATE.mcurl.retry_calls == [3.0]


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
        "event_loop",
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
        "authretry",
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
        elif key == "authretry":
            value = 2.5
        elif key == "log":
            value = 4
        elif key == "event_loop":
            value = "asyncio"
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
        cmd += f" --{name.replace('_', '-')}={value}"
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
