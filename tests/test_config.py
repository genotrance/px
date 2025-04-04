import configparser
import os
import shutil
import subprocess
import unittest.mock

import pytest

from px import config

from fixtures import *
from helpers import *


@pytest.mark.parametrize("location, expected", [
    (config.LOG_NONE, None),
    (config.LOG_SCRIPTDIR, config.get_script_dir()),
    (config.LOG_CWD, os.getcwd()),
    (config.LOG_UNIQLOG, os.getcwd()),
    (config.LOG_STDOUT, sys.stdout),
])
def test_get_logfile(location, expected):
    result = config.get_logfile(location)
    if isinstance(result, str):
        result = os.path.dirname(result)
    assert expected == result


def generate_config():
    values = []
    for key in [
        "allow", "auth", "client_auth", "client_nosspi",
        "client_username", "foreground", "gateway", "hostonly",
        "idle", "log", "noproxy", "pac", "pac_encoding",
        "port", "proxyreload", "server", "socktimeout", "threads",
        "username", "useragent", "workers"
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
        elif key in ["gateway", "hostonly", "foreground", "client_nosspi"]:
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

    # cwd, config, script_dir, custom location for px.ini
    if pxini_location == "cwd":
        monkeypatch.chdir(str(tmp_path))
        pxini_path = os.path.join(tmp_path, "px.ini")
    elif pxini_location == "config":
        env["HOME"] = str(tmp_path)
        if sys.platform == "win32":
            env["APPDATA"] = str(tmp_path)
            pxini_path = os.path.join(tmp_path, "px", "px.ini")
        elif sys.platform == "darwin":
            pxini_path = os.path.join(
                tmp_path, "Library", "Application Support", "px", "px.ini")
        else:
            pxini_path = os.path.join(tmp_path, ".config", "px", "px.ini")
    elif pxini_location == "script_dir":
        dirname = os.path.dirname(shutil.which(px_bin))
        pxini_path = os.path.join(dirname, "px.ini")

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


def test_save(px_bin, pxini_location, monkeypatch, tmp_path):
    cmd = f"{px_bin} --save"
    values = generate_config()

    # Setup config
    backup, cmd, env, pxini_path = config_setup(
        cmd, px_bin, pxini_location, monkeypatch, tmp_path)

    # File has to exist for --save to use it
    assert not os.path.exists(
        pxini_path), f"px.ini already exists at {pxini_path}"
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
    config = configparser.ConfigParser()
    config.read(pxini_path)

    # Cleanup
    config_cleanup(backup, pxini_path)

    # Check values
    for name, value in values:
        if config.has_section("proxy") and config.has_option("proxy", name):
            assert config.get("proxy", name) == str(value)
        elif config.has_section("client") and config.has_option("client", name):
            assert config.get("client", name) == str(value)
        elif config.has_section("settings") and config.has_option("settings", name):
            assert config.get("settings", name) == str(value)
        else:
            assert False, f"Unknown key: {name}"


def test_install(px_bin, pxini_location, monkeypatch, tmp_path_factory, tmp_path):
    if sys.platform != "win32":
        pytest.skip("Windows only test")

    # Setup config
    cmd = ""
    backup, _, env, pxini_path = config_setup(
        cmd, px_bin, pxini_location, monkeypatch, tmp_path)

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
    assert f"{dirname}\\pxw.exe" in cmd, f"Px path incorrect: {cmd} vs {dirname}\\pxw.exe"
    assert f"--config={pxini_path}" in cmd, f"Config path incorrect: {cmd} vs {pxini_path}"

    # Cleanup
    config_cleanup(backup, pxini_path)
