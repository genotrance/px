import copy
import os
import sys

import pytest
import pytest_httpbin

from helpers import *

##
# Session scope


@pytest.fixture(scope="session")
def monkeysession():
    with pytest.MonkeyPatch.context() as mp:
        yield mp


@pytest.fixture(scope="session")
def px_port(request):
    # unique port for this worker = 1
    port = 3148
    try:
        worker_id = request.config.workerinput.get("workerid", "gw0")

        # * 3 so that each worker has 3 different ports to use
        # 1st (+0) = client Px
        # 2nd (+1) = upstream Px
        # 3rd (+2) = chain Px
        port += int(worker_id.replace("gw", "")) * 3
    except AttributeError:
        # Not using pytest-xdist
        pass

    assert is_port_free(port), f"Port {port} in use"
    return port


@pytest.fixture(scope="session")
def px_upstream(px_port, tmp_path_factory):
    # Upstream authenticating Px server
    # port += 1 for upstream Px
    port = px_port + 1
    assert is_port_free(port), f"Upstream port {port} in use"

    # Set client auth password via env
    env = copy.deepcopy(os.environ)
    env["PX_CLIENT_USERNAME"] = PARAMS_USERNAME
    env["PX_CLIENT_PASSWORD"] = PARAMS_PASSWORD

    # Run px in the background
    name = "Upstream"
    flags = " --client-auth=ANY --noproxy=127.0.0.1"
    if sys.platform == "win32":
        flags += " --client-nosspi"
    subp, cmd, buffer = run_px(name, port, tmp_path_factory, flags, env)

    # Let tests run
    yield buffer

    # Quit Px
    quit_px(name, subp, cmd)


@pytest.fixture(scope="session")
def px_chain(px_port, tmp_path_factory):
    # Chaining auth=NONE Px server
    # port += 2 for chain Px
    port = px_port + 2
    assert is_port_free(port), f"Chain port {port} in use"

    # Run px in the background
    name = "Chain"
    flags = f" --auth=NONE --proxy=127.0.0.1:{px_port + 1}"
    subp, cmd, buffer = run_px(name, port, tmp_path_factory, flags)

    # Let tests run
    yield buffer

    # Quit Px
    quit_px(name, subp, cmd)


##
# Function scope


PARAMS_CLI_ENV = ["cli", "env"]


@pytest.fixture
def px_bin():
    # px module or binary = 2
    pxbin = os.getenv("PXBIN")
    if pxbin is None:
        # module test
        return "px"
    elif os.path.exists(pxbin):
        # binary test
        return pxbin
    pytest.skip("Skip binary - not found")


# CLI and env testing


@pytest.fixture(params=PARAMS_CLI_ENV)
def px_cli_env(request):
    # cli or env = 2
    return request.param


@pytest.fixture(params=PARAMS_CLI_ENV + [""])
def px_cli_env_none(request):
    # cli or env or none = 3
    return request.param


# Debug


@pytest.fixture
def px_debug(px_cli_env, monkeypatch):
    # debug via cli or env = 2
    if px_cli_env == "env":
        monkeypatch.setenv("PX_LOG", "1")
        return ""
    return "--debug"


@pytest.fixture
def px_debug_none(px_cli_env_none, monkeypatch):
    # debug via cli, env or none = 3
    if px_cli_env_none == "cli":
        return "--debug"
    elif px_cli_env_none == "env":
        monkeypatch.setenv("PX_LOG", "1")
    else:
        monkeypatch.delenv("PX_LOG", raising=False)

    return ""


# Auth
PARAMS_AUTH = ["NTLM", "DIGEST", "BASIC"]


@pytest.fixture(params=PARAMS_AUTH)
def px_auth(px_cli_env, request, monkeypatch):
    # cli or env = 2
    # NTLM or DIGEST or BASIC = 3
    # 6 combinations
    if px_cli_env == "env":
        monkeypatch.setenv("PX_AUTH", request.param)
        return ""
    return "--auth=" + request.param


@pytest.fixture(params=PARAMS_AUTH)
def px_client_auth(px_cli_env, request, monkeypatch):
    # cli or env = 2
    # NTLM or DIGEST or BASIC = 3
    # 6 combinations
    if px_cli_env == "env":
        monkeypatch.setenv("PX_CLIENT_AUTH", request.param)
        return ""
    return "--client-auth=" + request.param


# Username


PARAMS_USERNAME = "test"


@pytest.fixture
def px_username(px_cli_env, monkeypatch):
    # cli or env = 2
    if px_cli_env == "env":
        monkeypatch.setenv("PX_USERNAME", PARAMS_USERNAME)
        return ""
    return "--username=" + PARAMS_USERNAME


# Password


PARAMS_PASSWORD = "12345"


@pytest.fixture
def px_password(px_cli_env, monkeypatch):
    # keyring or env = 2
    if px_cli_env == "env":
        monkeypatch.setenv("PX_PASSWORD", PARAMS_PASSWORD)
        return "PX_PASSWORD=" + PARAMS_PASSWORD
    else:
        monkeypatch.delenv("PX_PASSWORD", raising=False)
        setup_keyring(PARAMS_USERNAME, PARAMS_PASSWORD)
        return "Keyring password=" + PARAMS_PASSWORD


# px.ini locations


LOCATIONS = ["cwd", "config", "script_dir", "custom"]


@pytest.fixture(params=LOCATIONS)
def pxini_location(request):
    return request.param


# Basic CLI


@pytest.fixture
def px_basic_cli(px_bin, px_debug_none, px_port, httpbin_both):
    # px module or binary = 1 (run in separate tox envs)
    # debug via cli, env or none = 3
    # unique port for this worker = 1
    # with http and https testing = 2
    # 6 combinations
    cmd = (
        f"{px_bin} {px_debug_none} --port={px_port}" + f" --test=all:{httpbin_both.url}"
    )
    return cmd


# Test auth


PARAMS_TEST_AUTH = ["", "--test-auth"]


@pytest.fixture(params=PARAMS_TEST_AUTH)
def px_test_auth(request):
    # without and with --test-auth = 2
    return request.param
