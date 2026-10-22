import copy
import os
import sys

import pytest
from helpers import *  # noqa: F403

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

    # Other test runs may share this host, so use the first free block of 3 ports
    port = find_free_port_block(port)
    assert port, "No free port block for Px tests"
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
    flags = " --client-auth=ANY --noproxy=127.0.0.1 --workers=1"
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
    # Keep the chain directed at its upstream even if a developer's dotenv
    # config supplies PX_NOPROXY for local addresses.
    flags = f" --auth=NONE --proxy=127.0.0.1:{px_port + 1} --noproxy= --workers=1"
    subp, cmd, buffer = run_px(name, port, tmp_path_factory, flags)

    # Let tests run
    yield buffer

    # Quit Px
    quit_px(name, subp, cmd)


##
# Function scope


@pytest.fixture
def px_bin():
    # px module or binary = 2
    pxbin = os.getenv("PXBIN")
    if pxbin is None:
        # module test
        return "px"
    elif os.path.exists(pxbin):
        # binary test
        return os.path.abspath(pxbin)
    pytest.skip("Skip binary - not found")


# CLI and env testing


PARAMS_CLI_ENV = ["cli", "env"]


@pytest.fixture(params=PARAMS_CLI_ENV)
def px_cli_env(request):
    # cli or env = 2
    return request.param


@pytest.fixture(params=[*PARAMS_CLI_ENV, ""])
def px_cli_env_none(request):
    # cli or env or none = 3
    return request.param


# Debug


@pytest.fixture
def px_debug(px_cli_env, monkeypatch):
    # debug via cli or env = 2
    if px_cli_env == "env":
        monkeypatch.setenv("PX_LOG", "4")
        return ""
    return "--verbose"


@pytest.fixture
def px_debug_none(px_cli_env_none, monkeypatch):
    # debug via cli, env or none = 3
    if px_cli_env_none == "cli":
        return "--verbose"
    elif px_cli_env_none == "env":
        monkeypatch.setenv("PX_LOG", "4")
    else:
        monkeypatch.delenv("PX_LOG", raising=False)

    return ""


# Auth


# Reduce test combinations for slow CI environments (e.g., macOS GitHub Actions)
# Strategy: Use paired combinations to maintain auth/env diversity while reducing total count
# Instead of full cartesian product, we pair auth types with cli/env modes
if os.getenv("PX_CI_MINIMAL") == "1":
    # Paired combinations: (auth, cli/env) to reduce from 6 to 3 combinations
    # NTLM+cli, DIGEST+env, BASIC+cli gives us all auth types and both modes
    PARAMS_AUTH_PAIRED = [
        ("NTLM", "cli"),
        ("DIGEST", "env"),
        ("BASIC", "cli"),
    ]
else:
    PARAMS_AUTH_PAIRED = None  # Use full cartesian product


PARAMS_AUTH = ["NTLM", "DIGEST", "BASIC"]


@pytest.fixture(params=PARAMS_AUTH)
def px_auth(px_cli_env, request, monkeypatch):
    # cli or env = 2
    # NTLM or DIGEST or BASIC = 3
    # 6 combinations (or 3 in minimal mode with pairing)

    auth_type = request.param

    # In minimal mode, skip combinations that don't match the pairing
    if PARAMS_AUTH_PAIRED is not None:
        # Check if this combination should be skipped
        matched = False
        for paired_auth, paired_mode in PARAMS_AUTH_PAIRED:
            if auth_type == paired_auth and px_cli_env == paired_mode:
                matched = True
                break
        if not matched:
            pytest.skip(f"Skipping {auth_type}+{px_cli_env} in minimal mode (not in paired set)")

    if px_cli_env == "env":
        monkeypatch.setenv("PX_AUTH", auth_type)
        return ""
    return "--auth=" + auth_type


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
    # Both paths set PX_PASSWORD in the environment. The difference:
    # - env: Px reads PX_PASSWORD directly from the environment
    # - cli: Uses plaintext keyring backend (set globally in conftest.py)
    monkeypatch.setenv("PX_PASSWORD", PARAMS_PASSWORD)
    if px_cli_env == "env":
        return ""
    else:
        setup_keyring(PARAMS_USERNAME, PARAMS_PASSWORD)
        return ""


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
    # Chain tests require requests to reach their configured proxy rather than
    # inheriting a local PX_NOPROXY entry through px's dotenv support.
    cmd = f"{px_bin} {px_debug_none} --port={px_port} --noproxy=" + f" --test=all:{httpbin_both.url}"
    return cmd


# Test auth


PARAMS_TEST_AUTH = ["", "--test-auth"]


@pytest.fixture(params=PARAMS_TEST_AUTH)
def px_test_auth(request):
    # without and with --test-auth = 2 (or 1 in minimal mode)
    return request.param
