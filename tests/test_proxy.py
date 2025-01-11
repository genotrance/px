import os

from fixtures import *
from helpers import *

##
# Tests


def test_proxy(px_basic_cli, tmp_path):
    # Px (test) -> Px -> httpbin
    # px basic cli = 6
    # 6 combinations
    run_in_temp(px_basic_cli, tmp_path)


def test_proxy_auth(px_basic_cli, px_auth, px_username, px_password, tmp_path):
    # Px (test) -> Px (auth unused) -> httpbin
    # px basic cli = 6
    # px auth = 6
    # 36 combinations
    cmd = f"{px_basic_cli} {px_auth} {px_username}"
    run_in_temp(cmd, tmp_path)


def test_proxy_auth_upstream(px_upstream, px_basic_cli, px_port, px_auth, px_username, px_password, px_test_auth, tmp_path):
    # Px (test?auth) -> Px (auth?) -> Px upstream (client auth) -> httpbin
    # px basic cli = 6
    # px auth = 6
    # px test-auth = 2
    # 72 combinations
    cmd = f"{px_basic_cli} {px_auth} {px_username}" + \
        f" --proxy=127.0.0.1:{px_port+1} {px_test_auth}"
    run_in_temp(cmd, tmp_path, px_upstream)


def test_proxy_auth_chain(px_upstream, px_chain, px_basic_cli, px_port, px_auth, px_username, px_password, px_test_auth, tmp_path):
    # Px (test?auth) -> Px (auth?) -> Px chain (no auth) -> Px upstream (client auth) -> httpbin
    # px basic cli = 6
    # px auth = 6
    # px test-auth = 2
    # 72 combinations
    cmd = f"{px_basic_cli} {px_auth} {px_username}" + \
        f" --proxy=127.0.0.1:{px_port+2} {px_test_auth}"
    run_in_temp(cmd, tmp_path, px_upstream, px_chain)
