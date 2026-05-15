from fixtures import *  # noqa: F403
from helpers import *  # noqa: F403

##
# Tests for multiprocessing with multiple workers


def test_multiprocessing_workers(px_port, tmp_path, httpbin_both):
    """Test Px with --workers=2"""
    cmd = f"px --verbose --port={px_port} --workers=2 --test=all:{httpbin_both.url}"
    run_in_temp(cmd, tmp_path)


def test_multiprocessing_workers_auth(px_port, px_auth, px_username, px_password, tmp_path, httpbin_both):
    """Test Px with --workers=2 and authentication"""
    cmd = (
        f"px --verbose --port={px_port} --workers=2 {px_auth} {px_username} {px_password} --test=all:{httpbin_both.url}"
    )
    run_in_temp(cmd, tmp_path)
