import os
import sys

# Add tests directory to path so helpers module can be imported
sys.path.insert(0, os.path.dirname(__file__))

# Set PX_KEYRING_PLAINTEXT so Px uses plaintext keyring backend for tests
# This allows all tests (including proxy auth tests that use keyring for
# server and client credentials) to run in any environment with a shared
# file-based keyring that works across parent and child processes.
os.environ["PX_KEYRING_PLAINTEXT"] = "1"

import keyring
import keyrings.alt.file

# Use plaintext keyring for tests on all OS
keyring.set_keyring(keyrings.alt.file.PlaintextKeyring())


def pytest_xdist_auto_num_workers():
    """Compute optimal xdist worker count for `pytest -n auto`.

    Each test spawns 1-3 Px subprocesses, but tests are mostly I/O-bound
    so we can run more workers than CPUs.  The real limits are platform
    connection handling and port space (each worker reserves 3 proxy
    ports + 10 network test ports).

    Windows uses fewer workers because socket/connection limits are
    tighter."""
    import sys

    cpus = os.cpu_count() or 2
    if sys.platform == "win32" and os.environ.get("CI"):
        # Single worker avoids Schannel TLS contention across concurrent
        # Px instances on resource-constrained CI runners.
        return 1
    return max(2, cpus // 4)
