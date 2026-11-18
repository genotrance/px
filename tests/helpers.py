import atexit
import contextlib
import os
import platform
import socket
import struct
import subprocess
import sys
import tempfile
import time

import keyring
import psutil

_port_reservations = set()

# Longest a fresh interpreter may take for each startup step before the CI
# macOS guard stops the run. The stall it exists for lasts about 35 seconds.
STARTUP_LIMIT = 10.0

# Steps of a px start that can block on a name or proxy lookup, each run in a
# fresh interpreter (argv[1] is an empty px.ini)
STARTUP_PROBES = {
    "gethostbyaddr": "import socket; socket.gethostbyaddr('127.0.0.1')",
    "getproxies": "import urllib.request; urllib.request.getproxies()",
    "parse_config": (
        "import sys; sys.argv = ['px', '--noproxy=', '--config=' + sys.argv[1]]; "
        "from px import main; main.STATE.parse_config()"
    ),
}


NTLM_TYPE_2_FLAGS = (
    0x00000001  # NEGOTIATE_UNICODE
    | 0x00000004  # REQUEST_TARGET
    | 0x00000200  # NEGOTIATE_NTLM
    | 0x00008000  # NEGOTIATE_ALWAYS_SIGN
    | 0x00010000  # TARGET_TYPE_DOMAIN
    | 0x00080000  # NEGOTIATE_EXTENDED_SESSIONSECURITY
    | 0x00800000  # NEGOTIATE_TARGET_INFO
    | 0x02000000  # NEGOTIATE_VERSION
    | 0x20000000  # NEGOTIATE_128
    | 0x80000000  # NEGOTIATE_56
)


def ntlm_type_2(domain="EXAMPLE", computer="FAKEPROXY"):
    """Return an NTLMv2-capable Type 2 challenge, as a current Windows server sends.

    Windows SSPI refuses to build a Type 3 (SEC_E_UNSUPPORTED_FUNCTION) for a
    challenge that offers only NTLMv1: no extended session security, 128-bit
    keys or target info. Fake NTLM proxies must send this form.
    """
    filetime = int((time.time() + 11644473600) * 10_000_000)
    target_name = domain.encode("utf-16-le")
    av_pairs = [
        (2, target_name),
        (1, computer.encode("utf-16-le")),
        (4, domain.lower().encode("utf-16-le") + b".\x00e\x00x\x00"),
        (3, computer.lower().encode("utf-16-le")),
        (7, struct.pack("<Q", filetime)),
        (0, b""),
    ]
    target_info = b"".join(struct.pack("<HH", av_id, len(value)) + value for av_id, value in av_pairs)
    header_len = 56
    return (
        b"NTLMSSP\x00"
        + struct.pack("<IHHII", 2, len(target_name), len(target_name), header_len, NTLM_TYPE_2_FLAGS)
        + os.urandom(8)
        + b"\x00" * 8
        + struct.pack("<HHI", len(target_info), len(target_info), header_len + len(target_name))
        + bytes((10, 0))
        + struct.pack("<H", 20348)
        + b"\x00\x00\x00\x0f"
        + target_name
        + target_info
    )


class PxStartupError(AssertionError):
    def __init__(self, listen_ip, port):
        super().__init__(f"Px didn't start @ {listen_ip}:{port}")


def _release_port_reservations():
    for path in _port_reservations:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(path)


atexit.register(_release_port_reservations)


@contextlib.contextmanager
def change_dir(path):
    old_dir = os.getcwd()
    try:
        os.chdir(path)
        yield
    finally:
        os.chdir(old_dir)


# CLI flags whose value is a credential, matched case-insensitively against
# "--name" or "--name=value" tokens in a logged command string.
SENSITIVE_CLI_FLAGS = {"--password", "--client-password"}

REDACTED = "***REDACTED***"


def _redact_cmd(cmd):
    """Mask --password/--client-password values in a loggable command string.

    The real cmd passed to subprocess/os.system is untouched; this only
    affects what gets printed."""
    tokens = cmd.split(" ")
    redacted_tokens = []
    skip_next = False
    for token in tokens:
        if skip_next:
            redacted_tokens.append(REDACTED)
            skip_next = False
            continue

        flag = token.split("=", 1)[0].lower()
        if flag in SENSITIVE_CLI_FLAGS:
            if "=" in token:
                redacted_tokens.append(f"{token.split('=', 1)[0]}={REDACTED}")
            else:
                redacted_tokens.append(token)
                skip_next = True
        else:
            redacted_tokens.append(token)

    return " ".join(redacted_tokens)


def px_print_env(cmd, env=os.environ):
    print(_redact_cmd(cmd))

    if env is not None:
        for key in env:
            if key.startswith("PX_"):
                # The supplied mapping can contain credentials under arbitrary
                # PX_* names, so report only that each setting is present.
                print(f"  {key}=<set>")


def is_port_free(port):
    try:
        socket.create_connection(("127.0.0.1", port), 1)
    except (TimeoutError, ConnectionRefusedError):
        return True
    else:
        return False


def can_connect(ip, port, timeout=2):
    """Check if a connection to ip:port succeeds."""
    try:
        s = socket.create_connection((ip, port), timeout)
        s.close()
    except (TimeoutError, ConnectionRefusedError, OSError):
        return False
    else:
        return True


def find_free_port(start=4000):
    """Find a free port starting from the given number."""
    port = start
    while port < start + 200:
        if is_port_free(port):
            return port
        port += 1
    return None


PORT_BLOCK_BASE = 3148
# Wide enough for parallel tox environments each running `pytest -n auto` on
# many-core hosts, and below the 4000+ ports other tests search from
PORT_BLOCK_SPAN = 800


def find_free_port_block(start=PORT_BLOCK_BASE, count=3):
    """Find the first port from start where count consecutive ports are free."""
    blocks = PORT_BLOCK_SPAN // count
    first = (start - PORT_BLOCK_BASE) // count
    for index in range(blocks):
        port = PORT_BLOCK_BASE + ((first + index) % blocks) * count
        if not all(is_port_free(port + i) for i in range(count)):
            continue

        # Reserve the block so concurrent pytest processes do not choose it too.
        path = os.path.join(tempfile.gettempdir(), f"px-test-ports-{port}-{count}")
        try:
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        except FileExistsError:
            try:
                with open(path) as reservation:
                    pid = int(reservation.read())
            except (FileNotFoundError, ValueError):
                # The owner may still be writing its PID.
                continue
            if not psutil.pid_exists(pid):
                with contextlib.suppress(FileNotFoundError):
                    os.unlink(path)
                continue
            continue

        with os.fdopen(fd, "w") as reservation:
            reservation.write(str(os.getpid()))
        _port_reservations.add(path)
        return port
    return None


def is_px_running(port, listen_ip="127.0.0.1", timeout=20):
    """Wait for Px to listen, allowing slower starts on loaded test hosts."""
    if sys.platform in ("darwin", "win32") or platform.machine() == "aarch64":
        # Nuitka builds take longer to start on Mac, Windows and aarch64
        timeout = max(timeout, 40)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            socket.create_connection((listen_ip, port), 1)
        except (TimeoutError, ConnectionRefusedError, OSError):
            time.sleep(0.25)
        else:
            return True
    raise PxStartupError(listen_ip, port)


def terminate_process_tree(subp, timeout=10):
    """Stop a launched process and every descendant it still owns."""
    try:
        root = psutil.Process(subp.pid)
        processes = [*root.children(recursive=True), root]
    except psutil.Error:
        processes = []

    for process in processes:
        with contextlib.suppress(psutil.Error):
            process.terminate()
    _, alive = psutil.wait_procs(processes, timeout=timeout)
    for process in alive:
        with contextlib.suppress(psutil.Error):
            process.kill()
    psutil.wait_procs(alive, timeout=timeout)

    with contextlib.suppress(subprocess.TimeoutExpired):
        subp.wait(timeout=timeout)


def quit_px(name, subp, cmd, strict=True, buffer=None):
    """Stop a running Px instance.

    If strict=True (default), asserts that --quit and exit succeed — use in
    fixture teardown where quit must work.  If strict=False, falls back to
    kill on failure — use in exception handlers / cleanup.  If buffer is
    given, Px's own verbose log prints when --quit fails, since that is
    otherwise the only record of what Px was doing when it stopped responding."""
    quit_cmd = cmd + " --quit"
    print(f"{name} quit cmd: {quit_cmd}\n")
    # Retry --quit for slow CI environments (e.g. Windows)
    ret = None
    for _attempt in range(3):
        ret = os.system(quit_cmd)
        if ret == 0:
            break
        time.sleep(2)
    if ret != 0 and buffer is not None:
        print(f"{name} Px log:")
        print_buffer(buffer)
    print(f"{name} Px --quit {'succeeded' if ret == 0 else 'failed'}")

    if ret != 0:
        terminate_process_tree(subp)
        if strict:
            assert ret == 0, f"Failed: Unable to --quit Px: {ret}"
        print(f"{name} Px exited")
        return
    try:
        retcode = subp.wait(timeout=10)
    except subprocess.TimeoutExpired:
        terminate_process_tree(subp)
        if strict:
            raise AssertionError(f"{name} Px did not exit after --quit") from None  # noqa: TRY003
    else:
        if strict:
            assert retcode == 0, f"{name} Px exited with {retcode}"
    print(f"{name} Px exited")


def run_px(name, port, tmp_path, flags="", env=None, listen_ip="127.0.0.1", startup_timeout=20):
    """Start a Px instance and wait for it to be ready.

    tmp_path can be a Path (function-scoped) or a tmp_path_factory
    (session-scoped) — if it has mktemp(), a subdirectory is created."""
    if hasattr(tmp_path, "mktemp"):
        tmp_path = tmp_path.mktemp(f"{name}-{port}")

    # Explicit config path keeps a px.ini that a parallel test_config run
    # temporarily writes next to the px script from being auto-discovered
    if "--config" not in flags:
        ini_path = os.path.join(tmp_path, "px.ini")
        open(ini_path, "a").close()
        flags += f" --config={ini_path}"

    cmd = f"px --verbose --port={port} {flags}"

    px_print_env(f"{name}: {cmd}", env)

    logfile = open(f"{tmp_path}{os.sep}{name}-{port}.log", "w+")
    popen_kwargs = {}
    if sys.platform == "win32":
        popen_kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW
    subp = subprocess.Popen(cmd, shell=True, stdout=logfile, stderr=logfile, env=env, cwd=tmp_path, **popen_kwargs)

    try:
        assert is_px_running(port, listen_ip, startup_timeout), f"{name} Px didn't start @ {listen_ip}:{port}"
    except Exception:
        # A failed startup must not leave a process holding a test port.
        terminate_process_tree(subp)
        logfile.close()
        raise

    return subp, cmd, logfile


def print_buffer(buffer):
    buffer.seek(0)
    while True:
        line = buffer.read(4096)
        sys.stdout.write(line)
        if len(line) < 4096:
            break
    buffer.seek(0)


def run_in_temp(cmd, tmp_path, upstream_buffer=None, chain_buffer=None):
    # Explicit config path prevents auto-discovery of stray px.ini files
    ini_path = os.path.join(tmp_path, "px.ini")
    if not os.path.exists(ini_path):
        open(ini_path, "w").close()
    cmd += f" --config={ini_path}"
    px_print_env(cmd)
    with change_dir(tmp_path):
        ret = os.system(cmd)

    if upstream_buffer is not None:
        print("Upstream Px:")
        print_buffer(upstream_buffer)

    if chain_buffer is not None:
        print("Chain Px:")
        print_buffer(chain_buffer)

    assert ret == 0, f"Px exited with {ret}"


def setup_keyring(username, password):
    # Run only once for entire test run
    if getattr(setup_keyring, "done", False):
        return
    setup_keyring.done = True

    if keyring.get_password("Px", username) == password:
        return
    keyring.set_password("Px", username, password)
    keyring.set_password("PxClient", username, password)


def touch(path):
    parent_dir = os.path.dirname(path)
    if parent_dir:
        os.makedirs(parent_dir, exist_ok=True)
    print("Writing " + path)
    with open(path, "w") as f:
        f.write("")


def probe_startup(timeout=2 * STARTUP_LIMIT):
    """Time each STARTUP_PROBES step in a fresh interpreter; returns {name: seconds}.

    A step that does not finish within timeout is reported as timeout."""
    results = {}
    env = {key: value for key, value in os.environ.items() if not key.startswith("PX_")}
    with tempfile.TemporaryDirectory() as tmp:
        ini = os.path.join(tmp, "px.ini")
        open(ini, "w").close()
        for name, code in STARTUP_PROBES.items():
            start = time.monotonic()
            with contextlib.suppress(subprocess.TimeoutExpired):
                subprocess.run(  # noqa: S603
                    [sys.executable, "-c", code, ini], cwd=tmp, env=env, timeout=timeout, capture_output=True
                )
            results[name] = min(time.monotonic() - start, timeout)
    return results


def slow_startup_steps(timings, limit=STARTUP_LIMIT):
    "Return the probe steps in timings that took longer than limit seconds"
    return {name: seconds for name, seconds in timings.items() if seconds > limit}
