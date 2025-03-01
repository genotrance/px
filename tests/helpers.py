import contextlib
import os
import platform
import socket
import subprocess
import sys
import time

import keyring
import psutil

try:
    ConnectionRefusedError
except NameError:
    ConnectionRefusedError = socket.error


@contextlib.contextmanager
def change_dir(path):
    old_dir = os.getcwd()
    try:
        os.chdir(path)
        yield
    finally:
        os.chdir(old_dir)


def px_print_env(cmd, env=os.environ):
    print(cmd)

    if env is not None:
        for key, value in env.items():
            if key.startswith("PX_"):
                print(f"  {key}={value}")


def is_port_free(port):
    try:
        socket.create_connection(("127.0.0.1", port), 1)
        return False
    except (socket.timeout, ConnectionRefusedError):
        return True


def is_px_running(port):
    # Make sure Px starts
    retry = 20
    if sys.platform == "darwin" or platform.machine() == "aarch64":
        # Nuitka builds take longer to start on Mac and aarch64
        retry = 40
    while True:
        try:
            socket.create_connection(("127.0.0.1", port), 1)
            break
        except (socket.timeout, ConnectionRefusedError):
            time.sleep(1)
            retry -= 1
            assert retry != 0, f"Px didn't start @ 127.0.0.1:{port}"

    return True


def quit_px(name, subp, cmd):
    if sys.platform == "linux" and platform.machine() == "aarch64":
        # psutil.net_if_stats() is not supported on aarch64
        # --hostonly and --quit don't work
        proc = psutil.Process(subp.pid)
        for child in proc.children(recursive=True):
            child.kill()
            try:
                child.wait(10)
            except psutil.TimeoutExpired:
                assert False, f"{name} failed to stop child process"
        subp.kill()
        goodret = -9
    else:
        cmd = cmd + " --quit"
        print(f"{name} quit cmd: {cmd}\n")
        ret = os.system(cmd)
        assert ret == 0, f"Failed: Unable to --quit Px: {ret}"
        print(f"{name} Px --quit succeeded")
        goodret = 0

    # Check exit code
    retcode = subp.wait()
    assert retcode == goodret, f"{name} Px exited with {retcode}"
    print(f"{name} Px exited")


def run_px(name, port, tmp_path_factory, flags, env=None):
    cmd = f"px --debug --port={port} {flags}"

    px_print_env(f"{name}: {cmd}", env)

    tmp_path = tmp_path_factory.mktemp(f"{name}-{port}")
    buffer = open(f"{tmp_path}{os.sep}{name}-{port}.log", "w+t")
    subp = subprocess.Popen(
        cmd, shell=True, stdout=buffer, stderr=buffer, env=env, cwd=tmp_path
    )

    assert is_px_running(port), f"{name} Px didn't start @ {port}"
    time.sleep(0.5)

    return subp, cmd, buffer


def print_buffer(buffer):
    buffer.seek(0)
    while True:
        line = buffer.read(4096)
        sys.stdout.write(line)
        if len(line) < 4096:
            break
    buffer.seek(0)


def run_in_temp(cmd, tmp_path, upstream_buffer=None, chain_buffer=None):
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
