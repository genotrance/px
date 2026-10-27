"""End-to-end scenarios against the Docker corporate-proxy lab.

These tests intentionally use Px's public CLI and real network clients. They
are not substitutes for the smaller fake-proxy tests in the main test suite.
"""

from __future__ import annotations

import base64
import concurrent.futures
import contextlib
import http.client
import os
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest

pytestmark = pytest.mark.scenario

ROOT = Path(__file__).parents[2]
ENV_FILE = Path(__file__).parent / "env" / "scenario.env"
ENV_TOOL = ROOT / "tools" / "scenario-env.sh"
BODY = b"px scenario origin\n"
ORIGIN_HTTP = "http://origin.corp.test:8080/small"
ORIGIN_HTTPS = "https://origin.corp.test:8443/small"


def _read_env() -> dict[str, str]:
    if not ENV_FILE.exists():
        return {}
    return dict(
        line.split("=", 1)
        for line in ENV_FILE.read_text(encoding="utf-8").splitlines()
        if line and not line.startswith("#") and "=" in line
    )


def _docker(*args: str, timeout: float = 30) -> subprocess.CompletedProcess[str]:
    command = [
        "docker",
        "compose",
        "--project-directory",
        str(ENV_FILE.parent),
        "-f",
        str(ENV_FILE.parent / "compose.yaml"),
        *args,
    ]
    return subprocess.run(  # noqa: S603
        command,
        check=True,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


@pytest.fixture(scope="session")
def scenario_env() -> dict[str, str]:
    started = False
    if os.getenv("PX_SCENARIO_ENV") == "start":
        subprocess.run([str(ENV_TOOL), "up"], check=True, timeout=300)  # noqa: S603
        started = True
    values = _read_env()
    if not values:
        pytest.skip(
            "corporate proxy scenario environment is not running; use "
            "tools/scenario-env.sh up or PX_SCENARIO_ENV=start"
        )
    try:
        with socket.create_connection(("127.0.0.1", 31280), timeout=1):
            pass
    except OSError:
        pytest.skip("corporate proxy scenario.env exists but its proxies are not reachable")
    yield values
    if started:
        subprocess.run([str(ENV_TOOL), "down"], check=True, timeout=120)  # noqa: S603


@pytest.fixture(scope="session")
def kerberos_cache(scenario_env, tmp_path_factory) -> Path:
    """Create a portable cache without exposing the lab KDC on the host."""
    container_cache = f"/tmp/px-scenario-{os.getpid()}.ccache"  # noqa: S108
    _docker(
        "exec",
        "-T",
        "-e",
        f"KRB5CCNAME={container_cache}",
        "client",
        "sh",
        "-c",
        f"printf '%s\\n' '{scenario_env['SCENARIO_PASSWORD']}' | "
        f"kinit {scenario_env['SCENARIO_USER']}@{scenario_env['SCENARIO_REALM']} && "
        "kvno HTTP/localhost",
    )
    cache = tmp_path_factory.mktemp("kerberos") / "krb5cc"
    cache.write_bytes(base64.b64decode(_docker("exec", "-T", "client", "base64", container_cache).stdout))
    return cache


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _proxy_addr(url: str) -> str:
    return url.removeprefix("http://")


def _scheme_config(env: dict[str, str], scheme: str) -> tuple[str, str]:
    if scheme == "BASIC":
        return env["SCENARIO_BASIC_PROXY"], env["SCENARIO_USER"]
    if scheme == "DIGEST":
        return env["SCENARIO_DIGEST_PROXY"], env["SCENARIO_USER"]
    proxy = env["SCENARIO_SSO_PROXY"]
    if scheme == "NEGOTIATE":
        proxy = proxy.replace("127.0.0.1", "localhost")
    return proxy, f'{env["SCENARIO_DOMAIN"]}\\{env["SCENARIO_USER"]}'


class PxProcess:
    def __init__(
        self,
        tmp_path: Path,
        env: dict[str, str],
        *,
        scheme: str = "BASIC",
        proxy: str | None = None,
        pac: str | None = None,
        password: str | None = None,
        event_loop: str = "asyncio",
        workers: int = 1,
        authretry: float = 0,
        kerberos_cache: Path | None = None,
    ):
        self.port = _free_port()
        self.log = tmp_path / f"px-{self.port}.log"
        config = tmp_path / f"px-{self.port}.ini"
        config.touch()
        default_proxy, username = _scheme_config(env, scheme)
        proxy = proxy or default_proxy
        args = [
            sys.executable,
            "-m",
            "px",
            f"--config={config}",
            "--foreground",
            "--log=4",
            "--listen=127.0.0.1",
            f"--port={self.port}",
            "--noproxy=",
            f"--auth={scheme}",
            f"--username={username}",
            f"--event-loop={event_loop}",
            f"--workers={workers}",
            "--threads=64",
            "--socktimeout=10",
            f"--authretry={authretry}",
        ]
        args.append(f"--pac={pac}" if pac else f"--proxy={_proxy_addr(proxy)}")
        proc_env = os.environ.copy()
        proc_env["PX_PASSWORD"] = env["SCENARIO_PASSWORD"] if password is None else password
        if kerberos_cache:
            proc_env["KRB5CCNAME"] = str(kerberos_cache)
            proc_env.pop("PX_PASSWORD", None)
        self.output = self.log.open("w+", encoding="utf-8")
        self.proc = subprocess.Popen(  # noqa: S603
            args,
            cwd=ROOT,
            env=proc_env,
            stdout=self.output,
            stderr=subprocess.STDOUT,
            text=True,
        )
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            if self.proc.poll() is not None:
                break
            try:
                with socket.create_connection(("127.0.0.1", self.port), timeout=0.2):
                    return
            except OSError:
                time.sleep(0.1)
        self.close()
        pytest.fail(f"Px did not start:\n{self.text()[-4000:]}")

    def text(self) -> str:
        self.output.flush()
        return self.log.read_text(encoding="utf-8", errors="replace")

    def close(self) -> None:
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(timeout=5)
        self.output.close()

    def assert_healthy(self) -> None:
        assert self.proc.poll() is None
        assert "Traceback (most recent call last)" not in self.text()


@contextlib.contextmanager
def running_px(*args, **kwargs):
    px = PxProcess(*args, **kwargs)
    try:
        yield px
    finally:
        px.close()


def _curl(px: PxProcess, url: str, *, timeout: float = 15) -> subprocess.CompletedProcess[bytes]:
    args = ["curl", "--silent", "--show-error", "--max-time", str(timeout), "--proxy", f"http://127.0.0.1:{px.port}"]
    if url.startswith("https:"):
        args.append("--insecure")
    return subprocess.run([*args, url], capture_output=True, timeout=timeout + 2)  # noqa: S603


def _status(px: PxProcess, url: str = ORIGIN_HTTP) -> int:
    result = _curl(px, url)
    if result.returncode:
        return 0
    return 200 if result.stdout == BODY else 502


@pytest.mark.parametrize("scheme", ["NTLM", "BASIC", "DIGEST"])
@pytest.mark.parametrize("source", ["proxy", "pac"])
def test_px_test_credentials(scenario_env, tmp_path, scheme, source):
    """`px --test` succeeds with the same proxy/PAC and PX_PASSWORD users supply."""
    if source == "pac" and scheme not in {"NTLM", "NEGOTIATE"}:
        pytest.skip("the lab PAC intentionally selects its SSO (NTLM/Negotiate) proxy")
    proxy, username = _scheme_config(scenario_env, scheme)
    config = tmp_path / "empty.ini"
    config.touch()
    command = [
        sys.executable,
        "-m",
        "px",
        f"--config={config}",
        f"--auth={scheme}",
        f"--username={username}",
        "--noproxy=",
        f"--test={ORIGIN_HTTP}",
    ]
    command.append(
        f'--pac={scenario_env["SCENARIO_PAC_URL"]}'
        if source == "pac"
        else f"--proxy={_proxy_addr(proxy)}"
    )
    proc_env = os.environ | {
        "PX_PASSWORD": scenario_env["SCENARIO_PASSWORD"],
        "PYTHONUNBUFFERED": "1",
    }
    result = subprocess.run(  # noqa: S603
        command,
        cwd=ROOT,
        env=proc_env,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "passed" in (result.stdout + result.stderr).lower()


def test_kerberos_ticket_no_password(scenario_env, kerberos_cache, tmp_path):
    """A test-owned ticket cache authenticates Px without exposing a password."""
    with running_px(tmp_path, scenario_env, scheme="NEGOTIATE", kerberos_cache=kerberos_cache) as px:
        assert _curl(px, ORIGIN_HTTP).stdout == BODY
        assert _curl(px, ORIGIN_HTTPS).stdout == BODY
        px.assert_healthy()


@pytest.mark.parametrize("authretry", [0, 0.5], ids=["disabled", "interval"])
def test_wrong_password_block_and_authretry(scenario_env, tmp_path, authretry):
    """Repeated bad credentials are bounded and never leave Px hung or crashed."""
    before = _docker("exec", "-T", "dc", "sh", "-c", "wc -l < /var/log/squid/access.log").stdout.strip()
    with running_px(
        tmp_path,
        scenario_env,
        scheme="NTLM",
        password=scenario_env["SCENARIO_WRONG_PASSWORD"],
        authretry=authretry,
    ) as px:
        statuses = [_status(px) for _ in range(8)]
        assert 200 not in statuses
        time.sleep(authretry + 0.2)
        assert _status(px) != 200
        px.assert_healthy()
    after = _docker("exec", "-T", "dc", "sh", "-c", "wc -l < /var/log/squid/access.log").stdout.strip()
    # NTLM challenge exchanges add two log entries beyond Px's three attempts.
    assert int(after) - int(before) <= (7 if authretry else 5)
    with running_px(tmp_path, scenario_env, scheme="NTLM", authretry=authretry) as recovered:
        assert _status(recovered) == 200


@pytest.mark.parametrize("scheme", ["NTLM", "NEGOTIATE", "BASIC"])
@pytest.mark.parametrize("protocol", ["http", "https"])
@pytest.mark.parametrize("event_loop", ["auto", "asyncio"])
@pytest.mark.parametrize("workers", [1, 2])
def test_burst_25_px268(scenario_env, kerberos_cache, tmp_path, scheme, protocol, event_loop, workers):
    """px#268 regression: 25 simultaneous real-client requests all complete."""
    cache = kerberos_cache if scheme == "NEGOTIATE" else None
    with running_px(
        tmp_path,
        scenario_env,
        scheme=scheme,
        event_loop=event_loop,
        workers=workers,
        kerberos_cache=cache,
    ) as px:
        url = ORIGIN_HTTPS if protocol == "https" else ORIGIN_HTTP
        gate = threading.Barrier(25)

        def request(_):
            gate.wait(timeout=10)
            result = _curl(px, url, timeout=30)
            return result.returncode, result.stdout, result.stderr

        with concurrent.futures.ThreadPoolExecutor(max_workers=25) as pool:
            results = list(pool.map(request, range(25)))
        assert all(code == 0 and body == BODY for code, body, _ in results), results
        assert not any(b"407" in error or b"502" in error for _, _, error in results)
        px.assert_healthy()


@pytest.mark.parametrize("proxy_key", ["SCENARIO_BASIC_PROXY", "SCENARIO_CLOSE_PROXY"])
def test_long_lived_tunnel_and_keepalive(scenario_env, tmp_path, proxy_key):
    """A 30-second CONNECT tunnel coexists with normal traffic."""
    with running_px(tmp_path, scenario_env, scheme="BASIC", proxy=scenario_env[proxy_key]) as px:
        tunnel = socket.create_connection(("127.0.0.1", px.port), timeout=5)
        tunnel.sendall(b"CONNECT echo.corp.test:8888 HTTP/1.1\r\nHost: echo.corp.test:8888\r\n\r\n")
        assert b" 200 " in tunnel.recv(4096)
        tunnel.sendall(b"start")
        assert tunnel.recv(5) == b"start"
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            assert _status(px) == 200
            tunnel.sendall(b".")
            assert tunnel.recv(1) == b"."
            time.sleep(2)
        tunnel.close()
        px.assert_healthy()


def test_mid_handshake_reset_recovers(scenario_env, tmp_path):
    """A reset during NTLM authentication is clean and later traffic works."""
    api = scenario_env["SCENARIO_TOXIPROXY_API"]
    toxic = b'{"name":"reset","type":"reset_peer","stream":"downstream","toxicity":1.0,"attributes":{"timeout":1}}'
    request = urllib.request.Request(  # noqa: S310
        f"{api}/proxies/sso/toxics",
        data=toxic,
        headers={"Content-Type": "application/json"},
    )
    with running_px(tmp_path, scenario_env, scheme="NTLM", proxy=scenario_env["SCENARIO_TOXIPROXY"]) as px:
        try:
            urllib.request.urlopen(request, timeout=5).read()  # noqa: S310
            failed = _curl(px, ORIGIN_HTTPS, timeout=10)
            assert failed.returncode != 0 or failed.stdout == BODY
        finally:
            with contextlib.suppress(urllib.error.URLError):
                delete = urllib.request.Request(f"{api}/proxies/sso/toxics/reset", method="DELETE")  # noqa: S310
                urllib.request.urlopen(delete, timeout=5).read()  # noqa: S310
        assert _status(px) == 200
        px.assert_healthy()


def test_connection_limit_fails_cleanly(scenario_env, tmp_path):
    """A burst above Squid's maxconn=16 limit completes or fails cleanly."""
    with running_px(
        tmp_path,
        scenario_env,
        scheme="BASIC",
        proxy=scenario_env["SCENARIO_CLOSE_PROXY"],
    ) as px:
        with concurrent.futures.ThreadPoolExecutor(max_workers=32) as pool:
            results = list(pool.map(lambda _: _curl(px, ORIGIN_HTTP, timeout=30), range(32)))
        assert all(result.returncode == 0 or b"timed out" not in result.stderr.lower() for result in results)
        assert any(result.stdout == BODY for result in results)
        assert _status(px) == 200
        px.assert_healthy()


@pytest.mark.parametrize("url", [ORIGIN_HTTP, ORIGIN_HTTPS], ids=["http", "https-connect"])
def test_proxy_chain(scenario_env, tmp_path, url):
    """Px -> authenticating child Squid -> parent Squid carries real traffic."""
    with running_px(tmp_path, scenario_env, scheme="BASIC", proxy=scenario_env["SCENARIO_CHAIN_PROXY"]) as px:
        assert _curl(px, url).stdout == BODY
        px.assert_healthy()


def test_pac_proxy_and_direct_with_python_client(scenario_env, tmp_path):
    """PAC selects SSO for corp.test and DIRECT for a host-side origin."""
    with running_px(tmp_path, scenario_env, scheme="NTLM", pac=scenario_env["SCENARIO_PAC_URL"]) as px:
        assert _curl(px, ORIGIN_HTTP).stdout == BODY
        conn = http.client.HTTPConnection("127.0.0.1", px.port, timeout=10)
        conn.request("GET", f'{scenario_env["SCENARIO_HTTP_ORIGIN"]}/small')
        response = conn.getresponse()
        assert response.status == 200
        assert response.read() == BODY
        conn.close()
        px.assert_healthy()
