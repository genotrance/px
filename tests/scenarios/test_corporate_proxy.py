"""End-to-end scenarios against the Docker corporate-proxy lab.

These tests intentionally use Px's public CLI and real network clients. They
are not substitutes for the smaller fake-proxy tests in the main test suite.
"""

from __future__ import annotations

import base64
import concurrent.futures
import contextlib
import dataclasses
import functools
import hashlib
import http.client
import json
import os
import select
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
import uuid
from collections.abc import Iterator
from pathlib import Path

import mcurl
import psutil
import pytest

pytestmark = pytest.mark.scenario

ROOT = Path(__file__).parents[2]
ENV_FILE = Path(__file__).parent / "env" / "scenario.env"
ENV_TOOL = ROOT / "tests" / "scenarios" / "env" / "scenario-env.sh"
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
        "-p",
        _read_env().get("SCENARIO_COMPOSE_PROJECT", "px-scenario"),
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
def scenario_env() -> Iterator[dict[str, str]]:
    started = False
    if os.getenv("PX_SCENARIO_ENV") == "start":
        subprocess.run([str(ENV_TOOL), "up"], check=True, timeout=300)  # noqa: S603
        started = True
    values = _read_env()
    if not values:
        pytest.skip(
            "corporate proxy scenario environment is not running; use tests/scenarios/env/scenario-env.sh up or PX_SCENARIO_ENV=start"
        )
    try:
        port = int(values["SCENARIO_BASIC_PROXY"].rsplit(":", 1)[1])
        with socket.create_connection(("127.0.0.1", port), timeout=1):
            pass
    except OSError:
        pytest.skip("corporate proxy scenario.env exists but its proxies are not reachable")
    yield values
    if started:
        subprocess.run([str(ENV_TOOL), "down"], check=True, timeout=120)  # noqa: S603


def _toxiproxy(env: dict[str, str], method: str, path: str, body: bytes | None = None) -> bytes:
    request = urllib.request.Request(  # noqa: S310
        f"{env['SCENARIO_TOXIPROXY_API']}{path}",
        data=body,
        headers={"Content-Type": "application/json"},
        method=method,
    )
    with urllib.request.urlopen(request, timeout=5) as response:  # noqa: S310
        return response.read()


@pytest.fixture(autouse=True)
def fault_free(scenario_env):
    """Every scenario starts and ends with no Toxiproxy toxic on the SSO hop."""
    _toxiproxy(scenario_env, "POST", "/reset")
    yield
    _toxiproxy(scenario_env, "POST", "/reset")


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
    return proxy, f"{env['SCENARIO_DOMAIN']}\\{env['SCENARIO_USER']}"


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
        username: str | None = None,
    ):
        self.port = _free_port()
        self.event_loop = event_loop
        self.log = tmp_path / f"px-{self.port}.log"
        config = tmp_path / f"px-{self.port}.ini"
        config.touch()
        default_proxy, default_username = _scheme_config(env, scheme)
        username = username or default_username
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


@pytest.mark.parametrize(
    ("source", "scheme"),
    # The lab PAC intentionally selects its SSO (NTLM/Negotiate) proxy
    [("proxy", "NTLM"), ("proxy", "BASIC"), ("proxy", "DIGEST"), ("pac", "NTLM")],
    ids=["proxy-NTLM", "proxy-BASIC", "proxy-DIGEST", "pac-NTLM"],
)
def test_px_test_credentials(scenario_env, tmp_path, scheme, source):
    """`px --test` succeeds with the same proxy/PAC and PX_PASSWORD users supply."""
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
    command.append(f"--pac={scenario_env['SCENARIO_PAC_URL']}" if source == "pac" else f"--proxy={_proxy_addr(proxy)}")
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


def test_px_test_auth_negotiate_matches_upstream_spn(scenario_env, kerberos_cache, tmp_path):
    """`px --test-auth` with NEGOTIATE must SPN-match the upstream proxy, not Px's listen address.

    Px listens on 127.0.0.2 here, not 127.0.0.1. The test client treats Px as
    the proxy it authenticates to, so before the fix libcurl built the
    Negotiate SPN from that listen address - for which Kerberos has no
    ticket - instead of the upstream SSO proxy's hostname (reached here as
    "localhost", the only SPN this lab's KDC issued a ticket for). KRB5_TRACE
    confirms which SPN libcurl actually requested.
    """
    proxy, username = _scheme_config(scenario_env, "NEGOTIATE")
    config = tmp_path / "empty.ini"
    config.touch()
    trace = tmp_path / "krb5_trace.log"
    command = [
        sys.executable,
        "-m",
        "px",
        f"--config={config}",
        "--auth=NEGOTIATE",
        f"--username={username}",
        "--noproxy=",
        "--listen=127.0.0.2",
        f"--proxy={_proxy_addr(proxy)}",
        "--test-auth",
        f"--test={ORIGIN_HTTP}",
    ]
    proc_env = os.environ | {
        "KRB5CCNAME": str(kerberos_cache),
        "KRB5_TRACE": str(trace),
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

    trace_text = trace.read_text(encoding="utf-8", errors="replace") if trace.exists() else ""
    assert "HTTP/localhost@" in trace_text, trace_text
    assert "HTTP/127.0.0.2@" not in trace_text, trace_text


###
# Multi-leg SPNEGO (NTLM-in-Negotiate): the Linux side of the Windows SSPI corporate case.
# SCENARIO_SSO_WRAPPER_PROXY advertises only "Proxy-Authenticate: Negotiate" via Squid's
# negotiate_wrapper_auth (docs/testing.md has the full background).

# smbpasswd-format line gss-ntlmssp's NTLM_USER_FILE understands; the NT hash is a precomputed
# MD4("GoodPass1!" as UTF-16LE). It is never checked here - the proxy below rejects the
# handshake before any credential reaches a validating helper.
NTLM_USER_FILE_LINE = (
    "pxgood:1000:AAD3B435B51404EEAAD3B435B51404EE:82B1AB6E2AAFED007B43698BA2781669:[U          ]:LCT-00000000:\n"
)


def _gss_ntlmssp_available() -> bool:
    "True if this host's GSSAPI mech glue has gss-ntlmssp registered (the gss-ntlmssp package)."
    mech_d = Path("/etc/gss/mech.d")
    return mech_d.is_dir() and any("ntlmssp" in path.name.lower() for path in mech_d.iterdir())


@pytest.mark.skipif(not _gss_ntlmssp_available(), reason="gss-ntlmssp is not installed on this host")
def test_negotiate_wrapper_cannot_route_spnego_wrapped_ntlm(scenario_env, tmp_path, monkeypatch):
    """Squid's negotiate_wrapper_auth never reaches NTLM for a standards-compliant SPNEGO client.

    gss-ntlmssp makes MIT krb5's GSSAPI do exactly what SSPI does with no Kerberos ticket and no
    reachable KDC: produce a real SPNEGO negTokenInit wrapping an NTLMSSP type-1 message (verified
    by decoding a captured "Proxy-Authorization: Negotiate" header from this exact setup).

    Squid's negotiate_wrapper_auth (src/auth/negotiate/wrapper/negotiate_wrapper.cc upstream)
    decides Kerberos vs. NTLM by checking whether the *decoded* token's first 8 bytes are the
    literal ASCII "NTLMSSP\\0" signature. A real SPNEGO envelope never starts with that signature -
    the NTLMSSP bytes are nested about 20 bytes into the ASN.1 structure - so every Negotiate
    token, Kerberos or SPNEGO-wrapped NTLM alike, is handed to the Kerberos helper, which rejects
    it; Squid repeats the bare challenge and the handshake never reaches a second, body-bearing
    leg. This is a Squid limitation, not a px/mcurl one: the client has nothing left to retry, so
    there is no libcurl leg sequence or mcurl fix to propose here.

    Because the proxy rejects the handshake before it reads a request method or body, the outcome
    does not depend on POST/PUT/PATCH or on body size/chunking - one representative GET is enough
    evidence; see docs/testing.md for the decoded token and the Windows SSPI follow-up.
    """
    if "SCENARIO_SSO_WRAPPER_PROXY" not in scenario_env:
        pytest.skip(f"the running lab predates SCENARIO_SSO_WRAPPER_PROXY; restart it with {ENV_TOOL} down and up")
    user_file = tmp_path / "ntlm_user_file"
    user_file.write_text(NTLM_USER_FILE_LINE, encoding="utf-8")
    monkeypatch.setenv("NTLM_USER_FILE", str(user_file))
    monkeypatch.setenv("NTLMUSER", "pxgood")
    monkeypatch.setenv("NETBIOS_DOMAIN_NAME", "CORP")
    monkeypatch.setenv("NETBIOS_COMPUTER_NAME", "PXCLIENT")
    monkeypatch.delenv("KRB5CCNAME", raising=False)  # no ticket cache: Kerberos cannot be used either
    with running_px(
        tmp_path, scenario_env, scheme="NEGOTIATE", proxy=scenario_env["SCENARIO_SSO_WRAPPER_PROXY"], username="pxgood"
    ) as px:
        assert _status(px) != 200
        px.assert_healthy()


def _sso_origin_requests() -> int:
    """Count SSO Squid log entries for origin requests.

    The DC's health check connects to Squid every few seconds and logs a
    `NONE_NONE/000` entry, so counting every line would include probes that
    land during a test.
    """
    command = "grep -c ' http://origin.corp.test:8080/' /var/log/squid/access.log || true"
    return int(_docker("exec", "-T", "dc", "sh", "-c", command).stdout.strip() or 0)


@pytest.mark.parametrize("authretry", [0, 0.5], ids=["disabled", "interval"])
def test_wrong_password_block_and_authretry(scenario_env, tmp_path, authretry):
    """Repeated bad credentials are bounded and never leave Px hung or crashed."""
    before = _sso_origin_requests()
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
    after = _sso_origin_requests()
    # NTLM challenge exchanges add two log entries beyond Px's three attempts.
    assert after - before <= (7 if authretry else 5)
    with running_px(tmp_path, scenario_env, scheme="NTLM", authretry=authretry) as recovered:
        assert _status(recovered) == 200


@pytest.mark.parametrize("scheme", ["NTLM", "NEGOTIATE", "BASIC"])
@pytest.mark.parametrize("protocol", ["http", "https"])
@pytest.mark.parametrize("event_loop", ["auto", "asyncio"])
@pytest.mark.parametrize("workers", [1, 2])
def test_burst_25_px268(scenario_env, kerberos_cache, tmp_path, scheme, protocol, event_loop, workers):
    """px#268 load half: 25 simultaneous real-client requests all complete."""
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
        results = _burst(px, url)
        assert all(code == 0 and body == BODY for code, body, _ in results), results
        assert not any(b"407" in error or b"502" in error for _, _, error in results)
        px.assert_healthy()


def _burst(px: PxProcess, url: str, count: int = 25) -> list[tuple[int, bytes, bytes]]:
    gate = threading.Barrier(count)

    def request(_):
        gate.wait(timeout=10)
        result = _curl(px, url, timeout=30)
        return result.returncode, result.stdout, result.stderr

    with concurrent.futures.ThreadPoolExecutor(max_workers=count) as pool:
        return list(pool.map(request, range(count)))


# Squid's first 407 is ~0.5 KiB of headers plus a 3 KiB error page: cutting the
# stream at 1500 bytes drops every handshake after its 407 status line arrived.
CUT_407_BYTES = 1500


@pytest.mark.parametrize("scheme", ["NTLM", "ANY"])
@pytest.mark.parametrize("protocol", ["http", "https"])
@pytest.mark.parametrize("event_loop", ["auto", "asyncio"])
def test_cut_handshakes_do_not_lock_out_proxy_px268(
    scenario_env, kerberos_cache, tmp_path, scheme, protocol, event_loop
):
    """px#268: a network drop during a burst of SSO handshakes must not lock Px out.

    The SSO Squid is reached through Toxiproxy, which cuts each connection in
    the middle of its first 407, as a Wi-Fi change or VPN drop does. libcurl
    then still reports that intermediate 407 as the CONNECT code. pymcurl
    8.23.0.2 counted every such cut handshake as a failed login, blocked the
    proxy after three, and Px answered every later request with
    `401 Proxy server authentication failed` until it was restarted. Once the
    network is back, the same 25-client burst must succeed again.

    NTLM always needs a 407 leg. Negotiate is cut only when Px starts without
    a token, as with the default `--auth=ANY` and a Kerberos ticket (the issue
    reporter's single sign-on setup): `--auth=NEGOTIATE` sends its token in the
    first request, so there is no 407 to interrupt. With ANY, Px also sends
    the token up front once a request has found the method, so that variant
    cuts the first burst after Px starts, as when `px --test` or a browser
    fires while the VPN is still reconnecting.
    """
    cache = kerberos_cache if scheme == "ANY" else None
    proxy = scenario_env["SCENARIO_TOXIPROXY"]
    if scheme == "ANY":
        proxy = proxy.replace("127.0.0.1", "localhost")
    url = ORIGIN_HTTPS if protocol == "https" else ORIGIN_HTTP
    with running_px(
        tmp_path,
        scenario_env,
        scheme=scheme,
        proxy=proxy,
        event_loop=event_loop,
        kerberos_cache=cache,
    ) as px:
        if scheme == "NTLM":
            assert _curl(px, url).stdout == BODY
        toxic = (
            '{"name":"cut407","type":"limit_data","stream":"downstream","toxicity":1.0,'
            f'"attributes":{{"bytes":{CUT_407_BYTES}}}}}'
        )
        _toxiproxy(scenario_env, "POST", "/proxies/sso/toxics", toxic.encode())
        try:
            dropped = _burst(px, url)
        finally:
            _toxiproxy(scenario_env, "DELETE", "/proxies/sso/toxics/cut407")
        # The fault must really have cut handshakes, or the check below is vacuous
        assert sum(body != BODY for _, body, _ in dropped) >= 3, dropped
        recovered = _burst(px, url)
        failures = [(code, body[-200:], error) for code, body, error in recovered if code or body != BODY]
        assert not failures, f"{len(failures)}/25 requests failed after the network recovered: {failures[:3]}"
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
        conn.request("GET", f"{scenario_env['SCENARIO_HTTP_ORIGIN']}/small")
        response = conn.getresponse()
        assert response.status == 200
        assert response.read() == BODY
        conn.close()
        px.assert_healthy()


###
# Plain-HTTP uploads (POST/PUT/PATCH) through proxy authentication
#
# Plain-HTTP request bodies cannot be replayed once Px has streamed them, yet
# NTLM (and Negotiate or Basic after a first unauthenticated 407) needs the
# request to be sent again on the authenticated connection. Before Px streamed
# bodies to mcurl these uploads failed with curl error 65 (503 from Px). The
# tests below send generated, streamed bodies through real Px processes and
# real Squid proxies to the origin's /echo endpoint, which hashes the body as
# it arrives, and assert status 200 plus the exact length and SHA-256.

# TEMPORARY until pymcurl 8.23.0.3 is on PyPI (docs/build.md): streamed uploads through proxy auth need
# its seek callback and Expect handling. CI sets PX_REQUIRE_MCURL_FIX=1 so these tests always run there
# and fail instead of being skipped silently.
needs_mcurl_streaming = pytest.mark.skipif(
    not hasattr(mcurl, "REWIND_ERROR") and os.environ.get("PX_REQUIRE_MCURL_FIX") != "1",
    reason="needs pymcurl>=8.23.0.3 (streamed uploads)",
)
ECHO_URL = "http://origin.corp.test:8080/echo"
BLOCK = 65536
SMALL_SIZE = 3 * BLOCK + 12345
BIG_SIZE = 100 * 1024 * 1024
MIB = 1024 * 1024
# Px holds about one chunk per upload in flight; a streaming Px grows by a few MiB, a buffering one by the body
BIG_RSS_GROWTH_LIMIT = 40 * MIB
PARALLEL_UPLOADS = 60
PARALLEL_SIZE = 8 * MIB
PARALLEL_RSS_GROWTH_LIMIT = 128 * MIB
METHODS = ["POST", "PUT", "PATCH"]
# Every scenario runs on both event loops; CI pins one per job through PX_EVENT_LOOP
UPLOAD_LOOPS = [os.environ["PX_EVENT_LOOP"]] if os.environ.get("PX_EVENT_LOOP") else ["auto", "asyncio"]


@dataclasses.dataclass(frozen=True)
class UploadScheme:
    """One way Px authenticates to one proxy."""

    name: str
    auth: str
    proxy_key: str
    kerberos: bool = False

    @contextlib.contextmanager
    def px(self, tmp_path, env, cache, *, event_loop, workers=1):
        if self.proxy_key not in env:
            pytest.skip(f"the running lab predates {self.proxy_key}; restart it with scenario-env.sh down and up")
        proxy = env[self.proxy_key]
        if self.kerberos:
            # The lab keytab has HTTP/localhost, not the loopback address
            proxy = proxy.replace("127.0.0.1", "localhost")
        plain = self.proxy_key in ("SCENARIO_BASIC_PROXY", "SCENARIO_CLOSE_PROXY")
        with running_px(
            tmp_path,
            env,
            scheme=self.auth,
            proxy=proxy,
            username=env["SCENARIO_USER"] if plain else None,
            event_loop=event_loop,
            workers=workers,
            kerberos_cache=cache if self.kerberos else None,
        ) as px:
            yield px


# NTLM: the first request needs a 407 leg whether Px knows the method (NTLM) or has to discover it
# (NONEGOTIATE); Kerberos: the token goes out with the first request when known (NEGOTIATE) and after a
# 407 when discovered (ANY); Basic with ANY always finds the method from the first 407. The "-close"
# variants run against Squids that close every connection after its response.
UPLOAD_SCHEMES = [
    UploadScheme("ntlm-known", "NTLM", "SCENARIO_SSO_PROXY"),
    UploadScheme("ntlm-unknown", "NONEGOTIATE", "SCENARIO_SSO_PROXY"),
    UploadScheme("negotiate-known", "NEGOTIATE", "SCENARIO_SSO_PROXY", kerberos=True),
    UploadScheme("kerberos-any", "ANY", "SCENARIO_SSO_PROXY", kerberos=True),
    UploadScheme("basic-any-keepalive", "ANY", "SCENARIO_BASIC_PROXY"),
    UploadScheme("basic-any-close", "ANY", "SCENARIO_CLOSE_PROXY"),
    UploadScheme("ntlm-known-close", "NTLM", "SCENARIO_SSO_CLOSE_PROXY"),
    UploadScheme("ntlm-unknown-close", "NONEGOTIATE", "SCENARIO_SSO_CLOSE_PROXY"),
    UploadScheme("negotiate-known-close", "NEGOTIATE", "SCENARIO_SSO_CLOSE_PROXY", kerberos=True),
    UploadScheme("kerberos-any-close", "ANY", "SCENARIO_SSO_CLOSE_PROXY", kerberos=True),
]
SCHEMES_BY_NAME = {scheme.name: scheme for scheme in UPLOAD_SCHEMES}
LOAD_SCHEMES = [SCHEMES_BY_NAME["ntlm-unknown"], SCHEMES_BY_NAME["kerberos-any"]]

by_scheme = pytest.mark.parametrize("scheme", UPLOAD_SCHEMES, ids=lambda scheme: scheme.name)
by_loop = pytest.mark.parametrize("event_loop", UPLOAD_LOOPS)
by_method = pytest.mark.parametrize("method", METHODS)
by_body = pytest.mark.parametrize("chunked", [False, True], ids=["content-length", "chunked"])


def body_blocks(size: int) -> Iterator[bytes]:
    """A deterministic body of exactly `size` bytes, generated one block at a time."""
    pattern = hashlib.sha256(b"px scenario upload").digest() * (BLOCK // 32)
    index = 0
    while size > 0:
        block = (index.to_bytes(8, "big") + pattern[8:])[: min(size, BLOCK)]
        yield block
        size -= len(block)
        index += 1


@functools.cache
def body_sha256(size: int) -> str:
    digest = hashlib.sha256()
    for block in body_blocks(size):
        digest.update(block)
    return digest.hexdigest()


@dataclasses.dataclass
class Upload:
    method: str
    size: int
    chunked: bool
    path: str
    status: int = 0
    body: bytes = b""
    error: str = ""
    interim: list[int] = dataclasses.field(default_factory=list)

    @property
    def description(self) -> str:
        return f"{self.method} {self.size} bytes {'chunked' if self.chunked else 'content-length'}"

    def check(self) -> dict:
        """Assert the origin received this exact upload and return its reply."""
        assert self.status == 200, f"{self.description}: status {self.status} {self.error} {self.body[:300]!r}"
        reply = json.loads(self.body)
        assert reply["method"] == self.method, f"{self.description}: {reply}"
        assert reply["url"].endswith(self.path), f"{self.description}: {reply}"
        assert reply["length"] == self.size, f"{self.description}: origin received {reply}"
        assert reply["sha256"] == body_sha256(self.size), f"{self.description}: origin received {reply}"
        return reply


class UploadClient:
    """Raw HTTP/1.1 client of Px that streams a generated body without holding it in memory.

    The timeout applies to each socket operation, so a 100 MB upload that keeps
    moving never hits it, while an upload Px has stopped answering fails after 30 s.
    """

    def __init__(self, port: int, timeout: float = 30):
        self.sock = socket.create_connection(("127.0.0.1", port), timeout=timeout)
        self.rfile = self.sock.makefile("rb")

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.rfile.close()
        self.sock.close()

    def upload(self, method: str, size: int, *, chunked: bool = False, expect: bool = False) -> Upload:
        path = f"/{method.lower()}/{size}/{uuid.uuid4().hex[:8]}"
        result = Upload(method, size, chunked, path)
        head = [
            f"{method} {ECHO_URL}{path} HTTP/1.1",
            "Host: origin.corp.test:8080",
            "Content-Type: application/octet-stream",
            "Transfer-Encoding: chunked" if chunked else f"Content-Length: {size}",
        ]
        if expect:
            head.append("Expect: 100-continue")
        try:
            self.sock.sendall(("\r\n".join(head) + "\r\n\r\n").encode())
            if expect and self._read_head(result) == 100:
                result.interim.append(100)
            elif expect:
                return result
            for block in body_blocks(size):
                if self._answered_early(result):
                    break
                self.sock.sendall(f"{len(block):x}\r\n".encode() + block + b"\r\n" if chunked else block)
            else:
                if chunked:
                    self.sock.sendall(b"0\r\n\r\n")
        except OSError as error:
            # Px may answer (and close) before the whole body is sent; the answer is still readable
            result.error = f"while sending: {error!r}"
        try:
            while self._read_head(result) == 100:
                result.interim.append(100)
        except (OSError, ValueError, IndexError) as error:
            result.error += f" while reading the response: {error!r}"
        return result

    def _answered_early(self, result: Upload) -> bool:
        """True when Px has already sent its final response (or closed) before the body ended."""
        while select.select([self.sock], [], [], 0)[0]:
            if not self.rfile.peek(12).startswith(b"HTTP/1.1 100"):
                return True
            self._read_head(result)
            result.interim.append(100)
        return False

    def _read_head(self, result: Upload) -> int:
        result.status = int(self.rfile.readline().split()[1])
        headers = {}
        while (line := self.rfile.readline()) not in (b"\r\n", b""):
            name, _, value = line.decode("latin-1").partition(":")
            headers[name.strip().lower()] = value.strip()
        if result.status != 100:
            result.body = self.rfile.read(int(headers.get("content-length", "0")))
        return result.status


def _tree_rss(root: psutil.Process) -> int:
    total = 0
    with contextlib.suppress(psutil.Error):
        for proc in [root, *root.children(recursive=True)]:
            with contextlib.suppress(psutil.Error):
                total += proc.memory_info().rss
    return total


class RssSampler:
    """Sample the RSS of Px and all its worker processes while a block runs."""

    def __init__(self, px: PxProcess):
        self.root = psutil.Process(px.proc.pid)
        self.before = self._settled()
        self.peak = self.before
        self._done = threading.Event()
        self._thread = threading.Thread(target=self._sample, daemon=True)

    def _settled(self) -> int:
        """RSS once startup allocations (a second worker's imports, say) have stopped growing."""
        rss = _tree_rss(self.root)
        for _ in range(20):
            time.sleep(0.25)
            latest = _tree_rss(self.root)
            if abs(latest - rss) < MIB:
                return latest
            rss = latest
        return rss

    def _sample(self):
        while not self._done.wait(0.02):
            self.peak = max(self.peak, _tree_rss(self.root))

    def __enter__(self):
        self._thread.start()
        return self

    def __exit__(self, *_):
        self._done.set()
        self._thread.join()
        self.peak = max(self.peak, _tree_rss(self.root))

    @property
    def growth(self) -> int:
        return self.peak - self.before

    def report(self, memory_report, label: str, uploaded: int) -> None:
        memory_report.append((label, self.before // MIB, self.peak // MIB, uploaded // MIB))


def _run_parallel(port: int, specs: list[tuple[str, int, bool]], *, gate_timeout: float = 60) -> list[Upload]:
    gate = threading.Barrier(len(specs))

    def one(spec):
        method, size, chunked = spec
        with UploadClient(port) as client:
            gate.wait(timeout=gate_timeout)
            return client.upload(method, size, chunked=chunked)

    with concurrent.futures.ThreadPoolExecutor(max_workers=len(specs)) as pool:
        return list(pool.map(one, specs))


###
# First request on a fresh Px: the upload itself has to carry the authentication handshake


@by_scheme
@by_loop
@by_method
@by_body
@needs_mcurl_streaming
def test_upload_first_request(scenario_env, kerberos_cache, tmp_path, scheme, event_loop, method, chunked):
    """The first request of a fresh Px is an upload that must authenticate mid-body."""
    with scheme.px(tmp_path, scenario_env, kerberos_cache, event_loop=event_loop) as px:
        with UploadClient(px.port) as client:
            client.upload(method, SMALL_SIZE, chunked=chunked).check()
        px.assert_healthy()


BIG_FIRST_REQUEST = [
    pytest.param(scheme, METHODS[i % 3], id=f"{scheme.name}-{METHODS[i % 3]}")
    for i, scheme in enumerate(UPLOAD_SCHEMES)
] + [
    pytest.param(SCHEMES_BY_NAME["ntlm-unknown"], method, id=f"ntlm-unknown-{method}")
    for method in (METHODS[0], METHODS[2])
]


@pytest.mark.parametrize(("scheme", "method"), BIG_FIRST_REQUEST)
@by_loop
@needs_mcurl_streaming
def test_upload_first_request_100mb(scenario_env, kerberos_cache, memory_report, tmp_path, scheme, method, event_loop):
    """A 100 MB first request streams through the handshake with Px's memory far below the body size."""
    with scheme.px(tmp_path, scenario_env, kerberos_cache, event_loop=event_loop) as px:
        with UploadClient(px.port) as client, RssSampler(px) as rss:
            upload = client.upload(method, BIG_SIZE)
        rss.report(memory_report, f"first request {scheme.name} {method} {event_loop}", BIG_SIZE)
        upload.check()
        assert rss.growth < BIG_RSS_GROWTH_LIMIT, f"px RSS grew {rss.growth // MIB} MiB for {BIG_SIZE // MIB} MiB"
        px.assert_healthy()


@pytest.mark.parametrize(
    "scheme",
    [SCHEMES_BY_NAME[name] for name in ("ntlm-unknown", "kerberos-any", "basic-any-close")],
    ids=lambda scheme: scheme.name,
)
@by_loop
@needs_mcurl_streaming
def test_upload_chunked_first_request_100mb(scenario_env, kerberos_cache, memory_report, tmp_path, scheme, event_loop):
    """A 100 MB chunked first request (unknown length, nothing to rewind) also streams in bounded memory."""
    with scheme.px(tmp_path, scenario_env, kerberos_cache, event_loop=event_loop) as px:
        with UploadClient(px.port) as client, RssSampler(px) as rss:
            upload = client.upload("PUT", BIG_SIZE, chunked=True)
        rss.report(memory_report, f"first request chunked {scheme.name} PUT {event_loop}", BIG_SIZE)
        upload.check()
        assert rss.growth < BIG_RSS_GROWTH_LIMIT, f"px RSS grew {rss.growth // MIB} MiB for {BIG_SIZE // MIB} MiB"
        px.assert_healthy()


###
# Later requests: Px has found the method and holds authenticated connections


@pytest.fixture(
    scope="module",
    params=[(scheme, loop) for scheme in UPLOAD_SCHEMES for loop in UPLOAD_LOOPS],
    ids=lambda param: f"{param[0].name}-{param[1]}",
)
def warm_px(request, scenario_env, kerberos_cache, tmp_path_factory):
    """One Px per scheme and event loop that has already authenticated once, shared by the tests below."""
    scheme, loop = request.param
    with scheme.px(tmp_path_factory.mktemp("warm"), scenario_env, kerberos_cache, event_loop=loop) as px:
        with UploadClient(px.port) as client:
            # A failed warm-up must show up as failing tests, not as a fixture error
            client.upload("POST", 1000)
        # mcurl records the discovered auth method after the response has reached the client, so an
        # upload sent at once can still start as unknown-auth and fail to rewind; let the cache settle
        time.sleep(1)
        yield scheme, px


@by_method
@by_body
@needs_mcurl_streaming
def test_upload_later_requests(warm_px, method, chunked):
    """Uploads after the first, on the same client connection and on new ones, all arrive exactly."""
    _, px = warm_px
    with UploadClient(px.port) as client:
        client.upload(method, SMALL_SIZE, chunked=chunked).check()
        client.upload(method, SMALL_SIZE, chunked=chunked).check()
    with UploadClient(px.port) as client:
        client.upload(method, SMALL_SIZE, chunked=chunked).check()
    px.assert_healthy()


@needs_mcurl_streaming
def test_upload_later_requests_100mb(warm_px, memory_report):
    """A 100 MB upload on an authenticated Px, then a small request on the same client connection."""
    scheme, px = warm_px
    method = METHODS[(UPLOAD_SCHEMES.index(scheme) + 1) % 3]
    with UploadClient(px.port) as client, RssSampler(px) as rss:
        upload = client.upload(method, BIG_SIZE)
        follow_up = client.upload("POST", SMALL_SIZE)
    rss.report(memory_report, f"later request {scheme.name} {method} {px.event_loop}", BIG_SIZE)
    upload.check()
    follow_up.check()
    assert rss.growth < BIG_RSS_GROWTH_LIMIT, f"px RSS grew {rss.growth // MIB} MiB for {BIG_SIZE // MIB} MiB"
    px.assert_healthy()


###
# Two worker processes, fresh: each worker authenticates for itself


@by_scheme
@by_loop
@by_method
@needs_mcurl_streaming
def test_upload_two_workers_first_requests(scenario_env, kerberos_cache, tmp_path, scheme, event_loop, method):
    """Concurrent first uploads spread over two fresh worker processes all arrive exactly."""
    with scheme.px(tmp_path, scenario_env, kerberos_cache, event_loop=event_loop, workers=2) as px:
        specs = [(method, SMALL_SIZE + i, bool(i % 2)) for i in range(6)]
        for upload in _run_parallel(px.port, specs):
            upload.check()
        px.assert_healthy()


@pytest.mark.parametrize("scheme", LOAD_SCHEMES, ids=lambda scheme: scheme.name)
@by_loop
@needs_mcurl_streaming
def test_upload_two_workers_100mb(scenario_env, kerberos_cache, memory_report, tmp_path, scheme, event_loop):
    """Two 100 MB uploads (Content-Length and chunked) at once through two fresh workers."""
    with scheme.px(tmp_path, scenario_env, kerberos_cache, event_loop=event_loop, workers=2) as px:
        with RssSampler(px) as rss:
            uploads = _run_parallel(px.port, [("POST", BIG_SIZE, False), ("PATCH", BIG_SIZE, True)])
        rss.report(memory_report, f"two workers {scheme.name} {event_loop}", 2 * BIG_SIZE)
        for upload in uploads:
            upload.check()
        assert rss.growth < 2 * BIG_RSS_GROWTH_LIMIT, (
            f"px RSS grew {rss.growth // MIB} MiB for {2 * BIG_SIZE // MIB} MiB"
        )
        px.assert_healthy()


###
# Many uploads at once


@pytest.mark.parametrize("scheme", LOAD_SCHEMES, ids=lambda scheme: scheme.name)
@pytest.mark.parametrize("workers", [1, 2])
@by_loop
@needs_mcurl_streaming
def test_parallel_uploads(scenario_env, kerberos_cache, memory_report, tmp_path, scheme, workers, event_loop):
    """60 simultaneous mixed POST/PUT/PATCH uploads, half chunked, each arrives exactly with bounded memory."""
    with scheme.px(tmp_path, scenario_env, kerberos_cache, event_loop=event_loop, workers=workers) as px:
        specs = [(METHODS[i % 3], PARALLEL_SIZE + i, bool(i // 3 % 2)) for i in range(PARALLEL_UPLOADS)]
        total = sum(size for _, size, _ in specs)
        with RssSampler(px) as rss:
            uploads = _run_parallel(px.port, specs, gate_timeout=120)
        rss.report(memory_report, f"{PARALLEL_UPLOADS} parallel {scheme.name} workers={workers} {event_loop}", total)
        failures = []
        for upload in uploads:
            try:
                upload.check()
            except AssertionError as error:
                failures.append(str(error)[:300])
        assert not failures, f"{len(failures)}/{PARALLEL_UPLOADS} uploads failed: {failures[:3]}"
        assert rss.growth < PARALLEL_RSS_GROWTH_LIMIT, f"px RSS grew {rss.growth // MIB} MiB for {total // MIB} MiB"
        px.assert_healthy()


###
# px --test=all:URL with an echo origin


TEST_ALL_SCHEMES = [
    SCHEMES_BY_NAME[name] for name in ("ntlm-unknown", "kerberos-any", "ntlm-unknown-close", "kerberos-any-close")
]


@pytest.mark.parametrize("scheme", TEST_ALL_SCHEMES, ids=lambda scheme: scheme.name)
@by_loop
@needs_mcurl_streaming
def test_px_test_all_methods_echo(scenario_env, kerberos_cache, tmp_path, scheme, event_loop):
    """`px --test=all:URL` sends GET, POST, PUT, DELETE and PATCH through the proxy and each must pass."""
    if scheme.proxy_key not in scenario_env:
        pytest.skip("the running lab predates SCENARIO_SSO_CLOSE_PROXY")
    proxy = scenario_env[scheme.proxy_key]
    if scheme.kerberos:
        proxy = proxy.replace("127.0.0.1", "localhost")
    config = tmp_path / "empty.ini"
    config.touch()
    command = [
        sys.executable,
        "-m",
        "px",
        f"--config={config}",
        f"--auth={scheme.auth}",
        f"--username={scenario_env['SCENARIO_DOMAIN']}\\{scenario_env['SCENARIO_USER']}",
        "--noproxy=",
        f"--proxy={_proxy_addr(proxy)}",
        f"--port={_free_port()}",
        f"--event-loop={event_loop}",
        f"--test=all:{ECHO_URL}",
    ]
    proc_env = os.environ | {"PYTHONUNBUFFERED": "1"}
    if scheme.kerberos:
        proc_env["KRB5CCNAME"] = str(kerberos_cache)
        proc_env.pop("PX_PASSWORD", None)
    else:
        proc_env["PX_PASSWORD"] = scenario_env["SCENARIO_PASSWORD"]
    result = subprocess.run(command, cwd=ROOT, env=proc_env, capture_output=True, text=True, timeout=60)  # noqa: S603
    output = result.stdout + result.stderr
    assert result.returncode == 0, output
    # The five queries run concurrently and their output interleaves, so count rather than match lines
    assert output.count("Passed") == 5, output
    for method in ("GET", "POST", "PUT", "DELETE", "PATCH"):
        assert f"Testing {method} {ECHO_URL}/{method.lower()}" in output, output
    assert "Failed" not in output, output


###
# Clients that send Expect: 100-continue (curl does for large uploads)


@pytest.mark.parametrize(
    "scheme",
    [SCHEMES_BY_NAME[name] for name in ("ntlm-unknown", "kerberos-any", "basic-any-close")],
    ids=lambda scheme: scheme.name,
)
@by_loop
@needs_mcurl_streaming
def test_upload_client_expect_continue(scenario_env, kerberos_cache, tmp_path, scheme, event_loop):
    """A client that waits for 100 Continue gets it and its upload still arrives exactly."""
    with scheme.px(tmp_path, scenario_env, kerberos_cache, event_loop=event_loop) as px:
        with UploadClient(px.port) as client:
            upload = client.upload("POST", SMALL_SIZE, expect=True)
            # Px answers 100 Continue itself and may also relay the proxy's own
            assert upload.interim
            assert set(upload.interim) == {100}, upload
            upload.check()
        px.assert_healthy()
