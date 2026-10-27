# Testing

---

## Test suite layout

Tests live in `tests/`.

| File | Scope |
|------|-------|
| `conftest.py` | Pytest configuration — path setup, plaintext keyring backend, event-loop selection, xdist auto-parallelism hook, loopback `getfqdn()` shortcut, macOS CI startup probe |
| `fixtures.py` | Shared test fixtures — port allocation, Px server instances (launched with `--verbose`), auth parametrisation |
| `helpers.py` | Utility functions — subprocess management (`run_px` launches Px with `--verbose`), port checks, keyring setup |
| `test_benchmark.py` | Concurrency benchmarks — HTTP/CONNECT throughput, thread count, memory at various concurrency levels (marked `benchmark`, run via `make benchmark`) |
| `test_event_loop.py` | Event loop integration — verifies the selected asyncio or uvloop/winloop loop and basic server operation |
| `test_config.py` | Configuration utility tests — `get_logfile`, `get_config_dir`, `get_host_ips`, defaults, save, install |
| `test_large_data.py` | Large data transfer reliability — concurrent multi-MB GET/POST over HTTP and HTTPS with SHA-256 integrity verification (marked `largedata`, run via `make test-large-data`) |
| `test_debug.py` | Debug module tests — `Debug` singleton, `pprint`, `dprint` |
| `test_kerberos.py` | Kerberos ticket management — unit tests (mocked subprocess, Linux/macOS only) and Docker-based integration tests against local MIT and Heimdal KDCs (marked `integration`, run via `make test-kerberos`) |
| `test_auth_retry.py` | `--authretry` integration tests — Px against a fake upstream proxy that denies or allows authenticated requests, proving latching after 3 consecutive 407s, exactly one probe per interval under a 50-client concurrent burst, and recovery |
| `test_ntlm_burst.py` | NTLM upstream regression tests — concurrent plain-HTTP handshakes and CONNECT tunnels through a fake proxy; the CONNECT burst drops its first Type 1 legs and verifies later tunnels are not latched as authentication failures on either event loop. The CONNECT cases are `xfail(strict=True)` when the installed mcurl lacks `Curl.get_os_errno` (the px#268 fix, shipped in pymcurl 8.23.0.3): the locked 8.23.0.2 still has the bug, so they must fail there, and an unexpected pass fails the run. Once the lock is bumped the condition is false and they run normally |
| `test_network.py` | Network integration tests — `--quit`, `--listen`, `--hostonly`, `--gateway`, `--allow`, `--noproxy` |
| `test_pac.py` | PAC file tests — loading, evaluation, encoding, JS callables (`dnsResolve` returning `null` on failure, `isResolvable`, `isInNet`, `myIpAddress`) |
| `test_multiprocessing.py` | Multi-worker tests — `--workers=2` with and without auth on all platforms |
| `test_proxy.py` | Proxy functionality tests — HTTP methods, auth, upstream auth, chaining |
| `test_startup.py` | Startup bounds — the startup probe and its macOS CI guard, and px listening and quitting within a bounded time |
| `test_build_python.py` | Build tooling — newest-patch Windows embed zip selection, bundled-version logging, macOS Mach-O portability check, macOS CI interpreter choice, workflow input checks, `build.yml`/`publish.yml` release publishing split |
| `test_ci_matrix.py` | `tools/ci_matrix.py` — fast vs full mode, marker expression and matrix contents |
| `test_auto_release.py` | `tools/auto_release.py` — version bump and dependency-change helpers for the automatic release |
| `test_resolver.py` | Resolver tests — positive/negative caching, in-flight de-duplication, lookup timeout with late cache fill, bounded pool, IP literals, DNS-free `myIpAddress` discovery |
| `test_wproxy.py` | Proxy parsing tests — `parse_proxy`, `parse_noproxy`, `_WproxyBase` methods, resolver-backed `--noproxy` IP matching |

---

## Running tests

### Corporate proxy scenario environment

`tests/scenarios/env/` is a reproducible enterprise-proxy lab for scenario
tests and manual regression work. It exists because protocol-shaped fake
proxies do not reproduce connection-oriented NTLM, Kerberos tickets, Squid
helper behaviour, CONNECT authentication, or failures between handshake
rounds. The lab runs entirely in Docker and does not change the host's DNS,
Kerberos, or Samba configuration.

Start it and run its independent smoke check with:

```bash
tools/scenario-env.sh up
tools/scenario-env.sh smoke
tools/scenario-env.sh down
```

`up` builds pinned Debian 12.12 and Python 3.13.9/Alpine 3.22 images, waits for
service health checks, exports the generated origin CA as
`tests/scenarios/env/origin-ca.crt`, and writes the same `KEY=VALUE` inventory
it prints to `tests/scenarios/env/scenario.env`. A cold build normally takes
two to five minutes; subsequent starts reuse Docker's build cache. `down`
removes the project containers, network, named volume, CA, and generated env
file. Use `status`, `logs [service]`, or `env` to inspect the lab without
changing it.

The fixed test identity is `CORP\pxgood` / `GoodPass1!` in realm `CORP.TEST`.
`CORP\pxother` / `OtherPass2!` supports identity-isolation tests, and
`WrongPass9!` is the deliberately invalid password. These credentials are
public test data and must never be reused outside this local environment.

| Host endpoint | Purpose |
|---|---|
| `127.0.0.1:31280` | Squid Basic authentication |
| `127.0.0.1:31281` | Squid Digest authentication |
| `127.0.0.1:31282` | Domain-joined Squid offering Negotiate and NTLM fallback |
| `127.0.0.1:31283` | Basic Squid with client/server persistence disabled |
| `127.0.0.1:31284` | Unauthenticated parent Squid |
| `127.0.0.1:31285` | Authenticating child Squid chained to the parent |
| `127.0.0.1:31286` | Toxiproxy hop in front of the SSO Squid |
| `127.0.0.1:8474` | Toxiproxy control API for latency/reset toxics |
| `127.0.0.1:18080`, `18443` | HTTP and self-signed HTTPS origins |
| `127.0.0.1:18081/proxy.pac` | PAC file selecting the SSO proxy for `.corp.test` |
| `127.0.0.1:18888` | Long-lived raw TCP echo endpoint |

The origin also provides `/small`, `/large`, `/stream`, and `/slow`. Every
Squid limits one client address to 16 concurrent connections. The smoke check
runs from the client container so Docker DNS resolves the deterministic
`.corp.test` names; it verifies success and 407 rejection for Basic, Digest,
NTLM, and Kerberos over both HTTP and HTTPS CONNECT, then checks the chain,
connection-close proxy, and PAC response.

Limitations: the lab models one AD site and one Squid version from Debian,
not AD replication, transparent interception, TLS inspection, or proxy
auto-discovery. The self-signed certificate is an origin certificate rather
than a TLS-inspection CA. The Samba DC container alone runs privileged because
its AD database requires filesystem ACL/xattr operations; its AD ports remain
private to the Compose network. Toxiproxy is configured without a toxic by default;
scenario tests add and remove latency, timeout, reset, or bandwidth toxics
through its API so one test cannot contaminate another.

### Quick run

```bash
make test
```

This runs `pytest` with coverage via `uv run`.

### Manual run

```bash
# Install dev dependencies
uv sync --upgrade-package quickjs-ng
uv pip install -e .

# Run all tests
uv run python -m pytest tests -q

# Run a specific file
uv run python -m pytest tests/test_proxy.py -q

# Run with coverage
uv run python -m pytest tests --cov --cov-config=pyproject.toml --cov-report=xml

# Run with parallel execution (auto-scales to hardware)
uv run python -m pytest tests -n auto

# Run the suite with Python's standard asyncio event loop
PX_EVENT_LOOP=asyncio uv run python -m pytest tests -n auto
```

`uv sync --upgrade-package quickjs-ng` refreshes `quickjs-ng` from PyPI while
keeping every other locked package. CI does not do this: it installs the locked
versions (`uv sync --locked`) and prints the resolved `quickjs-ng` version. Only
release builds refresh it (`refresh-quickjs` in
`.github/actions/setup-python-env`), and the musl test container upgrades it
explicitly.

### Selections

Local runs and CI use the same marker expressions. A plain run uses the
`addopts` filter in `pyproject.toml`, which deselects `integration`,
`benchmark` and `largedata`; a `-m` expression replaces that filter. Counts
come from `--collect-only` on the current tree and change as tests are added.

| Selection | Command (`uv run --locked python -m pytest ...`) | Tests |
|---|---|---|
| Default (`make test`, without coverage) | `tests -n auto` | 496 |
| Fast (push and PR CI) | `tests -n auto -m "not integration and not benchmark and not largedata and not slow"` | 346 |
| Slow only | `tests -n auto -m slow` | 150 |
| Kerberos (`make test-kerberos`) | `tests/test_kerberos.py -m integration` | 14 |
| Large data (`make test-large-data`) | `tests/test_large_data.py -m largedata` | 22 |
| Benchmarks (`make benchmark`) | `tests/test_benchmark.py -m benchmark` | 6 |
| Everything (full CI set) | all rows above | 538 |
| macOS CI | `tests -n auto --ignore=tests/test_network.py`, with `PX_CI_MINIMAL=1` | 486 |

The markers registered in `pyproject.toml` are:

| Marker | Used by | Run by default |
|---|---|---|
| `integration` | `test_kerberos.py` (Docker KDCs) | no |
| `benchmark` | `test_benchmark.py` | no |
| `largedata` | `test_large_data.py` | no |
| `slow` | `test_auth_retry.py` (all tests), `test_proxy.py` chain tests | yes |

There is no `smoke` marker. The artifact smoke check is `smoke_binary` in
`build.sh`, which runs outside pytest.

Prefix any row with `PX_EVENT_LOOP=asyncio` to run it on the standard asyncio
loop; the asyncio CI jobs do exactly that.

### Windows testing via WSL2

When running Windows tests from WSL2 using a Windows Python venv, the venv
`Scripts` directory must be on `PATH` so that test helpers can find `px` when
they call it via `os.system()` or `subprocess`. On systems where `px.exe`
cannot run directly (e.g. policy restrictions), replace `px.exe` and `pxw.exe`
in the venv `Scripts` directory with `.bat` wrappers that invoke
`python -m px` instead.

Setup (one-time):

1. Create a Windows venv and install dev dependencies:
   ```cmd
   python -m venv .venv-win
   .venv-win\Scripts\pip install -e . -f mcurllib
   .venv-win\Scripts\pip install pytest pytest-xdist pytest-httpbin pytest-cov psutil
   ```

2. If `px.exe` cannot run, replace it with bat wrappers in `.venv-win/Scripts/`:
   - `px.bat`: `@"%~dp0python.exe" -m px %*`
   - `pxw.bat`: `@"%~dp0pythonw.exe" -m px %*`

3. Prepend the `Scripts` directory to `PATH` before running pytest:
   ```bash
   VENV=/mnt/c/path/to/.venv-win
   export PATH="$VENV/Scripts:$PATH"
   ```

Running tests (use the same commands as the Makefile targets):

```bash
PY="$VENV/Scripts/python.exe"

# Default test suite (matches: make test)
$PY -m pytest tests -n auto --cov --cov-config=pyproject.toml --cov-report=xml

# Benchmarks (matches: make benchmark)
$PY -m pytest tests/test_benchmark.py -m benchmark -v -s

# Large data tests (matches: make test-large-data)
$PY -m pytest tests/test_large_data.py -m largedata -v -s
```

### With a specific Python version

```bash
uv run -p 3.14 python -m pytest tests -q
```

### Artifact tests via tox

The `[tool.tox]` configuration in `pyproject.toml` defines py310–py314 and a
`binary` environment. Each Python environment installs the release wheel and
runs the default selection; the `binary` environment runs the same suite
against the compiled binary named by `PXBIN`. Linux runs `pytest -n auto`, and
the native macOS and Windows runs use `-n 2`. tox and tox-uv are not dev
dependencies: the `test-binary` job in `build.yml` installs them, and
`make test-glibc` or `make test-musl` (`build_local` in `build.sh`) run the same
matrix locally in the build containers. See [Build](build.md#github-actions).

### Developer machine notes

Some failures on a developer machine come from the environment rather than from
px. Check these before debugging a test:

- **Run from outside your home directory.** px loads `.env` files from the
  current directory and every parent directory. A `.env` in `$HOME` that sets
  `PX_NOPROXY` or `PX_THREADS` changes proxy routing and threading under the
  tests, and it breaks the auth-chain tests in particular. Run the suite from a
  git worktree under `/tmp` or `$ORC_SCRATCH_DIR`, or make sure no `PX_` variables
  are set in any parent `.env` and in the shell environment.
- **Pin Python 3.14 when it matters.** CI and ORC verification run on 3.14
  (`UV_PYTHON=3.14`). `uv` may otherwise pick a newer interpreter such as 3.15,
  which px does not support yet.
- **Stop leftover px processes between runs.** A failed test can leave px
  servers listening on the test ports, and the next run then fails with port
  conflicts or stale behaviour. Check for running px processes and stop them
  before starting another run.

---

## Parallel test execution

Tests use `pytest-xdist` with `-n auto` in the Makefile, in tox on Linux and in
CI; the native macOS and Windows artifact runs use `-n 2`.
The `pytest_xdist_auto_num_workers` hook in `conftest.py` computes the worker
count based on CPU count and platform:

- **All platforms**: `max(2, cpu_count // 4)` — each test can spawn up to 4
  processes, so dividing by 4 avoids oversubscription.
- **Windows CI**: forced to 1 (`CI` env var set) — Schannel TLS handshakes fail
  under concurrent HTTPS CONNECT tests when multiple Px instances compete for
  connections on resource-constrained CI runners.

Each xdist worker starts its search for proxy test ports (`fixtures.py`) at a
worker-specific offset and atomically reserves the first free block of 3
consecutive ports, so concurrent test runs on the same host skip ports already
in use. Network
tests (`test_network.py`) reserve 10 ports for their own worker offset, falling
back to the next free port when the computed one is busy.

To override the auto-computed value, either pass an explicit `-n N` or set the
`PYTEST_XDIST_AUTO_NUM_WORKERS` environment variable.

---

## CI testing

`.github/workflows/ci.yml` runs in two modes. Pushes and pull requests run a fast
set so feedback is quick; the full set runs weekly, on manual dispatch, as the
pre-release gate and on the automatic-release candidate, so every configuration
is still covered before a release. A `plan` job runs `tools/ci_matrix.py`, which
holds the single list of test configurations (each flagged fast or not) and
emits the matrices; `tests/test_ci_matrix.py` checks the selection logic.

| Trigger | Mode |
|---|---|
| push to `devel`/`working`, pull request | fast |
| `workflow_dispatch` (`full` input, default true) | full unless `full` is unticked |
| weekly `schedule` (Sundays 05:37 UTC, runs on `devel`) | full |
| `workflow_call` (`full` input, default true) | full unless `full: false` |

Callers: a manual `build.yml` dispatch on `devel` calls `ci.yml` through
`workflow_call` with `full: true`, and `auto-release.yml` dispatches it on the
release candidate branch with `-f full=true`. To run the full set by hand, use
`gh workflow run ci.yml --ref devel`; add `-f full=false` for a fast run.

**Fast mode** runs `quality` (pre-commit and mypy), `kerberos` and these test
jobs, with the `slow` marker deselected (`-m "not integration and not benchmark
and not largedata and not slow"`, see [Slow tests](#slow-tests)):

- Ubuntu x86_64 Python 3.10 and 3.14: the oldest and newest supported Python.
- Ubuntu Python 3.14 with `PX_EVENT_LOOP=asyncio`: the fast set's coverage of
  the standard-library event loop; the other Linux jobs use uvloop.
- Windows Python 3.14: the fast set's coverage of SSPI, Windows paths and
  winloop. It is the slowest fast job and sets the wall time.
- Windows Python 3.14 with `PX_EVENT_LOOP=asyncio`: asyncio's Proactor loop is a
  different code path from winloop, and the CPython Proactor accept-loop bug
  that motivated winloop only appears there. It runs alongside the other
  Windows job.
- `tests-musl` x86_64 Python 3.14: musl has its own wheels (the musllinux image,
  uvloop and psutil builds), so one job covers it.
- `kerberos` (about a minute) is the only job that runs against real MIT and
  Heimdal KDCs. It runs in both modes.

Only the full set runs Ubuntu Python 3.11–3.13, ARM64 and musl aarch64 (same
Python code, different wheel build), musl Python 3.10, Windows Python 3.10, both
macOS jobs, large-data, benchmarks and the `slow` tests.

Why the split:

- **Small project, bounded CI.** Every push would pay for the whole matrix, but
  the extra versions add little signal per push. The fast set keeps the two ends
  of the supported range and the platforms with distinct code paths.
- **macOS.** GitHub's macOS runners are expensive, slow and few, so macOS jobs
  queue behind each other. Both macOS jobs are full-only. `px/config.py` has
  darwin-only paths, so macOS regressions are caught by the weekly or release
  run. The earlier 19-minute macOS jobs were traced to an interpreter DNS stall,
  fixed by uv-managed CPython (see
  [macOS-specific reasoning](#macos-specific-reasoning)). Those jobs have not
  been re-measured, so macOS stays out of the fast set. If a minimal macOS job
  takes a few minutes, add `"fast": True` to its entry in `tools/ci_matrix.py`
  and update this list.
- **Python versions.** px's Python code is the same on 3.10–3.14, so differences
  come from the interpreter and native wheels. Stable-ABI (abi3) wheels, such as
  psutil's `cp36-abi3` wheels, need testing only at the oldest and newest
  supported Python, plus free-threaded and PyPy builds where a project ships
  them. px ships neither, so there is no free-threaded or PyPy job. The `binary`
  tox environment deliberately avoids free-threaded 3.14 (see
  [Build](build.md#github-actions)).
- **Architectures.** ARM64 and musl aarch64 run the same Python code with a
  different wheel build, so they are full-only.

**Full mode** runs everything: 13 test jobs (Ubuntu x86_64 on Python
3.10–3.14 plus asyncio on 3.14, Ubuntu ARM64 (`ubuntu-24.04-arm`) on 3.10 and
3.14, macOS on 3.10 and 3.14 with `PX_CI_MINIMAL=1`, Windows on 3.10 and 3.14
plus asyncio on 3.14), 4 `tests-musl` jobs (x86_64 and aarch64, Python 3.10 and
3.14), `large-data-linux`, `large-data-windows`, 3 `benchmark` jobs (Ubuntu,
macOS, Windows), `kerberos` and `quality`, with no `-m` override so the `slow`
tests run too. The asyncio jobs set `PX_EVENT_LOOP=asyncio`; all other jobs
cover automatic winloop/uvloop selection.

Every pytest invocation in CI passes `--durations=30`, so each job log lists
the 30 slowest tests; use it to spot tests that grow slow.

### Coverage before a release

The CI set does not cover every Python, OS and architecture combination, but
every supported one is covered before each release. The full set runs on the
devel dry run and on the automatic-release candidate. Then `test-binary` in
`build.yml` runs tox on py310–py314 against the built release artifacts for six
platforms: glibc and musl on x86_64 and aarch64, macOS arm64 and Windows amd64.
`test-binary` runs on the devel dry run and on the master push that publishes,
and the `release` job needs it to pass. The mechanics are in
[Build](build.md#github-actions).

---

## Local container testing

The `build_local` function in `build.sh` provides end-to-end local build and
test using Docker containers. It builds the sdist on the host, then runs the
wheels, binary, and test steps inside appropriate container images.

```bash
# Build and test in musl (Alpine) containers
make test-musl

# Build and test in glibc (manylinux) containers
make test-glibc
```

This matches the CI pipeline closely and is useful for verifying Linux builds
locally before pushing.

---

## Reduced test matrix for macOS CI

macOS GitHub Actions runners are scarce and the chain and upstream proxy tests
spawn multiple Px processes with real network authentication flows, so macOS
uses a reduced test matrix controlled by the `PX_CI_MINIMAL` environment
variable. The reduction is not what made macOS jobs take about 19 minutes;
that was an interpreter-specific name-lookup stall, described under
"macOS-specific reasoning" below.

When `PX_CI_MINIMAL=1` is set:

1. **Auth/env pairing**: Instead of testing all combinations of auth types (NTLM,
   DIGEST, BASIC) with all CLI/env modes, we use strategic pairing:
   - NTLM + cli
   - DIGEST + env
   - BASIC + cli

   This maintains coverage of all auth types and both configuration modes while
   reducing combinations from 6 to 3.

2. **Skip chain tests**: `test_proxy_auth_upstream` and `test_proxy_auth_chain`
   are skipped entirely as they spawn multiple Px processes and are too slow for
   GitHub Actions macOS runners.

3. **Network tests excluded**: `test_network.py` is excluded on macOS CI as these
   tests fail in the GitHub Actions environment but pass on real macOS hardware.

**Result**: the macOS selection collects 486 tests, which is the default 496
minus the 10 network tests. The skips above reduce what actually runs, while
keeping every auth type (NTLM, DIGEST, BASIC) and both config modes (cli, env).

`tests/fixtures.py` builds `PARAMS_AUTH_PAIRED` from `PX_CI_MINIMAL`, and the
`px_auth` fixture skips the combinations outside it at setup. Those tests are
still collected but skipped. Chain tests are skipped with `@pytest.mark.skipif`
in `tests/test_proxy.py`.

---

## Slow tests

A `slow` pytest marker identifies tests that are inherently slow — they are
*not* excluded by the default `addopts` filter (`-m 'not integration and not
benchmark and not largedata'`), so `pytest tests` and `make test` still run
them every time, the same as any other test. Use the marker to skip them for
a fast inner-loop run:

```bash
pytest tests -m "not integration and not benchmark and not largedata and not slow"
```

Test counts are from `--collect-only` on the current tree. The wall times are
from an earlier run on Linux/Python 3.14 with `pytest -n auto` on a smaller
test count, and they vary with host load, so read them only for the relative
drop:

| Selection | Tests | Wall time (earlier run) |
|---|---|---|
| Default (`pytest tests`) | 496 | ~21-27s |
| macOS CI (`PX_CI_MINIMAL=1 --ignore=tests/test_network.py`) | 486 | ~13s |
| Fast (`-m "... and not slow"`) | 346 | ~6s |

In that run the fast selection took roughly a quarter of the full suite's time. Two
specific fixes (below) also measured cleanly in isolation, independent of
host load: `test_network.py::test_allow_specific_subnet` dropped from 17.4-
17.7s to 0.5s, and `test_network.py::test_quit_stops_px` dropped from 2.0-
2.5s to about 1.0s (both measured with `pytest --durations=0`, no `-n`, run
alone before and after).

Two groups carry the marker, because they are slow by what they verify, not
by an avoidable wait:

- `test_auth_retry.py` (all tests) — `--authretry` latches a blocked upstream
  for a real interval and these tests assert on that interval actually
  elapsing (`time.sleep`), plus a 50-client concurrent burst. There is no way
  to assert "this retry interval was honoured" without waiting it out.
- `test_proxy.py::test_proxy_auth_upstream` and `test_proxy_auth_chain` — each
  spawns 2-3 real Px processes and covers the full auth × cli/env × http/https
  × test-auth matrix (72 combinations each). This is the same matrix
  `PX_CI_MINIMAL` already skips entirely on macOS CI (see below); the `slow`
  marker makes that selection available on any platform without the env var.
  Basic proxy auth (one hop, no chaining) stays fast via `test_proxy_auth`.

Everything else in the suite — including `test_network.py`'s process-spawning
tests — runs in roughly a second or two per test once the avoidable waits
below are fixed, so it stays in the fast selection.

### Avoidable waits fixed

Profiling the suite with `pytest --durations=0` found tests that were slow
only because of waits the test itself didn't need:

- `test_pac.py`'s `dnsResolve` tests (`test_dns_resolve`,
  `test_dns_resolve_bad_host`, `test_unresolvable_host_is_not_resolvable_or_in_net`)
  performed real DNS lookups (including a deliberately-unresolvable
  `*.invalid` name). `px.resolver.Resolver.lookup()` bounds a failed lookup to
  `LOOKUP_TIMEOUT` (3s), so a slow or absent resolver — plausible on macOS
  GitHub Actions runners, which route DNS through `mDNSResponder` and can be
  slow to fail unqualified or unusual names — made each of these tests pay
  up to 3 extra seconds for no benefit: the test only checks that `Pac`
  plumbs failures through as `null`, which `tests/test_resolver.py` already
  proves against a mocked resolver. They now monkeypatch
  `resolver.socket.getaddrinfo` the same way, so they're instant and
  deterministic on every platform instead of depending on real DNS behaviour
  (including which family "localhost" resolves to first, which also differs
  on macOS).
- `test_network.py::TestAllow::test_allow_specific_subnet` starts Px with
  `--gateway --allow=10.0.*.*` and tore it down with the normal `--quit`
  flow. `--quit`'s target interface comes from `get_listen()` in
  `px/config.py`, which picks the first local IP that matches `--allow` — but
  no real test host has an IP in `10.0.0.0/8`, so that match never succeeds
  and `--quit` was *guaranteed* to fail every run. The test tolerates that
  (`quit_px(..., strict=False)`), but tolerating it still meant paying for 3
  doomed `--quit` attempts (with 2s backoff) and then a 10s wait before
  falling back to killing the process — about 17s of pure waiting for an
  outcome that was never in doubt. The test only needs the process gone, so
  teardown now terminates it directly instead of routing through a `--quit`
  that can't work for this `--allow` value.
- `test_network.py::TestQuit::test_quit_stops_px` also had a fixed `time.sleep(1)`
  "to let Px finish starting" before issuing `--quit`, even though the
  existing 3-attempt retry loop (with a 2s backoff) already tolerates an
  early `--quit` failing. It also waited a fixed `time.sleep(0.5)` for the
  port to free up after the process exited. Both are now a bounded poll
  (removed, and a `is_port_free()` poll up to 5s) instead of a fixed delay.

### macOS-specific reasoning

Run 40139662524 (build.yml dispatch on devel at a72ce5d) gave real
`--durations` data for the macOS jobs, all on `macos-26-arm64`:

| Job | Before |
|---|---|
| ci-full `test macos-latest py3.10` / `py3.14` | 19m34s each (1175.79s of pytest) |
| `test-binary mac-arm64` py311, py312, py313, py314 | 19m31s each (1171.25s, 1170.93s, 1170.61s, 1171.24s of pytest) |
| `test-binary mac-arm64` py310 | 15.04s of pytest (20.71s tox) |

The same selection takes about 13s on Linux and took 15s for py310. In the
slow runs the unit tests finished in seconds, then every test that starts px
(or imports it and calls `parse_config()`) took 35.3-35.5s, and tests that
start and quit px took 72s (two stalls): `test_proxy`, `test_proxy_auth`,
`test_multiprocessing_workers*`, the `test_config.py::TestEventLoopSelection`
cases and all six `test_auth_retry.py` tests. A first-use `setup` of 35.0s on
the stdlib test servers (`http.server`'s fake upstream and pytest-httpbin)
pointed at a name lookup: those servers call `socket.getfqdn()` on the address
they bind.

The cause is the macOS 15+ runner image (`macos-latest` is `macos-26`), not
px or the test selection: since macOS 15 a process without the Local Network
permission pauses for about 35s on reverse lookups such as
`socket.getfqdn("127.0.0.1")` (actions/runner-images#10924,
actions/setup-python#1223). Pythons from setup-python and the image's
Homebrew/toolcache installs are affected; uv-managed (python-build-standalone)
CPython is not. That is also why only py310 was fast in `test-binary`: no
system Python 3.10 exists on the image, so tox-uv downloaded a uv-managed one,
while py311-py314 used the system interpreters. In ci-full, py3.10 comes from
setup-python and was slow like py3.14.

Fixes:

- macOS test jobs use uv-managed CPython (`managed-python` input of
  `.github/actions/setup-python-env`, which also sets
  `UV_PYTHON_PREFERENCE=only-managed` for tox-uv; `build.sh` `test_binary`
  exports the same on macOS). `tests/test_build_python.py` checks that the
  workflows keep passing the input.
- `tests/conftest.py` makes `socket.getfqdn()` return loopback names
  unchanged, so the fake upstream and pytest-httpbin no longer reverse-resolve
  the address they bind on any interpreter. This removes only a lookup the
  tests never needed.
- A session-start probe (`helpers.probe_startup`) runs only on macOS CI. It
  times `socket.gethostbyaddr('127.0.0.1')`, `urllib.request.getproxies()` and
  px's `parse_config()` in fresh interpreters, prints the timings in the
  pytest header (`px startup probe: ...`) and exits with a message if any
  takes over 10s. A regression of the interpreter choice now fails in under a
  minute instead of after 19 minutes of 35s waits, and the header shows which
  step stalls. The exact lookup inside a px start that waits was not
  identified without a macOS host; the probe's `parse_config` step and
  `tests/test_startup.py::test_px_start_and_quit_are_bounded` (px listens and
  quits within 15s) are the diagnostics for it.

Expected after: macOS wheel environments in the minutes-or-less range like
py310's 15s and Linux's ~1 minute, instead of 19m31s each.

---

## Keyring backend for testing

Tests use the plaintext keyring backend to avoid system keyring prompts and ensure
consistent behavior across platforms. This is set globally in `conftest.py` which:

- Sets `PX_KEYRING_PLAINTEXT=1` environment variable for all test runs
- Configures `keyring.set_keyring(keyrings.alt.file.PlaintextKeyring())`

The plaintext backend stores passwords unencrypted in a file, which is acceptable
for testing but not for production use. This configuration is inherited by all
tests including those run via `tox`.

---

## Test dependencies

Test dependencies (`pytest`, `pytest-xdist`, `pytest-httpbin`, `pytest-cov`,
`psutil`) are declared in the `dev` dependency group in `pyproject.toml`
alongside linting and type checking tools (`pre-commit`, `ruff`, `mypy`).
`uv sync` installs them all.

---

## Testing a new pymcurl

px's HTTPS proxy-auth tests exercise pymcurl (and the libcurl it wraps) in ways
that pymcurl's own test suite does not. A pymcurl release that passes mcurl's
tests can still break px: pymcurl 8.23.0.1 passed mcurl's tests but broke
px's HTTPS proxy-auth tests, which only px's suite covers. Validate every new
pymcurl this way before raising px's pymcurl minimum or adopting it, including
release candidates built from mcurl.

1. **Build a baseline with the previous pymcurl.** In a clean environment (see
   [Developer machine notes](#developer-machine-notes)), install the pymcurl
   version px currently uses and run the full suite at least twice for each
   setting: with `PX_EVENT_LOOP` unset and with `PX_EVENT_LOOP=asyncio`. Stop
   leftover px processes before each run.
2. **Run the same matrix with the new pymcurl.** Install the candidate into the
   same px environment, replacing the old version, and run the full suite at
   least twice on each event loop setting, stopping leftover px processes before
   each run.
3. **Compare per test case.** Record which tests fail in each run. Judge
   failures against the baseline that used the old pymcurl, never against a run
   where the new pymcurl was already installed. The HTTPS proxy-auth tests fail
   intermittently with `SSL connect` errors or Px exiting with 1024, and the
   failing set changes between runs. A single failure is not a regression, but
   a test that fails consistently on the new pymcurl and passes on the old one
   is.

Do not rely on `uv sync` to switch versions for the comparison: it restores the
locked pymcurl. Install the candidate with `uv pip install` after the sync, and
check the installed version (`uv pip show pymcurl`) before each run.

---

## Coverage

Coverage is configured in `pyproject.toml` under `[tool.coverage.*]`. Branch
coverage is enabled and scoped to the `px` package. Empty files are skipped
in reports.

---

## Kerberos integration tests

The unit tests in `test_kerberos.py` mock all subprocess calls to verify the
`KerberosManager` logic in isolation. The same file also contains Docker-based
integration tests that exercise the real Kerberos stack against local KDCs —
both MIT krb5 and Heimdal.

### How it works

Two test classes run against separate KDCs:

**MIT KDC tests** (`TestKerberosIntegration`) — a `kdc` pytest fixture
(module-scoped) starts a throwaway container from the pre-built `px-test-mit-kdc`
image running an MIT KDC with a `TEST.LOCAL` realm and a test principal. Each
test runs `docker run` against the px image with `--network host`, mounts a
generated `krb5.conf`, starts gnome-keyring inside the container, stores a
password via keyring, and then exercises the `KerberosManager` Python code.
Nine tests cover ticket acquisition, renewal, expiry parsing (4-digit year,
2-digit year), klist validity, ccache cleanup, wrong password, bad principal,
and force-retry after failure.

**Heimdal KDC tests** (`TestHeimdalKerberosIntegration`) — a `heimdal_kdc`
fixture starts a container from the pre-built `px-test-heimdal-kdc` image
running a Heimdal KDC, and tests run in the pre-built `px-test-heimdal-client`
image which has px installed from source alongside Heimdal client tools. Five
tests verify ticket acquisition, Heimdal-format expiry parsing (`Mon DD
HH:MM:SS YYYY`), `klist --test` validity check, wrong password handling, and
automatic Heimdal detection via `klist --version`.

All containers use `--network host` so the KDC is accessible at `localhost`
from both the test runner and other containers.

### Docker images

Pre-built Docker images avoid installing packages at container runtime:

- `px-test-mit-kdc` — built from `docker/Dockerfile.mit-kdc` (Alpine +
  krb5-server).
- `px-test-heimdal-kdc` — built from `docker/Dockerfile.heimdal-kdc` (Debian +
  heimdal-kdc).
- `px-test-heimdal-client` — built from `docker/Dockerfile.heimdal-client`
  (python:alpine + Heimdal client + px from source).

KDC setup scripts configure the realm and start the daemon at container
startup.

### Running

Integration tests are marked with `@pytest.mark.integration` and excluded from
the default test run via `addopts` in `pyproject.toml`. To run them locally:

```bash
# Build all Docker images then run the integration tests
make test-kerberos

# Or run them directly (assumes images are already built)
uv run python -m pytest tests/test_kerberos.py -m integration -v
```

### CI

The `kerberos` job in `ci.yml` runs in both modes, on push, on pull request and
in the full set. On `ubuntu-latest` it builds the images with
`make docker-kerberos` and runs the `integration` selection, the same tests as
`make test-kerberos`.

### Requirements

- Docker daemon running (containers use `--network host`).
- Pre-built Docker images (`make docker-kerberos`). If images are missing, the
  tests are skipped with a clear message.
- The `--cap-add IPC_LOCK` capability is passed to the px container so that
  `gnome-keyring-daemon` can lock memory pages for secure credential storage.

---

## DNS stall benchmark

`tools/bench_dns_stalls.py` is a standalone script (not part of the pytest run)
that measures how slow or failing name resolution affects px request latency
and throughput through a PAC file and through a `--noproxy` IP list. It starts
a local asyncio upstream and a px subprocess per scenario and mode, and
injects a `sitecustomize` hook into the px process that delays or fails
`socket.getaddrinfo`/`gethostbyname` calls made from `px.pac` and
`px.wproxy` only, so no root or real DNS is needed and px's own sockets are
unaffected.

- Scenarios: `pac` (PAC calling `myIpAddress()`, `dnsResolve()`, `isInNet()`
  and `isResolvable()`) and `noproxy` (`--noproxy` with IPs, which triggers an
  uncached lookup per request).
- Modes: `normal`, `slow1` (1 s per lookup), `slow5` (5 s per lookup), `fail`
  (lookups raise `gaierror`).
- Output: per concurrency level (default 1, 10 and 50 simultaneous requests)
  successes, failures, requests per second, p50, p95 and max latency.

Run it from a directory outside the repo with a clean `HOME` and
`PX_EVENT_LOOP` unset so a developer `.env` (`PX_NOPROXY`, `PX_THREADS`) does
not interfere; `--json` saves results for before/after comparison, and
`--timeout` bounds each request (requests stalled beyond it count as failures).

### Before/after results

The full default matrix below was run with `--timeout 35 --json <result>.json`
against baseline `a2bb145` (before the bounded resolver) and integrated
revision `2c5c1d5` (after it). `Done` is completed requests out of the selected
concurrency; p95 is seconds and RPS is completed requests per wall-clock
second.

| Scenario | Mode | Concurrency | Before Done | Before p95 | Before RPS | After Done | After p95 | After RPS |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| pac | normal | 1 | 1/1 | 0.047 | 20.91 | 1/1 | 0.052 | 19.13 |
| pac | normal | 10 | 10/10 | 0.195 | 50.05 | 10/10 | 0.131 | 73.43 |
| pac | normal | 50 | 50/50 | 0.794 | 59.22 | 50/50 | 0.600 | 77.91 |
| pac | slow1 | 1 | 1/1 | 4.050 | 0.25 | 1/1 | 0.053 | 18.77 |
| pac | slow1 | 10 | 8/10 | 35.036 | 0.23 | 10/10 | 0.142 | 67.94 |
| pac | slow1 | 50 | 0/50 | 35.037 | 0.00 | 50/50 | 0.618 | 75.84 |
| pac | slow5 | 1 | 1/1 | 20.052 | 0.05 | 1/1 | 0.053 | 18.53 |
| pac | slow5 | 10 | 1/10 | 35.037 | 0.03 | 10/10 | 0.147 | 65.74 |
| pac | slow5 | 50 | 0/50 | 35.037 | 0.00 | 50/50 | 0.594 | 78.69 |
| pac | fail | 1 | 1/1 | 0.043 | 23.18 | 1/1 | 0.054 | 18.41 |
| pac | fail | 10 | 10/10 | 0.141 | 68.29 | 10/10 | 0.135 | 71.10 |
| pac | fail | 50 | 50/50 | 0.578 | 82.03 | 50/50 | 0.607 | 79.54 |
| noproxy | normal | 1 | 1/1 | 0.031 | 31.69 | 1/1 | 0.038 | 25.90 |
| noproxy | normal | 10 | 10/10 | 0.029 | 300.32 | 10/10 | 0.026 | 323.64 |
| noproxy | normal | 50 | 50/50 | 0.068 | 489.49 | 50/50 | 0.041 | 492.08 |
| noproxy | slow1 | 1 | 1/1 | 1.032 | 0.97 | 1/1 | 0.036 | 27.30 |
| noproxy | slow1 | 10 | 10/10 | 1.035 | 9.61 | 10/10 | 0.026 | 326.89 |
| noproxy | slow1 | 50 | 50/50 | 2.015 | 24.53 | 50/50 | 0.043 | 590.11 |
| noproxy | slow5 | 1 | 1/1 | 5.032 | 0.20 | 1/1 | 0.036 | 27.27 |
| noproxy | slow5 | 10 | 10/10 | 5.029 | 1.99 | 10/10 | 0.026 | 327.37 |
| noproxy | slow5 | 50 | 50/50 | 10.019 | 4.98 | 50/50 | 0.055 | 504.03 |
| noproxy | fail | 1 | 1/1 | 0.027 | 35.79 | 1/1 | 0.035 | 27.75 |
| noproxy | fail | 10 | 10/10 | 0.038 | 223.15 | 10/10 | 0.025 | 331.62 |
| noproxy | fail | 50 | 50/50 | 0.073 | 411.06 | 50/50 | 0.042 | 599.28 |

The slow-DNS rows show the resolver improvement directly: bounded asynchronous
resolution prevents the PAC worker from serially holding requests and caches
the `--noproxy` lookup. For normal and failing DNS, especially 50-concurrency
PAC runs, repeated measurements can vary by roughly 70--90 RPS on the same
revision. Those throughput deltas are noise rather than a performance claim;
compare repeated alternating runs when assessing non-stall modes.

---

## Concurrency benchmarks

`test_benchmark.py` measures the async server's performance under concurrent
load. The tests are marked with `@pytest.mark.benchmark` and excluded from the
default test run. Benchmarks use `mcurl.Curl` as the HTTP client and a fast
async upstream server (pure asyncio, not httpbin) to ensure the proxy is always
the bottleneck being measured.

### What is measured

- **HTTP GET throughput** (`TestHTTPBenchmark`) — requests per second at
  concurrency 1–1 000, verifying ≥80% success rate.
- **CONNECT tunnel throughput** (`TestCONNECTBenchmark`) — CONNECT + TLS
  handshake + GET at concurrency 1–1 000, verifying ≥60% success rate.
- **Thread count bounded** (`TestResourceUsage`) — verifies thread count stays
  constant under 50 concurrent connections (async relay should not spawn threads
  proportional to tunnels).
- **Memory bounded** (`TestResourceUsage`) — verifies RSS does not more than
  double under 200 concurrent requests.
- **Thread pool saturation** (`TestThreadSaturation`) — escalates concurrency
  from 16 to 1 024 to find the point where the `--threads` pool becomes the
  bottleneck and throughput plateaus.
- **Active data exchange** (`TestActiveDataExchange`) — launches 4–1 024
  simultaneous CONNECT tunnels that all actively exchange data via a barrier,
  stressing the event loop's FD watcher / IOCP multiplexing. Uses a sliding
  success threshold (60% ≤256, 40% at 512, 25% at 1 024) since OS-level
  limits dominate at extreme concurrency.

### Running

```bash
# Via make
make benchmark

# Via pytest directly
uv run python -m pytest tests/test_benchmark.py -m benchmark -v -s
```

Results are printed as a table with columns for concurrency, success/failure
counts, latency percentiles (avg, p50, p99), requests/sec, thread count, and
RSS memory.

### CI

The `benchmark` job in `ci.yml` runs this selection on Ubuntu, macOS and
Windows. It runs in full mode only, not on push or pull request.

---

## Large data transfer tests

`test_large_data.py` verifies that the proxy reliably transfers multi-megabyte
payloads with data integrity. The tests are marked with `@pytest.mark.largedata`
and excluded from the default test run. They use a custom async upstream server
(HTTP + HTTPS) spawned in a separate process and `mcurl.Curl` as the client.

### What is tested

- **HTTP/HTTPS large GET** (`TestLargeGET`) — single downloads at 2, 5, 10, and
  20 MB with SHA-256 integrity verification, plus 4 concurrent 5 MB downloads.
- **HTTP/HTTPS large POST** (`TestLargePOST`) — single uploads at 2, 5, 10, and
  20 MB with server-side SHA-256 verification, plus 4 concurrent 5 MB uploads.
- **Mixed concurrent** (`TestMixedConcurrent`) — 3 GET + 3 POST transfers
  running simultaneously over HTTP and HTTPS.

### Running

```bash
# Via make
make test-large-data

# Via pytest directly
uv run python -m pytest tests/test_large_data.py -m largedata -v -s
```

### CI

The `large-data-linux` and `large-data-windows` jobs in `ci.yml` run these
tests in full mode only: the weekly run, a manual full dispatch and the
pre-release dry run. They are not part of the fast set, so they do not run on
push or pull request.
