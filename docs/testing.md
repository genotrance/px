# Testing

---

## Test suite layout

Tests live in `tests/`.

| File | Scope |
|------|-------|
| `conftest.py` | Pytest configuration — path setup, plaintext keyring backend, event-loop selection, xdist auto-parallelism hook, scenario memory report, loopback `getfqdn()` shortcut, macOS CI startup probe |
| `fixtures.py` | Shared test fixtures — port allocation, Px server instances (launched with `--verbose`), auth parametrisation |
| `helpers.py` | Utility functions — subprocess management (`run_px` launches Px with `--verbose`, `quit_px` stops it and, given its captured log `buffer`, prints Px's own verbose output when `--quit` fails), port checks, keyring setup |
| `test_benchmark.py` | Concurrency benchmarks — HTTP/CONNECT throughput, thread count, memory at various concurrency levels (marked `benchmark`, run via `make benchmark`) |
| `test_event_loop.py` | Event loop integration — verifies the selected asyncio or uvloop/winloop loop and basic server operation |
| `test_config.py` | Configuration utility tests — `get_logfile`, `get_config_dir`, `get_host_ips`, defaults, save, install |
| `test_large_data.py` | Large data transfer reliability — concurrent multi-MB GET/POST over HTTP and HTTPS with SHA-256 integrity verification (marked `largedata`, run via `make test-large-data`) |
| `test_debug.py` | Debug module tests — `Debug` singleton, `pprint`, `dprint` |
| `test_kerberos.py` | Kerberos ticket management — unit tests (mocked subprocess, Linux/macOS only) and Docker-based integration tests against local MIT and Heimdal KDCs (marked `integration`, run via `make test-kerberos`) |
| `test_client_auth.py` | Downstream client authentication unit tests — failed NEGOTIATE/NTLM/Digest/Basic credentials restart with a fresh 407, cached password lookups, and the connection handling of a 407 answering a held-back `Expect: 100-continue` (closes unless a handshake is in progress, in which case the late body is released and discarded and never parsed as the next request) |
| `test_auth_retry.py` | `--authretry` integration tests — Px against a fake upstream proxy that denies or allows authenticated requests, proving latching after 3 consecutive 407s, exactly one probe per interval under a 50-client concurrent burst, and recovery |
| `test_stream_upload.py` | Streamed upload unit and subprocess tests: body formats, trailers, `Expect: 100-continue`, authentication retries, header stripping, integrity, memory bounds, stalled clients, connection reuse, and parallel uploads. Proxy retry tests require libcurl NTLM. |
| `test_ntlm_burst.py` | NTLM upstream regression tests — concurrent plain-HTTP handshakes and CONNECT tunnels through a fake proxy; the CONNECT burst drops its first Type 1 legs and verifies later tunnels are not latched as authentication failures on either event loop. The CONNECT cases need the px#268 fix in pymcurl 8.23.0.3 (`Curl.get_os_errno`) and always run. The whole module is skipped when libcurl lacks NTLM support (the macOS pymcurl wheels) |
| `test_network.py` | Network integration tests — `--quit`, `--listen`, `--hostonly`, `--gateway`, `--allow`, `--noproxy` |
| `test_pac.py` | PAC file tests — loading, evaluation, encoding, JS callables (`dnsResolve` returning `null` on failure, `isResolvable`, `isInNet`, `myIpAddress`) |
| `test_multiprocessing.py` | Multi-worker tests — `--workers=2` with and without auth on all platforms |
| `test_proxy.py` | Proxy functionality tests — HTTP methods, auth, upstream auth, chaining |
| `test_startup.py` | Startup bounds — the startup probe and its macOS CI guard, and px listening and quitting within a bounded time |
| `test_build_python.py` | Build tooling — newest-patch Windows embed zip selection, bundled-version logging, macOS Mach-O portability check, macOS CI interpreter choice, workflow input checks, `build.yml`/`publish.yml` release publishing split |
| `test_ci_plan.py` | The `plan` step of `ci.yml` — runs its script for each trigger and checks fast vs full mode, the marker expression and the job counts of each matrix (needs bash, jq and PyYAML) |
| `test_auto_release.py` | `tools.py --auto-release` — version bump and dependency-change helpers for the automatic release |
| `test_scenario_env.py` | Guards the `MCURL_WHEELS` candidate-wheel wiring in `scenario-env.sh` used by mcurl's release gate |
| `test_test_action.py` | The `--test`/`--test-auth` actions — unit tests of probe reporting, final-status (401/407) failure, paced httpbin body echoes, bounded 429 retries and separate rate-limit exits, and Negotiate SPN addressing (`_negotiate_test_target`) |
| `test_resolver.py` | Resolver and upstream-proxy DNS seeding tests — positive/negative caching, in-flight de-duplication, lookup timeout with late cache fill, bounded pool, IPv4/IPv6 literals and results, temporary libcurl entries, DNS-free `myIpAddress` discovery |
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

Start it, run its independent smoke check, and run scenarios through the
network-resident client with:

```bash
tests/scenarios/env/scenario-env.sh up
tests/scenarios/env/scenario-env.sh smoke
MCURL_WHEELS=/path/to/candidate-wheels tests/scenarios/env/scenario-env.sh test
tests/scenarios/env/scenario-env.sh down
```

`up` builds pinned Debian 12.12 and Python 3.13.9/Alpine 3.22 images, waits for
service health checks, exports the generated origin CA as
`tests/scenarios/env/origin-ca.crt`, and writes the same `KEY=VALUE` inventory
it prints to `tests/scenarios/env/scenario.env`. `test` uses Docker CLI
`exec` to run pytest, its Python environment, and every Px subprocess in the
existing `client` service on the private `corp` network. The checkout is a
read-only bind mount at `/px` and the runner copies it before installing, so
this always tests the current source without writing build metadata into the
checkout or using an image layer. A cold build normally takes two to five minutes;
subsequent starts reuse Docker's build cache. `down`
removes the project containers, network, named volume, CA, and generated env
file. Use `status`, `logs [service]`, or `env` to inspect the lab without
changing it.

`test` installs the locked dependencies (pymcurl from PyPI) in the client and runs pytest, so the streamed-upload coverage always runs.

`MCURL_WHEELS` is the downstream release-candidate interface used by mcurl's
`build.yml` release gate, which supplies one selected candidate wheel. When set
to a directory containing `pymcurl-*.whl`, the directory is copied into the
client at the same path and, after `uv sync`, exactly that wheel's version is
reinstalled with `--no-index`, so the gate tests the candidate and not PyPI.
It fails if the directory or wheel is missing. Unset, nothing changes.
`tests/test_scenario_env.py` guards this wiring.

`test_parallel_uploads` also guards against a DNS-resolution burst at an
upstream proxy. The GitHub 2-vCPU failure reported libcurl's `Resolving timed
out after 10000 milliseconds`: 60 simultaneous handles each tried to resolve
the same proxy before the connection timeout, rather than timing out while
uploading. Px now shares all cached IPv4/IPv6 proxy addresses with libcurl
through a temporary `CURLOPT_RESOLVE` entry, preserving the proxy hostname for
Kerberos while avoiding the burst and retaining libcurl failover. To reproduce
this coverage locally, limit the selected lab client's
CPU allocation to two, then run the test with `UV_PYTHON=3.11` and
each of `PX_EVENT_LOOP=asyncio` and `PX_EVENT_LOOP=auto`; restore the
allocation after the run. The scenario test's 60 mixed, 8 MiB uploads and both
one- and two-worker parametrisations must pass without changing their load or
the 10-second connection timeout.

`SCENARIO_INSTANCE` (an integer from 0 to 50, default 0) selects a private lab
instance: instance N uses Compose project `px-scenario-N` and subnet
`172.30.N.0/24`. `scenario.env` records the instance's project name and
network endpoints, and the scenario tests read both from it, so set the
variable only for `tests/scenarios/env/scenario-env.sh`. Previously every
checkout shared one fixed `px-scenario` project, so a second `up` from
another checkout silently replaced the first lab's containers in the middle of
its run, and requests failed for reasons that had nothing to do with Px. `up`,
`smoke`, and `down` now refuse an instance whose containers another checkout
started. Pick a different instance when several checkouts or agents test in
parallel.

The default lab publishes no host ports: this keeps the test path valid in
sandboxed workers whose loopback namespace cannot reach Docker's loopback
ports. The inventory therefore names Docker services such as `squid-basic`,
`squid-sso.corp.test`, `origin.corp.test`, and `toxiproxy`. The
`scenario-windows` WSL2 job is the deliberate exception; it sets
`SCENARIO_HOST_PORTS=1` to load `compose.host.yaml` and retain its native
Windows port-based path.

The fixed test identity is `CORP\pxgood` / `GoodPass1!` in realm `CORP.TEST`.
`CORP\pxother` / `OtherPass2!` supports identity-isolation tests, and
`WrongPass9!` is the deliberately invalid password. These credentials are
public test data and must never be reused outside this local environment.

| Private-network endpoint | Purpose |
|---|---|
| `squid-basic:3128` | Squid Basic authentication |
| `squid-digest:3128` | Squid Digest authentication |
| `squid-sso.corp.test:3128` | Domain-joined Squid offering Negotiate and NTLM fallback |
| `squid-sso.corp.test:3130` | Domain-joined Squid advertising only Negotiate (`negotiate_wrapper_auth`) |
| `squid-close:3128` | Basic Squid with client/server persistence disabled |
| `squid-parent.corp.test:3128` | Unauthenticated parent Squid |
| `squid-child:3128` | Authenticating child Squid chained to the parent |
| `toxiproxy:8666`, `toxiproxy:8474` | Toxiproxy proxy hop and control API |
| `origin.corp.test:8080`, `:8443` | HTTP and self-signed HTTPS origins |
| `pac.corp.test:8081/proxy.pac` | PAC file selecting the SSO proxy for `.corp.test` |
| `127.0.0.1:18888` | Long-lived raw TCP echo endpoint |

The origin also provides `/small`, `/large`, `/stream`, and `/slow`. Its HTTPS
listener completes each TLS handshake in that connection's own thread, with a
listen backlog of 128. It used to wrap the listening socket instead, which
ran every handshake one at a time inside `accept()` with a backlog of 5. One
tunnel whose ClientHello was still in flight then stalled every queued
connection, and HTTPS bursts failed with `curl: (35) ... unexpected eof while
reading` on every mcurl version and every auth scheme, Basic included.
Each Squid limits one client address to 64 concurrent connections, and the
connection-close Squid to 16. The smoke check
runs from the client container so Docker DNS resolves the deterministic
`.corp.test` names; it verifies success and 407 rejection for Basic, Digest,
NTLM, and Kerberos over both HTTP and HTTPS CONNECT, then checks the chain,
connection-close proxy, and PAC response.
The domain controller runs three Squid instances concurrently; their service
names are `squid`, `squidclose`, and `squidwrapper`. Squid 5.7 includes the
service name in its shared-memory segment prefix, so the instances can start
without colliding.

Limitations: the lab models one AD site and one Squid version from Debian,
not AD replication, transparent interception, TLS inspection, or proxy
auto-discovery. The self-signed certificate is an origin certificate rather
than a TLS-inspection CA. The Samba DC container alone runs privileged because
its AD database requires filesystem ACL/xattr operations; its AD ports remain
private to the Compose network. Toxiproxy is configured without a toxic by default.
Scenario tests add toxics through its API, and an autouse fixture resets
Toxiproxy (`POST /reset`) before and after every test, so a toxic left behind
by an interrupted test cannot affect the next one. The wrong-password scenario
bounds how many requests Px sends to the SSO Squid by counting only the
access-log entries for origin requests. The DC's Docker health check logs a
`NONE_NONE/000` entry every few seconds, and counting every line made the
bound fail at random.

The test helper starts every Px instance with an explicit empty config file,
so a `px.ini` that `test_config` temporarily writes next to the px script under
`pytest -n auto` cannot leak into other tests' Px processes.

#### Real Px scenarios

`tests/scenarios/test_corporate_proxy.py` starts Px through `python -m px` in
the lab's client container, the same entry point as the `px` console script,
and sends traffic from curl and Python's HTTP client in that container. The
suite covers `px --test` through an explicit proxy
and PAC, a test-owned Kerberos ticket cache, wrong-password blocking and
`--authretry`, the px#268 25-client burst and cut-handshake regressions, sustained CONNECT
tunnels, connection-close behaviour, a mid-handshake reset, Squid connection
limits, a child/parent proxy chain, and PAC proxy-versus-DIRECT selection.
`test_px_test_auth_negotiate_matches_upstream_spn` runs Px on a non-loopback
listen address (`127.0.0.2`) with `--test-auth` and a single explicit
`--proxy`, and reads `KRB5_TRACE` to confirm libcurl requests the upstream
SSO proxy's SPN rather than one derived from Px's own listen address.
Authentication coverage includes NTLM, Negotiate, Basic, and Digest; the burst
matrix also covers HTTP, HTTPS CONNECT, `auto` and `asyncio` event loops, and
one and two workers.

`test_cut_handshakes_do_not_lock_out_proxy_px268` reproduces px#268 itself,
which a clean load burst never triggers. It routes Px to the real SSO Squid
through Toxiproxy with a `limit_data` toxic. The toxic cuts every connection
1500 bytes into the downstream stream, which is inside the body of Squid's
first 407 (about 0.5 KiB of headers plus a 3 KiB error page), as a Wi-Fi
change or VPN drop would. libcurl then still reports that intermediate 407 as
the CONNECT code. pymcurl 8.23.0.2 counted each cut handshake as a failed
login and blocked the proxy after three. With `authretry=0`, Px then answered
every later request with `401 Proxy server authentication failed`, which is
what the issue reporter saw from `px --test`. The test asserts that at least
three requests were really cut, removes the toxic, and requires a second
25-client burst to succeed completely.

It runs NTLM (`--auth=NTLM` after one successful request) and Negotiate
single sign-on (the reporter's default `--auth=ANY` with a Kerberos ticket,
cut on the first burst after Px starts). With `--auth=NEGOTIATE`, or with ANY
once Px has found the method, the token goes in the first request, so there
is no 407 leg to cut. Each scheme runs over HTTP and HTTPS CONNECT on both
event loops. Only the HTTPS CONNECT variants fail on pymcurl 8.23.0.2. For
plain HTTP, 8.23.0.2 never counted the cut handshake, so those variants guard
recovery and must pass on every version.

#### Streamed upload scenarios

Plain-HTTP request bodies cannot be replayed once Px has streamed them, yet
NTLM (and Negotiate or Basic after a first unauthenticated 407) needs the
request sent again on the authenticated connection. Before Px streamed bodies
into mcurl, such uploads failed with curl error 65 ("necessary data rewind was
impossible") and Px answered 503. The upload scenarios in
`test_corporate_proxy.py` send generated, streamed bodies through real Px
processes and real Squid proxies to the origin's `/echo` endpoint
(`tests/scenarios/env/origin/server.py`), which hashes the body as it arrives
(Content-Length or chunked, never buffering it) and answers with the method,
URL, length and SHA-256. Every test asserts status 200 and the exact length and
digest at the origin. Bodies are generated block by block and hashed on the
fly, so neither the tests nor Px hold a large body in memory.

The schemes cover each way Px can authenticate, against Squids that keep
connections alive (`SCENARIO_SSO_PROXY`, `SCENARIO_BASIC_PROXY`) and Squids
that close every connection after each response (`SCENARIO_CLOSE_PROXY`, and
the second SSO Squid on `SCENARIO_SSO_CLOSE_PROXY`, port 3129 of the domain
controller container):

| Scheme | `--auth` | Proxy credentials | Keep-alive proxy | Close proxy |
|---|---|---|---|---|
| NTLM, method known | `NTLM` | password | `ntlm-known` | `ntlm-known-close` |
| NTLM, method unknown | `NONEGOTIATE` | password | `ntlm-unknown` | `ntlm-unknown-close` |
| Negotiate, method known | `NEGOTIATE` | Kerberos ticket cache | `negotiate-known` | `negotiate-known-close` |
| Negotiate-only, method known | `NEGOTIATE` | Kerberos ticket cache | `negotiate-wrapper-known` | — |
| Kerberos, method unknown | `ANY` | Kerberos ticket cache | `kerberos-any` | `kerberos-any-close` |
| Basic, method unknown | `ANY` | password | `basic-any-keepalive` | `basic-any-close` |

The tests, each on the event loops selected (`auto` and `asyncio`, or only the
one named by `PX_EVENT_LOOP`, which CI sets so every job covers one loop):

- `test_upload_first_request`: a fresh Px whose very first request is a
  POST, PUT or PATCH (Content-Length or chunked), so the upload itself carries
  the authentication handshake. All 10 schemes.
- `test_upload_first_request_100mb` and
  `test_upload_chunked_first_request_100mb`: the same with 100 MB bodies, one
  method per scheme (rotating POST, PUT, PATCH; all three for `ntlm-unknown`)
  and a chunked 100 MB upload for `ntlm-unknown`, `kerberos-any` and
  `basic-any-close`. These also assert Px's memory (below).
- `test_upload_back_to_back_immediately`: every scheme, event loop,
  POST/PUT/PATCH and Content-Length/chunked framing sends an upload immediately
  after the first response, on the same and a new client connection, races two
  fresh client uploads, and repeats the succession with two Px workers. Each
  origin echo checks the exact length and SHA-256.
- `test_upload_later_requests` and `test_upload_later_requests_100mb`: a Px
  per scheme that has already authenticated once (module-scoped fixture
  `warm_px`); uploads on the same client connection and on new ones reuse the
  authenticated upstream connections, followed by a 100 MB upload and a small
  request on the same client connection.
- `test_upload_two_workers_first_requests` and
  `test_upload_two_workers_100mb`: `--workers=2` on a fresh Px, concurrent
  uploads spread over both worker processes, each authenticating for itself,
  and two simultaneous 100 MB uploads (Content-Length and chunked).
- `test_parallel_uploads`: 60 simultaneous uploads of about 8 MiB (mixed
  POST/PUT/PATCH, half chunked, 480 MiB in total) through `ntlm-unknown` and
  `kerberos-any`, with one and two workers.
- `test_px_test_all_methods_echo`: `px --test=all:<echo URL>` for NTLM and
  Kerberos with unknown auth on both kinds of proxy; GET, POST, PUT, DELETE and
  PATCH must all pass, which requires the echoed body to match what was sent.
- `test_upload_client_expect_continue`: a client that sends
  `Expect: 100-continue` receives exactly one `100 Continue` and its upload
  arrives intact, including known and unknown NTLM.

Memory is measured with psutil: `RssSampler` sums the RSS of Px and its worker
processes every 20 ms after startup allocations settle. The 100 MB tests and
parallel upload test enforce fixed RSS-growth limits, and the
`memory_report` fixture prints each measurement. This verifies that memory
scales with uploads in flight rather than request-body size.

Lab details that these tests depend on: the origin answers `/echo` for GET,
POST, PUT, PATCH and DELETE; the SSO Squid's second port (3129) disables
client and server persistent connections; all Squids use
`client_request_buffer_max_size 16 MB` because Squid's 512 KB default aborts a
fraction of the concurrent uploads whose bodies arrive while its auth helpers
are busy (plain `curl`, with no Px involved, loses about 10% of 60 concurrent
3 MB uploads), and the SSO Squids have no `maxconn` limit because after a long
run of aborted uploads Squid kept counting the closed connections and answered
403 to every later request from the same address (the connection-limit test
uses the close Squid's 16-connection limit instead).

The scenarios skip with an actionable message only when no lab has been
requested. Once `up` has written an inventory, a missing or unreachable service
is a pytest failure rather than a skip. A plain test run therefore remains
quick, while a requested lab cannot silently hide an infrastructure error.
Select individual behaviours with pytest's normal `-k` option:

```bash
# Start a unique lab and run only the px#268 matrix on asyncio.
SCENARIO_INSTANCE=1 tests/scenarios/env/scenario-env.sh up
SCENARIO_INSTANCE=1 \
  PX_EVENT_LOOP=asyncio tests/scenarios/env/scenario-env.sh test \
  tests/scenarios -m scenario -k px268 -v
SCENARIO_INSTANCE=1 tests/scenarios/env/scenario-env.sh down

# Reuse a lab started separately and run the full suite on its default loop.
tests/scenarios/env/scenario-env.sh up
tests/scenarios/env/scenario-env.sh test
tests/scenarios/env/scenario-env.sh down
```

A complete warm run of the pre-existing scenarios takes about 1.5-3 minutes and the
streamed upload scenarios add about 11 minutes per event loop (21 minutes with
both), dominated by the 100 MB uploads (about 18 s each, 36 s chunked); a cold Docker image build adds 2-5 minutes. Run only
the pre-existing ones with `-k "not (upload or parallel or px_test_all)"`, only the uploads with
`-k "test_upload or test_parallel or test_px_test_all"`, and pin one loop with `PX_EVENT_LOOP=auto` or
`PX_EVENT_LOOP=asyncio`. The
normal authentication proxies allow the 25-client regression burst, while the
connection-close variant retains a 16-connection limit for overload testing. Every
subprocess and network operation has a bounded timeout, and scenarios assert
that Px remains alive without a traceback. The cut-handshake test is
deliberately not an xfail: its HTTPS variants must fail on pymcurl 8.23.0.2
and pass on pymcurl 8.23.0.3 (the minimum), while the rest of the suite passes
on both. Because the lab is deterministic, any other failure is a real
regression.

The lab remains a focused single-site Debian Squid model. AD replication,
transparent interception, TLS inspection, WPAD, platform SSPI, and interaction
with a real organisation's proxy policies remain manual tests.

#### Multi-leg SPNEGO (NTLM-in-Negotiate)

A Windows corporate proxy that is Negotiate-only (advertises only
"Proxy-Authenticate: Negotiate", no bare "NTLM") falls back from Kerberos to
NTLM *inside* SPNEGO when SSPI cannot reach a KDC for the target SPN - type-1,
type-2 and type-3 NTLM messages wrapped in SPNEGO tokens, more legs than
libcurl otherwise assumes for Negotiate. `SCENARIO_SSO_WRAPPER_PROXY` (port
31288, the domain controller's third Squid instance) models that proxy: it
uses Squid's `negotiate_wrapper_auth` to multiplex the lab's existing
Kerberos and NTLM helpers behind a single `negotiate` `auth_param`, so only
"Negotiate" is advertised (`tests/scenarios/env/dc/entrypoint.sh`). Its
Kerberos leg works exactly like `SCENARIO_SSO_PROXY`'s (the smoke check's
`negotiate-wrapper HTTP (Kerberos leg)`).

Reproducing the NTLM-in-SPNEGO leg on Linux needs a GSSAPI mechanism that can
produce it: `gss-ntlmssp` (registered via `/etc/gss/mech.d`) makes MIT krb5's
GSSAPI - the library mcurl's `CURLAUTH_NEGOTIATE` uses - emit a real SPNEGO
`negTokenInit` wrapping an NTLMSSP type-1 message when no Kerberos ticket is
available. `test_negotiate_wrapper_cannot_route_spnego_wrapped_ntlm` in
`test_corporate_proxy.py` drives exactly that against
`SCENARIO_SSO_WRAPPER_PROXY`. The scenario client image includes
`gss-ntlmssp`; the skip remains useful only for a deliberately custom runner
that omits it.

That test documents a confirmed Squid-side limitation rather than a working
upload. Decoding a token captured from this exact setup (a
`Proxy-Authorization: Negotiate` value starting `YEgGBisGAQUFAqA+...`, a DER
SPNEGO `negTokenInit`) shows the NTLMSSP bytes start about 20 bytes into the
ASN.1 structure, never at offset 0. Squid's `negotiate_wrapper_auth`
(`src/auth/negotiate/wrapper/negotiate_wrapper.cc` upstream) decides Kerberos
vs. NTLM by checking whether the *decoded* token's first 8 bytes are the
literal ASCII `NTLMSSP\0` signature; a standards-compliant SPNEGO envelope
never starts with it, so every Negotiate token - Kerberos or SPNEGO-wrapped
NTLM alike - is handed to the Kerberos helper, which rejects it. Squid then
repeats the bare 407 challenge and the handshake never reaches a second,
body-bearing leg. There is no libcurl leg sequence or mcurl fix to report for
this path: the failure is entirely inside Squid's own helper, confirmed
independently of px/mcurl with a bare `curl --proxy-negotiate` against a
throwaway Squid running the same helper. Because the rejection happens before
Squid reads a request method or body, the outcome does not depend on
POST/PUT/PATCH or on body size/chunking, so the test sends one representative
GET.

This is also why the wrapper port still exists in the lab: Windows SSPI is
reported to send its NTLM fallback as a bare, unwrapped NTLMSSP token
labelled "Negotiate" - a long-standing interoperability behaviour
`negotiate_wrapper_auth`'s detection was written for - which the helper's
prefix check *would* recognise, unlike MIT krb5's strict RFC 4178 wrapping.
The `scenario-windows` CI job (below) is what actually settles that for real
SSPI; this Linux lab cannot.

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
| `scenario` | `scenarios/test_corporate_proxy.py` (optional corporate proxy lab) | when the lab is available |
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
  git worktree under `/tmp`, or make sure no `PX_` variables
  are set in any parent `.env` and in the shell environment.
- **Pin Python 3.14 when it matters.** CI runs on 3.14
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
is still covered before a release. A `plan` job in `ci.yml` holds the static fast and full
matrices (`TESTS_*`, `MUSL_*`, `SCENARIO_FULL`) and emits the one chosen by the
mode; `tests/test_ci_plan.py` runs that step and checks the selection logic.

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
  run. macOS jobs use uv-managed CPython and a startup probe to avoid
  interpreter DNS stalls. If a minimal macOS job takes a few minutes, add it
  to the `TESTS_FAST` matrix in the
  `plan` step of `ci.yml` and update this list.
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
macOS, Windows), `kerberos`, `quality`, 10 `scenario-linux` jobs and
`scenario-windows`, with no `-m` override so the `slow` tests run too. The
asyncio jobs set `PX_EVENT_LOOP=asyncio`; all other jobs cover automatic
winloop/uvloop selection.

Every pytest invocation in CI passes `--durations=30`, so each job log lists
the 30 slowest tests; use it to spot tests that grow slow.

### Real Px scenarios in CI

Full mode also runs the Docker corporate-proxy lab's real-Px suite
(`tests/scenarios`, marker `scenario`, see
[Running tests](#corporate-proxy-scenario-environment)):

- **`scenario-linux`** (the `SCENARIO_FULL` matrix in `ci.yml`) runs on
  `ubuntu-latest` across Python 3.10–3.14 and both event loops (10 jobs, each
  bringing the lab up and down itself with `tests/scenarios/env/scenario-env.sh`
  and invoking pytest with its `test` subcommand). Every job gives the lab a
  unique instance, bind-mounts the checkout into the client. A job that fails uploads `docker compose logs`
  for every Squid and the Samba domain controller plus each Px `--log=4`
  output copied from the client; the lab is torn down whether the suite
  passed, failed, or the job was cancelled.
- **`scenario-windows`** runs a real Windows Px against the same lab's NTLM
  proxy (`127.0.0.1:31282`) with explicit credentials: `--auth=NTLM`,
  `--username=CORP\pxgood`, `PX_PASSWORD` (keyring works the same way
  locally). It checks `px --test` against the origin and then a 20-request
  HTTPS burst through a running Px, both over the same connection-oriented
  NTLM handshake the lab exists to exercise. GitHub's `windows-latest`
  runners cannot run the lab's Linux containers directly, and a separate
  Linux job cannot expose the lab either since jobs run on distinct machines
  with no shared network between them. The job instead brings the lab up
  inside WSL2 on the same runner (`Vampire/setup-wsl`); WSL2's built-in
  localhost forwarding then makes the lab's `127.0.0.1` ports reachable from
  the Windows side of the same job. This works because DNS for a proxied
  target (`origin.corp.test`) is resolved by Squid inside the lab, never by
  the client, so the Windows host never needs to resolve lab-internal names
  itself. Because the following Px, upload, and SSPI steps run on Windows,
  the job keeps a detached `wsl.exe --exec sleep infinity` client running until
  logs are collected and the lab is torn down. Without that client WSL2 can
  idle-terminate the distro, which stops dockerd and all lab containers with
  SIGTERM between steps. The health step confirms that client is still alive
  and makes a direct authenticated NTLM proxy health check using the project's
  `uv` and `mcurl` environment immediately before the HTTPS burst. If the
  Windows localhost relay accepts TCP while WSL's Docker daemon is resuming,
  it wakes Docker and retries for a bounded 30 seconds; a final failure records
  `docker ps -a` instead of reporting resulting 502 responses as a Px
  regression.
- The same job also runs Px against the Negotiate-only proxy
  (`squid-sso.corp.test:31288`, resolved to the WSL2 localhost-forwarded
  proxy port; see
  [Multi-leg SPNEGO](#multi-leg-spnego-ntlm-in-negotiate) above) with
  `--auth=NEGOTIATE` and `--auth=ANY`, with explicit
  `pxgood@CORP.TEST` credentials. libcurl 8.23 deliberately excludes NTLM
  from its SSPI Negotiate package, so the former `CORP\pxgood` request to
  `127.0.0.1` could neither fall back to NTLM nor obtain a Kerberos ticket:
  `InitializeSecurityContext` returned `SEC_E_NO_CREDENTIALS` before sending
  a token. The job now publishes the AD DC's Kerberos and LDAP ports through WSL2 and
  declares `CORP.TEST` to Windows with `ksetup` (called by its absolute
  `System32` path, since the JDK's Java `klist` shadows `PATH` names):
  `/addkdc` names `dc.corp.test` as the KDC, `/setrealmflags` enables TCP, and
  `/addhosttorealmmap` maps `squid-sso.corp.test` and `.corp.test` to the realm.
  It does not use `klist add_bind`, which locates the DC through the AD DC
  locator and fails on a workgroup runner with `DsGetDCName 0x6ba`. The job
  then uses `squid-sso.corp.test`, matching the lab keytab's
  `HTTP/squid-sso.corp.test` SPN. A native `curl.exe --proxy-negotiate`
  probe must succeed and `klist` records the resulting ticket-cache state
  before Px is tested. For each auth value,
  `px --test=all:http://origin.corp.test:8080/echo`
  must pass GET/POST/PUT/DELETE/PATCH; a separate step then uploads small
  (12345-byte), multi-MB (5 MiB) and chunked (unknown-length) bodies for
  POST, PUT and PATCH through a foregrounded Px and checks the origin's
  `/echo` reply length and SHA-256 against the bytes actually sent. A run
  that instead reports `SEC_E_NO_CREDENTIALS` means Windows did not acquire
  the lab Kerberos credentials; a repeated 407 means the service ticket did
  not authenticate at Squid. Both fail before upload checks rather than
  silently passing on a different authentication path. The `--test=all` step runs both
  auth values with `--verbose` (so libcurl's header trace is in the job log)
  even if the first fails, and a failed job uploads the Squid access and cache
  logs (`squid-logs.txt`) next to `compose.log`. `px --test` flushes its
  output before exiting, since it ends with `os._exit`, which previously
  discarded everything it printed when stdout was a pipe.
- **Domain-joined SSPI single sign-on is out of scope for GitHub runners.**
  `--auth=NTLM`/`--auth=NEGOTIATE` with no `--username`/`--password` relies on
  the OS caching a logged-on domain user's credentials (Windows SSPI, or a
  Kerberos ticket on Linux/macOS); that requires the runner itself to be
  joined to `CORP.TEST`, which GitHub-hosted runners cannot be. Verify it by
  hand instead, on a domain-joined Windows host that can reach the lab's
  Squid (or an equivalent corporate SSO proxy):
  1. Join the host to the test domain (or point it at a real corporate
     domain) and log on as a domain user the proxy accepts.
  2. Run `px --auth=NTLM` (or `--auth=NEGOTIATE`) with no `--username` and no
     `PX_PASSWORD`/keyring entry; confirm it authenticates using the logged-on
     user's cached credentials alone.
  3. Run `px --test` through that Px and confirm it passes.
  4. Repeat the 20-request HTTPS burst used in `scenario-windows` through
     that Px and confirm every request succeeds.
  5. Safety-check wrong-password lockout: force a bad credential (for example
     a second, deliberately mismatched account) and confirm Px surfaces the
     407 instead of retrying into an account lockout, matching
     `test_wrong_password_block_and_authretry` in
     `tests/scenarios/test_corporate_proxy.py`.

### Coverage before a release

The CI set does not cover every Python, OS and architecture combination, but
every supported one is covered before each release. The full set runs on the
devel dry run and on the automatic-release candidate. Then `test-binary` in
`build.yml` runs tox on py310–py314 against the built release artifacts for six
platforms: glibc and musl on x86_64 and aarch64, macOS arm64 and Windows amd64.
`test-binary` runs on the devel dry run and on the master push that publishes,
and the `release` job needs it to pass. The mechanics are in
[Build](build.md#github-actions).

The full set's `scenario-linux` and `scenario-windows` jobs mean the real-Px
corporate-proxy scenario suite also runs on the devel dry run and the
automatic-release candidate before every release.
`./build.sh release_check scenario`'s `scenario` stage (default, part of `all`) runs the
same suite locally first. The one thing neither covers is domain-joined SSPI
single sign-on; see the manual checklist above, and run it before a release
that touches NTLM/Negotiate or SSPI handling.

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
variable. macOS jobs use uv-managed CPython and loopback lookup safeguards to
avoid runner-specific name-resolution stalls.

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

## Platform-specific test reliability

Tests avoid external DNS and fixed startup delays so results are deterministic.
macOS CI uses uv-managed CPython, leaves loopback names unchanged in
`getfqdn()`, and runs a startup probe to detect slow runner configuration.
On Windows, client-password lookups are cached after the initial authentication
attempt; Px log buffers are included when fixture shutdown fails.

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
