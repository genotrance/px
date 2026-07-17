# Changelog

---

## v0.12.0 — TBD

### Bug fixes
- Fixed `--workers` > 1 crashing on Windows with `OSError: [WinError 87]` due
  to IOCP socket registration conflict.  Each worker now creates its own
  independent listening sockets instead of sharing from the parent process
  (#267).
- Enabled `--workers` on macOS — previously disabled because the old socket
  sharing approach was incompatible.  The new per-worker socket model uses
  `SO_REUSEPORT` on Linux and macOS and `SO_REUSEADDR` on Windows.
- Fixed px randomly becoming unresponsive after running for days when using
  `--debug` mode.  `os.fsync()` in the debug log write path could block the
  asyncio event loop indefinitely on slow or locked filesystems (antivirus,
  network drives). Replaced with `file.flush()` which pushes data to the OS
  page cache without blocking (#268).

### Improvements
- Px now automatically raises the open file descriptor soft limit
  (`RLIMIT_NOFILE`) at startup on Linux and macOS.  macOS `launchd` defaults to
  256 and Linux defaults to 1024, both too low for a proxy handling concurrent
  CONNECT tunnels.  The limit is raised to `min(hard_limit, 65536)` with a
  step-down fallback for macOS where `kern.maxfilesperproc` may reject high
  values (#272).

---

## v0.11.0 — 2026-04-03

### New features
- Added Kerberos ticket management (`--kerberos`) for Linux and macOS — Px
  acquires and renews Kerberos tickets automatically using `kinit` with the
  configured `--username` and password from `PX_PASSWORD` or keyring. No keytab
  file is created. Addresses #252 and #258.

### Bug fixes
- Fixed auth failure recovery when a Kerberos ticket becomes available after Px
  startup — clearing `MCURL.failed` allows previously-blocked proxies to be
  retried (#258).
- Fixed `--verbose` output not appearing in non-TTY environments (e.g. Docker
  with `workers=1`) due to Python block-buffering stdout.

### Docker
- Added `BUILDER` build arg and local builder stage to `Dockerfile` to support
  both CI (pre-built wheel) and local (source tree) builds.
- The full Docker image now requires `--cap-add IPC_LOCK` — gnome-keyring 48+
  (Alpine 3.23+) links libcap-ng which aborts without the `IPC_LOCK` capability.

### Improvements
- Replaced synchronous `http.server` + threading with `asyncio` + `h11`.
  CONNECT tunnels now use zero-thread bidirectional relays: `TunnelRelay`
  (FD watchers via `add_reader`/`add_writer`) on Linux, and
  `_async_tunnel_relay` (asyncio `StreamReader`/`StreamWriter` for the
  client side, IOCP-backed `sock_recv`/`sock_sendall` for the upstream
  libcurl socket) on Windows. Thread count stays bounded at the thread
  pool size regardless of active tunnel count.
- Changed `--workers` default from 2 to 1 — the async event loop handles
  concurrency without multiple processes.
- Reduced per-request overhead: double-checked locking in `reload_proxy()`,
  cached `get_curl_features()` and `noproxy_hosts`, shallow copy for proxy
  server lists, tuples for hot-path membership checks.
- Optimized `--verbose` logging: skipped file I/O overhead and
  process/thread name lookup when `--workers=1`. Log output is more
  compact (timestamp + call tree + message) while retaining diagnostic value.
- Added Winget package support — Px can now be installed on Windows via
  `winget install genotrance.px`. Manifests are submitted automatically on
  release via `vedantmgoyal9/winget-releaser`. Addresses #115, PR #264.
- Documented WinSW service account and environment variable options for
  running Px as a Windows service with SSPI or explicit credentials (#259).

### Internal
- Added `h11` runtime dependency, `psutil` dev dependency.
- Wired `--threads` to `asyncio` default executor pool size.
- Dynamic xdist worker count (`-n auto`) — auto-scales to hardware via a
  platform-aware `pytest_xdist_auto_num_workers` hook in `conftest.py`.
- Switched test fixtures and helpers from `--debug` (file logging) to
  `--verbose` (stdout logging), reducing test suite runtime by ~58%.
- Added concurrency benchmark tests (`make benchmark`) covering HTTP
  throughput, CONNECT tunnel throughput, thread pool saturation, active data
  exchange, thread count bounds, and memory bounds. Benchmarks now test up to
  1 000–1 024 concurrent connections with sliding success thresholds for
  barrier-synchronised active tunnel tests.
- Added large data transfer reliability tests (`make test-large-data`) with
  SHA-256 integrity verification for concurrent multi-MB GET/POST over HTTP
  and HTTPS. CI jobs run these on both Linux and Windows.

---

## v0.10.3 — 2026-03-11

### Bug fixes
- Fixed #248 — check install cmd if modified.
- Fixed #255 — handle Python v3.13 runtime context on startup.
- Fixed `set_client_auth()` mutating the global `AUTH_SUPPORTED` list when
  called with `ANY` or `ANYSAFE` — now copies the list.
- Fixed `cfg_int_init()`/`cfg_float_init()` passing invalid string values to
  callbacks when config values fail to parse — now falls back to default.
- Fixed `send_html()` in handler inserting a tuple instead of a string into
  the error page `explain` field.
- Fixed `file_url_to_local_path()` returning `None` for non-Windows file URLs.
- Fixed `--hostonly` and `--quit` failing in emulated/virtualized environments
  (QEMU, Docker on ARM) by adding a fallback when `psutil.net_if_stats()` is
  unavailable ([psutil#2693](https://github.com/giampaolo/psutil/issues/2693)).

### Improvements
- Replaced `quickjs` dependency with `quickjs-ng`.
- Dropped Python 3.8 and 3.9 support; minimum is now Python 3.10.
- Added Python 3.14 classifier.
- Restructured `README.md` with basic install/config/usage info and full
  `github.com` links (for PyPI/Docker Hub display).
- Made `docs/configuration.md` a complete user-facing reference with all CLI
  flags, environment variables, INI keys, defaults, and auth types.
- Split detailed documentation into user-facing (`docs/installation.md`,
  `docs/usage.md`, `docs/configuration.md`) and developer (`docs/architecture.md`,
  `docs/build.md`, `docs/testing.md`) sections.

### Internal
- Modernised project tooling: ruff, mypy, pre-commit, Makefile, `docs/` folder.
- CI workflow (`ci.yml`) now triggers on `devel` push and PRs only (not
  `master`). Test matrix expanded to 9 jobs: Ubuntu on Python 3.10–3.14, macOS
  on 3.10 and 3.14, Windows on 3.10 and 3.14.
- Build workflow (`build.yml`) now triggers on `master` push and
  `workflow_dispatch` only. Docker build and push steps merged into the
  `release` job (separate `docker` job removed).
- Added Dependabot configuration for monthly pip and GitHub Actions updates.
- `tools.py`: all `sys.exit()` calls changed to `sys.exit(1)` for proper error
  propagation. Docker function updated to accept `--push` flag and
  `--wheels-dir` option for CI usage.
- `build.sh`: added `build_local` function for end-to-end local build and test
  using Docker containers (musl or glibc). Added `auditwheel` to pip install in
  `build_binary` for both musl and glibc. Added error checking (`|| return 1`)
  to `build_local` steps.
- Added `test-musl` and `test-glibc` Makefile targets for local container
  testing.
- Updated GitHub Actions to Node 24: `actions/setup-python` v6,
  `astral-sh/setup-uv` v7, Docker actions v4.
- Fixed build workflow: Linux musl Nuitka builds now use Alpine containers
  (both x86_64 and aarch64) since musllinux containers lack Python dev headers
  needed by Nuitka. Linux glibc builds use Python 3.13 from the manylinux
  container (`/opt/python/cp313-cp313/`). All Linux container builds install
  `uv` via curl consistently.
- Fixed test-binary workflow: release archives from the binary job are now
  extracted before testing. The `PXBIN` environment variable is now properly
  exported to tox so the `binary` tox environment actually tests the compiled
  Nuitka/embedded binary.
- Resolved ruff violations in `px/` package — reduced suppressed rules to
  minimal intentional set.
- Ported `HISTORY.txt` to `docs/changelog.md` and removed the original file.
- Expanded `docs/architecture.md` with State singleton, request handling, spnego
  monkey-patching, PAC evaluation, proxy reload, and error handling details.
- Expanded pytest suite: added `test_debug.py`, `test_wproxy.py`, `test_pac.py`,
  `test_network.py`; expanded `test_config.py` with unit tests for utility
  functions and defaults. Deleted legacy `test.py`.
- Updated tox configuration to run all test files.
- Added `./mcurllib` as local wheel index to Makefile install for testing with
  unreleased mcurl versions.
- Cleaned up `tools.py`: removed obsolete functions (`get_curl`, `pyinstaller`,
  `scoop`, and all GitHub API release management). Remaining targets are
  `--wheel`, `--nuitka`, `--embed`, `--deps`, `--depspkg`, and `--docker`.
- Removed old `build.sh` and `build.ps1` monolithic build scripts — replaced
  by GitHub Actions workflows and the new `build.sh` function library.
- Added GitHub Actions CI workflow (`ci.yml`) with quality checks and test
  matrix across Python 3.10–3.14 on ubuntu, macos, and windows.
- Added GitHub Actions build workflow (`build.yml`) for wheels, Nuitka/embedded
  binaries, multi-distro testing, GitHub release posting, and PyPI publishing.
  Platform matrix covers all targets where both `pymcurl` and `quickjs-ng`
  provide wheels.
- Added shared `.github/actions/setup-python-env` composite action.
- Added `build.sh` as a shell function library sourced by `build.yml`. It
  consolidates repeated CI scaffolding (uv installation, Python discovery,
  wheel building, binary building, archive extraction, test execution) into
  reusable functions, keeping `build.yml` concise.
- Refactored `tools.py`: made `pymcurl` import lazy so the script can run
  without it installed (guards in `curl()` and `nuitka()`). Added
  `make_archive_with_hash()` helper to deduplicate archive+hash blocks.
  Added `--history` flag to print the latest changelog section (used by the
  release job). Made version import resilient with a `pyproject.toml`
  fallback when `px-proxy` is not installed as a package.

---

## v0.10.2 — 2025-04-07

### Bug fixes
- Fixed #246 — resolved crash caused by PAC hostname resolution.

### New features
- Added gui script `pxw.exe` to run Px in the background on Windows, addressing
  #203, #213 and #235 by providing correct path for `px.ini` and logs.
- Enhanced `px --install` to write `--config=path` into the registry to support
  non-standard locations for `px.ini`.
- Fixed #217 — updated `px --install` to write `pxw` into the registry to run
  Px in the background on Windows startup.
- Added support to read and write `px.ini` from the user config directory.
- Fixed #218 — improved config load order to cwd, user config or script path
  if file already exists. If `--save`, the file should be writable, otherwise use
  the user config directory.

---

## v0.10.1 — 2025-03-08

### Bug fixes
- Fixed docker image to work correctly with command line flags, include kerberos
  packages.
- Fixed #225, #245 — better handling of PAC file failures and fallback to DIRECT
  mode when they happen.
- Fixed #208 — try GSS-API authentication on all OS if supported by libcurl.

### Improvements
- Merged PR #233 — force flag to overwrite existing installation of Px in the
  Windows registry.
- Merged PR #237 — handle pid reuse and support for pwsh.
- Replaced quickjs `Context` with `Function` as recommended in #206 to avoid thread
  safety issues in PAC handling.
- Proxy reload support also for `MODE_CONFIG_PAC` if loading a PAC URL.

---

## v0.10.0 — 2025-01-10

### Breaking changes
- Replaced ctypes-based libcurl backend with `pymcurl` which uses cffi and includes
  the latest libcurl binaries.

### Bug fixes
- Fixed #219, #224 — pymcurl uses libcurl with schannel on Windows which loads
  certs from the OS.
- Fixed #214 — handle case where no headers are received from client.
- Fixed issue `curl/discussions/15700` where POST was failing in `auth=NONE` mode for
  NTLM proxies.
- Fixed issue in the Px docker container that would not stop unless it was killed.

---

## v0.9.2 — 2024-03-08

### Bug fixes
- Fixed issue with libcurl binary on Windows — #212.

---

## v0.9.1 — 2024-03-02

### Bug fixes
- Fixed issue with logging not working when set from `px.ini` — #204.
- Fixed issue with environment variables not propagating to all processes in Linux.
- Fixed issue with quickjs crashing in PAC mode with multiple threads — #198 / #206.

### Improvements
- Documented how to install binary version of Px on Windows without running in a
  console window — #203.

---

## v0.9.0 — 2024-01-25

### New features
- Added support for domains in noproxy — #2.
- Expanded noproxy to work in all proxy modes — #177.
- Added `--test` to verify Px configuration.
- Added support for Python 3.11 and 3.12, removed Python 2.7.
- Added support to load Px flags from environment variables and dotenv files.
- Added support to log to the working directory — #189.
- Added `--restart` to quit Px and start a new instance — #185.
- Added support to listen on multiple interfaces — #195.
- Added support for `--auth=NONE` which defers all authentication to the client.
- Added support for client authentication — NEGOTIATE, NTLM, DIGEST and
  BASIC auth with SSPI when available — #117.

### Bug fixes
- Fixed #183 — keyring import on OSX.
- Fixed #187 — removed dependency on `keyring_jeepney` which is deprecated.
- Fixed #188 — removed `keyrings.alt` and added docs for leveraging third
  party keyring backends.
- Fixed #200 — print debug messages when `--gateway` or `--hostonly` overrides
  listen and allow rules.
- Fixed #199 — cache auth mechanism that libcurl discovers and uses with
  upstream proxy.
- Fixed #184 — PAC proxy list was including blank entries.
- Fixed #152 — increased number of default threads from 5 to 32.
- Fixed issue leading to connection reuse by client after HTTPS connection was
  closed by server.
- Fixed issue with getting all interfaces correctly for `--hostonly`.
- Fixed issue with HTTP PUT not working in some scenarios.

### Improvements
- Windows binary now created with embeddable Python to avoid being flagged
  by virus scanners — #182, #197.
- Changed loading order of `px.ini` — from CLI flag first, environment next,
  working directory and finally from the Px directory.
- Mapped additional libcurl errors to HTTP errors to inform client.
- Refined `--quit` to directly communicate with running instances instead of looking
  for process matches.

---

## v0.8.4 — 2023-02-06

- Support for specifying PAC file encoding — #167.
- Fixed #164 — PAC function `myIpAddress()` was broken.
- Fixed #161 — PAC regex search was failing.
- Fixed #171 — Verbose output implies `--foreground`.

---

## v0.8.3 — 2022-07-19

- Fixed #157 — libcurl wrapper was missing socket definitions for OSX.
- Fixed #158 — win32ctypes was not being included in Windows binary.
- Fixed #160 — need to convert PAC return values into `CURLOPT_PROXY` schemes.

---

## v0.8.2 — 2022-06-29

- Fixed #155 — prevent SSL connection reuse for libcurl < v7.45.

---

## v0.8.1 — 2022-06-27

- Fixed #154 — improved SSL connection handling with libcurl.
- Fixed keyring dependencies on Linux.
- Added infrastructure to generate and post binary wheels for Px and all its
  dependencies for offline installation.

---

## v0.8.0 — 2022-06-18

- Added PAC file support for Linux.
- Local PAC files on Windows are now processed using QuickJS instead of WinHttp.
- Added CAINFO bundle in Windows builds.

---

## v0.7.2 — 2022-06-14

- Fixed #152 — handle connection errors in select loop gracefully.
- Fixed #151 — handle libcurl 7.29 on Centos7.

---

## v0.7.1 — 2022-06-13

- Fixed #146 — `px --install` was broken when run in `cmd.exe`, also when
  run as `python -m px`.
- Fixed #148 — 407 proxy required was not being detected generically.
- Fixed #151 — handle older versions of libcurl gracefully.
- Fixed issues with `--quit` not exiting child processes or working correctly
  in binary mode.

---

## v0.7.0 — 2022-05-12

### Breaking changes
- Switched to using libcurl for all outbound HTTP connections and proxy auth.
- Removed dependency on `ntlm-auth`, `pywin32` and `winkerberos`.

### New features
- Added `--password` to prompt and save password to default keyring for non single
  sign-on use cases.
- Added `--verbose` to log to stdout but not write to files.

### Improvements
- Px is no longer involved in and hence unable to cache the proxy authentication
  mechanism used by libcurl for subsequent connections.
- Logging output now includes more details of the call tree.
- Fixed issue where debug output from child processes on Linux were duplicated
  to the main process log.
- Package structure has changed significantly to meet Python / pip requirements.
- Updated release process to post Windows binary wheels.

---

## v0.6.3 — 2022-04-25

- Fixed #139, #141 — bug in noproxy parsing.

---

## v0.6.2 — 2022-04-06

- Fixed #137 — `quit()` and `save()` don't work on Windows.

---

## v0.6.1 — 2022-04-05

- Enabled multiprocessing on Linux.

---

## v0.6.0 — 2022-04-02

- Moved all Windows proxy detection code into `wproxy.py`.
- Moved debugging code into separate `debug.py` module.
- Added support in wproxy to detect proxies defined via environment variables.
- Added support for Linux — only NTLM and BASIC authentication supported initially.

---

## v0.5.1 — 2022-03-22

- Fixed #128 — IP:port split once from the right.
- Binary is now built using Nuitka.

---

## v0.5.0 — 2022-01-26

- Added support for authentication with user/password when SSPI is unavailable — #58.
- Implemented support for specifying PAC in INI — #65.
- Implemented force auth mechanism in INI — #73.
- Merged multiple PRs for auth handling, shutdown, connection management.
- Switched to Python 3.7, dropped 3.4 support.
- Added basic auth support (PR #82).
- Fixed multiple auth-related issues: #88, #71, #108, #116, #122.

---

## v0.4.0 — 2018-09-04

- Support for multiple NTLM proxies — #18.
- Added `--socktimeout` configuration.
- Fixed #27, #26 — quit and console attachment issues.
- Added support for Kerberos authentication — #22.
- Added `--hostonly` mode — PR20.
- Added proxy info discovery from Internet Options — #30.
- Added `--proxyreload` flag.
- Added `setup.py` for pip install — #24.
- Many bug fixes: #31, #36, #34, #38, #39, #43, #44, #46, #47, #48, #51, #52, #57, #60.

---

## v0.3.0 — 2018-02-19

- Added support for winkerberos — #9.
- Added `--allow` and `--gateway` features.
- Fixed multiple connection handling and logging issues.
- Added ability to run Px at user login — #17.
- Added CLI flags for all config options, `--config`, `--save`, `--help`.

---

## v0.2.1 — 2017-03-30

- Added `--listen` setting — #7.
- Fixed #3, #5, #6 — SSPI, port-in-use, HTTP method support.

---

## v0.2.0 — 2017-02-05

- Added noproxy feature.
- Added `--threads` setting.
- Added test script for basic validation.
- Multiple bug fixes for connection handling and chunked encoding.

---

## v0.1.0 — 2016-08-18

- Initial release.
