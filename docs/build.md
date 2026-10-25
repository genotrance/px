# Build & Distribution

---

## Overview

Px is a pure Python application but depends on several packages that have OS and
machine specific binaries. As a result, Px ships two kinds of artifacts:

- **Wheels** — all packages needed to install Px on supported versions of Python.
- **Binary** — compiled binary using Python Embedded on Windows and Nuitka on Mac
  and Linux.

## Supported platforms

Platform coverage is determined by the intersection of native dependency wheels
available from `pymcurl` and `quickjs-ng` on PyPI:

| Platform | Arch | Binary type |
|----------|------|-------------|
| Linux glibc | x86_64, aarch64 | Nuitka |
| Linux musl | x86_64, aarch64 | Nuitka |
| macOS | arm64 | Nuitka |
| Windows | amd64 | Python Embedded |

Each platform produces two archives (`.tar.gz` on Linux/Mac, `.zip` on Windows):
- `px-vX.Y.Z-<os>-<abi>-<arch>` — standalone binary.
- `px-vX.Y.Z-<os>-<abi>-<arch>-wheels` — prebuilt dependency wheels for
  offline `pip install` across Python 3.10–3.14.

The wheel archives include the platform's default event loop: `uvloop` for
Linux (glibc and musl) and macOS, or `winloop` for Windows. They cannot omit
`uvloop` while it remains a declared `px-proxy` dependency: offline `pip
install --no-index` needs the wheel to resolve the package. The musl wheel
archive is also the input to the CI Docker build.

Linux and macOS Nuitka builds explicitly include `uvloop` and `spnego`
(pyspnego), and Windows Nuitka builds explicitly include `winloop`, since
guarded imports are not reliably discovered by Nuitka. Including `spnego`
preserves the cryptography-backed NTLM imports used by `px.handler`. The binary
job runs each completed artifact with `--help`; imports happen before that
option is processed, so this cheap smoke check catches missing authentication
dependencies before the longer binary test job. The Windows Python Embedded
build installs `winloop` from the matching wheel archive when it installs
`px-proxy`. Px falls back to `asyncio` when either loop cannot be imported at
runtime.

## `pyproject.toml`

Package metadata, dependencies, and all tool configuration (ruff, mypy, pytest,
coverage, tox) live in `pyproject.toml`. The build backend is
`setuptools.build_meta`.

## Dependency lock

`uv.lock` is committed so developer checkouts, CI, and ORC verification use the
same reviewed dependency versions. Normal installs and `uv run` commands use
the lock in `--locked` mode and fail when it no longer matches
`pyproject.toml`.

Dependabot opens monthly `uv` pull requests for routine dependency updates,
grouping minor and patch releases into one review. To intentionally update
dependencies locally, run `uv lock --upgrade` for all packages or
`uv lock --upgrade-package <name>` for one package, run the relevant tests,
and commit both `pyproject.toml` (when changed) and `uv.lock`. Review and test
Dependabot pull requests in the same way.

The automatic release workflow also runs `uv lock --upgrade` against the last
release on `master`. A changed lock is treated as a release candidate, including
changes to transitive dependencies that do not have a minimum in
`pyproject.toml`.

## GitHub Actions

All CI and release builds run via GitHub Actions. The workflows live in
`.github/workflows/`.

### CI (`ci.yml`)

Runs a fast set on pushes to `devel`/`working` and on pull requests, and the
full set on `workflow_dispatch` (`full` boolean input, default true), a weekly
`schedule` (Sundays 05:37 UTC, on the default `devel` branch) and
`workflow_call`. A manual `build.yml` dispatch and the automatic release
candidate call it with `full: true`. Start the full set with
`gh workflow run ci.yml --ref devel`. The split exists because macOS runners
are expensive, slow and few. The policy, per-mode job lists and rationale are in
[Testing](testing.md#ci-testing).

- **plan** — runs `tools/ci_matrix.py`, which resolves the mode (an explicit
  `full` input wins, a schedule is full, push/PR is fast) and emits the
  `tests` and `tests-musl` matrices as JSON plus the pytest `-m` expression
  (empty in full mode, so slow tests run). Keeping both matrices in one
  script gives each job kind a single definition instead of duplicated blocks.
- **quality** — runs `make check` (pre-commit, ruff, mypy).
- **tests** — runs `pytest` across the planned matrix. Fast: Ubuntu Python
  3.10 and 3.14, Ubuntu asyncio, Windows Python 3.14 and asyncio (5 jobs).
  Full: Ubuntu x86_64 on Python 3.10–3.14 plus asyncio on 3.14, Ubuntu ARM64
  (`ubuntu-24.04-arm`) on 3.10 and 3.14, macOS on 3.10 and 3.14, Windows on
  3.10 and 3.14 plus asyncio on 3.14 (13 jobs). Uses the shared
  `.github/actions/setup-python-env` action for consistent environment
  setup. macOS test jobs use `macos-latest`, set `PX_CI_MINIMAL=1` and exclude
  `test_network.py` due to GitHub Actions environment limitations (see
  [Testing](testing.md#reduced-test-matrix-for-macos-ci)).
- **tests-musl** — runs `pytest` inside musllinux Docker containers. Fast:
  x86_64 on Python 3.14. Full: x86_64 (`ubuntu-latest`) and aarch64
  (`ubuntu-24.04-arm`) with Python 3.10 and 3.14 (4 jobs). This verifies Px
  works correctly on musl libc without relying on the build workflow.
- **large-data-linux** / **large-data-windows** — full mode only; run the
  large data transfer reliability tests (`test_large_data.py`) on Ubuntu and
  Windows respectively. These verify multi-megabyte GET/POST integrity over
  HTTP and HTTPS with concurrent connections.
- **benchmark** — full mode only; the concurrency benchmarks on Ubuntu, macOS
  and Windows.
- **kerberos** — both modes; builds the KDC Docker images
  (`make docker-kerberos`) and runs the Kerberos integration tests against
  local MIT and Heimdal KDCs on Ubuntu. Exercises real ticket acquisition,
  renewal, expiry parsing, and Heimdal detection.

Every pytest call in the workflow passes `--durations=30` so the job logs show
the slowest tests.

### Automatic release (`auto-release.yml`)

Runs on Tuesdays at 06:17 UTC (the cron in `auto-release.yml`) and can also be
started manually. Scheduled workflows run from the default `devel` branch, but
this workflow explicitly checks out `master`; unreleased work on `devel` can
therefore never enter an automatic release.

`tools/auto_release.py` upgrades `uv.lock` and uses the same python.org lookup
as the release build guard to compare the newest CPython 3.13 patch with
`.github/bundled-python-version`, which records the patch bundled by the last
release. If neither the lock nor CPython changed, the workflow exits
successfully. Otherwise it:

1. Raises the `pymcurl` and `quickjs-ng` minimums to their newly resolved
   versions, bumps Px's patch version, records the CPython patch, and inserts a
   changelog section listing every changed locked dependency.
2. Pushes that single candidate commit to `release/auto-<version>` and
   dispatches the existing `ci.yml` workflow on that exact branch with
   `full=true`, so the candidate runs the complete matrix. It does not add or
   duplicate CI matrix jobs.
3. On CI success, verifies that the version still has no tag or GitHub release
   and that `master` has not moved, then fast-forwards `master` to the tested
   commit. That push starts `build.yml`, whose CPython freshness guards run
   again before anything is published.
4. Merges the released `master` back into `devel` without forcing. A merge
   conflict or concurrent `devel` update emits a warning for manual follow-up
   but does not rewrite either branch.

If CI fails, nothing reaches `master`. The workflow opens or updates the single
GitHub issue titled `auto-release blocked` with the run and failing job names;
a later successful automatic release closes it. A manual dispatch defaults to
`dry_run: true`: it performs dependency and CPython detection, prepares the
candidate in the runner, and writes the proposed versions to the workflow
summary without pushing a branch, dispatching CI, or publishing.

### Build (`build.yml`)

Triggered by pushes to `master` and manual dispatch (`workflow_dispatch`). A
manual dispatch on `devel` is the single pre-release gate: it calls `ci.yml`
with its full matrix at the same time as the release artifact jobs, so it
checks every CI configuration plus every wheel, binary and built-artifact test
before a merge to `master`. Run it with `gh workflow run build.yml --ref devel`
after `tools/release-check.sh` passes, and do not merge until it is green.
Master pushes do not call CI again. Automatic release already runs the full
matrix against its exact candidate before
fast-forwarding master, so calling it twice would add delay without covering a
new revision. Publishing remains guarded by the `release` job's master-only
condition. All CI scaffolding (environment setup, wheel building, binary
building, archive extraction, and test execution) is implemented as shell
functions in `build.sh` and called from the workflow steps.

Release builds deliberately refresh `quickjs-ng` from PyPI on every run,
subject only to the minimum version declared in `pyproject.toml`, and print the
resolved version. This is the explicit exception to locked dependency installs.
`build_wheels` uses `pip wheel --no-cache-dir` with the same minimum so each
Python job fetches the newest available wheel before creating dependency
archives. The Linux, macOS, and Windows binary jobs therefore consume the
newly resolved wheel. The Docker builders also print the installed version; CI
Docker images install from that generated wheel archive while local images
resolve the newest release from PyPI.

- **setup** — extracts the version from `pyproject.toml` and makes it available
  to downstream jobs.
- **sdist** — builds the sdist and pure-Python wheel using `tools.py --wheel`.
- **wheels** — builds dependency wheels for each platform inside manylinux,
  musllinux, or native runners across Python 3.10–3.14. x86_64 Linux jobs
  run on `ubuntu-latest`, aarch64 Linux jobs run on `ubuntu-24.04-arm`
  (native ARM64 runners) with the same container images running natively
  instead of under QEMU emulation. The macOS wheel archive is built on the
  pinned `macos-15` runner. Uses `build_wheels` from `build.sh`.
- **binary** — builds Nuitka binaries (Linux/macOS) or the Python Embedded
  distribution (Windows) using `tools.py --nuitka` / `tools.py --embed`.
  Also packages dependency wheel archives with `tools.py --depspkg`.
  Uses `build_binary` from `build.sh`.
  Linux jobs restore and save separate `actions/cache` entries for Nuitka's
  compiler cache and uv downloads. The cache keys include the Nuitka version,
  target platform and relevant source or lock-file hashes; prefix restores let
  Nuitka invalidate changed inputs itself. Both cache directories are mounted
  into the glibc and Alpine containers, so they survive ephemeral runners
  without mixing architectures or compiler environments.
  Every job first prints and checks the interpreter version that it will
  bundle against the newest published CPython 3.13 patch release on
  python.org. The check is run again when the build selects its interpreter,
  so a release cannot continue with a stale runner or container image.
  macOS always uses the newest uv-managed python-build-standalone CPython:
  `actions/setup-python`'s macOS CPython links Homebrew's OpenSSL by absolute
  path (`/opt/homebrew/Cellar/openssl@3/<version>/lib/libcrypto.3.dylib`), so
  the Nuitka binary built from it ran only on Macs with that exact Homebrew
  version. python-build-standalone avoids that interpreter dependency. Linux
  glibc uses the manylinux interpreter when it
  passes the check, otherwise it installs the newest managed CPython through
  the current uv release. Linux musl always uses that managed CPython because
  Alpine's system Python can have a different minor version; its
  python-build-standalone distribution includes the headers Nuitka needs.
  Windows instead checks that python.org publishes the newest patch's amd64
  embeddable zip, then deterministically downloads that exact asset.
  During validation on 2026-10-22, the python.org, manylinux, and uv-managed
  resolutions all returned CPython 3.13.17. Aarch64 builds run on native
  `ubuntu-24.04-arm` runners. Alpine's `patchelf` package (0.18.0) is
  intentionally not used because Nuitka rejects it as a known buggy release;
  instead `build.sh` installs `patchelf==0.17.2.4` from PyPI into the build
  venv. `build.sh` pins Nuitka to 4.1.3 for every Nuitka target. Later
  releases bundle SCons 4.10.1, whose `ilink` tool discovery fails with the
  GCC 10 compiler in manylinux2014; 4.1.3 is the newest version verified by
  the v0.12.0 Linux glibc build. Pinning all Nuitka targets keeps their
  compiler behavior aligned while the upstream regression is unresolved.
  Linux glibc builds run inside manylinux2014 containers using
  `/opt/python/cp313-cp313/bin/python3`. Linux musl builds use Alpine
  containers with system Python and dev headers since Nuitka needs
  `Python.h` which the musllinux containers lack. The macOS binary is built on
  the pinned `macos-15` runner. Neither `tools.py` nor `build.sh` sets
  `MACOSX_DEPLOYMENT_TARGET`, so the macOS minimum version comes from the
  toolchain on that image; pinning the runner keeps it from drifting when
  `macos-latest` moves to a newer image.
  The macOS build creates a fresh venv from the managed CPython, installs the
  wheels archive into it, and runs `tools.py --check-ssl` (imports `ssl`,
  `hashlib` and `spnego`, and fails if `_ssl` or `_hashlib` link a library
  from `/opt/homebrew` or `/usr/local`) before the slow Nuitka compile. After the
  build, `smoke_binary` launches `px --help`, which imports `ssl` and
  `spnego` before processing the option, and fails if either import reports
  `Requires module`. On macOS it also runs `tools.py --check-portable` over
  `px.dist`. The guard uses `otool -L` on every Mach-O file and fails on any
  `/opt/homebrew` or `/usr/local` reference, including `_ssl.so`, OpenSSL
  dylibs, and the libcurl/pymcurl stack. The build runner has
  Homebrew, so the binary loads fine there and a host library dependency is
  invisible to a launch check; the install-name check is the one that catches
  it on the build job. `test-binary` also launches the extracted binary
  (`smoke_binary`) on the clean test runner before any tox environment, so a
  missing library fails in seconds instead of as about 20 minutes of auth
  timeouts per tox environment.

- **test-binary** — extracts the release archives produced by the binary job,
  then tests them using `tox` to verify functionality across all Python
  versions (3.10–3.14). The five Python tox environments install and execute
  the release wheel from the offline archive; the separate `binary`
  environment executes the compiled Nuitka or embedded binary through
  `PXBIN`. This avoids running the same binary suite five extra times while
  retaining every test of every wheel and binary artifact. The wheel
  environments run two at a time, then the binary environment runs, which
  safely shortens the slow macOS and Windows stages without sharing a binary
  configuration file between concurrent tests. Tests run inside musllinux and
  Ubuntu containers on Linux and on the `macos-latest`/Windows test runners.
  Aarch64 Linux tests run on native `ubuntu-24.04-arm` runners. Uses
  `extract_archives` and `test_binary` from `build.sh`.
  `test_binary` first runs `smoke_binary` on the extracted artifact inside the
  clean test container or runner (the same `--help` launch and auth import
  check, plus the macOS portability check), so a library that only exists on
  the build host fails the job in seconds instead of as 28 failing tests after
  the wheel suites.
  On macOS the test job uses uv-managed CPython (the setup action's
  `managed-python` input and `UV_PYTHON_PREFERENCE=only-managed` for the tox
  environments) rather than setup-python's or Homebrew's: on the macOS 15+
  runners those interpreters stall name lookups for about 35 seconds each (see
  [Testing](testing.md#macos-specific-reasoning)), which made every macOS wheel
  environment run for about 19.5 minutes. The wheels, binary and release build
  jobs are unchanged.
  `build.sh` ensures the tox driver venv is created with a non-free-threaded
  Python 3.14 (`/opt/python/cp314-cp314/bin` is preferred when present; the
  version is pinned because the glibc test container has no Python and uv
  would otherwise download 3.15, for which no wheels exist) so the
  `binary` environment does not default to a free-threaded ABI (`cp314t`) that
  abi3 wheels like `psutil` cannot satisfy. macOS uses the same policy as
  ci.yml's full matrix: it excludes only `test_network.py` via
  `PX_CI_MINIMAL`, retains slow tests, and records the 30 slowest test
  durations. Linux and Windows retain their complete artifact tests.
- **release** — on `master` only: publishes the sdist and wheel to PyPI using
  trusted publishing, creates and pushes a version tag, creates a GitHub
  release with changelog notes extracted via `tools.py --history`, submits
  the Windows installer to [Winget](https://learn.microsoft.com/en-us/windows/package-manager/winget/)
  via `vedantmgoyal9/winget-releaser`, and builds and pushes Docker images
  to Docker Hub. The Winget step requires a `WINGET_TOKEN` repository secret
  (classic PAT with `public_repo` scope).

### Local release check (`tools/release-check.sh`)

CI on `devel` and `working` runs only the fast `ci.yml` set. It never runs
`build_wheels` or the binary builds from `build.sh`, so the release jobs run only
when `build.yml` is dispatched or pushed to `master`. Before merging `devel` into
`master` for a release, run `tools/release-check.sh`, then the dry run
`gh workflow run build.yml --ref devel`, which must pass. The dry run does not
publish, because the `release` job is `master`-only. The first release build for
v0.13.0 failed in every wheels job because `build.sh` used `pip wheel --upgrade`,
an option `pip wheel` does not have. Nothing was published, but only the real
jobs revealed the failure, and the dry run is slow and shared, so failures should
be found locally first.

The script replays the Linux x86_64 jobs of `build.yml` with Docker, using the
same containers, `build.sh` functions and artifact hand-offs:

1. `sdist` on the host with uv, refreshing `quickjs-ng`, into `wheel/`.
2. `wheels` in `manylinux2014_x86_64` and `musllinux_1_2_x86_64`
   (`build_wheels`).
3. `binary` in `manylinux2014_x86_64` and `alpine:3.21`
   (`check_bundled_python`, then `build_binary`, which runs Nuitka).
4. `test-binary` in `ubuntu` and `musllinux_1_2_x86_64` against a fresh tree
   that only contains the binary archives, as the workflow's download step
   provides (`extract_archives`, then `test_binary` with tox).

Usage is `tools/release-check.sh [--fresh] [glibc|musl|all]`; the default is
both. Each job works on its own copy of the working tree (tracked and
untracked, not ignored) under `RELEASE_CHECK_DIR` (default `px-release-check`
under `$ORC_SCRATCH_DIR` or `/tmp`), so the checkout never receives root-owned
build output. Completed stages are remembered and skipped on re-runs, which
makes iterating on a failing stage cheap; `--fresh` discards them. The glibc
test container defaults to `ubuntu` as in `build.yml` and can be changed with
`TEST_IMAGE_GLIBC`. The script fails if `build.yml` stops referencing the
images it replays, so the two cannot drift silently. A full run downloads
dependencies and compiles Nuitka binaries, so it needs network access and
takes a while. The aarch64, macOS and Windows jobs are not covered and still
rely on the real workflow.

## `build.sh`

Shell function library sourced by the `build.yml` workflow. It consolidates
repeated CI scaffolding (uv installation, Python discovery, package manager
detection, archive handling) into reusable functions so the workflow YAML
stays concise. Functions include:

- `ensure_uv` — installs uv if not already present.
- `find_python` — locates a Python binary by version (container paths or
  `uv python find --system`).
- `get_os` / `get_version` — detect the current OS flavour and project version.
- `build_wheels` — builds dependency wheels for all supported Python versions.
- `build_binary` — installs build dependencies and runs `tools.py --nuitka` or
  `--embed` plus `--depspkg`.
- `check_bundled_python` — the pre-build release guard; resolves and logs the
  interpreter a binary job will bundle, and rejects it if it is behind the
  newest published CPython 3.13 patch release.
- `extract_archives` — unpacks binary and wheel archives for the test-binary job.
- `smoke_binary` — launches `px --help` on an artifact, failing if `ssl` or
  `spnego` cannot load; on macOS it also runs `tools.py --check-portable`.
  `build_binary` and `test_binary` both call it.
- `test_binary` — runs `smoke_binary`, then the tox matrix against the built
  artifacts.
- `build_local` — end-to-end local build and test using Docker containers.
  Accepts `musl` or `glibc` as argument. Builds the sdist, wheels, binary, and
  runs the full tox test suite in the appropriate container images. Invoked via
  `make test-musl` or `make test-glibc`.

## `tools.py`

Local build helper used by both developers and the GitHub Actions workflows:

- `--wheel` — builds sdist and wheel into `wheel/`.
- `--nuitka` — builds a standalone Nuitka binary for the current platform.
  On Linux/macOS, adds `--include-package=uvloop` and `--include-package=spnego`;
  on Windows, adds `--include-package=win32ctypes` (keyring) and
  `--include-package=winloop`. Guarded imports may not be detected automatically
  by Nuitka.
- `--check-python` / `--check-embed` — fail unless the interpreter (or the
  Windows embeddable zip) is the newest published CPython 3.13 release. Used by
  `check_bundled_python`.
- `--check-ssl` — fails unless `ssl`, `hashlib` and `spnego` import in this
  interpreter and, on macOS, `_ssl`/`_hashlib` have no `/opt/homebrew` or
  `/usr/local` library reference.
- `--check-portable DIR` — macOS only; scans every Mach-O file under `DIR`
  with `otool -L` and fails on `/opt/homebrew` or `/usr/local` references.
- `--embed` — downloads a Python embeddable distribution, installs the wheel,
  and packages `px.exe` (Windows only). It selects the highest versioned
  amd64 embeddable zip published for the newest CPython 3.13 release rather
  than relying on the order of python.org's directory listing. The install
  uses the matching Windows wheel archive, so the platform dependency metadata
  installs `winloop`.
- `--deps` — builds dependency wheels for the current Python version.
- `--depspkg` — packages all dependency wheels into a release archive with
  sha256 checksums.
- `--docker` — builds `genotrance/px` Docker images (full and mini, Linux only).
  Accepts `--push` to push images to Docker Hub and `--wheels-dir` to specify the
  wheel directory path.
- `--history` — prints the latest changelog section from `docs/changelog.md`
  (used by the release job for GitHub release notes).

## Docker

Px is available as a prebuilt Docker image at `genotrance/px`. Two variants
are posted — the default includes keyring and dependencies, while the mini
version is smaller but requires `PX_PASSWORD` and `PX_CLIENT_PASSWORD`
environment variables for credentials. The full image requires
`--cap-add IPC_LOCK` at runtime because gnome-keyring-daemon (48+) links
libcap-ng which aborts without the `IPC_LOCK` capability in containers.
Mounted keyring volumes must be owned by `root` with mode `700` inside the
container; gnome-keyring-daemon 48+ refuses to create the collection otherwise.
Images are built and pushed automatically
as part of the `release` job in `build.yml` on merge to `master`. Docker Hub
credentials are stored as repository secrets (`DOCKERHUB_USERNAME` and
`DOCKERHUB_TOKEN`).

`docker/Dockerfile` supports both CI and local builds via a `BUILDER` arg.
CI uses the default (`ci`) which installs from pre-built wheel archives. Local
builds use `BUILDER=local` which copies the source tree and runs `pip install`.
The CI image uses the Linux musl wheel archive, including its `uvloop` wheel;
local source installs resolve the same dependency. Thus both image variants use
the Linux default event loop, with Px retaining its runtime `asyncio` fallback.
The moving `python:3.13-alpine` base tag is pulled before each image build and
its interpreter is compared with python.org's newest 3.13 release. The
completed mini image is checked again before it can be pushed. This makes local
and release Docker builds fail rather than publishing a stale CPython patch.
Run `make docker` to build both images locally.

Three additional Dockerfiles support the Kerberos integration test
infrastructure:

- `docker/Dockerfile.mit-kdc` — Alpine with MIT krb5-server for the MIT KDC
  test fixture.
- `docker/Dockerfile.heimdal-kdc` — Debian with heimdal-kdc for the Heimdal
  KDC test fixture.
- `docker/Dockerfile.heimdal-client` — python:alpine with Heimdal client
  libraries and px installed from source, used to run integration tests against
  the Heimdal KDC.

Run `make docker-kerberos` to build all five images (px full, px mini, and the
three test images). `make test-kerberos` depends on this target.

## Dependabot

Dependabot is configured in `.github/dependabot.yml` to check for updates
monthly for both pip dependencies and GitHub Actions versions.
