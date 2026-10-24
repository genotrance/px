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

Linux and macOS Nuitka builds explicitly include `uvloop`, and Windows Nuitka
builds explicitly include `winloop`, since their guarded imports are not
reliably discovered by Nuitka. The Windows Python Embedded build installs
`winloop` from the matching wheel archive when it installs `px-proxy`. Px falls
back to `asyncio` when either loop cannot be imported at runtime.

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

Runs on pushes to the `devel` branch and on pull requests (fast feedback loop).

- **quality** — runs `make check` (pre-commit, ruff, mypy).
- **tests** — runs `pytest` across a matrix: Ubuntu x86_64 on Python
  3.10–3.14, Ubuntu ARM64 (`ubuntu-24.04-arm`) on 3.10 and 3.14, macOS on
  3.10 and 3.14, Windows on 3.10 and 3.14 (11 jobs total). Uses the shared
  `.github/actions/setup-python-env` action for consistent environment
  setup. macOS test jobs use `macos-latest` and exclude `test_network.py` due
  to GitHub Actions environment limitations.
- **tests-musl** — runs `pytest` inside musllinux Docker containers on both
  x86_64 (`ubuntu-latest`) and aarch64 (`ubuntu-24.04-arm`) with Python
  3.10 and 3.14 (4 jobs total). This verifies Px works correctly on musl
  libc without relying on the build workflow.
- **large-data-linux** / **large-data-windows** — runs the large data transfer
  reliability tests (`test_large_data.py`) on Ubuntu and Windows respectively.
  These verify multi-megabyte GET/POST integrity over HTTP and HTTPS with
  concurrent connections.
- **kerberos** — builds the KDC Docker images (`make docker-kerberos`) and runs
  the Kerberos integration tests against local MIT and Heimdal KDCs on
  Ubuntu. Exercises real ticket acquisition, renewal, expiry parsing, and
  Heimdal detection.

### Automatic release (`auto-release.yml`)

Runs every Tuesday after mcurl's Monday dependency check and can also be
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
   dispatches the existing `ci.yml` workflow on that exact branch. It does not
   add or duplicate CI matrix jobs.
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

Triggered by pushes to `master` and manual dispatch (`workflow_dispatch`). All CI
scaffolding (environment setup, wheel building, binary building, archive
extraction, and test execution) is implemented as shell functions in `build.sh`
and called from the workflow steps.

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
  Every job first prints and checks the interpreter version that it will
  bundle against the newest published CPython 3.13 patch release on
  python.org. The check is run again when the build selects its interpreter,
  so a release cannot continue with a stale runner or container image.
  macOS resolves the newest patch with `actions/setup-python`'s
  `check-latest` option. Linux glibc uses the manylinux interpreter when it
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

- **test-binary** — extracts the release archives produced by the binary job,
  then tests them using `tox` to verify functionality across all Python
  versions (3.10–3.14). Tests run inside musllinux and Ubuntu containers
  on Linux and on the `macos-latest`/Windows test runners. Aarch64 Linux tests
  run on native `ubuntu-24.04-arm` runners. Uses `extract_archives`
  and `test_binary` from `build.sh`. The `PXBIN` environment variable is
  set so the `binary` tox environment can test the Nuitka binary directly.
  `build.sh` ensures the tox driver venv is created with a non-free-threaded
  Python 3.14 (`/opt/python/cp314-cp314/bin` is preferred when present; the
  version is pinned because the glibc test container has no Python and uv
  would otherwise download 3.15, for which no wheels exist) so the
  `binary` environment does not default to a free-threaded ABI (`cp314t`) that
  abi3 wheels like `psutil` cannot satisfy. macOS excludes `test_network.py`
  via `PX_CI_MINIMAL`.
- **release** — on `master` only: publishes the sdist and wheel to PyPI using
  trusted publishing, creates and pushes a version tag, creates a GitHub
  release with changelog notes extracted via `tools.py --history`, submits
  the Windows installer to [Winget](https://learn.microsoft.com/en-us/windows/package-manager/winget/)
  via `vedantmgoyal9/winget-releaser`, and builds and pushes Docker images
  to Docker Hub. The Winget step requires a `WINGET_TOKEN` repository secret
  (classic PAT with `public_repo` scope).

### Local release check (`tools/release-check.sh`)

CI on `devel` and `working` only runs `ci.yml` (tests from source), so the
`build.yml` release jobs are never exercised until they are dispatched. Run
`tools/release-check.sh` before dispatching `build.yml` on `devel` (and before
any merge to `master`); it is the required step before that dry run. The first
release build failed in every wheels job on a problem that only the real jobs
reveal, and the dry run is slow and shared, so failures should be found
locally first.

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
- `test_binary` — sets up tox and runs the test suite against the built artifacts.
- `build_local` — end-to-end local build and test using Docker containers.
  Accepts `musl` or `glibc` as argument. Builds the sdist, wheels, binary, and
  runs the full tox test suite in the appropriate container images. Invoked via
  `make test-musl` or `make test-glibc`.

## `tools.py`

Local build helper used by both developers and the GitHub Actions workflows:

- `--wheel` — builds sdist and wheel into `wheel/`.
- `--nuitka` — builds a standalone Nuitka binary for the current platform.
  On Linux/macOS, adds `--include-package=uvloop`; on Windows, adds
  `--include-package=winloop` alongside the keyring package. The guarded loop
  imports may not be detected automatically by Nuitka.
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
