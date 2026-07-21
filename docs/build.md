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

## `pyproject.toml`

Package metadata, dependencies, and all tool configuration (ruff, mypy, pytest,
coverage, tox) live in `pyproject.toml`. The build backend is
`setuptools.build_meta`.

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
  setup. macOS excludes `test_network.py` due to GitHub Actions environment
  limitations.
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

### Build (`build.yml`)

Triggered by pushes to `master` and manual dispatch (`workflow_dispatch`). All CI
scaffolding (environment setup, wheel building, binary building, archive
extraction, and test execution) is implemented as shell functions in `build.sh`
and called from the workflow steps.

- **setup** — extracts the version from `pyproject.toml` and makes it available
  to downstream jobs.
- **sdist** — builds the sdist and pure-Python wheel using `tools.py --wheel`.
- **wheels** — builds dependency wheels for each platform inside manylinux,
  musllinux, or native runners across Python 3.10–3.14. x86_64 Linux jobs
  run on `ubuntu-latest`, aarch64 Linux jobs run on `ubuntu-24.04-arm`
  (native ARM64 runners) with the same container images running natively
  instead of under QEMU emulation. Uses `build_wheels` from `build.sh`.
- **binary** — builds Nuitka binaries (Linux/macOS) or the Python Embedded
  distribution (Windows) using `tools.py --nuitka` / `tools.py --embed`.
  Also packages dependency wheel archives with `tools.py --depspkg`.
  Uses `build_binary` from `build.sh`.
  Linux glibc builds run inside manylinux2014 containers using
  `/opt/python/cp313-cp313/bin/python3`. Linux musl builds use Alpine
  containers with system Python and dev headers since Nuitka needs
  `Python.h` which the musllinux containers lack. Alpine's `patchelf`
  package (0.18.0) is intentionally not used because Nuitka rejects it as a
  known buggy release; instead `build.sh` installs `patchelf==0.17.2.4`
  from PyPI into the build venv. Aarch64 builds run on native
  `ubuntu-24.04-arm` runners.
- **test-binary** — extracts the release archives produced by the binary job,
  then tests them using `tox` to verify functionality across all Python
  versions (3.10–3.14). Tests run inside musllinux and Ubuntu containers
  on Linux and on native macOS/Windows runners. Aarch64 Linux tests run on
  native `ubuntu-24.04-arm` runners. Uses `extract_archives`
  and `test_binary` from `build.sh`. The `PXBIN` environment variable is
  set so the `binary` tox environment can test the Nuitka binary directly.
  macOS excludes `test_network.py` via `PX_CI_MINIMAL`.
- **release** — on `master` only: publishes the sdist and wheel to PyPI using
  trusted publishing, creates and pushes a version tag, creates a GitHub
  release with changelog notes extracted via `tools.py --history`, submits
  the Windows installer to [Winget](https://learn.microsoft.com/en-us/windows/package-manager/winget/)
  via `vedantmgoyal9/winget-releaser`, and builds and pushes Docker images
  to Docker Hub. The Winget step requires a `WINGET_TOKEN` repository secret
  (classic PAT with `public_repo` scope).

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
- `--embed` — downloads a Python embeddable distribution, installs the wheel,
  and packages `px.exe` (Windows only).
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
