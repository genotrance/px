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

### Temporary: pymcurl 8.23.0.3 from mcurl devel builds

Px 0.13.1 needs pymcurl 8.23.0.3, including mcurl commit `7e25b12`, the release that fixes px#268 (it
adds `Curl.get_os_errno`) and streams `bridge()` request bodies through proxy
authentication (it adds `mcurl.REWIND_ERROR`, a seek callback and the
`Expect: 100-continue` probe and immediate auth-method cache that px's streamed uploads rely on). Until that version is on PyPI it exists only as
artifacts of a dry-run `build.yml` run on genotrance/mcurl `devel`, so
`pyproject.toml` deliberately keeps the minimum at `pymcurl>=8.23.0.2` and the
committed `uv.lock` keeps pinning the PyPI 8.23.0.2. Raising the minimum first
would make every locked install unsatisfiable: `uv sync --locked`, `uv run` and
`pip install` resolve against PyPI, where no matching pymcurl exists, so local
development and the integration gate would break. Locking the devel wheels
instead would record local paths or artifact URLs that only exist on one
machine or expire, so they are never committed either.

CI and `build.yml` bridge the gap in one place, the
`.github/actions/mcurl-devel` composite action:

- It finds the latest successful `workflow_dispatch` run of mcurl's
  `build.yml` on `devel`, downloads the `wheels-<os>-<arch>` artifact for the
  runner (abi3 and free-threaded wheels, manylinux and musllinux on Linux) into
  `$RUNNER_TEMP/mcurl-wheels`, and exports `PIP_FIND_LINKS`, `UV_FIND_LINKS`
  and `MCURL_WHEELS` pointing at it.
- `setup-python-env` calls it, then relocks only pymcurl
  (`uv lock --upgrade-package pymcurl`) in the runner's checkout so every
  existing `--locked` command keeps working, and runs
  `.github/actions/mcurl-devel/check.py` to assert that the installed pymcurl
  is at least 8.23.0.3 and has `Curl.get_os_errno`.
- Container jobs (`ci.yml` musl tests, `build.yml` Linux wheels) call it
  directly and mount the wheels at `/mcurl-wheels` with the find-links variable
  set inside the container. The musl tests run the same check; the `build.yml`
  `wheels` job checks that every collected pymcurl wheel is at least 8.23.0.3,
  and those wheels are what the binary and artifact-test jobs install.
- The action also exports `PX_REQUIRE_MCURL_FIX=1`; the musl and Linux
  artifact-test containers set it explicitly and tox passes it through. With it
  set, the interrupted-CONNECT test in `tests/test_ntlm_burst.py` runs (and
  fails) even if an old pymcurl slipped in, instead of skipping silently as it
  does on a plain 8.23.0.2 install (`docs/testing.md`).

Locally nothing extra is needed: with the 8.23.0.2 minimum the committed lock
installs as usual and the px#268 test is skipped. To test against the fix,
download the artifact for your platform (for example `gh run download <run-id>
-R genotrance/mcurl -n wheels-ubuntu-latest-x86_64 -D /tmp/mcurl-wheels`), run
`UV_FIND_LINKS=/tmp/mcurl-wheels uv lock --upgrade-package pymcurl` before
`make install`, and do not commit the resulting `uv.lock`.

Release order:

1. Release mcurl 8.23.0.3 to PyPI.
2. In px, raise the dependency to `pymcurl>=8.23.0.3` in `pyproject.toml`, run
   `uv lock --upgrade-package pymcurl` and commit both. Remove the temporary
   mechanism in the same change: delete `.github/actions/mcurl-devel/`, the
   "Use pymcurl devel wheels" and "Relock pymcurl" steps and the `check.py`
   call in `setup-python-env`, the mcurl-devel steps, `/mcurl-wheels` mounts,
   find-links variables, checks and `PX_REQUIRE_MCURL_FIX` settings in
   `ci.yml` and `build.yml`, `PX_REQUIRE_MCURL_FIX` in the tox `passenv`
   lists, the `skipif` in `tests/test_ntlm_burst.py`, and this section.
3. Release px 0.13.1.

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

- **plan** — resolves the mode (an explicit `full` input wins, a schedule is
  full, push/PR is fast) and emits the `tests`, `musl` and `scenario` matrices
  as JSON plus the pytest `-m` expression (empty in full mode, so slow tests
  run). The fast and full matrices are static lists in the step's `env`, so
  each job kind has one definition in `ci.yml`; `tests/test_ci_plan.py` checks
  the selection and job counts.
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
- **scenario-linux** — full mode only; brings up the Docker corporate-proxy
  lab and runs pytest through its `client` service
  (`tests/scenarios/env/scenario-env.sh test`). The runner includes
  `gss-ntlmssp` (lets libcurl's GSSAPI backend produce a real
  SPNEGO-wrapped NTLM token, see
  [Testing](testing.md#multi-leg-spnego-ntlm-in-negotiate)) and tests the
  bind-mounted checkout on Ubuntu across Python
  3.10–3.14 and both event loops (10 jobs), uploading Squid/Samba/Px logs as
  an artifact and tearing the lab down whenever a job fails or finishes. The
  suite includes the streamed upload scenarios (POST/PUT/PATCH through NTLM
  and Kerberos Squids, 100 MB, chunked, parallel, two workers). Every job
  exports `PX_EVENT_LOOP` (`auto` or
  `asyncio`, even `auto`) so those scenarios run on exactly the job's loop, and
  `setup-python-env` supplies the pymcurl devel wheels and
  `PX_REQUIRE_MCURL_FIX=1`, so a missing wheel fails them instead of skipping.
  Each job's pytest step has a 60-minute timeout; the suite takes about
  11 minutes on one loop locally (about 21 for both loops; expect up to roughly twice that on GitHub runners). See
  [Testing](testing.md#ci-testing) and
  [Testing](testing.md#corporate-proxy-scenario-environment).
- **scenario-windows** — full mode only; runs real Px natively on
  `windows-latest` against the same lab's NTLM proxy with explicit
  credentials (`--auth=NTLM`, `--username`, `PX_PASSWORD`), including
  `px --test` and a 20-request HTTPS burst through a running Px, and then
  against the lab's Negotiate-only proxy (`--auth=NEGOTIATE` and `--auth=ANY`,
  explicit `pxgood@CORP.TEST` credentials): `px --test=all:` over
  GET/POST/PUT/DELETE/PATCH,
  plus small, multi-MB and chunked POST/PUT/PATCH uploads checked by length
  and SHA-256 at the origin. libcurl 8.23 blocks NTLM fallback inside SPNEGO,
  so the job exposes the lab AD DC's Kerberos and LDAP ports to Windows,
  declares the realm to Windows with `ksetup` (not `klist add_bind`, which a
  workgroup runner cannot use), and addresses the proxy by the hostname in its
  HTTP SPN. A native curl probe verifies SSPI ticket acquisition before Px
  runs (see [Testing](testing.md#multi-leg-spnego-ntlm-in-negotiate)). GitHub's Windows
  runners have no Linux-container backend, so the lab runs inside WSL2
  (`Vampire/setup-wsl`) on the same runner; WSL2's built-in localhost
  forwarding exposes the lab's `127.0.0.1` ports to the Windows side of the
  job. Domain-joined SSPI single sign-on cannot be exercised this way — see
  the manual checklist in [Testing](testing.md#ci-testing).

Every pytest call in the workflow passes `--durations=30` so the job logs show
the slowest tests.

### Automatic release (`auto-release.yml`)

Runs on Tuesdays at 06:17 UTC (the cron in `auto-release.yml`) and can also be
started manually. Scheduled workflows run from the default `devel` branch, but
this workflow explicitly checks out `master`; unreleased work on `devel` can
therefore never enter an automatic release.

`tools.py --auto-release` upgrades `uv.lock` and looks up the newest CPython
3.14 patch published on python.org to compare against
`.github/bundled-python-version`, which records the patch bundled by the last
release. This lookup only decides whether a new patch is worth cutting a
release for; it never fails the release build itself. If neither the lock nor
CPython changed, the workflow exits successfully. Otherwise it:

1. Raises the `pymcurl` and `quickjs-ng` minimums to their newly resolved
   versions, bumps Px's patch version, records the CPython patch, and inserts a
   changelog section listing every changed locked dependency.
2. Pushes that single candidate commit to `release/auto-<version>` and
   dispatches the existing `ci.yml` workflow on that exact branch with
   `full=true`, so the candidate runs the complete matrix. It does not add or
   duplicate CI matrix jobs.
3. On CI success, verifies that the version still has no tag or GitHub release
   and that `master` has not moved, then fast-forwards `master` to the tested
   commit. Pushes made with `GITHUB_TOKEN` do not trigger workflows, so the
   workflow explicitly dispatches `build.yml` on `master` and logs the run URL
   without waiting for it. That build bundles and logs whatever CPython patch
   its own build tools provide, builds and tests the release artifacts, and
   publishes PyPI and the GitHub release. Any manual dispatch, including this
   one, also invokes `build.yml`'s reusable full CI gate while the artifact
   jobs run; the candidate's exact full CI run in step 2 remains the release
   precondition, so this second run adds no additional coverage.
4. The automatic-release workflow then attempts to merge the released
   `master` back into `devel` without waiting for the dispatched build. In
   parallel, a successful `build.yml` run on `master` emits the `workflow_run`
   event that starts `publish.yml`, which publishes Docker and Winget from the
   existing GitHub release. A merge conflict or concurrent `devel` update
   emits a warning for manual follow-up but does not rewrite either branch.

If CI fails, nothing reaches `master`. The workflow opens or updates the single
GitHub issue titled `auto-release blocked` with the run and failing job names;
a later successful automatic release closes it. A manual dispatch defaults to
`dry_run: true`: it performs dependency and CPython detection, prepares the
candidate in the runner, and writes the proposed versions to the workflow
summary without pushing a branch, dispatching CI, or publishing.

### Build (`build.yml`)

Triggered by pushes to `master` and manual dispatch (`workflow_dispatch`).
`build.yml` always builds and tests every release artifact, uploads to PyPI,
and creates the GitHub release; Docker Hub and Winget are published afterwards
by `publish.yml` (below).

The release job is idempotent so a re-run (for example after a partial
failure) cannot double-publish: it skips creating the version tag and GitHub
release when they already exist, and PyPI publication uses trusted
publishing's `skip-existing`. There is no separate mode or plan step — every
run builds, tests, and attempts the same publication steps regardless of what
already exists.

A manual dispatch on `devel` is the single pre-release gate: it calls `ci.yml`
with its full matrix at the same time as the release artifact jobs, so it
checks every CI configuration plus every wheel, binary and built-artifact test
before a merge to `master`. Run it with `gh workflow run build.yml --ref devel`
after `./build.sh release_check` passes, and do not merge until it is green.
Publishing never runs from this dispatch because the `release` job is guarded
by a master-only condition, so a devel dispatch is effectively a dry run.
Master pushes do not call CI again. Automatic release already runs the full
matrix against its exact candidate before
fast-forwarding master, so calling it twice would add delay without covering a
new revision. All CI scaffolding (environment setup, wheel building, binary
building, archive extraction, and test execution) is implemented as shell
functions in `build.sh` and called from the workflow steps.

Publication is safe to repeat: `publish.yml` only pushes Docker tags
that are missing or do not identify the release version. `latest` and
`latest-mini` are updated when missing, when their digest differs from the
version tag, or when the version tag is being pushed. This decision lives in
`docker_plan()` in `tools.py` (`python3 tools.py --docker-plan=VERSION` prints
the tags to push) and is tested through the CLI path in
`tests/test_build_python.py`.
`publish.yml` computes the plan before writing its GitHub output, so a planning
failure stops publication instead of silently skipping the Docker push. It also
does not open a duplicate Winget submission when the manifest exists or an
open `genotrance.px` pull request for that version exists. `docker manifest
inspect --verbose genotrance/px:0.12.0` reports one `linux/amd64` manifest, so
the release continues to build and publish amd64 images; no prior Docker
architecture is dropped.

### Publish (`publish.yml`)

Publishes an existing GitHub release to Docker Hub and Winget. It never builds
release binaries or wheels and never runs the test suite; its only inputs are
the release's assets, and the only thing it builds is the Docker images, from
the released `px-v<VERSION>-linux-musl-x86_64-wheels.tar.gz`. Splitting it
from `build.yml` keeps the Docker Hub and Winget secrets out of the long build
and lets publication be finished or repeated without touching PyPI or the
GitHub release.

It runs in two ways:

- **After `build.yml`** (`workflow_run`). It proceeds for every successful
  `build.yml` run on `master`, whether triggered by a push or a manual
  dispatch. The version is read from `pyproject.toml` at the build's commit.
  Because `workflow_run` workflows run from the default branch, `publish.yml`
  must also be present on `devel`.
- **Manual dispatch** with a required `version` (`0.13.0` or `v0.13.0`) and a
  `dry_run` boolean (default `true`), to finish or repeat publication of a
  release. A real publication must be dispatched from `master`.

The `resolve` job checks out the build's commit (or the dispatched ref) and
requires it to carry the requested version in `pyproject.toml` and to contain
the `v<VERSION>` tag. This keeps an old version from being republished as
`latest` from newer sources, and lets the current `tools.py` (with
`--docker-plan`) publish a release whose own tag predates it, as v0.13.0's
does. It then requires the release to have the musl wheel archive, the
Windows zip and their `.sha256` files.

The `docker` job downloads and verifies the wheel archive into
`px.dist-linux-musl-x86_64-wheels/`, runs `tools.py --docker-plan=VERSION` and,
when tags are needed, builds both images with `tools.py --docker` (which checks
the base image and the local build output's CPython version). Only outside a
dry run does it log in to Docker Hub, push exactly the planned tags with
`--push-tags`, and re-run the plan to confirm nothing is left. The `winget`
job checks for an existing `manifests/g/genotrance/px/<VERSION>` manifest or
an open `genotrance.px <VERSION>` pull request using the workflow token, then
verifies the released `px-v<VERSION>-windows-amd64.zip` against its checksum.
Outside a dry run it installs a pinned, checksum-verified
[komac](https://github.com/russellbanks/Komac), syncs the `winget-pkgs` fork
and submits that zip's release URL. `WINGET_TOKEN` is only given to that step;
it needs the `workflow` scope as well as `public_repo` because syncing the
fork updates its workflow files. Docker Hub secrets are only used by the login
step. Every job has read-only `contents` permission.

To re-publish an existing release's Docker and Winget artifacts, such as
v0.13.0, use the following procedure. It is also the recovery path for a
release created before the Docker/Winget split:

1. Confirm that `master` contains the `v0.13.0` tag and that the GitHub
   release contains the musl wheel archive, Windows archive, and their
   checksums. `publish.yml` cannot recreate a missing binary or wheel
   archive; it stops with an actionable error if one is absent. A release
   with missing assets has to be repaired by hand (`gh release upload`) or by
   deleting the tag and GitHub release and re-dispatching `build.yml`, which
   rebuilds and re-publishes everything from scratch.
2. Preview publication from `master`:

   ```
   gh workflow run publish.yml --ref master -f version=0.13.0 -f dry_run=true
   ```

   Inspect the workflow summary. It lists the Docker tags that are missing or
   stale and whether the Winget manifest or an open pull request causes the
   submission to be skipped. A dry run may build Docker images for validation,
   but it does not log in, push tags, or submit Winget.
3. If the preview is correct, run the real publication from `master`:

   ```
   gh workflow run publish.yml --ref master -f version=0.13.0 -f dry_run=false
   ```

   The workflow pushes only the planned Docker tags and submits Winget only
   when neither a manifest nor an open pull request exists.
4. Dispatch the dry run once more to verify that no Docker tags remain and that
   Winget is recognized as submitted or already present. Later runs for the
   same version are no-ops. Do not use `build.yml` to repeat Docker or Winget
   publication; it owns PyPI and GitHub release assets, while `publish.yml`
   owns those two downstream destinations.

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
  Every job bundles the newest CPython 3.14 patch available to its own build
  tools and logs the interpreter version (and path) it selected. The release
  guards still reject a missing, unparsable, or wrong-minor interpreter, but
  only warn when python.org has published a newer patch than uv's
  python-build-standalone, `actions/setup-python`, the Windows embeddable zip
  index, or the `python:3.14-alpine` Docker image provide yet. A release build
  previously failed this way in all six binary jobs (dry run 40266792761) the
  day python.org published 3.13.18 before any of those tools did; weekly
  automatic releases (see "Automatic release" above) now keep the bundled
  patch current on their own, which is also what fixed issue #275's
  months-long release gap, so a hard python.org gate on every build added
  delay without adding safety.
  macOS and Linux musl always use the newest uv-managed python-build-standalone
  CPython. For macOS this also sidesteps `actions/setup-python`'s CPython,
  which links Homebrew's OpenSSL by absolute path
  (`/opt/homebrew/Cellar/openssl@3/<version>/lib/libcrypto.3.dylib`) so a
  Nuitka binary built from it only ran on Macs with that exact Homebrew
  version; python-build-standalone avoids that interpreter dependency. Alpine's
  system Python can have a different minor version than Px targets, and its
  python-build-standalone distribution includes the headers Nuitka needs.
  Linux glibc compares the manylinux image's Python against a freshly
  installed uv-managed one — both resolved locally, no python.org lookup —
  and bundles whichever reports the newer version. Windows selects the newest
  python.org release that actually ships a Windows embeddable zip yet (the
  zip can lag a day or two behind the interpreter's python-build-standalone
  release) and downloads exactly that asset. Aarch64 builds run on native
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
  release with changelog notes extracted via `tools.py --history`. Docker
  Hub images and the Windows installer's
  [Winget](https://learn.microsoft.com/en-us/windows/package-manager/winget/)
  submission are published by `publish.yml` once the build succeeds. Winget
  submission requires a `WINGET_TOKEN` repository secret (classic PAT with
  `public_repo` and `workflow` scopes).

### Local release check (`./build.sh release_check`)

CI on `devel` and `working` runs only the fast `ci.yml` set. It never runs
`build_wheels` or the binary builds from `build.sh`, so the release jobs run only
when `build.yml` is dispatched or pushed to `master`. Before merging `devel` into
`master` for a release, run `./build.sh release_check` (now including the
corporate-proxy scenario suite by default), then the dry run
`gh workflow run build.yml --ref devel`, which also runs `ci.yml`'s full
matrix including `scenario-linux` and `scenario-windows`; both must pass. The
`ci-full` job is how the dry run runs `tests/scenarios`, so the upload scenarios
run against the same temporary pymcurl devel wheels as the other jobs. The
mcurl release gate runs this suite on px devel too through the scenario
client (Python 3.13, a devel wheel overlaid with `PX_REQUIRE_MCURL_FIX=1`, no
`PX_EVENT_LOOP`, so both loops run in one job). The
dry run does not publish, because the `release` job is `master`-only. The
first release build for v0.13.0 failed in every wheels job because `build.sh`
used `pip wheel --upgrade`, an option `pip wheel` does not have. Nothing was
published, but only the real jobs revealed the failure, and the dry run is
slow and shared, so failures should be found locally first. The release
checklist also includes the manual domain-joined SSPI checklist in
[Testing](testing.md#ci-testing), since GitHub runners cannot exercise it.

The script replays the Linux x86_64 jobs of `build.yml` with Docker, using the
same containers, `build.sh` functions and artifact hand-offs, plus a
`scenario` stage that is not part of `build.yml`:

1. `sdist` on the host with uv, refreshing `quickjs-ng`, into `wheel/`.
2. `wheels` in `manylinux2014_x86_64` and `musllinux_1_2_x86_64`
   (`build_wheels`).
3. `binary` in `manylinux2014_x86_64` and `alpine:3.21` (`build_binary`, which
   runs Nuitka).
4. `test-binary` in `ubuntu` and `musllinux_1_2_x86_64` against a fresh tree
   that only contains the binary archives, as the workflow's download step
   provides (`extract_archives`, then `test_binary` with tox).
5. `scenario` brings up the Docker corporate-proxy lab and runs
   `tests/scenarios -m scenario` through its network-resident client, then
   tears the lab down. It archives `/home/gt/code/mcurl` at `devel` and builds
   a temporary wheel in the release-check directory for the runner, without
   modifying that checkout. It skips with a message instead of failing when
   Docker is unavailable, and ignores `--fresh` (there is no tree copy to
   discard).

Usage is `./build.sh release_check [--fresh] [glibc|musl|scenario|all]`; the
default is all three. Each glibc/musl job works on its own copy of the
working tree (tracked and untracked, not ignored) under `RELEASE_CHECK_DIR`
(default `px-release-check` under `$ORC_SCRATCH_DIR` or `/tmp`), so the
checkout never receives root-owned build output. Completed stages are
remembered and skipped on re-runs, which makes iterating on a failing stage
cheap; `--fresh` discards them. The glibc
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
- `select_python` — resolves the interpreter a binary job will bundle (the
  newest one its own build tools provide) and logs its version and path; it
  never fails on python.org freshness. Called by `build_binary`.
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
- `--check-ssl` — fails unless `ssl`, `hashlib` and `spnego` import in this
  interpreter and, on macOS, `_ssl`/`_hashlib` have no `/opt/homebrew` or
  `/usr/local` library reference.
- `--check-portable DIR` — macOS only; scans every Mach-O file under `DIR`
  with `otool -L` and fails on `/opt/homebrew` or `/usr/local` references.
- `--embed` — downloads a Python embeddable distribution, installs the wheel,
  and packages `px.exe` (Windows only). It selects the highest versioned
  amd64 embeddable zip published for the newest CPython 3.14 release rather
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
Images are built from the released musl wheel archive and pushed automatically
by `publish.yml` after a successful `build.yml` run on `master`. Docker Hub
credentials are stored as repository secrets (`DOCKERHUB_USERNAME` and
`DOCKERHUB_TOKEN`).

`docker/Dockerfile` supports both CI and local builds via a `BUILDER` arg.
CI uses the default (`ci`) which installs from pre-built wheel archives. Local
builds use `BUILDER=local` which copies the source tree and runs `pip install`.
The CI image uses the Linux musl wheel archive, including its `uvloop` wheel;
local source installs resolve the same dependency. Thus both image variants use
the Linux default event loop, with Px retaining its runtime `asyncio` fallback.
The moving `python:3.14-alpine` base tag is pulled fresh (`docker build --pull`)
before each image build, and its bundled interpreter version is validated and
logged. The completed mini and full images are checked again after they build.
A wrong, missing, or unparsable Python version fails the build; an older patch
than python.org only emits a warning, because weekly automatic releases keep
the bundled patch current instead.
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
