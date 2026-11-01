#!/bin/sh
# CI helper functions for build.yml
# Usage: . ./build.sh && <function> [args]   or   ./build.sh <function> [args]

set -e

# --- Common helpers ---

get_os() {
    case "$(uname -s)" in
        Linux)
            if ldd /bin/ls 2>/dev/null | grep -q musl; then
                echo "linux-musl"
            else
                echo "linux-glibc"
            fi
            ;;
        Darwin) echo "mac" ;;
        MINGW*|MSYS*|CYGWIN*) echo "windows" ;;
        *) echo "unsupported" ;;
    esac
}

# CPython minor version bundled in every binary (keep in sync with PY_MINOR in
# tools.py). Build tools select their newest available patch version.
PY_MINOR="${PY_MINOR:-3.14}"
# Nuitka 4.2+ bundles SCons 4.10.1, which cannot select the linker in the
# manylinux2014 GCC 10 environment. Keep every binary target on the newest
# version validated there until upstream fixes that regression.
NUITKA_VERSION="4.1.3"
# Minimum pymcurl release, read from pyproject.toml so the two never drift
PYMCURL_MIN=$(sed -n 's/.*"pymcurl>=\([0-9.]*\)".*/\1/p' pyproject.toml 2>/dev/null | head -1)

get_version() {
    grep '^version' pyproject.toml | head -1 | cut -d'"' -f2
}

log_quickjs_version() {
    "$1" -c 'import importlib.metadata as m; print("quickjs-ng version:", m.version("quickjs-ng"))'
}

ensure_uv() {
    if command -v uv > /dev/null 2>&1; then
        return
    fi
    curl -LsSf https://astral.sh/uv/install.sh | sh
    . ~/.local/bin/env
}

# Find Python binary for a given version
# Usage: find_python 313  (compact) or find_python 3.13 (dotted)
find_python() {
    pyver="$1"
    if [ -d "/opt/python" ]; then
        # manylinux/musllinux container
        echo "/opt/python/cp${pyver}-cp${pyver}/bin/python3"
    else
        # Native runner — use uv (--system skips venvs)
        uv python find --no-project --system "$pyver" 2>/dev/null || echo ""
    fi
}

# --- Wheel building ---

build_wheels() {
    ensure_uv

    if [ -d "/opt/python" ]; then
        # manylinux/musllinux container — compact version numbers
        for pyver in 310 311 312 313 314; do
            PY=$(find_python "$pyver")
            if [ -f "$PY" ]; then
                echo "Building wheels for Python $pyver"
                "$PY" -m pip wheel --no-cache-dir 'quickjs-ng>=0.17.0.2' -w wheels
                "$PY" -m pip wheel . -w wheels
                echo "quickjs-ng wheel: $(find wheels -maxdepth 1 -name 'quickjs_ng-*.whl' -printf '%f\n' | tail -1)"
            fi
        done
    else
        # Native runner (macOS/Windows) — dotted version numbers
        for pyver in 3.10 3.11 3.12 3.13 3.14; do
            uv python install "$pyver" || continue
            PY=$(find_python "$pyver") || continue
            if [ -n "$PY" ]; then
                echo "Building wheels for Python $pyver"
                "$PY" -m pip wheel --no-cache-dir 'quickjs-ng>=0.17.0.2' -w wheels
                "$PY" -m pip wheel . -w wheels
                echo "quickjs-ng wheel: $(find wheels -maxdepth 1 -name 'quickjs_ng-*.whl' -printf '%f\n' | tail -1)"
            fi
        done
    fi
}

# --- Binary building ---

# The system package steps below need root. CI containers run as root; the
# local Docker runs use the host user and a derived image (docker_image_with)
# that already ran these steps, so the functions skip when not root.
is_root() { [ "$(id -u)" = 0 ]; }

# Install upx per platform
install_upx() {
    OS=$(get_os)
    case "$OS" in
        linux-musl)
            is_root || return 0
            apk add --no-cache upx 2>/dev/null || true
            ;;
        linux-glibc)
            is_root || return 0
            # Nuitka detects ccache automatically. Its cache is mounted by
            # build.yml, avoiding another full C compilation on later runs.
            yum install -y upx ccache 2>/dev/null || dnf install -y upx ccache 2>/dev/null || true
            ;;
        mac)
            brew install upx
            ;;
        windows)
            choco install upx -y
            ;;
    esac
}

# Install system build dependencies for Alpine
install_alpine_deps() {
    is_root || return 0
    apk add --no-cache curl gcc musl-dev libffi-dev ccache upx
}

# Install the newest uv-managed (python-build-standalone) CPython of PY_MINOR
# and set PY to it. python-build-standalone ships new patch releases within a
# day of python.org and provides musl builds, unlike distro or image pythons.
install_managed_python() {
    # uv only knows the Python releases that existed when it was released, and
    # images may ship an older uv, so put the latest one first on PATH
    curl -LsSf https://astral.sh/uv/install.sh | UV_NO_MODIFY_PATH=1 sh
    export PATH="$HOME/.local/bin:$PATH"
    uv --version
    uv python install "$PY_MINOR"
    PY=$(uv python find --no-project --managed-python "$PY_MINOR")
}

# Set PY to the interpreter to bundle for this platform, validate its minor,
# and warn (without failing) if python.org has a newer patch.
# Linux glibc compares the manylinux image's python with a freshly installed
# uv-managed one and uses whichever is newer (no python.org lookup); musl
# always uses a uv-managed one (Alpine's apk python is a different minor
# release); macOS always uses a uv-managed one because setup-python's macOS
# CPython links Homebrew's OpenSSL by absolute path.
select_python() {
    OS=$(get_os)
    PY=""
    case "$OS" in
        linux-musl|mac)
            install_managed_python
            ;;
        linux-glibc)
            MANYLINUX_PY="/opt/python/cp$(echo "$PY_MINOR" | tr -d .)-cp$(echo "$PY_MINOR" | tr -d .)/bin/python3"
            install_managed_python
            MANYLINUX_VERSION=$("$MANYLINUX_PY" -V | awk '{print $2}')
            MANAGED_VERSION=$("$PY" -V | awk '{print $2}')
            if [ "$(printf '%s\n%s\n' "$MANYLINUX_VERSION" "$MANAGED_VERSION" | sort -V | tail -1)" = "$MANYLINUX_VERSION" ]; then
                PY="$MANYLINUX_PY"
            fi
            ;;
        windows)
            PY=$(uv python find "$PY_MINOR")
            ;;
    esac
    if [ "$OS" = "windows" ]; then
        "$PY" tools.py --check-embed
    else
        "$PY" tools.py --check-python
    fi
}

# Resolve and validate the interpreter that build_binary will bundle.
check_bundled_python() {
    NAME="$1"
    OS=$(get_os)
    case "$OS" in
        linux-musl) install_alpine_deps ;;
        linux-glibc) setup_manylinux ;;
        mac|windows) ensure_uv ;;
    esac
    select_python
    echo "Python bundled in ${NAME}: $("$PY" -V) ($PY)"
}

smoke_binary() {
    NAME="$1"
    OS=$(get_os)
    PXBIN="px.dist-${NAME}/px.dist/px"
    if [ "$OS" = "windows" ]; then
        PXBIN="px.dist-${NAME}/px.dist/px.exe"
    fi

    echo "Smoke check ssl and spnego imports: $PXBIN --help"
    # Px imports ssl and pyspnego before handling --help, reporting a missing
    # or unloadable dependency before artifact tests begin.
    if ! OUT=$("$PXBIN" --help 2>&1); then
        echo "$OUT" | head -20
        echo "ERROR: $PXBIN --help failed"
        return 1
    fi
    if echo "$OUT" | grep -q "Requires module"; then
        echo "$OUT" | head -20
        echo "ERROR: $PXBIN could not import a required module"
        return 1
    fi

    # The build host has Homebrew, so loading can succeed here while failing
    # on any other Mac: check install names instead
    if [ "$OS" = "mac" ]; then
        "${PY:-python3}" tools.py --check-portable "px.dist-${NAME}/px.dist"
    fi
}

# Set up manylinux static libs
setup_manylinux() {
    is_root || return 0
    if [ -f "/opt/_internal/static-libs-for-embedding-only.tar.xz" ]; then
        (cd /opt/_internal && tar xf static-libs-for-embedding-only.tar.xz)
    fi
}

# Install pymcurl from the PyPI release only: never from the wheels directory
# or the uv cache, where a stale wheel with the same version label can hide
install_released_pymcurl() {
    uv pip install --no-cache --reinstall-package pymcurl "pymcurl>=$PYMCURL_MIN"
}

build_binary() {
    NAME="$1"
    WHEELS="px.dist-${NAME}-wheels/px.dist"
    OS=$(get_os)

    case "$OS" in
        linux-musl)
            install_alpine_deps
            select_python
            "$PY" -m venv .venv
            . .venv/bin/activate
            uv pip install 'patchelf==0.17.2.4'
            install_released_pymcurl
            uv pip install "nuitka==$NUITKA_VERSION" auditwheel
            uv pip install px-proxy --no-index -f "$WHEELS"
            log_quickjs_version python
            python tools.py --check-mcurl
            python tools.py --nuitka
            python tools.py --depspkg
            ;;
        linux-glibc)
            install_upx
            setup_manylinux
            ensure_uv
            select_python
            "$PY" -m venv .venv
            . .venv/bin/activate
            install_released_pymcurl
            uv pip install "nuitka==$NUITKA_VERSION" auditwheel
            uv pip install px-proxy --no-index -f "$WHEELS"
            log_quickjs_version python
            python tools.py --check-mcurl
            python tools.py --nuitka
            python tools.py --depspkg
            ;;
        mac)
            install_upx
            ensure_uv
            select_python
            rm -rf .venv
            "$PY" -m venv .venv
            . .venv/bin/activate
            install_released_pymcurl
            uv pip install "nuitka==$NUITKA_VERSION"
            uv pip install px-proxy --no-index -f "$WHEELS"
            log_quickjs_version python
            python tools.py --check-ssl
            python tools.py --nuitka
            python tools.py --depspkg
            ;;
        windows)
            install_upx
            ensure_uv
            select_python
            uv pip install pymcurl -f "$WHEELS"
            uv run --locked python -c "import importlib.metadata as m; print(\"quickjs-ng version:\", m.version(\"quickjs-ng\"))"
            uv run --no-sync python tools.py --embed
            uv run --no-sync python tools.py --depspkg
            ;;
    esac

    # Keep local release checks aligned with the CI smoke step.
    smoke_binary "$NAME" || return 1

    # Serve real requests through the binary so one that cannot is never
    # published (Linux: the venv python of this job runs the client side)
    case "$OS" in
        linux-*) python tools.py --smoke-request "px.dist-${NAME}/px.dist/px" || return 1 ;;
    esac
}

# --- Archive extraction ---

extract_archives() {
    NAME="$1"

    # Extract binary archive into px.dist-{name}/px.dist/
    mkdir -p "px.dist-${NAME}/px.dist"
    for f in "px.dist-${NAME}"/px-v*-"${NAME}".tar.gz; do
        [ -f "$f" ] && tar xf "$f" -C "px.dist-${NAME}/px.dist"
    done
    for f in "px.dist-${NAME}"/px-v*-"${NAME}".zip; do
        [ -f "$f" ] && unzip -q "$f" -d "px.dist-${NAME}/px.dist"
    done

    # Extract wheels archive into px.dist-{name}-wheels/px.dist/
    mkdir -p "px.dist-${NAME}-wheels/px.dist"
    for f in "px.dist-${NAME}-wheels"/px-v*-wheels.tar.gz; do
        [ -f "$f" ] && tar xf "$f" -C "px.dist-${NAME}-wheels/px.dist"
    done
    for f in "px.dist-${NAME}-wheels"/px-v*-wheels.zip; do
        [ -f "$f" ] && unzip -q "$f" -d "px.dist-${NAME}-wheels/px.dist"
    done

    # Debug: show what was extracted
    ls -la "px.dist-${NAME}/px.dist/" || true
    ls -la "px.dist-${NAME}-wheels/px.dist/" || true
}

# --- Test binary ---

# Install curl in the test container if missing (needs root, see is_root)
install_test_deps() {
    command -v curl > /dev/null 2>&1 && return 0
    is_root || {
        echo "ERROR: curl is missing and this is not root; preinstall it in the image" >&2
        return 1
    }
    if command -v apk > /dev/null; then
        apk add --no-cache curl
    else
        apt-get update -qq
        apt-get install -y -qq curl > /dev/null
    fi
}

test_binary() {
    NAME="$1"
    OS=$(get_os)

    # Set paths
    PXBIN="px.dist-${NAME}/px.dist/px"
    if [ "$OS" = "windows" ]; then
        PXBIN="px.dist-${NAME}/px.dist/px.exe"
    fi
    WHEELS="px.dist-${NAME}-wheels/px.dist"
    PXWHEEL=""
    for whl in "$WHEELS"/px_proxy*.whl; do
        [ -f "$whl" ] && PXWHEEL="$whl" && break
    done
    if [ -z "$PXWHEEL" ]; then
        echo "ERROR: No px_proxy wheel found in $WHEELS"
        return 1
    fi

    # Load the artifact on this clean runner or container before the long
    # suite so a missing library fails in seconds rather than as timeouts
    smoke_binary "$NAME" || return 1

    if [ "$OS" = "linux-musl" ] || [ "$OS" = "linux-glibc" ]; then
        # Inside container — install curl if needed (before ensure_uv)
        install_test_deps || return 1

        ensure_uv

        # Prefer non-free-threaded Python for the tox driver venv so the
        # 'binary' tox environment does not default to a free-threaded ABI
        # (cp314t) that abi3 wheels like psutil cannot satisfy. Pin it to 3.14,
        # the newest version the wheels are built for: without a system Python
        # (the ubuntu image) uv would otherwise download the newest release
        # (3.15), for which there are no uvloop wheels.
        if [ -d /opt/python/cp314-cp314/bin ]; then
            export PATH=/opt/python/cp314-cp314/bin:$PATH
        fi

        # Run tests with tox in a venv
        uv venv --python 3.14 /tmp/tox-env
        . /tmp/tox-env/bin/activate
        uv pip install tox tox-uv
        # The Python tox environments exercise the installed release wheel at
        # each supported Python version. Only the binary environment receives
        # PXBIN, so it alone runs the compiled executable instead of repeating
        # that same binary suite once per Python.
        tox --parallel 2 -e py310,py311,py312,py313,py314 --installpkg "$PXWHEEL" \
            --override "tool.tox.env_run_base.install_command=uv pip install --no-index -f $WHEELS" \
            --workdir /tmp
        PXBIN="$PXBIN" tox -e binary --installpkg "$PXWHEEL" \
            --override "tool.tox.env_run_base.install_command=uv pip install --no-index -f $WHEELS" \
            --workdir /tmp
    else
        # Native runner (macOS/Windows)
        ensure_uv
        if [ "$OS" = "mac" ]; then
            # Python from setup-python or Homebrew stalls every name lookup
            # on macOS 15+ runners; uv-managed CPython does not
            export UV_PYTHON_PREFERENCE=only-managed
        fi
        PYTEST_CMD="pytest -n 2 tests --durations=30"
        if [ "${PX_CI_MINIMAL:-}" = "1" ]; then
            # Keep macOS artifact testing aligned with ci.yml's full matrix:
            # only its unsupported network test is excluded; slow tests run.
            PYTEST_CMD="pytest -n 2 tests --ignore=tests/test_network.py --durations=30"
        fi
        uv pip install tox tox-uv
        uv run --locked tox --parallel 2 -e py310,py311,py312,py313,py314 --installpkg "$PXWHEEL" \
            --override "tool.tox.env_run_base.install_command=uv pip install --no-index -f $WHEELS" \
            --override "tool.tox.env_run_base.commands=$PYTEST_CMD"
        PXBIN="$PXBIN" uv run --locked tox -e binary --installpkg "$PXWHEEL" \
            --override "tool.tox.env_run_base.install_command=uv pip install --no-index -f $WHEELS" \
            --override "tool.tox.env_run_base.commands=$PYTEST_CMD"
    fi
}

# --- Local build and test ---

# Container images and shells of a local Linux x86_64 target (musl|glibc);
# keep in sync with the wheels, binary and test-binary matrices in build.yml
target_config() {
    case "$1" in
        musl)
            NAME="linux-musl-x86_64"
            WHEELS_IMAGE="quay.io/pypa/musllinux_1_2_x86_64"
            BINARY_IMAGE="alpine:3.21"
            BINARY_SHELL="/bin/sh"
            BINARY_SETUP="install_alpine_deps"
            TEST_IMAGE="$WHEELS_IMAGE"
            TEST_SHELL="/bin/bash"
            ;;
        glibc)
            NAME="linux-glibc-x86_64"
            WHEELS_IMAGE="quay.io/pypa/manylinux2014_x86_64"
            BINARY_IMAGE="$WHEELS_IMAGE"
            BINARY_SHELL="/bin/bash"
            BINARY_SETUP="install_upx setup_manylinux"
            TEST_IMAGE="${TEST_IMAGE_GLIBC:-ubuntu}"
            TEST_SHELL="/bin/bash"
            ;;
        *) return 1 ;;
    esac
}

# Containers that mount a checkout run as the host user, never root, so no
# root-owned entry is ever written to the mount. Root-only steps (system
# packages) run at image build time, not on the mount.

# docker_image_with <image> <shell> <function>...: print the tag of <image> with
# the given build.sh root setup functions already run (a derived image made by
# docker commit of a root container that mounts nothing writable; cached per
# build.sh content); print <image> itself when there are none
docker_image_with() {
    _dimg="$1" _dsh="$2"
    shift 2
    [ $# -gt 0 ] || { echo "$_dimg"; return 0; }
    _dtag="px-build:$(printf '%s-%s-%s' "$_dimg" "$*" "$(sha256sum build.sh | cut -c1-12)" | tr 'A-Z /:' 'a-z---' | tr -cd 'a-z0-9._-')"
    if ! docker image inspect "$_dtag" > /dev/null 2>&1; then
        _dname="px-build-$$"
        _dfns="$(printf ' && %s' "$@")"
        docker run --name "$_dname" -v "$(pwd)/build.sh":/tmp/build.sh:ro "$_dimg" "$_dsh" -c ". /tmp/build.sh$_dfns" >&2 &&
            docker commit "$_dname" "$_dtag" > /dev/null || { docker rm -f "$_dname" > /dev/null 2>&1; return 1; }
        docker rm "$_dname" > /dev/null
    fi
    echo "$_dtag"
}

# docker_run_user <dir> <image> <shell> <setup> <script> [docker args...]: run a
# script in a container with <dir> at /px as the host user. <setup> is a quoted
# list of root-only build.sh functions run in a derived image first. HOME and
# the tool caches live in /tmp inside the container.
docker_run_user() {
    _ddir="$1" _dimage="$2" _dsh="$3" _dsetup="$4" _dscript="$5"
    shift 5
    # shellcheck disable=SC2086
    _drun="$(docker_image_with "$_dimage" "$_dsh" $_dsetup)" || return 1
    _dh=/tmp/home
    docker run --rm "$@" --user "$(id -u):$(id -g)" -v "$_ddir":/px -w /px \
        -e HOME=$_dh -e USER="$(id -un)" -e LOGNAME="$(id -un)" \
        -e XDG_CACHE_HOME=$_dh/.cache -e XDG_DATA_HOME=$_dh/.local/share \
        -e UV_CACHE_DIR=$_dh/.cache/uv -e PIP_CACHE_DIR=$_dh/.cache/pip \
        -e UV_PYTHON_INSTALL_DIR=$_dh/.local/share/uv/python \
        -e NUITKA_CACHE_DIR=$_dh/.cache/Nuitka -e CCACHE_DIR=$_dh/.ccache \
        "$_drun" "$_dsh" -c "mkdir -p $_dh && $_dscript"
}

# find_non_host_owned <dir>...: print non-device entries not owned by the host
# user. On Linux, mount points below the checked trees are pruned because the
# sandbox mounts its own uid-65534 placeholders there.
find_non_host_owned() {
    for _droot in "$@"; do
        _droot="$(cd "$_droot" && pwd -P)" || return 1
        _dmounts=""
        if [ -r /proc/self/mountinfo ]; then
            _dmounts="$(awk -v root="$_droot/" 'index($5, root) == 1 { print $5 }' /proc/self/mountinfo |
                while IFS= read -r _dmount; do printf '%b\n' "$_dmount"; done)"
        fi
        # -xdev avoids descent into nested sandbox mounts; filter their mount
        # points too, since find still visits the mount point itself.
        find "$_droot" -xdev ! -type c ! -user "$(id -u)" -print 2>/dev/null |
            while IFS= read -r _dentry; do
                if [ -n "$_dmounts" ] &&
                    printf '%s\n' "$_dmounts" | grep -F -x -- "$_dentry" >/dev/null; then
                    continue
                fi
                printf '%s\n' "$_dentry"
            done
    done
}

# check_no_root_files <dir>...: fail if a mounted tree holds entries not owned by
# the host user (a container wrote to the mount as a different user). Skipped when
# the host user is root. Device nodes and nested mount points are ignored.
check_no_root_files() {
    [ "$(id -u)" != 0 ] || return 0
    _dfound="$(find_non_host_owned "$@" | head -20)"
    [ -z "$_dfound" ] || {
        printf 'ERROR: files not owned by the host user in a mounted tree (containers must run as the host user):\n%s\n' "$_dfound" >&2
        return 1
    }
}

# Build wheels, binary, and run tests locally using Docker containers
# Usage: . ./build.sh && build_local [musl|glibc]
build_local() {
    TYPE="${1:-musl}"
    target_config "$TYPE" || {
        echo "Usage: build_local [musl|glibc]"
        return 1
    }

    WHEELS_DIR="px.dist-${NAME}-wheels/px.dist"

    echo "=== Building sdist ==="
    # Release builds intentionally resolve the latest quickjs-ng.
    uv sync --upgrade-package quickjs-ng
    uv pip install build twine
    uv run --locked python tools.py --wheel || return 1

    echo "=== Building wheels in $WHEELS_IMAGE ==="
    docker_run_user "$(pwd)" "$WHEELS_IMAGE" /bin/bash "" \
        ". /px/build.sh && build_wheels" || return 1
    check_no_root_files "$(pwd)" || return 1

    # Move wheels into expected location for build_binary
    rm -rf "px.dist-${NAME}-wheels"
    mkdir -p "$WHEELS_DIR"
    cp wheels/*.whl "$WHEELS_DIR/"

    echo "=== Building binary in $BINARY_IMAGE ==="
    docker_run_user "$(pwd)" "$BINARY_IMAGE" "$BINARY_SHELL" "$BINARY_SETUP" \
        "rm -rf .venv && . /px/build.sh && build_binary $NAME" || return 1
    check_no_root_files "$(pwd)" || return 1

    echo "=== Extracting archives ==="
    extract_archives "$NAME"

    echo "=== Testing binary in $TEST_IMAGE ==="
    docker_run_user "$(pwd)" "$TEST_IMAGE" "$TEST_SHELL" install_test_deps \
        "rm -rf .venv && . /px/build.sh && test_binary $NAME" --privileged || return 1
    check_no_root_files "$(pwd)" || return 1

    echo "=== All done ==="
}

# --- Local release check ---

# Local replica of build.yml's Linux x86_64 release jobs (sdist, wheels, binary,
# test-binary) using the same containers, commands and artifact hand-offs, plus
# the real-Px scenario suite against the Docker corporate-proxy lab
# (tests/scenarios/env/scenario-env.sh). Run before dispatching build.yml.
# Usage: ./build.sh release_check [--fresh] [glibc|musl|scenario|all]
# Environment: RELEASE_CHECK_DIR (work dir, default /tmp/px-release-check),
#   UV_PYTHON (host sdist build, default 3.14), TEST_IMAGE_GLIBC (glibc test
#   container, default ubuntu).
# The working tree (tracked and untracked, not ignored) is copied per job, so
# the checkout is never touched. Finished stages are skipped on re-runs while
# the tree is unchanged; --fresh starts over. The scenario stage runs against
# the checkout and is skipped, not failed, when Docker is unavailable.

rc_log() { printf '\n=== %s ===\n' "$*"; }

rc_check_workflow() {
    for img in "$@"; do
        grep -q "image: \"$img\"\|container: \"$img\"" .github/workflows/build.yml || {
            echo "build.yml no longer references $img; update target_config in build.sh" >&2
            return 1
        }
    done
}

# Regular files only: skips deleted paths and non-file placeholders
rc_tree_files() {
    git ls-files -z --cached --others --exclude-standard --deduplicate |
        xargs -0 sh -c 'for f; do if [ -f "$f" ]; then printf "%s\0" "$f"; fi; done' sh
}

rc_prepare() {
    [ "$(cat "$1/.tree-hash" 2>/dev/null)" != "$RC_HASH" ] || return 0
    mkdir -p "$1"
    rm -f "$1"/.done-*
    rc_tree_files | tar --null -T - -cf - | tar -C "$1" -xf -
    echo "$RC_HASH" > "$1/.tree-hash"
}

# rc_stage <dir> <name> <command...>: run once, remember success
rc_stage() {
    _dir="$1" _name="$2"
    shift 2
    if [ -f "$_dir/.done-$_name" ]; then echo "(skipping $_name: already done in $_dir)"; return 0; fi
    "$@"
    touch "$_dir/.done-$_name"
}

# rc_run_in <dir> <image> <shell> <setup> <script> [docker args...]: run a
# build.sh function in a container as the host user with the tree at /px, then
# fail if the container left root-owned entries in the tree
rc_run_in() {
    _rc=0
    docker_run_user "$@" || _rc=$?
    check_no_root_files "$1" || return 1
    return "$_rc"
}

rc_sdist() {
    rc_log "sdist (host, uv with latest quickjs-ng, as the sdist job)"
    rc_prepare "$RC_ROOT/sdist"
    rc_stage "$RC_ROOT/sdist" sdist sh -c "cd '$RC_ROOT/sdist' && uv sync --upgrade-package quickjs-ng &&
        uv pip install -e . && uv pip install build twine && uv run --locked python tools.py --wheel"
}

rc_target() {
    target_config "$1"
    rc_log "$NAME: wheels in $WHEELS_IMAGE"
    rc_prepare "$RC_ROOT/$1/wheels"
    rc_stage "$RC_ROOT/$1/wheels" wheels rc_run_in "$RC_ROOT/$1/wheels" "$WHEELS_IMAGE" /bin/bash "" \
        ". /px/build.sh && build_wheels"

    rc_log "$NAME: binary in $BINARY_IMAGE"
    _b="$RC_ROOT/$1/binary" _t="$RC_ROOT/$1/test"
    rc_prepare "$_b"
    # wheels artifact -> px.dist-NAME-wheels/px.dist/, sdist artifact -> wheel/
    mkdir -p "$_b/px.dist-$NAME-wheels/px.dist" "$_b/wheel"
    cp "$RC_ROOT/$1"/wheels/wheels/*.whl "$_b/px.dist-$NAME-wheels/px.dist/"
    cp "$RC_ROOT"/sdist/wheel/* "$_b/wheel/"
    rc_stage "$_b" binary rc_run_in "$_b" "$BINARY_IMAGE" "$BINARY_SHELL" "$BINARY_SETUP" \
        ". /px/build.sh && build_binary $NAME"

    rc_log "$NAME: test-binary in $TEST_IMAGE"
    rc_prepare "$_t"
    # binary artifact (px.dist-*/px-v*) -> fresh checkout, as test-binary downloads it
    (cd "$_b" && for f in px.dist-*/px-v*; do mkdir -p "$_t/$(dirname "$f")" && cp "$f" "$_t/$f"; done)
    rc_stage "$_t" extract sh -c "cd '$_t' && . ./build.sh && extract_archives $NAME"
    rc_stage "$_t" test rc_run_in "$_t" "$TEST_IMAGE" /bin/sh install_test_deps \
        ". /px/build.sh && test_binary $NAME" --privileged
    rc_log "$NAME: PASSED"
}

rc_scenario() {
    rc_log "scenario: corporate proxy lab suite"
    if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then
        echo "Docker is not available; skipping the scenario stage" >&2
        return 0
    fi
    export SCENARIO_INSTANCE="${SCENARIO_INSTANCE:-$(( $$ % 50 + 1 ))}"
    tests/scenarios/env/scenario-env.sh up
    _rc=0
    tests/scenarios/env/scenario-env.sh test tests/scenarios -m scenario -v --durations=30 || _rc=$?
    tests/scenarios/env/scenario-env.sh down
    [ "$_rc" -eq 0 ] || return "$_rc"
    rc_log "scenario: PASSED"
}

release_check() {
    RC_FRESH=0 RC_TARGETS=""
    for _arg in "$@"; do
        case "$_arg" in
            --fresh) RC_FRESH=1 ;;
            glibc|musl|scenario) RC_TARGETS="$RC_TARGETS $_arg" ;;
            all) RC_TARGETS="$RC_TARGETS glibc musl scenario" ;;
            *) echo "Usage: release_check [--fresh] [glibc|musl|scenario|all]" >&2; return 2 ;;
        esac
    done
    RC_TARGETS="${RC_TARGETS:-glibc musl scenario}"
    RC_ROOT="${RELEASE_CHECK_DIR:-/tmp/px-release-check}"
    export UV_PYTHON="${UV_PYTHON:-3.14}"
    cd "$(dirname "$0")"

    target_config glibc && _imgs="$WHEELS_IMAGE $BINARY_IMAGE"
    target_config musl && _imgs="$_imgs $WHEELS_IMAGE $BINARY_IMAGE $TEST_IMAGE"
    rc_check_workflow $_imgs
    RC_HASH="$(rc_tree_files | tar --null -T - -cf - | sha256sum | cut -d' ' -f1)"
    [ "$RC_FRESH" = 0 ] || rm -rf "$RC_ROOT"
    mkdir -p "$RC_ROOT"
    case "$RC_TARGETS" in *glibc*|*musl*) rc_sdist ;; esac
    for _t in $RC_TARGETS; do
        case "$_t" in scenario) rc_scenario ;; *) rc_target "$_t" ;; esac
    done
    check_no_root_files "$RC_ROOT" . || return 1
    rc_log "release check passed for:$RC_TARGETS (work dir: $RC_ROOT)"
}

# Run a function directly: ./build.sh <function> [args]
case "${0##*/}" in
    build.sh)
        if [ $# -eq 0 ]; then
            echo "Usage: ./build.sh <function> [args], e.g. build_local [musl|glibc] or release_check [--fresh] [glibc|musl|scenario|all]" >&2
            exit 2
        fi
        "$@"
        ;;
esac
