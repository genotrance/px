#!/bin/sh
# CI helper functions for build.yml
# Usage: . ./build.sh && <function> [args]

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
# tools.py). The newest published patch release is always used, never a pinned
# patch version.
PY_MINOR="${PY_MINOR:-3.13}"
# Nuitka 4.2+ bundles SCons 4.10.1, which cannot select the linker in the
# manylinux2014 GCC 10 environment. Keep every binary target on the newest
# version validated there until upstream fixes that regression.
NUITKA_VERSION="4.1.3"

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

# Install upx per platform
install_upx() {
    OS=$(get_os)
    case "$OS" in
        linux-musl)
            apk add --no-cache upx 2>/dev/null || true
            ;;
        linux-glibc)
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
    PY=$(uv python find --managed-python "$PY_MINOR")
}

# Fail unless interpreter $1 is the newest published release of PY_MINOR
# (fetched from python.org at run time). Prints the bundled version.
check_python() {
    "$1" tools.py --check-python
}

# Set PY to the interpreter to bundle for this platform, failing early if it
# is not the newest published release of PY_MINOR. Linux glibc prefers the
# manylinux image's python and falls back to a uv-managed one when the image
# is stale; musl always uses a uv-managed one (Alpine's apk python is a
# different minor release); macOS uses setup-python (check-latest).
select_python() {
    OS=$(get_os)
    PY=""
    case "$OS" in
        linux-musl)
            install_managed_python
            ;;
        linux-glibc)
            PY="/opt/python/cp$(echo "$PY_MINOR" | tr -d .)-cp$(echo "$PY_MINOR" | tr -d .)/bin/python3"
            if ! check_python "$PY"; then
                echo "manylinux python is stale, using uv-managed CPython $PY_MINOR"
                install_managed_python
            fi
            ;;
        mac|windows)
            PY=$(uv python find "$PY_MINOR")
            ;;
    esac
    if [ "$OS" = "windows" ]; then
        "$PY" tools.py --check-embed
    else
        check_python "$PY"
    fi
}

# Pre-build guard: resolve the interpreter that build_binary will bundle and
# fail if it is not the newest published release of PY_MINOR
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

    echo "Smoke check auth imports: $PXBIN --help"
    "$PXBIN" --help > /dev/null
}

# Set up manylinux static libs
setup_manylinux() {
    if [ -f "/opt/_internal/static-libs-for-embedding-only.tar.xz" ]; then
        (cd /opt/_internal && tar xf static-libs-for-embedding-only.tar.xz)
    fi
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
            uv pip install "nuitka==$NUITKA_VERSION" auditwheel pymcurl -f "$WHEELS"
            uv pip install px-proxy --no-index -f "$WHEELS"
            log_quickjs_version python
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
            uv pip install "nuitka==$NUITKA_VERSION" auditwheel pymcurl -f "$WHEELS"
            uv pip install px-proxy --no-index -f "$WHEELS"
            log_quickjs_version python
            python tools.py --nuitka
            python tools.py --depspkg
            ;;
        mac)
            install_upx
            ensure_uv
            select_python
            uv pip install "nuitka==$NUITKA_VERSION" pymcurl -f "$WHEELS"
            uv run --locked python -c "import importlib.metadata as m; print(\"quickjs-ng version:\", m.version(\"quickjs-ng\"))"
            "$PY" tools.py --nuitka
            "$PY" tools.py --depspkg
            ;;
        windows)
            install_upx
            ensure_uv
            select_python
            uv pip install pymcurl -f "$WHEELS"
            uv run --locked python -c "import importlib.metadata as m; print(\"quickjs-ng version:\", m.version(\"quickjs-ng\"))"
            "$PY" tools.py --embed
            "$PY" tools.py --depspkg
            ;;
    esac

    # Keep local release checks aligned with the CI smoke step.
    smoke_binary "$NAME"
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

    if [ "$OS" = "linux-musl" ] || [ "$OS" = "linux-glibc" ]; then
        # Inside container — install curl if needed (before ensure_uv)
        if ! command -v curl > /dev/null 2>&1; then
            if command -v apk > /dev/null; then
                apk add --no-cache curl
            else
                apt-get update -qq
                apt-get install -y -qq curl > /dev/null
            fi
        fi

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

# Build wheels, binary, and run tests locally using Docker containers
# Usage: . ./build.sh && build_local [musl|glibc]
build_local() {
    TYPE="${1:-musl}"
    case "$TYPE" in
        musl)
            NAME="linux-musl-x86_64"
            WHEELS_IMAGE="quay.io/pypa/musllinux_1_2_x86_64"
            BINARY_IMAGE="alpine:3.21"
            BINARY_SHELL="/bin/sh"
            TEST_IMAGE="$WHEELS_IMAGE"
            TEST_SHELL="/bin/bash"
            ;;
        glibc)
            NAME="linux-glibc-x86_64"
            WHEELS_IMAGE="quay.io/pypa/manylinux2014_x86_64"
            BINARY_IMAGE="$WHEELS_IMAGE"
            BINARY_SHELL="/bin/bash"
            TEST_IMAGE="ubuntu"
            TEST_SHELL="/bin/bash"
            ;;
        *)
            echo "Usage: build_local [musl|glibc]"
            return 1
            ;;
    esac

    WHEELS_DIR="px.dist-${NAME}-wheels/px.dist"
    HOSTUID="$(id -u)"
    HOSTGID="$(id -g)"
    CHOWN="chown -R $HOSTUID:$HOSTGID"

    # Clean up root-owned leftovers from previous Docker runs that would
    # block the host-side tools.py --wheel (its rmtree loops forever on
    # permission errors)
    for d in build px_proxy.egg-info .venv; do
        if [ -d "$d" ] && [ "$(stat -c '%u' "$d")" != "$HOSTUID" ]; then
            sudo rm -rf "$d"
        fi
    done

    echo "=== Building sdist ==="
    # Release builds intentionally resolve the latest quickjs-ng.
    uv sync --upgrade-package quickjs-ng
    uv pip install build twine
    uv run --locked python tools.py --wheel || return 1

    echo "=== Building wheels in $WHEELS_IMAGE ==="
    docker run --rm -v "$(pwd)":/px -w /px \
        "$WHEELS_IMAGE" /bin/bash -c "
            . /px/build.sh && build_wheels
            RC=\$?; $CHOWN wheels/ 2>/dev/null || true; exit \$RC
        " || return 1

    # Move wheels into expected location for build_binary
    rm -rf "px.dist-${NAME}-wheels"
    mkdir -p "$WHEELS_DIR"
    cp wheels/*.whl "$WHEELS_DIR/"

    echo "=== Building binary in $BINARY_IMAGE ==="
    docker run --rm -v "$(pwd)":/px -w /px \
        "$BINARY_IMAGE" $BINARY_SHELL -c "
            rm -rf .venv && . /px/build.sh && build_binary $NAME
            RC=\$?; $CHOWN px.dist-* wheel/ build/ .venv px_proxy.egg-info 2>/dev/null || true; exit \$RC
        " || return 1

    echo "=== Extracting archives ==="
    extract_archives "$NAME"

    echo "=== Testing binary in $TEST_IMAGE ==="
    docker run --rm --privileged -v "$(pwd)":/px -w /px \
        "$TEST_IMAGE" $TEST_SHELL -c "
            rm -rf .venv && . /px/build.sh && test_binary $NAME
            RC=\$?; $CHOWN .venv 2>/dev/null || true; exit \$RC
        "

    echo "=== All done ==="
}
