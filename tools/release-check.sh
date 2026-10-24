#!/usr/bin/env bash
# Local replica of build.yml's Linux x86_64 release jobs (sdist, wheels,
# binary, test-binary) using the same containers, commands and artifact
# hand-offs as the workflow. Run this before dispatching build.yml.
#
# Usage: tools/release-check.sh [--fresh] [glibc|musl|all]
#
# Environment:
#   RELEASE_CHECK_DIR  work directory (default: px-release-check under
#                      $ORC_SCRATCH_DIR or /tmp); one copy of the tree per job
#   UV_PYTHON          Python for the host sdist build (default: 3.13)
#   TEST_IMAGE_GLIBC   glibc test-binary container (default: ubuntu, as in build.yml)
#
# The current working tree (tracked and untracked, not ignored) is copied for
# each job, so the checkout is never touched. Finished stages are recorded in
# the work directory and skipped on re-runs while the tree is unchanged;
# --fresh starts over.

set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ROOT="${RELEASE_CHECK_DIR:-${ORC_SCRATCH_DIR:-/tmp}/px-release-check}"
export UV_PYTHON="${UV_PYTHON:-3.13}"

FRESH=0
TARGETS=()
for arg in "$@"; do
    case "$arg" in
        --fresh) FRESH=1 ;;
        glibc|musl) TARGETS+=("$arg") ;;
        all) TARGETS+=(glibc musl) ;;
        *) echo "Usage: $0 [--fresh] [glibc|musl|all]" >&2; exit 2 ;;
    esac
done
[ ${#TARGETS[@]} -gt 0 ] || TARGETS=(glibc musl)

# Keep in sync with the wheels, binary and test-binary matrices in build.yml
# (verified by check_workflow below).
glibc_name=linux-glibc-x86_64
glibc_wheels_image=quay.io/pypa/manylinux2014_x86_64
glibc_binary_image=quay.io/pypa/manylinux2014_x86_64
glibc_binary_shell=/bin/bash
glibc_test_image="${TEST_IMAGE_GLIBC:-ubuntu}"
musl_name=linux-musl-x86_64
musl_wheels_image=quay.io/pypa/musllinux_1_2_x86_64
musl_binary_image=alpine:3.21
musl_binary_shell=/bin/sh
musl_test_image=quay.io/pypa/musllinux_1_2_x86_64

UIDGID="$(id -u):$(id -g)"

log() { printf '\n=== %s ===\n' "$*"; }

check_workflow() {
    local wf="$REPO/.github/workflows/build.yml" img
    for img in "$glibc_wheels_image" "$glibc_binary_image" "$musl_wheels_image" "$musl_binary_image" "$musl_test_image"; do
        grep -q "image: \"$img\"\|container: \"$img\"" "$wf" || {
            echo "build.yml no longer references $img; update tools/release-check.sh" >&2
            exit 1
        }
    done
}

# Regular files only: skips deleted paths and non-file placeholders
tree_files() {
    git -C "$REPO" ls-files -z --cached --others --exclude-standard --deduplicate |
        while IFS= read -r -d '' f; do
            if [ -f "$REPO/$f" ]; then printf '%s\0' "$f"; fi
        done
}

# Fingerprint of the files copy_tree copies; stale stage results are dropped
# when it changes so a re-run never reports on an older tree
tree_hash() {
    tree_files | tar -C "$REPO" --null -T - -cf - | sha256sum | cut -d' ' -f1
}

copy_tree() {
    mkdir -p "$1"
    rm -f "$1"/.done-*
    tree_files | tar -C "$REPO" --null -T - -cf - | tar -C "$1" -xf -
    echo "$TREE_HASH" > "$1/.tree-hash"
}

# stage <dir> <name> <command...>: run once, remember success
stage() {
    local dir="$1" name="$2"
    shift 2
    if [ -f "$dir/.done-$name" ]; then
        echo "(skipping $name: already done in $dir)"
        return
    fi
    "$@"
    touch "$dir/.done-$name"
}

# run_in <dir> <image> <shell> <script> [docker args...]: run a build.sh
# function in a container with the tree mounted at /px, then give the files
# back to the host user so the work directory stays removable
run_in() {
    local dir="$1" image="$2" shell="$3" script="$4" rc=0
    shift 4
    docker run --rm "$@" -v "$dir":/px -w /px "$image" "$shell" -c \
        "$script; RC=\$?; chown -R $UIDGID /px 2>/dev/null || true; exit \$RC" || rc=$?
    return $rc
}

build_sdist() {
    local dir="$ROOT/sdist"
    log "sdist (host, uv with latest quickjs-ng, as the sdist job)"
    if [ "$FRESH" = 1 ]; then rm -rf "$dir"; fi
    stage_dir_prepare "$dir"
    stage "$dir" sdist bash -c "cd '$dir' && uv sync --upgrade-package quickjs-ng && uv pip install -e . &&
        uv pip install build twine && uv run --locked python tools.py --wheel"
}

stage_dir_prepare() {
    if [ "$(cat "$1/.tree-hash" 2>/dev/null)" != "$TREE_HASH" ]; then copy_tree "$1"; fi
}

run_target() {
    local t="$1" name wheels_image binary_image binary_shell test_image
    eval "name=\$${t}_name wheels_image=\$${t}_wheels_image binary_image=\$${t}_binary_image
          binary_shell=\$${t}_binary_shell test_image=\$${t}_test_image"
    local wdir="$ROOT/$t/wheels" bdir="$ROOT/$t/binary" tdir="$ROOT/$t/test"

    log "$name: wheels in $wheels_image"
    if [ "$FRESH" = 1 ]; then rm -rf "$ROOT/$t"; fi
    stage_dir_prepare "$wdir"
    stage "$wdir" wheels run_in "$wdir" "$wheels_image" /bin/bash \
        ". /px/build.sh && build_wheels"

    log "$name: binary in $binary_image"
    stage_dir_prepare "$bdir"
    # wheels artifact -> px.dist-NAME-wheels/px.dist/, sdist artifact -> wheel/
    mkdir -p "$bdir/px.dist-$name-wheels/px.dist" "$bdir/wheel"
    cp "$wdir"/wheels/*.whl "$bdir/px.dist-$name-wheels/px.dist/"
    cp "$ROOT"/sdist/wheel/* "$bdir/wheel/"
    stage "$bdir" check-python run_in "$bdir" "$binary_image" "$binary_shell" \
        ". /px/build.sh && check_bundled_python $name"
    stage "$bdir" binary run_in "$bdir" "$binary_image" "$binary_shell" \
        ". /px/build.sh && build_binary $name"

    log "$name: test-binary in $test_image"
    stage_dir_prepare "$tdir"
    # binary artifact (px.dist-*/px-v*) -> fresh checkout, as test-binary downloads it
    (cd "$bdir" && for f in px.dist-*/px-v*; do mkdir -p "$tdir/$(dirname "$f")" && cp "$f" "$tdir/$f"; done)
    stage "$tdir" extract bash -c "cd '$tdir' && . ./build.sh && extract_archives $name"
    stage "$tdir" test run_in "$tdir" "$test_image" /bin/sh \
        ". /px/build.sh && test_binary $name" --privileged
    log "$name: PASSED"
}

check_workflow
TREE_HASH="$(tree_hash)"
mkdir -p "$ROOT"
build_sdist
for t in "${TARGETS[@]}"; do
    run_target "$t"
done
log "release check passed for: ${TARGETS[*]} (work dir: $ROOT)"
