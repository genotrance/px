#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
ENV_DIR="$ROOT/tests/scenarios/env"
ENV_FILE=${SCENARIO_ENV_FILE:-"$ENV_DIR/scenario.env"}
export SCENARIO_SOURCE_DIR="$ROOT"

# Instance 0 is the documented default lab. Each other instance gets its own
# Compose project, host ports, and subnet, so checkouts running in parallel
# never replace each other's containers.
INSTANCE=${SCENARIO_INSTANCE:-0}
if ! [[ "$INSTANCE" =~ ^[0-9]+$ ]] || ((INSTANCE > 50)); then
    echo "SCENARIO_INSTANCE must be an integer from 0 to 50" >&2
    exit 2
fi
PROJECT=px-scenario
((INSTANCE)) && PROJECT=px-scenario-$INSTANCE
OFFSET=$((INSTANCE * 10))
export SCENARIO_BASIC_PORT=$((31280 + OFFSET)) SCENARIO_DIGEST_PORT=$((31281 + OFFSET))
export SCENARIO_SSO_PORT=$((31282 + OFFSET)) SCENARIO_CLOSE_PORT=$((31283 + OFFSET))
export SCENARIO_PARENT_PORT=$((31284 + OFFSET)) SCENARIO_CHAIN_PORT=$((31285 + OFFSET))
export SCENARIO_TOXIPROXY_PORT=$((31286 + OFFSET)) SCENARIO_TOXIPROXY_API_PORT=$((8474 + OFFSET))
export SCENARIO_SSO_CLOSE_PORT=$((31287 + OFFSET)) SCENARIO_SSO_WRAPPER_PORT=$((31288 + OFFSET))
export SCENARIO_HTTP_ORIGIN_PORT=$((18080 + OFFSET)) SCENARIO_PAC_PORT=$((18081 + OFFSET))
export SCENARIO_HTTPS_ORIGIN_PORT=$((18443 + OFFSET)) SCENARIO_ECHO_PORT=$((18888 + OFFSET))
export SCENARIO_SUBNET=172.30.$INSTANCE
COMPOSE=(docker compose -p "$PROJECT" --project-directory "$ENV_DIR" -f "$ENV_DIR/compose.yaml")
if [[ ${SCENARIO_HOST_PORTS:-0} == 1 ]]; then
    COMPOSE+=(-f "$ENV_DIR/compose.host.yaml")
fi

# Sandboxed workers can talk to Docker but cannot write their mounted home
# directory. Keep Docker's mutable CLI state in the task scratch directory.
if [[ -z ${DOCKER_CONFIG:-} && ! -w "${HOME}/.docker" && ( -e "${HOME}/.docker" || ! -w "$HOME" ) ]]; then
    : "${ORC_SCRATCH_DIR:?ORC_SCRATCH_DIR is required when ~/.docker is not writable}"
    export DOCKER_CONFIG="$ORC_SCRATCH_DIR/docker-config-$PROJECT"
    mkdir -p "$DOCKER_CONFIG"
fi

check_owner() {
    # Refuse to drive a lab instance that another checkout started
    local owners
    owners=$(docker ps -a --filter "label=com.docker.compose.project=$PROJECT" \
        --format '{{.Label "com.docker.compose.project.working_dir"}}' | sort -u)
    if [[ -n "$owners" && "$owners" != "$ENV_DIR" ]]; then
        printf 'lab %s belongs to %s; set SCENARIO_INSTANCE to use another instance\n' \
            "$PROJECT" "$owners" >&2
        exit 1
    fi
}

print_env() {
    cat <<EOF
SCENARIO_INSTANCE=$INSTANCE
SCENARIO_COMPOSE_PROJECT=$PROJECT
SCENARIO_REALM=CORP.TEST
SCENARIO_DOMAIN=CORP
SCENARIO_USER=pxgood
SCENARIO_PASSWORD=GoodPass1!
SCENARIO_OTHER_USER=pxother
SCENARIO_OTHER_PASSWORD=OtherPass2!
SCENARIO_WRONG_PASSWORD=WrongPass9!
SCENARIO_BASIC_PROXY=http://squid-basic:3128
SCENARIO_DIGEST_PROXY=http://squid-digest:3128
SCENARIO_SSO_PROXY=http://squid-sso.corp.test:3128
SCENARIO_CLOSE_PROXY=http://squid-close:3128
SCENARIO_SSO_CLOSE_PROXY=http://squid-sso.corp.test:3129
SCENARIO_SSO_WRAPPER_PROXY=http://squid-sso.corp.test:3130
SCENARIO_PARENT_PROXY=http://squid-parent.corp.test:3128
SCENARIO_CHAIN_PROXY=http://squid-child:3128
SCENARIO_TOXIPROXY=http://toxiproxy:8666
SCENARIO_TOXIPROXY_API=http://toxiproxy:8474
SCENARIO_HTTP_ORIGIN=http://origin.corp.test:8080
SCENARIO_HTTPS_ORIGIN=https://origin.corp.test:8443
SCENARIO_PAC_URL=http://pac.corp.test:8081/proxy.pac
SCENARIO_ECHO=echo.corp.test:8888
SCENARIO_SQUID_LOG_DIR=/scenario-logs
SCENARIO_CA_FILE=tests/scenarios/env/origin-ca.crt
EOF
}

compose_exec() {
    "${COMPOSE[@]}" exec -T client "$@"
}

test() {
    # This suite includes the streamed-auth regression; fail rather than
    # letting pytest skip it when a devel pymcurl wheel was not supplied.
    local wheels="" require_mcurl_fix=1 started=0 status=0
    if [[ -n ${MCURL_WHEELS:-} ]]; then
        [[ -d $MCURL_WHEELS ]] || { echo "MCURL_WHEELS is not a directory: $MCURL_WHEELS" >&2; return 2; }
        # The host's relocked uv.lock records these wheels by absolute path
        # (a find-links registry), and the directory holds one wheel per
        # interpreter and platform, so mirror the whole directory at the same
        # path inside the client instead of picking a single wheel.
        wheels=$(cd "$MCURL_WHEELS" && pwd)
        [[ $wheels != / ]] || { echo "MCURL_WHEELS must not be /" >&2; return 2; }
        compgen -G "$wheels/pymcurl-*.whl" >/dev/null || { echo "no pymcurl wheel in MCURL_WHEELS=$MCURL_WHEELS" >&2; return 2; }
        require_mcurl_fix=1
    fi

    local -a pytest_args=("$@")
    if ((${#pytest_args[@]} == 0)); then
        pytest_args=(tests/scenarios -m scenario -v --durations=30)
    fi
    if [[ ${PX_SCENARIO_ENV:-} == start ]]; then
        "${COMPOSE[@]}" up --build --detach --wait --wait-timeout 180
        "${COMPOSE[@]}" cp origin:/shared/origin.crt "$ENV_DIR/origin-ca.crt"
        print_env | tee "$ENV_FILE"
        started=1
    fi
    if compose_exec sh -c 'rm -rf /tmp/px-venv "$1" && if [ -n "$1" ]; then mkdir -p "$1"; fi' sh "$wheels"; then
        :
    else
        status=$?
    fi
    if ((status == 0)) && [[ -n $wheels ]]; then
        if "${COMPOSE[@]}" cp "$wheels/." "client:$wheels/"; then
            :
        else
            status=$?
        fi
    fi
    if ((status == 0)) && "${COMPOSE[@]}" exec -T \
        -e "UV_PYTHON=${UV_PYTHON:-}" \
        -e "MCURL_WHEELS=$wheels" \
        -e "PX_EVENT_LOOP=${PX_EVENT_LOOP:-}" \
        -e "PX_REQUIRE_MCURL_FIX=$require_mcurl_fix" \
        client sh -ceu '
            # Build from a fresh copy so setuptools never writes egg-info into
            # the read-only checkout mount, while still testing this invocation
            # source rather than an image layer.
            rm -rf /tmp/px-source
            mkdir -p /tmp/px-source
            tar -C /px --exclude=.git --exclude=.o-\* --exclude=.venv -cf - . | tar -C /tmp/px-source -xf -
            cd /tmp/px-source
            export UV_PROJECT_ENVIRONMENT=/tmp/px-venv
            uv sync --locked --group dev
            if [ -n "$MCURL_WHEELS" ]; then
                # Reinstall from the devel wheels even when the lock still
                # pins PyPI; uv picks the wheel for this interpreter.
                wheel=$(find "$MCURL_WHEELS" -maxdepth 1 -type f -name "pymcurl-*.whl" -print -quit)
                version=$(basename "$wheel" | cut -d- -f2)
                uv pip install --python "$UV_PROJECT_ENVIRONMENT/bin/python" --no-deps --no-index \
                    --find-links "$MCURL_WHEELS" --reinstall-package pymcurl "pymcurl==$version"
            fi
            if [ "${PX_REQUIRE_MCURL_FIX:-}" = 1 ]; then
                "$UV_PROJECT_ENVIRONMENT/bin/python" .github/actions/mcurl-devel/check.py
            fi
            exec "$UV_PROJECT_ENVIRONMENT/bin/python" -m pytest "$@"
        ' scenario-pytest "${pytest_args[@]}"; then
        :
    else
        status=$?
    fi
    if ((started)); then
        "${COMPOSE[@]}" down --volumes --remove-orphans || status=$?
        rm -f "$ENV_FILE" "$ENV_DIR/origin-ca.crt"
    fi
    return "$status"
}

artifacts() {
    local destination=${1:?usage: scenario-env.sh artifacts DESTINATION}
    mkdir -p "$destination"
    "${COMPOSE[@]}" cp client:/tmp/px-scenario-tmp "$destination/px-scenario-tmp" 2>/dev/null || true
}

expect_code() {
    local expected=$1
    local label=$2
    shift 2
    local actual output
    output=$(compose_exec curl --silent --show-error --verbose --output /dev/null \
        --write-out $'\nCODE:%{http_code}' --max-time 15 "$@" 2>&1 || true)
    actual=$(sed -n 's/^CODE://p' <<<"$output" | tail -1)
    if [[ "$actual" == 000 && "$output" == *"HTTP/1.1 407"* ]]; then
        actual=407
    fi
    if [[ "$actual" != "$expected" ]]; then
        printf 'FAIL %s expected=%s actual=%s\n' "$label" "$expected" "$actual" >&2
        printf '%s\n' "$output" >&2
        return 1
    fi
    printf 'PASS %s code=%s\n' "$label" "$actual"
}

smoke_scheme() {
    local name=$1 proxy=$2 option=$3
    local auth=(--proxy-user 'CORP\pxgood:GoodPass1!')
    local wrong=(--proxy-user 'CORP\pxgood:WrongPass9!')
    [[ "$name" == basic || "$name" == digest ]] && {
        auth=(--proxy-user 'pxgood:GoodPass1!')
        wrong=(--proxy-user 'pxgood:WrongPass9!')
    }
    expect_code 200 "$name HTTP" --proxy "$proxy" "$option" "${auth[@]}" \
        http://origin.corp.test:8080/small
    expect_code 407 "$name HTTP wrong password" --proxy "$proxy" "$option" "${wrong[@]}" \
        http://origin.corp.test:8080/small
    expect_code 200 "$name CONNECT" --insecure --proxy "$proxy" "$option" "${auth[@]}" \
        https://origin.corp.test:8443/small
    expect_code 407 "$name CONNECT wrong password" --insecure --proxy "$proxy" "$option" "${wrong[@]}" \
        https://origin.corp.test:8443/small
}

smoke() {
    smoke_scheme basic squid-basic:3128 --proxy-basic
    smoke_scheme digest squid-digest:3128 --proxy-digest
    smoke_scheme ntlm squid-sso.corp.test:3128 --proxy-ntlm
    printf '%s\n' 'GoodPass1!' | compose_exec kinit pxgood@CORP.TEST
    expect_code 200 "negotiate HTTP" --proxy squid-sso.corp.test:3128 \
        --proxy-negotiate --proxy-user : http://origin.corp.test:8080/small
    expect_code 200 "negotiate CONNECT" --insecure --proxy squid-sso.corp.test:3128 \
        --proxy-negotiate --proxy-user : https://origin.corp.test:8443/small
    expect_code 200 "negotiate-wrapper HTTP (Kerberos leg)" --proxy squid-sso.corp.test:3130 \
        --proxy-negotiate --proxy-user : http://origin.corp.test:8080/small
    compose_exec kdestroy
    if printf '%s\n' 'WrongPass9!' | compose_exec kinit pxgood@CORP.TEST 2>/dev/null; then
        echo "FAIL negotiate wrong password unexpectedly obtained a ticket" >&2
        return 1
    fi
    expect_code 407 "negotiate HTTP wrong password" --proxy squid-sso.corp.test:3128 \
        --proxy-negotiate --proxy-user : http://origin.corp.test:8080/small
    expect_code 407 "negotiate CONNECT wrong password" --insecure --proxy squid-sso.corp.test:3128 \
        --proxy-negotiate --proxy-user : https://origin.corp.test:8443/small
    expect_code 200 "chain" --proxy squid-child:3128 --proxy-basic \
        --proxy-user 'pxgood:GoodPass1!' http://origin.corp.test:8080/small
    expect_code 200 "connection-close" --proxy squid-close:3128 --proxy-basic \
        --proxy-user 'pxgood:GoodPass1!' http://origin.corp.test:8080/small
    compose_exec sh -c "curl -sv --proxy squid-close:3128 --proxy-basic \
        --proxy-user 'pxgood:GoodPass1!' http://origin.corp.test:8080/small \
        -o /dev/null 2>&1 | grep -qi '< connection: close'"
    expect_code 200 "fault-injection hop" --proxy toxiproxy:8666 --proxy-ntlm \
        --proxy-user 'CORP\pxgood:GoodPass1!' http://origin.corp.test:8080/small
    compose_exec curl -fsS http://toxiproxy:8474/proxies/sso >/dev/null
    "${COMPOSE[@]}" exec -T squid-close grep -q 'maxconn 16' /etc/squid/squid.conf
    expect_code 200 "PAC fetch" http://pac.corp.test:8081/proxy.pac
    compose_exec sh -c \
        "curl -fsS http://pac.corp.test:8081/proxy.pac | grep -q 'PROXY squid-sso.corp.test:3128'"
    printf 'PASS close semantics, connection limits, and fault-injection hop\n'
    printf 'PASS all corporate proxy smoke checks\n'
}

case "${1:-}" in
up)
    check_owner
    "${COMPOSE[@]}" up --build --detach --wait --wait-timeout 180
    "${COMPOSE[@]}" cp origin:/shared/origin.crt "$ENV_DIR/origin-ca.crt"
    print_env | tee "$ENV_FILE"
    ;;
down)
    check_owner
    "${COMPOSE[@]}" down --volumes --remove-orphans
    rm -f "$ENV_FILE" "$ENV_DIR/origin-ca.crt"
    ;;
status)
    "${COMPOSE[@]}" ps
    print_env
    ;;
logs)
    "${COMPOSE[@]}" logs "${@:2}"
    ;;
smoke)
    check_owner
    smoke
    ;;
test)
    check_owner
    shift
    test "$@"
    ;;
artifacts)
    check_owner
    shift
    artifacts "$@"
    ;;
env)
    print_env
    ;;
*)
    echo "usage: $0 {up|down|status|logs|smoke|test [pytest args]|artifacts DESTINATION|env}" >&2
    exit 2
    ;;
esac
