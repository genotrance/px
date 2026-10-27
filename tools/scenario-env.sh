#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
ENV_DIR="$ROOT/tests/scenarios/env"
ENV_FILE=${SCENARIO_ENV_FILE:-"$ENV_DIR/scenario.env"}

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
export SCENARIO_HTTP_ORIGIN_PORT=$((18080 + OFFSET)) SCENARIO_PAC_PORT=$((18081 + OFFSET))
export SCENARIO_HTTPS_ORIGIN_PORT=$((18443 + OFFSET)) SCENARIO_ECHO_PORT=$((18888 + OFFSET))
export SCENARIO_SUBNET=172.30.$INSTANCE
COMPOSE=(docker compose -p "$PROJECT" --project-directory "$ENV_DIR" -f "$ENV_DIR/compose.yaml")

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
SCENARIO_BASIC_PROXY=http://127.0.0.1:$SCENARIO_BASIC_PORT
SCENARIO_DIGEST_PROXY=http://127.0.0.1:$SCENARIO_DIGEST_PORT
SCENARIO_SSO_PROXY=http://127.0.0.1:$SCENARIO_SSO_PORT
SCENARIO_CLOSE_PROXY=http://127.0.0.1:$SCENARIO_CLOSE_PORT
SCENARIO_PARENT_PROXY=http://127.0.0.1:$SCENARIO_PARENT_PORT
SCENARIO_CHAIN_PROXY=http://127.0.0.1:$SCENARIO_CHAIN_PORT
SCENARIO_TOXIPROXY=http://127.0.0.1:$SCENARIO_TOXIPROXY_PORT
SCENARIO_TOXIPROXY_API=http://127.0.0.1:$SCENARIO_TOXIPROXY_API_PORT
SCENARIO_HTTP_ORIGIN=http://127.0.0.1:$SCENARIO_HTTP_ORIGIN_PORT
SCENARIO_HTTPS_ORIGIN=https://127.0.0.1:$SCENARIO_HTTPS_ORIGIN_PORT
SCENARIO_PAC_URL=http://127.0.0.1:$SCENARIO_PAC_PORT/proxy.pac
SCENARIO_ECHO=127.0.0.1:$SCENARIO_ECHO_PORT
SCENARIO_CA_FILE=tests/scenarios/env/origin-ca.crt
EOF
}

compose_exec() {
    "${COMPOSE[@]}" exec -T client "$@"
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
        "curl -fsS http://pac.corp.test:8081/proxy.pac | grep -q 'PROXY 127.0.0.1:$SCENARIO_SSO_PORT'"
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
env)
    print_env
    ;;
*)
    echo "usage: $0 {up|down|status|logs|smoke|env}" >&2
    exit 2
    ;;
esac
