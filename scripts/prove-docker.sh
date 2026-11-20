#!/usr/bin/env bash
# Proves both Compose stacks over real HTTP and containers. Not run by ./check.sh.
set -euo pipefail
umask 077

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROJECT="doorward-proof"
IMAGE="doorward-proof-gateway:local"
OWNER_EMAIL="owner@example.com"
DRIVER="$ROOT/scripts/prove/driver.py"
UPSTREAM_SCRIPT="$ROOT/scripts/prove/fake_upstream.py"
CADDY_FILES=(-f "$ROOT/compose.caddy.yaml" -f "$ROOT/scripts/prove/compose.caddy.proof.yaml")
PLAIN_FILES=(-f "$ROOT/compose.yaml" -f "$ROOT/scripts/prove/compose.proof.yaml")
CALLERS=(doorward-proof-caller-1 doorward-proof-caller-2)
# The tight general limit of A12: room for the health probe, the sign-in and the MCP calls of A13 and A14.
LIMITED_BURST=10

WORK=""
RUN_LOG=""
ENV_FILE=""
STATE=""
IMAGE_PREEXISTED=1
HTTP_PORT=""
HTTPS_PORT=""
PLAIN_PORT=""
CADDY_ID=""
GW_ID=""
PLAIN_ID=""
SECONDS_AT_START=$SECONDS

cleanup() {
    local rc=$?
    trap - EXIT
    set +e
    local name
    for name in "${CALLERS[@]}"; do
        docker rm -fv "$name" >/dev/null 2>&1
    done
    if [[ -n "$ENV_FILE" && -f "$ENV_FILE" ]]; then
        docker compose -p "$PROJECT" --env-file "$ENV_FILE" "${CADDY_FILES[@]}" down -v --remove-orphans >/dev/null 2>&1
        docker compose -p "$PROJECT" --env-file "$ENV_FILE" "${PLAIN_FILES[@]}" down -v --remove-orphans >/dev/null 2>&1
    fi
    # The image is removed only when this run built it: it was absent before the run.
    if [[ "$IMAGE_PREEXISTED" == 0 ]]; then
        docker image rm "$IMAGE" >/dev/null 2>&1
    fi
    if [[ -n "$WORK" ]]; then
        rm -rf "$WORK"
    fi
    exit "$rc"
}
trap cleanup EXIT

emit() {
    printf '%s\n' "$1" | tee -a "$RUN_LOG"
}

pass() {
    emit "PASS $*"
}

die() {
    emit "FAIL $*"
    exit 1
}

# Prints the last lines of a log with the repository and home paths hidden.
show_tail() {
    tail -n 12 "$1" | sed -e "s#$ROOT#<repo>#g" -e "s#$HOME#<home>#g" | tee -a "$RUN_LOG" >&2
}

compose_caddy() {
    docker compose -p "$PROJECT" --env-file "$ENV_FILE" "${CADDY_FILES[@]}" "$@"
}

compose_plain() {
    docker compose -p "$PROJECT" --env-file "$ENV_FILE" "${PLAIN_FILES[@]}" "$@"
}

driver() {
    python3 "$DRIVER" --state "$STATE" "$@" 2>&1 | tee -a "$RUN_LOG"
}

# Runs a command with its output in a log; on failure shows the log tail and stops with the label.
logged() {
    local log="$1" label="$2" rc=0
    shift 2
    "$@" >>"$log" 2>&1 || rc=$?
    if (( rc != 0 )); then
        show_tail "$log"
        die "$label: exit $rc"
    fi
}

# Lists the objects whose names start with doorward-proof, as kind:name lines.
leftovers() {
    { docker ps -a --format '{{.Names}}' | grep -E '^doorward-proof' | sed 's/^/container:/' || true; }
    { docker network ls --format '{{.Name}}' | grep -E '^doorward-proof' | sed 's/^/network:/' || true; }
    { docker volume ls --format '{{.Name}}' | grep -E '^doorward-proof' | sed 's/^/volume:/' || true; }
}

preflight() {
    local found kind name
    found="$(leftovers)"
    if [[ -z "$found" ]]; then
        return 0
    fi
    # Leftovers of an earlier failed run of this script: remove exactly these.
    docker compose -p "$PROJECT" --env-file "$ENV_FILE" "${CADDY_FILES[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
    docker compose -p "$PROJECT" --env-file "$ENV_FILE" "${PLAIN_FILES[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
    while IFS=: read -r kind name; do
        case "$kind" in
            container) docker rm -fv "$name" >/dev/null 2>&1 || true ;;
            network) docker network rm "$name" >/dev/null 2>&1 || true ;;
            volume) docker volume rm "$name" >/dev/null 2>&1 || true ;;
        esac
    done <<< "$found"
    found="$(leftovers)"
    [[ -z "$found" ]] || die "PRE preflight: objects named doorward-proof remain after removing an earlier run's leftovers"
    emit "INFO removed leftovers of an earlier failed run"
}

health_of() {
    docker inspect -f '{{.State.Health.Status}}' "$1" 2>/dev/null || echo none
}

# Polls the container's health status until healthy, unhealthy or the deadline.
wait_healthy() {
    local cid="$1" deadline=$((SECONDS + $2)) status
    while :; do
        status="$(health_of "$cid")"
        if [[ "$status" == healthy ]]; then
            return 0
        fi
        if [[ "$status" == unhealthy ]]; then
            return 1
        fi
        (( SECONDS < deadline )) || return 1
        sleep 1
    done
}

# Counts the gateway log lines that contain the given text.
count_logs() {
    local n
    n="$(docker logs "$1" 2>&1 | grep -c -F -- "$2" || true)"
    echo "$n"
}

nothing_left() {
    local label="$1" left
    left="$({
        docker ps -aq --filter name=doorward-proof
        docker volume ls -q --filter name=doorward-proof
        docker network ls -q --filter name=doorward-proof
    })"
    if [[ -n "$left" ]]; then
        die "$label nothing named doorward-proof is left: container, volume or network remains"
    fi
    pass "$label down: no container, volume or network named doorward-proof is left"
}

write_env() {
    # The gateway limits come in as the two PROOF_GENERAL_* values; empty means the product default.
    local file="$1" url="$2" burst="$3" per_minute="$4"
    cat > "$file" <<EOF
DOORWARD_PUBLIC_URL=$url
PROOF_HTTP_PORT=$HTTP_PORT
PROOF_HTTPS_PORT=$HTTPS_PORT
PROOF_PLAIN_PORT=$PLAIN_PORT
PROOF_GENERAL_BURST=$burst
PROOF_GENERAL_PER_MINUTE=$per_minute
PROOF_UPSTREAM_SCRIPT=$UPSTREAM_SCRIPT
PROOF_UPSTREAM_SECRET=$UPSTREAM_SECRET
IMAGE=$IMAGE
EOF
}

write_plain_env() {
    local file="$1"
    cat > "$file" <<EOF
DOORWARD_PUBLIC_URL=https://doorward.example.com
PROOF_HTTP_PORT=$HTTP_PORT
PROOF_HTTPS_PORT=$HTTPS_PORT
PROOF_PLAIN_PORT=$PLAIN_PORT
PROOF_GENERAL_BURST=3
PROOF_GENERAL_PER_MINUTE=1
PROOF_UPSTREAM_SCRIPT=$UPSTREAM_SCRIPT
PROOF_UPSTREAM_SECRET=$UPSTREAM_SECRET
IMAGE=$IMAGE
EOF
}

# A caller container on the stack's edge network: reaches Caddy by its address there.
caddy_edge_address() {
    docker inspect -f "{{with index .NetworkSettings.Networks \"${PROJECT}_edge\"}}{{.IPAddress}}{{end}}" "$CADDY_ID"
}

stage_a() {
    local started old_gw warnings_before warnings_after

    # A1: the image is built from the repository and runs as the fixed user.
    local image_before image_after
    image_before="$(docker image inspect -f '{{.Id}}' "$IMAGE" 2>/dev/null || echo none)"
    logged "$WORK/build.log" "A1 image build" compose_caddy build doorward
    image_after="$(docker image inspect -f '{{.Id}}' "$IMAGE")"
    emit "INFO image $IMAGE built from this tree: ${image_before:0:19} -> ${image_after:0:19}"
    driver image --image "$IMAGE"

    # A2: fresh volumes, gateway healthy within 90 seconds.
    started=$SECONDS
    logged "$WORK/up.log" "A2 up" compose_caddy up -d
    CADDY_ID="$(compose_caddy ps -q caddy)"
    GW_ID="$(compose_caddy ps -q doorward)"
    [[ -n "$CADDY_ID" && -n "$GW_ID" ]] || die "A2 up: the caddy or gateway container is missing"
    wait_healthy "$GW_ID" 90 || die "A2 gateway healthy within 90 s: health is $(health_of "$GW_ID")"
    pass "A2 up on fresh volumes; gateway healthy after $((SECONDS - started)) s"

    # A3: hardening of both containers, read from docker inspect.
    driver inspect --cid "$CADDY_ID" --role caddy --label A3
    driver inspect --cid "$GW_ID" --role gateway --label A3
    driver addresses --caddy-cid "$CADDY_ID" --gw-cid "$GW_ID" --network "${PROJECT}_proxy"

    # Caddy's internal root certificate, copied out of its data volume once it exists.
    local deadline=$((SECONDS + 60))
    until docker cp "$CADDY_ID:/data/caddy/pki/authorities/local/root.crt" "$WORK/root.crt" >/dev/null 2>&1; do
        (( SECONDS < deadline )) || die "A2 Caddy root certificate: not written within 60 s"
        sleep 1
    done
    # The root is public; the caller containers drop all capabilities, so they must read it as a file mode 0644.
    chmod 644 "$WORK/root.crt"
    driver wait-healthz --port "$HTTPS_PORT" --ca "$WORK/root.crt" --label A2

    # A4 to A6: setup code, sign-up, account page, headers on /login.
    driver setup --port "$HTTPS_PORT" --ca "$WORK/root.crt" --gw-cid "$GW_ID"

    # A7 to A11: server, client, consent, token, MCP, streaming, body limits.
    driver app --port "$HTTPS_PORT" --ca "$WORK/root.crt"
    driver mcp --port "$HTTPS_PORT" --ca "$WORK/root.crt"
    driver limits --port "$HTTPS_PORT" --ca "$WORK/root.crt"

    # A12: recreate with a tight general limit; callers in separate containers.
    warnings_before="$(( $(count_logs "$GW_ID" "the client address is private") + $(count_logs "$GW_ID" "sent no X-Forwarded-For") ))"
    old_gw="$GW_ID"
    ENV_FILE="$WORK/limited.env"
    logged "$WORK/up.log" "A12 recreate" compose_caddy up -d
    GW_ID="$(compose_caddy ps -q doorward)"
    [[ -n "$GW_ID" && "$GW_ID" != "$old_gw" ]] || die "A12 recreate: the gateway container was not recreated"
    wait_healthy "$GW_ID" 90 || die "A12 recreate: gateway healthy within 90 s: health is $(health_of "$GW_ID")"
    driver wait-healthz --port "$HTTPS_PORT" --ca "$WORK/root.crt" --label A12

    local caller_ip
    caller_ip="$(caddy_edge_address)"
    [[ -n "$caller_ip" ]] || die "A12 callers: Caddy has no address on the edge network"
    local name
    for name in "${CALLERS[@]}"; do
        docker run -d --name "$name" --network "${PROJECT}_edge" --cap-drop ALL \
            --security-opt no-new-privileges:true \
            -v "$DRIVER:/opt/driver.py:ro" -v "$WORK/root.crt:/ca/root.crt:ro" \
            python:3.13-alpine sleep 900 >/dev/null || die "A12 callers: cannot start $name"
    done
    docker exec "${CALLERS[0]}" python -I /opt/driver.py caller \
        --port "$HTTPS_PORT" --ca /ca/root.crt --connect "$caller_ip" --role 1 --burst "$LIMITED_BURST" 2>&1 | tee -a "$RUN_LOG"
    docker exec "${CALLERS[1]}" python -I /opt/driver.py caller \
        --port "$HTTPS_PORT" --ca /ca/root.crt --connect "$caller_ip" --role 2 2>&1 | tee -a "$RUN_LOG"
    for name in "${CALLERS[@]}"; do
        docker rm -fv "$name" >/dev/null 2>&1 || true
    done

    # A13: data survived the recreate; no warning about addresses in the logs.
    driver signin-a13 --port "$HTTPS_PORT" --ca "$WORK/root.crt"
    warnings_after="$(( $(count_logs "$GW_ID" "the client address is private") + $(count_logs "$GW_ID" "sent no X-Forwarded-For") ))"
    if (( warnings_before + warnings_after > 0 )); then
        die "A13 gateway logs: $((warnings_before + warnings_after)) line(s) say the client address is private or that no X-Forwarded-For was sent"
    fi
    pass "A13 gateway logs hold no 'the client address is private' and no 'sent no X-Forwarded-For' line"

    # A14: backup and restore as docs/DOCKER.md writes them, with the proof's volume and project.
    logged "$WORK/up.log" "A14 stop" compose_caddy stop
    mkdir -p "$WORK/backup"
    logged "$WORK/backup.log" "A14 backup" docker run --rm -e HOST_UID="$(id -u)" -e HOST_GID="$(id -g)" \
        -v doorward-proof-data:/data:ro -v "$WORK/backup:/backup" busybox sh -c \
        'umask 077 && tar -C /data -czf /backup/doorward-data.tar.gz . && chown "$HOST_UID:$HOST_GID" /backup/doorward-data.tar.gz'
    local archive="$WORK/backup/doorward-data.tar.gz" mode owner
    [[ -f "$archive" ]] || die "A14 backup: no archive was written"
    mode="$(stat -c '%a' "$archive")"
    owner="$(stat -c '%u' "$archive")"
    [[ "$mode" == 600 && "$owner" == "$(id -u)" ]] || die "A14 backup: archive mode $mode owner $owner, wanted 600 and $(id -u)"
    pass "A14 backup: archive is mode 0600 and owned by the invoking user"
    logged "$WORK/restore.log" "A14 empty" docker run --rm -v doorward-proof-data:/data busybox sh -c 'rm -rf /data/* /data/.[!.]*'
    local emptied
    emptied="$(docker run --rm -v doorward-proof-data:/data busybox sh -c 'if [ -z "$(ls -A /data)" ]; then echo empty; else echo full; fi')"
    [[ "$emptied" == empty ]] || die "A14 restore: the data volume is not empty before the restore"
    logged "$WORK/restore.log" "A14 restore" docker run --rm -v doorward-proof-data:/data -v "$WORK/backup:/backup:ro" busybox \
        sh -c 'rm -rf /data/* /data/.[!.]* ; tar -C /data -xzf /backup/doorward-data.tar.gz'
    logged "$WORK/up.log" "A14 start" compose_caddy start
    GW_ID="$(compose_caddy ps -q doorward)"
    wait_healthy "$GW_ID" 90 || die "A14 start: gateway healthy within 90 s: health is $(health_of "$GW_ID")"
    driver wait-healthz --port "$HTTPS_PORT" --ca "$WORK/root.crt" --label A14
    pass "A14 restore: data volume emptied, archive restored, stack started"

    # Six stop and start cycles in a row: every start must succeed and the gateway must be healthy.
    local cycle
    for cycle in 1 2 3 4 5 6; do
        logged "$WORK/up.log" "A14 cycle $cycle stop" compose_caddy stop
        logged "$WORK/up.log" "A14 cycle $cycle start" compose_caddy start
        GW_ID="$(compose_caddy ps -q doorward)"
        wait_healthy "$GW_ID" 90 || die "A14 cycle $cycle: gateway healthy within 90 s: health is $(health_of "$GW_ID")"
        driver wait-healthz --port "$HTTPS_PORT" --ca "$WORK/root.crt" --label "A14 cycle $cycle"
    done
    pass "A14 six stop and start cycles in a row: every start succeeded and the gateway was healthy each time"
    driver signin-a14 --port "$HTTPS_PORT" --ca "$WORK/root.crt"

    # A15: the unlock command inside the running container.
    local unlocked
    if ! unlocked="$(compose_caddy exec -T doorward /usr/local/bin/doorward unlock "$OWNER_EMAIL" 2>"$WORK/unlock.err")"; then
        die "A15 unlock: exec failed"
    fi
    [[ "$unlocked" == "unlocked $OWNER_EMAIL" ]] || die "A15 unlock: output does not match the documented line"
    pass "A15 unlock: exit 0 and prints unlocked <owner email>"

    # A16: down, then nothing named doorward-proof is left.
    logged "$WORK/up.log" "A16 down" compose_caddy down -v --remove-orphans
    nothing_left A16
}

stage_b() {
    local warnings

    ENV_FILE="$WORK/plain.env"
    logged "$WORK/build-plain.log" "B1 build" compose_plain build doorward
    logged "$WORK/up-plain.log" "B1 up" compose_plain up -d
    PLAIN_ID="$(compose_plain ps -q doorward)"
    [[ -n "$PLAIN_ID" ]] || die "B1 up: the gateway container is missing"
    wait_healthy "$PLAIN_ID" 90 || die "B1 gateway healthy within 90 s: health is $(health_of "$PLAIN_ID")"
    local setup_lines
    setup_lines="$(docker logs "$PLAIN_ID" 2>&1 | grep -c -F 'doorward setup code:' || true)"
    [[ "$setup_lines" == 1 ]] || die "B1 setup code: exactly one setup code line in the logs, found $setup_lines"
    pass "B1 up on a fresh volume; gateway healthy; exactly one setup code line in the logs"
    driver inspect --cid "$PLAIN_ID" --role plain --port "$PLAIN_PORT" --label B1

    driver forward --port "$PLAIN_PORT"

    warnings="$(count_logs "$PLAIN_ID" "the client address is private")"
    [[ "$warnings" == 0 ]] || die "B3 gateway logs: $warnings line(s) say the client address is private"
    pass "B3 gateway logs hold no 'the client address is private' line"

    driver hsts --port "$PLAIN_PORT"

    logged "$WORK/up-plain.log" "B6 down" compose_plain down -v --remove-orphans
    nothing_left B6
}

main() {
    WORK="$(mktemp -d)"
    if docker image inspect "$IMAGE" >/dev/null 2>&1; then
        IMAGE_PREEXISTED=1
    else
        IMAGE_PREEXISTED=0
    fi
    RUN_LOG="$WORK/run.txt"
    STATE="$WORK/state.json"
    printf '{}' > "$STATE"
    ENV_FILE="$WORK/caddy.env"

    read -r HTTP_PORT HTTPS_PORT PLAIN_PORT <<< "$(python3 -c '
import socket
socks = [socket.socket() for _ in range(3)]
for s in socks:
    s.bind(("127.0.0.1", 0))
print(*(s.getsockname()[1] for s in socks))
for s in socks:
    s.close()
')"
    UPSTREAM_SECRET="$(python3 -c 'import secrets; print(secrets.token_hex(24))')"
    export PROOF_UPSTREAM_SECRET="$UPSTREAM_SECRET"
    write_env "$WORK/caddy.env" "https://localhost:$HTTPS_PORT" "" ""
    write_env "$WORK/limited.env" "https://localhost:$HTTPS_PORT" "$LIMITED_BURST" 1
    write_plain_env "$WORK/plain.env"

    preflight
    stage_a
    stage_b

    emit "PROVE-DOCKER PASS"
    mkdir -p "$ROOT/proof"
    grep -E '^(PASS |PROVE-DOCKER PASS$)' "$RUN_LOG" > "$ROOT/proof/docker-run.txt"
}

main "$@"
