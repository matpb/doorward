#!/usr/bin/env bash
# Runs the official MCP conformance suite against the gateway and against its reference server.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SUITE_VERSION="0.2.0-alpha.12"
REF_REPO="https://github.com/modelcontextprotocol/conformance.git"
REF_SHA="f44482ba17df816d3176962a11cdf36aec9bda00"
PROVE="$ROOT/target/prove-conformance"
TOOLS="$PROVE/tools"
WORK="$PROVE/run"
REPORT="$ROOT/proof/conformance-run.txt"
SUITE_BIN="$TOOLS/suite/node_modules/.bin/conformance"
REF_DIR="$TOOLS/reference-tree/examples/servers/typescript"
# The largest value the config accepts; no run's requests are then refused by a rate limit.
LIMIT_MAX=9223372036854775807
MARK_KEY="PROVE_CONFORMANCE_RUN"
RUN_MARK="prove-conformance-$$-$RANDOM$RANDOM"
KEEP=0
BIN=""
REF_PORT=""
GW_PORT=""
FWD_PORT=""
REF_PID=""
GW_PID=""
FWD_PID=""

fail() {
    echo "PROVE-CONFORMANCE FAIL: $*"
    exit 1
}

# Lists the pids whose environment holds this run's marker; other processes never match.
run_pids() {
    local file pid
    for file in /proc/[0-9]*/environ; do
        if grep -aqP -- "(^|\\x00)${MARK_KEY}=${RUN_MARK}(\\x00|\$)" "$file" 2>/dev/null; then
            pid="${file#/proc/}"
            echo "${pid%/environ}"
        fi
    done
}

# Sends TERM to this run's processes, then KILL after five seconds, and returns when none is left.
stop_run_processes() {
    local pids=() i
    for ((i = 0; i <= 50; i++)); do
        mapfile -t pids < <(run_pids)
        if (( ${#pids[@]} == 0 )); then
            return 0
        fi
        if (( i == 0 )); then
            kill -TERM "${pids[@]}" 2>/dev/null || true
        elif (( i == 50 )); then
            kill -KILL "${pids[@]}" 2>/dev/null || true
        fi
        sleep 0.1
    done
}

# Reaps the children this script started, so that none is left as a zombie.
reap_children() {
    local pid
    for pid in "$FWD_PID" "$GW_PID" "$REF_PID"; do
        if [[ -n "$pid" ]]; then
            wait "$pid" 2>/dev/null || true
        fi
    done
}

# Stops this run's processes, then removes the database and key, the tokens and the gateway logs.
cleanup() {
    stop_run_processes
    reap_children
    if [[ "$KEEP" -eq 0 && -d "$WORK" ]]; then
        rm -f -- "$WORK"/doorward.db* "$WORK/tokens.json" "$WORK/tokens.json.tmp" \
            "$WORK/gateway.err" "$WORK/gateway.out"
    fi
    if [[ "$KEEP" -eq 1 && -d "$WORK" ]]; then
        echo "work directory kept: $WORK"
    fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# Stops this run's processes and fails when one of them is still alive.
finish_run() {
    stop_run_processes
    reap_children
    local left
    left="$(run_pids | tr '\n' ' ')"
    if [[ -n "$left" ]]; then
        fail "processes of this run are still alive: $left"
    fi
}

for arg in "$@"; do
    case "$arg" in
        --keep) KEEP=1 ;;
        *) fail "unknown argument $arg; usage: scripts/prove-conformance.sh [--keep]" ;;
    esac
done

check_tools() {
    local tool
    for tool in node npm git tar cargo python3 curl; do
        command -v "$tool" >/dev/null 2>&1 || fail "$tool is not installed"
    done
}

# Runs the forwarder's name-mapping checks in memory, first; the run stops when one fails.
run_selftest() {
    mkdir -p "$PROVE"
    if ! python3 -I "$ROOT/scripts/prove/conformance.py" selftest >"$PROVE/selftest.txt" 2>&1; then
        cat "$PROVE/selftest.txt"
        fail "the forwarder self-test failed"
    fi
    cat "$PROVE/selftest.txt"
}

# Installs the pinned suite under the ignored work directory unless that version is present.
ensure_suite() {
    local installed
    installed="$(node -p 'require(process.argv[1]).version' \
        "$TOOLS/suite/node_modules/@modelcontextprotocol/conformance/package.json" 2>/dev/null || true)"
    if [[ "$installed" != "$SUITE_VERSION" ]]; then
        mkdir -p "$TOOLS/suite"
        (cd "$TOOLS/suite" && npm install --ignore-scripts --save-exact --no-audit --no-fund \
            "@modelcontextprotocol/conformance@$SUITE_VERSION") \
            || fail "npm install of the pinned suite failed"
    fi
    [[ -x "$SUITE_BIN" ]] || fail "the suite binary is missing after npm install"
}

# Fetches the pinned reference server commit into a git cache and extracts its tree, unless present.
ensure_reference() {
    local git_dir="$TOOLS/reference" marker="$TOOLS/reference.sha"
    if [[ "$(cat "$marker" 2>/dev/null || true)" != "$REF_SHA" ]]; then
        mkdir -p "$git_dir"
        git -C "$git_dir" init -q || fail "git init of the reference cache failed"
        git -C "$git_dir" remote add origin "$REF_REPO" 2>/dev/null \
            || git -C "$git_dir" remote set-url origin "$REF_REPO" \
            || fail "cannot set the reference remote"
        git -C "$git_dir" fetch -q --depth 1 origin "$REF_SHA" \
            || fail "git fetch of the reference server commit failed"
        [[ "$(git -C "$git_dir" rev-parse FETCH_HEAD)" == "$REF_SHA" ]] \
            || fail "the fetched reference commit is not the pinned one"
        rm -rf -- "$TOOLS/reference-tree"
        mkdir -p "$TOOLS/reference-tree"
        git -C "$git_dir" archive FETCH_HEAD | tar -x -C "$TOOLS/reference-tree" \
            || fail "extracting the reference server tree failed"
        printf '%s\n' "$REF_SHA" > "$marker"
    fi
    if [[ ! -x "$REF_DIR/node_modules/.bin/tsx" ]]; then
        (cd "$REF_DIR" && npm ci --ignore-scripts --no-audit --no-fund) \
            || fail "npm ci of the reference server failed"
    fi
}

build_gateway() {
    (cd "$ROOT" && cargo build --release --quiet) || fail "cargo build --release failed"
    BIN="${CARGO_TARGET_DIR:-$ROOT/target}/release/doorward"
    [[ -x "$BIN" ]] || fail "release binary not found at $BIN"
}

free_port() {
    python3 -I -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()'
}

# Waits until the file holds the text; fails when the process is gone or after 30 seconds.
wait_for_log() {
    local file="$1" text="$2" pid="$3" tries=0
    until grep -qF -- "$text" "$file" 2>/dev/null; do
        kill -0 "$pid" 2>/dev/null || return 1
        tries=$((tries + 1))
        (( tries < 300 )) || return 1
        sleep 0.1
    done
}

# Binds the reference server to loopback: its source calls listen() without a host.
write_loopback_shim() {
    cat > "$WORK/reference-loopback.mjs" <<'EOF'
import net from "node:net";

const listen = net.Server.prototype.listen;
net.Server.prototype.listen = function (...args) {
  const portFirst = typeof args[0] === "number" || typeof args[0] === "string";
  if (portFirst && (args.length === 1 || typeof args[1] === "function")) {
    args.splice(1, 0, "127.0.0.1");
  }
  return listen.apply(this, args);
};
EOF
}

# The gateway config for this run; the four rate limits are raised to the largest accepted value.
write_config() {
    cat > "$WORK/doorward.toml" <<EOF
public_url = "http://127.0.0.1:$FWD_PORT"
listen = "127.0.0.1:$GW_PORT"
database = "$WORK/doorward.db"

[limits]
general_burst = $LIMIT_MAX
general_per_minute = $LIMIT_MAX
mcp_burst = $LIMIT_MAX
mcp_per_minute = $LIMIT_MAX
EOF
}

start_reference() {
    write_loopback_shim
    (cd "$REF_DIR" && exec env "$MARK_KEY=$RUN_MARK" PORT="$REF_PORT" \
        NODE_OPTIONS="--import=file://$WORK/reference-loopback.mjs" \
        ./node_modules/.bin/tsx everything-server.ts) >"$WORK/reference.log" 2>&1 &
    REF_PID=$!
    wait_for_log "$WORK/reference.log" "running on http://localhost:$REF_PORT" "$REF_PID" \
        || fail "the reference server did not start on its loopback port"
}

start_gateway() {
    (cd "$WORK" && exec env "$MARK_KEY=$RUN_MARK" "$BIN" --config doorward.toml) \
        >"$WORK/gateway.out" 2>"$WORK/gateway.err" &
    GW_PID=$!
}

start_forwarder() {
    env "$MARK_KEY=$RUN_MARK" python3 -I "$ROOT/scripts/prove/conformance.py" forward \
        --listen "$FWD_PORT" --target "http://127.0.0.1:$GW_PORT" --token-file "$WORK/tokens.json" \
        >"$WORK/forward.log" 2>&1 &
    FWD_PID=$!
}

# Health is asked through the forwarder, the address the gateway calls its public address.
wait_for_gateway() {
    local body="" deadline=$((SECONDS + 20))
    while (( SECONDS < deadline )); do
        kill -0 "$GW_PID" 2>/dev/null \
            || fail "doorward exited before answering: $(tail -n 1 "$WORK/gateway.err" 2>/dev/null)"
        body="$(curl -fsS --max-time 1 "http://127.0.0.1:$FWD_PORT/healthz" 2>/dev/null || true)"
        if [[ "$body" == '{"status":"ok"}' ]]; then
            return 0
        fi
        sleep 0.2
    done
    fail "healthz did not answer {\"status\":\"ok\"} through the forwarder within 20 seconds"
}

# Runs the suite once and records its exit code; a failing suite run is data, not a stop.
# The fourth argument 1 passes the revision's expected-failures file, when it has one.
run_suite() {
    local name="$1" url="$2" rev="$3" use_expected="$4" code=0
    local expected="$ROOT/scripts/prove/conformance-expected-$rev.yaml"
    local extra=()
    if [[ "$use_expected" == 1 && -f "$expected" ]]; then
        extra=(--expected-failures "$expected")
    fi
    set +e
    "$SUITE_BIN" server --url "$url" --requirements "$rev" -o "$WORK/results/$name" \
        ${extra[@]+"${extra[@]}"} >"$WORK/$name.txt" 2>&1
    code=$?
    set -e
    printf '%s\t%s\n' "$name" "$code" >> "$WORK/exits.tsv"
}

# Fails with the first suite output line that holds a rate-limit answer (code -32029 or HTTP 429).
check_rate_limits() {
    local hit
    hit="$(cd "$WORK" && grep -rnF -e '-32029' -e ' 429' results ./*.txt 2>/dev/null | head -n 1 || true)"
    if [[ -n "$hit" ]]; then
        fail "a suite output file holds a rate-limit answer: ${hit:0:300}"
    fi
}

check_tools
run_selftest
ensure_suite
ensure_reference
build_gateway

rm -rf -- "$WORK"
mkdir -p "$WORK/results" "$ROOT/proof"
: > "$WORK/exits.tsv"

REF_PORT="$(free_port)" || fail "cannot pick a free port"
GW_PORT="$(free_port)" || fail "cannot pick a free port"
FWD_PORT="$(free_port)" || fail "cannot pick a free port"

write_config
start_reference
start_gateway
start_forwarder
wait_for_gateway

python3 -I "$ROOT/scripts/prove/conformance.py" drive --port "$FWD_PORT" \
    --setup-log "$WORK/gateway.err" --upstream "http://127.0.0.1:$REF_PORT/mcp" \
    --token-file "$WORK/tokens.json" \
    || fail "the gateway driver stopped at the step printed above"

for rev in 2025-11-25 2026-07-28; do
    run_suite "direct-$rev" "http://127.0.0.1:$REF_PORT/mcp" "$rev" 0
done
for rev in 2025-11-25 2026-07-28; do
    run_suite "gateway-$rev" "http://127.0.0.1:$FWD_PORT/everything" "$rev" 1
done
for rev in 2025-11-25 2026-07-28; do
    run_suite "combined-$rev" "http://127.0.0.1:$FWD_PORT/mcp" "$rev" 1
done

report_status=0
set +e
python3 -I "$ROOT/scripts/prove/conformance.py" report --work "$WORK" --exits "$WORK/exits.tsv" \
    --config "$WORK/doorward.toml" --out "$REPORT" \
    --suite-version "$SUITE_VERSION" --ref-sha "$REF_SHA" --selftest "$PROVE/selftest.txt"
report_status=$?
set -e

check_rate_limits
finish_run

if [[ "$report_status" -ne 0 ]]; then
    fail "the report verdict is FAIL: an unlisted failing check, a stale or mismatched expected-failure entry, or a missing run (see the report)"
fi
echo "PROVE-CONFORMANCE PASS"
