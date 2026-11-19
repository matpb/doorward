#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK=""
PID=""

cleanup() {
    if [[ -n "$PID" ]]; then
        kill "$PID" 2>/dev/null || true
        wait "$PID" 2>/dev/null || true
    fi
    if [[ -n "$WORK" ]]; then
        rm -rf "$WORK"
    fi
}
trap cleanup EXIT

fail() {
    echo "PROVE-INSTALL FAIL: $*"
    exit 1
}

cd "$ROOT"
cargo build --release --quiet || fail "cargo build --release failed"
BIN="${CARGO_TARGET_DIR:-$ROOT/target}/release/doorward"
[[ -x "$BIN" ]] || fail "release binary not found at $BIN"

WORK="$(mktemp -d)"
cp "$BIN" "$WORK/doorward"

PORT="$(python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()')" \
    || fail "cannot pick a free port"
cat > "$WORK/doorward.toml" <<EOF
public_url = "http://127.0.0.1:$PORT"
listen = "127.0.0.1:$PORT"
database = "$WORK/doorward.db"
EOF

( cd "$WORK" && exec ./doorward --config doorward.toml ) >"$WORK/stdout.log" 2>"$WORK/stderr.log" &
PID=$!

healthy=0
deadline=$((SECONDS + 10))
while (( SECONDS < deadline )); do
    if ! kill -0 "$PID" 2>/dev/null; then
        fail "doorward exited before answering: $(tail -n 1 "$WORK/stderr.log")"
    fi
    body="$(curl -fsS --max-time 1 "http://127.0.0.1:$PORT/healthz" 2>/dev/null || true)"
    if [[ "$body" == '{"status":"ok"}' ]]; then
        healthy=1
        break
    fi
    sleep 0.1
done
[[ "$healthy" -eq 1 ]] || fail "healthz did not answer {\"status\":\"ok\"} within 10 seconds"

[[ -f "$WORK/doorward.db" ]] || fail "database file was not created"

kill -TERM "$PID" || fail "cannot send SIGTERM to doorward"
stop_deadline=$((SECONDS + 5))
while kill -0 "$PID" 2>/dev/null; do
    (( SECONDS < stop_deadline )) || fail "doorward did not stop within 5 seconds of SIGTERM"
    sleep 0.1
done
if wait "$PID"; then
    status=0
else
    status=$?
fi
PID=""
[[ "$status" -eq 0 ]] || fail "doorward exited with status $status after SIGTERM"

echo "PROVE-INSTALL PASS"
