#!/usr/bin/env bash
# Local stack for the hand-driven real-client runs: up, status, activity, selfcheck [--toggle], rule on|off, deny-after-first-call, headers, store-value, down.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HELPER="$ROOT/scripts/prove/clients.py"

usage() {
    echo "usage: [PROVE_CLIENTS_DIR=<dir>] scripts/prove-clients.sh up|status|activity [--user <email>] [--out <file>]|selfcheck [--toggle]|rule off|rule on|deny-after-first-call [--timeout <seconds>] [--tool <name>]|headers --pass on|off --store on|off|store-value --header <name> [--value-file <path>]|down [--wipe]" >&2
    exit 2
}

[[ $# -ge 1 ]] || usage
command="$1"
shift

case "$command" in
    up)
        [[ $# -eq 0 ]] || usage
        python3 -I "$HELPER" check-free || exit 1
        (cd "$ROOT" && cargo build --release --quiet) || {
            echo "PROVE-CLIENTS FAIL: cargo build --release failed" >&2
            exit 1
        }
        python3 -I "$HELPER" up --binary "${CARGO_TARGET_DIR:-$ROOT/target}/release/doorward"
        ;;
    status)
        [[ $# -eq 0 ]] || usage
        python3 -I "$HELPER" status
        ;;
    selfcheck)
        [[ $# -eq 0 || ( $# -eq 1 && "$1" == "--toggle" ) ]] || usage
        python3 -I "$HELPER" selfcheck "$@"
        ;;
    rule)
        [[ $# -eq 1 && ( "$1" == "off" || "$1" == "on" ) ]] || usage
        python3 -I "$HELPER" rule "$1"
        ;;
    deny-after-first-call)
        forward=()
        while [[ $# -gt 0 ]]; do
            case "$1" in
                --timeout | --tool)
                    [[ $# -ge 2 ]] || usage
                    forward+=("$1" "$2")
                    shift 2
                    ;;
                *)
                    usage
                    ;;
            esac
        done
        python3 -I "$HELPER" deny-after-first-call "${forward[@]}"
        ;;
    activity)
        python3 -I "$HELPER" activity "$@"
        ;;
    headers)
        python3 -I "$HELPER" headers "$@"
        ;;
    store-value)
        python3 -I "$HELPER" store-value "$@"
        ;;
    down)
        python3 -I "$HELPER" down "$@"
        ;;
    *)
        usage
        ;;
esac
