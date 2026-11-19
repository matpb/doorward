#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

DENYLIST="${DOORWARD_HYGIENE_DENYLIST:-$HOME/.config/doorward/hygiene-deny.txt}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
FOUND=0

HOME_RE='/home/[a-z]|/Users/[A-Za-z]'
EMAIL_RE='[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}'
IP_RE='(?<![0-9.])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9]|\.[0-9])'

DENY=()
if [[ -f "$DENYLIST" ]]; then
    while IFS= read -r entry || [[ -n "$entry" ]]; do
        if [[ -n "${entry//[[:space:]]/}" ]]; then
            DENY+=("$entry")
        fi
    done < "$DENYLIST"
fi

# Succeeds when $1 is four dotted numbers 0-255 that are not an allowed address.
ip_is_flagged() {
    local ip="$1" octet
    for octet in ${ip//./ }; do
        (( 10#$octet <= 255 )) || return 1
    done
    case "$ip" in
        127.0.0.1|0.0.0.0|192.0.2.*|198.51.100.*|203.0.113.*) return 1 ;;
    esac
    return 0
}

# Prints "LINE<TAB>REASON" for each problem in file $1. Never prints matched text.
findings() {
    local file="$1" ln match ip entry
    { grep -nI -E "$HOME_RE" "$file" || true; } | while IFS=: read -r ln _; do
        printf '%s\tpath under a home directory\n' "$ln"
    done
    { grep -noI -E "$EMAIL_RE" "$file" || true; } | while IFS=: read -r ln match; do
        case "${match#*@}" in
            example.com|example.org|example.net|*.example.com|*.example.org|*.example.net) ;;
            *) printf '%s\temail address outside example domains\n' "$ln" ;;
        esac
    done
    { grep -noI -P "$IP_RE" "$file" || true; } | while IFS=: read -r ln ip; do
        if ip_is_flagged "$ip"; then
            printf '%s\tIPv4 address other than 127.0.0.1 or a documentation range\n' "$ln"
        fi
    done
    for entry in "${DENY[@]+"${DENY[@]}"}"; do
        { grep -nI -i -F -- "$entry" "$file" || true; } | while IFS=: read -r ln _; do
            printf '%s\tmatches the private deny list\n' "$ln"
        done
    done
    return 0
}

# Prints one line per problem: "FILE:LINE: reason", or "WHERE: reason" when WHERE is set.
report_findings() {
    local path="$1" where="$2" ln reason
    findings "$path" | sort -u | while IFS=$'\t' read -r ln reason; do
        if [[ -n "$where" ]]; then
            printf '%s: %s\n' "$where" "$reason"
        else
            printf '%s:%s: %s\n' "$path" "$ln" "$reason"
        fi
    done
}

while IFS= read -r -d '' file; do
    [[ -f "$file" ]] || continue
    case "$file" in
        Cargo.lock|deny.toml|scripts/hygiene.sh) continue ;;
    esac
    out="$(report_findings "$file" "")"
    if [[ -n "$out" ]]; then
        printf '%s\n' "$out"
        FOUND=1
    fi
done < <(git ls-files -co --exclude-standard -z)

if git rev-parse --verify --quiet HEAD >/dev/null; then
    while read -r short; do
        git log -1 --format=%B "$short" > "$TMP/message"
        out="$(report_findings "$TMP/message" "commit $short")"
        if [[ -n "$out" ]]; then
            printf '%s\n' "$out"
            FOUND=1
        fi
    done < <(git log --format=%h)
fi

if [[ "$FOUND" -ne 0 ]]; then
    exit 1
fi
echo "HYGIENE PASS"
