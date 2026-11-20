#!/usr/bin/env bash
# One real test email per provider through a throwaway gateway; prints PASS, FAIL or SKIP per provider.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HELPER="$ROOT/scripts/prove/mail.py"

usage() {
    cat >&2 <<'EOF'
usage: scripts/prove-mail.sh [smtp] [resend] [mailgun]   (no argument runs all three)
  common:  PROVE_MAIL_FROM, PROVE_MAIL_TO (required for any provider)
  smtp:    PROVE_MAIL_SMTP_HOST, PROVE_MAIL_SMTP_PORT, PROVE_MAIL_SMTP_TLS (off, starttls or implicit);
           optional PROVE_MAIL_SMTP_USERNAME, PROVE_MAIL_SMTP_PASSWORD
  resend:  PROVE_MAIL_RESEND_KEY; optional PROVE_MAIL_RESEND_BASE_URL
  mailgun: PROVE_MAIL_MAILGUN_KEY, PROVE_MAIL_MAILGUN_DOMAIN; optional PROVE_MAIL_MAILGUN_BASE_URL
EOF
    exit 2
}

providers=()
requested=" "
for arg in "$@"; do
    case "$arg" in
        smtp | resend | mailgun) ;;
        *) usage ;;
    esac
    [[ "$requested" != *" $arg "* ]] || usage
    requested+="$arg "
    providers+=("$arg")
done
if [[ ${#providers[@]} -eq 0 ]]; then
    providers=(smtp resend mailgun)
fi

(cd "$ROOT" && cargo build --release --quiet) || {
    echo "PROVE-MAIL FAIL: cargo build --release failed" >&2
    exit 1
}
python3 -I "$HELPER" run --binary "${CARGO_TARGET_DIR:-$ROOT/target}/release/doorward" "${providers[@]}"
