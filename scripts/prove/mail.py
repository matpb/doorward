"""One real test email per provider, sent through the gateway's mail page with the settings the owner types.

Run with python3 -I from scripts/prove-mail.sh. Standard library only. Work directory: target/prove-mail/run.
"""

import argparse
import html
import html.parser
import os
import secrets
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, HERE)
import clients as k  # Gateway start, process control and the activity page, shared with the client stack.
import conformance as cf

MARK_KEY = "PROVE_MAIL_RUN"
RUN = os.path.join(ROOT, "target", "prove-mail", "run")
MARKER_FILE = os.path.join(RUN, "marker.txt")
REPORT = os.path.join(ROOT, "proof", "mail-run.txt")
PROVIDERS = ("smtp", "resend", "mailgun")
DELIVERED = "Test email sent."
REQUIRED = {
    "smtp": (
        "PROVE_MAIL_FROM",
        "PROVE_MAIL_TO",
        "PROVE_MAIL_SMTP_HOST",
        "PROVE_MAIL_SMTP_PORT",
        "PROVE_MAIL_SMTP_TLS",
    ),
    "resend": ("PROVE_MAIL_FROM", "PROVE_MAIL_TO", "PROVE_MAIL_RESEND_KEY"),
    "mailgun": ("PROVE_MAIL_FROM", "PROVE_MAIL_TO", "PROVE_MAIL_MAILGUN_KEY", "PROVE_MAIL_MAILGUN_DOMAIN"),
}
SECRETS = {
    "smtp": "PROVE_MAIL_SMTP_PASSWORD",
    "resend": "PROVE_MAIL_RESEND_KEY",
    "mailgun": "PROVE_MAIL_MAILGUN_KEY",
}
# Every value read from the environment, with the text that replaces it in any printed line.
PLACEHOLDERS = {
    "PROVE_MAIL_FROM": "<from>",
    "PROVE_MAIL_TO": "<to>",
    "PROVE_MAIL_SMTP_HOST": "<host>",
    "PROVE_MAIL_SMTP_USERNAME": "<username>",
    "PROVE_MAIL_SMTP_PASSWORD": "<secret>",
    "PROVE_MAIL_RESEND_KEY": "<secret>",
    "PROVE_MAIL_RESEND_BASE_URL": "<base-url>",
    "PROVE_MAIL_MAILGUN_KEY": "<secret>",
    "PROVE_MAIL_MAILGUN_DOMAIN": "<domain>",
    "PROVE_MAIL_MAILGUN_BASE_URL": "<base-url>",
}


def missing(provider, env):
    return [name for name in REQUIRED[provider] if not env.get(name)]


def scrubber(env):
    """A function that replaces every configured value in a text with its placeholder, longest first."""
    pairs = sorted(
        # A value equal to a provider name is left alone, or the verdict line would lose that name.
        ((env[name], text) for name, text in PLACEHOLDERS.items() if env.get(name) and env[name] not in PROVIDERS),
        key=lambda pair: len(pair[0]),
        reverse=True,
    )

    def scrub(text):
        for value, placeholder in pairs:
            text = text.replace(value, placeholder)
        return text

    return scrub


def settings_fields(provider, env):
    """The fields of the provider's form on the mail page, as a browser posts them."""
    sender = env["PROVE_MAIL_FROM"]
    if provider == "smtp":
        return [
            ("provider", "smtp"),
            ("from", sender),
            ("smtp_host", env["PROVE_MAIL_SMTP_HOST"]),
            ("smtp_port", env["PROVE_MAIL_SMTP_PORT"]),
            ("smtp_username", env.get("PROVE_MAIL_SMTP_USERNAME", "")),
            ("smtp_password", env.get("PROVE_MAIL_SMTP_PASSWORD", "")),
            ("smtp_tls", env["PROVE_MAIL_SMTP_TLS"]),
        ]
    if provider == "resend":
        return [
            ("provider", "resend"),
            ("from", sender),
            ("resend_api_key", env["PROVE_MAIL_RESEND_KEY"]),
            ("resend_base_url", env.get("PROVE_MAIL_RESEND_BASE_URL", "")),
        ]
    return [
        ("provider", "mailgun"),
        ("from", sender),
        ("mailgun_api_key", env["PROVE_MAIL_MAILGUN_KEY"]),
        ("mailgun_domain", env["PROVE_MAIL_MAILGUN_DOMAIN"]),
        ("mailgun_base_url", env.get("PROVE_MAIL_MAILGUN_BASE_URL", "")),
    ]


class Messages(html.parser.HTMLParser):
    """The text of the first notice paragraph and the first error paragraph of a page."""

    def __init__(self):
        super().__init__()
        self.found = {}
        self.kind = None
        self.tone = None
        self.text = ""

    def handle_starttag(self, tag, attrs):
        attributes = dict(attrs)
        classes = (attributes.get("class") or "").split()
        if tag == "div" and "notice" in classes:
            # A notice is a div whose data-notice names its tone; its paragraph carries the words.
            self.tone = {"ok": "notice", "error": "error"}.get(attributes.get("data-notice"))
            return
        if tag != "p":
            return
        for name in ("notice", "error"):
            if name in classes and name not in self.found:
                self.kind = name
                self.text = ""
        if self.kind is None and self.tone is not None and self.tone not in self.found:
            self.kind = self.tone
            self.text = ""
        self.tone = None

    def handle_endtag(self, tag):
        if tag == "p" and self.kind is not None:
            self.found[self.kind] = self.text.strip()
            self.kind = None
        if tag == "div":
            self.tone = None

    def handle_data(self, data):
        if self.kind is not None:
            self.text += data


def page_messages(text):
    parser = Messages()
    parser.feed(text)
    return parser.found


def mail_rows(owner):
    """The activity rows of every user, oldest first."""
    return list(reversed(k.all_activity_rows(owner, "/admin/activity")))


def shows(page_text, secret):
    return secret in page_text or html.escape(secret, quote=True) in page_text


def all_secrets(env):
    return [env[name] for name in SECRETS.values() if env.get(name)]


def prepare_directory():
    """Empties the work directory of an earlier run of this script and writes this run's marker."""
    cf.need(
        not os.path.islink(RUN) and not os.path.islink(os.path.dirname(RUN)),
        "the work directory or its parent is a symbolic link; refusing to use it",
    )
    if os.path.isfile(MARKER_FILE):
        with open(MARKER_FILE, encoding="utf-8") as handle:
            old = handle.read().strip()
        cf.need(not (old and k.marked_pids(old, MARK_KEY)), "a run of this script is still alive; stop it first")
    if os.path.isdir(RUN):
        shutil.rmtree(RUN)
    os.makedirs(RUN, mode=0o700)
    marker = f"prove-mail-{os.getpid()}-{secrets.token_hex(8)}"
    k.write_private(MARKER_FILE, marker + "\n")
    return marker


def start_gateway(binary, marker, env):
    """Starts the throwaway gateway on loopback and sets up the owner; returns the owner's client."""
    cf.need(os.access(binary, os.X_OK), f"the gateway binary is missing: {k.rel(binary)}")
    gw_port = k.free_port()
    k.write_config(gw_port, run=RUN)
    # The gateway gets the marker and a PATH only; the provider secrets stay out of its environment.
    gateway_env = {"PATH": env.get("PATH", ""), MARK_KEY: marker}
    k.launch([binary, "--config", "doorward.toml"], gateway_env, "gateway", run=RUN)
    k.wait_listening(gw_port, "the gateway")
    cf.need(k.healthy(gw_port), "the gateway does not answer /healthz with ok")
    owner = cf.Client(gw_port)
    cf.setup_owner(owner, cf.read_setup_code(os.path.join(RUN, "gateway.err")), k.new_password())
    return owner


def failed_rows(owner):
    """The mail_failed rows, oldest first."""
    return [row for row in mail_rows(owner) if row["kind"] == "mail_failed"]


def delivered(provider, owner, env, before, say):
    """The checks after a delivered send: no secret on the page, and no failure row written by the send."""
    new = failed_rows(owner)[len(before):]
    page = owner.get("/admin/mail")
    cf.need(page.status == 200, f"the mail page answered {page.status}")
    if any(shows(page.text, secret) for secret in all_secrets(env)):
        say(f"FAIL {provider}: a saved secret is shown on the settings page")
        return "fail"
    if new:
        say(f"FAIL {provider}: the activity log has a mail_failed row for the send")
        return "fail"
    say(f"PASS {provider}: the gateway reports delivered")
    if env.get(SECRETS[provider]):
        say(f"PASS {provider}: the saved secret is not shown on the settings page")
    else:
        say(f"PASS {provider}: no secret is saved for this provider, so none is shown on the settings page")
    say(f"PASS {provider}: the activity log has no mail_failed row for the send")
    return "pass"


def refused_send(provider, owner, error, before, say):
    """The provider's own error is shown; the failure must also be in the activity log."""
    new = failed_rows(owner)[len(before):]
    logged = [row for row in new if error in row["detail"]]
    say(f"FAIL {provider}: {error}")
    if logged:
        say(f"CHECK {provider}: the activity log has the mail_failed row for the send")
    else:
        say(f"FAIL {provider}: the activity log has no mail_failed row for the send")
    return "fail"


def run_provider(provider, owner, env, say):
    """Saves the provider's settings, presses send test email, and reports what the page says."""
    try:
        saved = owner.form("/admin/mail", "/admin/mail", settings_fields(provider, env))
        if saved.status != 303:
            error = page_messages(saved.text).get("error") or f"the settings page answered {saved.status}"
            say(f"FAIL {provider}: {error}")
            return "fail"
        # Activity times have one-second resolution, so new rows are counted, not compared by time.
        before = failed_rows(owner)
        answer = owner.form("/admin/mail", "/admin/mail/test", [("to", env["PROVE_MAIL_TO"])])
        messages = page_messages(answer.text)
        if answer.status == 200 and messages.get("notice") == DELIVERED:
            return delivered(provider, owner, env, before, say)
        error = messages.get("error") or f"the test answered {answer.status} without a notice"
        return refused_send(provider, owner, error, before, say)
    except cf.Fail as failure:
        say(f"FAIL {provider}: {failure}")
        return "fail"


def commit_id():
    result = subprocess.run(
        ["git", "-C", ROOT, "rev-parse", "--short", "HEAD"], capture_output=True, text=True, check=False
    )
    return result.stdout.strip() or "unknown"


def command_run(binary, providers):
    env = dict(os.environ)
    scrub = scrubber(env)
    lines = []

    def say(text):
        printed = scrub(text)
        lines.append(printed)
        print(printed, flush=True)

    results = {}
    marker = None
    owner = None
    survivors = []
    try:
        for provider in providers:
            absent = missing(provider, env)
            if absent:
                say(f"SKIP {provider}: not configured ({', '.join(absent)})")
                results[provider] = "skip"
                continue
            if owner is None:
                marker = prepare_directory()
                owner = start_gateway(binary, marker, env)
            results[provider] = run_provider(provider, owner, env, say)
    except cf.Fail as failure:
        say(f"FAIL setup: {failure}")
        for provider in providers:
            if provider not in results:
                say(f"FAIL {provider}: the gateway did not start")
                results[provider] = "fail"
    finally:
        if marker is not None:
            survivors = k.stop_marked(marker, MARK_KEY)
        if os.path.isdir(RUN) and not os.path.islink(RUN):
            shutil.rmtree(RUN)
    if survivors:
        say(f"FAIL setup: processes of this run survive: {survivors}")
    delivered_names = [p for p in providers if results.get(p) == "pass"]
    failed = [p for p in providers if results.get(p) == "fail"]
    skipped = [p for p in providers if results.get(p) == "skip"]
    not_requested = [p for p in PROVIDERS if p not in providers]
    verdict = (
        f"VERDICT: {len(delivered_names)} of 3 providers delivered; "
        f"failed: {', '.join(failed) or 'none'}; skipped: {', '.join(skipped) or 'none'}"
    )
    if not_requested:
        verdict += f"; not requested: {', '.join(not_requested)}"
    say(verdict)
    report = [f"date: {k.utc_now()}", f"commit: {commit_id()}", *lines]
    os.makedirs(os.path.dirname(REPORT), exist_ok=True)
    with open(REPORT, "w", encoding="utf-8") as handle:
        handle.write("\n".join(report) + "\n")
    passed = bool(providers) and all(results.get(p) == "pass" for p in providers)
    return 0 if passed and not survivors else 1


def build_parser():
    parser = argparse.ArgumentParser(description="One real test email per provider through the gateway.")
    sub = parser.add_subparsers(dest="cmd", required=True)
    run = sub.add_parser("run", help="run the requested providers")
    run.add_argument("--binary", required=True)
    run.add_argument("providers", nargs="*", choices=PROVIDERS)
    return parser


def main(argv):
    args = build_parser().parse_args(argv)
    providers = args.providers or list(PROVIDERS)
    if len(set(providers)) != len(providers):
        print("usage: a provider is named once", file=sys.stderr)
        return 2
    return command_run(args.binary, providers)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
