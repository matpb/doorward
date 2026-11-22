"""Local stack for the hand-driven real-client runs: gateway and fake upstream, driven as a person would.

Run with python3 -I. Standard library only. Work directory: target/prove-clients/run, or the
directory named by PROVE_CLIENTS_DIR (relative paths are taken from the repository root).
"""

import argparse
import hashlib
import html.parser
import http.client
import http.server
import importlib.util
import json
import os
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import time
from datetime import datetime, timezone
from urllib.parse import parse_qs, urlencode, urljoin, urlsplit

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, HERE)
import conformance as cf  # The driver's HTTP client and its OAuth steps.
import fake_upstream  # The per-user header names, parsed as the fake upstream parses them.

MARK_KEY = "PROVE_CLIENTS_RUN"
SECRET_KEY = "PROOF_UPSTREAM_SECRET"
DEFAULT_DIR = os.path.join("target", "prove-clients", "run")
DEFAULT_RUN = os.path.join(ROOT, DEFAULT_DIR)
RUN = os.path.normpath(os.path.join(ROOT, os.environ.get("PROVE_CLIENTS_DIR") or DEFAULT_DIR))
BASE = os.path.realpath(os.path.join(ROOT, "target", "prove-clients"))
WORK_REFUSED = "PROVE-CLIENTS FAIL: PROVE_CLIENTS_DIR must name a directory under target/prove-clients"
# Evidence of the default stack goes to proof/clients; another work directory keeps its own.
EVIDENCE = os.path.join(ROOT, "proof", "clients") if RUN == DEFAULT_RUN else os.path.join(RUN, "evidence")
MARKER_FILE = os.path.join(RUN, "marker.txt")
STACK_FILE = os.path.join(RUN, "stack.txt")
UP_FILE = os.path.join(EVIDENCE, "up.txt")
SELFCHECK_FILE = os.path.join(EVIDENCE, "selfcheck.txt")
FAKE_UPSTREAM = os.path.join(HERE, "fake_upstream.py")
BOB_EMAIL = "bob@example.com"
SLUG = "demo"
DENIED_TOOL = "slow"
SECRET_HEADER = "x-upstream-secret"
PASSWORD_BYTES = 24
STOP_SECONDS = 5
POLL_SECONDS = 0.3
# The fake upstream stays silent for 90 seconds before a slow answer; the gateway allows 300.
SLOW_TIMEOUT_SECONDS = 400


def rel(path):
    return os.path.relpath(path, ROOT)


def write_private(path, text):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(text)
    os.chmod(path, 0o600)


def new_password():
    return secrets.token_urlsafe(PASSWORD_BYTES)


def utc_now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def wait_listening(port, label):
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                return
        except OSError:
            time.sleep(0.2)
    cf.need(False, f"{label} does not listen on its loopback port within 30 seconds")


def healthy(port):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
    try:
        conn.request("GET", "/healthz")
        response = conn.getresponse()
        return response.status == 200 and response.read() == b'{"status":"ok"}'
    except (OSError, http.client.HTTPException):
        return False
    finally:
        conn.close()


def environ_entries(pid):
    try:
        with open(f"/proc/{pid}/environ", "rb") as handle:
            return handle.read().split(b"\0")
    except OSError:
        return []


def has_marker(pid, marker, key=MARK_KEY):
    return f"{key}={marker}".encode() in environ_entries(pid)


def marked_pids(marker, key=MARK_KEY):
    """The pids whose environment holds this stack's marker, exactly; no other process matches."""
    found = []
    for name in os.listdir("/proc"):
        if name.isdigit() and has_marker(int(name), marker, key):
            found.append(int(name))
    return sorted(found)


def signal_marked(pid, sig, marker, key=MARK_KEY):
    if has_marker(pid, marker, key):
        try:
            os.kill(pid, sig)
        except ProcessLookupError:
            pass


def stop_marked(marker, key=MARK_KEY):
    """TERM to the marked processes, KILL after five seconds; returns the pids still alive."""
    for pid in marked_pids(marker, key):
        signal_marked(pid, signal.SIGTERM, marker, key)
    deadline = time.monotonic() + STOP_SECONDS
    while marked_pids(marker, key) and time.monotonic() < deadline:
        time.sleep(0.1)
    for pid in marked_pids(marker, key):
        signal_marked(pid, signal.SIGKILL, marker, key)
    deadline = time.monotonic() + 2
    while marked_pids(marker, key) and time.monotonic() < deadline:
        time.sleep(0.1)
    return marked_pids(marker, key)


def read_marker():
    try:
        with open(MARKER_FILE, encoding="utf-8") as handle:
            return handle.read().strip() or None
    except FileNotFoundError:
        return None


def read_stack():
    cf.need(os.path.isfile(STACK_FILE), "there is no stack file; run up first")
    values = {}
    with open(STACK_FILE, encoding="utf-8") as handle:
        for line in handle:
            key, sep, value = line.rstrip("\n").partition(": ")
            if sep:
                values[key] = value
    return values


def set_stack_rule(text):
    """Replaces the rule line of the stack file, so it always says what the gateway holds."""
    with open(STACK_FILE, encoding="utf-8") as handle:
        lines = handle.read().splitlines()
    out = []
    replaced = False
    for line in lines:
        if line.startswith("rule: "):
            out.append(f"rule: {text}")
            replaced = True
        else:
            out.append(line)
    if not replaced:
        out.append(f"rule: {text}")
    write_private(STACK_FILE, "\n".join(out) + "\n")


def launch(argv, env, name, run=RUN):
    """Starts a process in its own session, so it outlives this command; its output goes to the work directory."""
    out = open(os.path.join(run, f"{name}.out"), "ab")
    err = open(os.path.join(run, f"{name}.err"), "ab")
    try:
        proc = subprocess.Popen(
            argv, cwd=run, env=env, stdin=subprocess.DEVNULL, stdout=out, stderr=err, start_new_session=True
        )
    finally:
        out.close()
        err.close()
    return proc.pid


def run_upstream(port):
    """The fake upstream's own handler, bound to loopback; its module binds 0.0.0.0 when run as a script."""
    spec = importlib.util.spec_from_file_location("fake_upstream", FAKE_UPSTREAM)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    server = http.server.ThreadingHTTPServer(("127.0.0.1", port), module.Handler)
    server.serve_forever()
    return 0


# Behind a tunnel, for a client on the internet: PROVE_CLIENTS_PUBLIC_URL is its https address, PROVE_CLIENTS_GW_PORT the port it forwards to.
def write_config(gw_port, run=RUN):
    text = (
        f'public_url = "{os.environ.get("PROVE_CLIENTS_PUBLIC_URL") or f"http://127.0.0.1:{gw_port}"}"\n'
        f'listen = "127.0.0.1:{gw_port}"\n'
        f'database = "{os.path.join(run, "doorward.db")}"\n'
    )
    if os.environ.get("PROVE_CLIENTS_PUBLIC_URL"):
        text += 'trusted_proxies = ["127.0.0.1", "::1"]\n'
    write_private(os.path.join(run, "doorward.toml"), text)


def drive(gw_port, up_port, secret, setup_log):
    """Owner setup, the demo server, bob's invitation, the assignment and the deny rule, as a person does them."""
    lines = []
    owner = cf.Client(gw_port)
    owner_password = new_password()
    cf.setup_owner(owner, cf.read_setup_code(setup_log), owner_password)
    lines.append(f"PASS owner setup: {cf.OWNER_EMAIL} signed in")

    added = owner.form(
        "/admin/servers",
        "/admin/servers",
        [
            ("name", SLUG),
            ("slug", SLUG),
            ("upstream_url", f"http://127.0.0.1:{up_port}/mcp"),
            ("secret_header_name", SECRET_HEADER),
            ("secret_header_value", secret),
        ],
    )
    prefix = "/admin/servers/"
    cf.need(
        added.status == 303 and added.location is not None and added.location.startswith(prefix),
        f"the server form answered {added.status}, wanted 303 to the server page",
    )
    server_path = added.location
    server_id = server_path[len(prefix):]
    refreshed = owner.form(server_path, f"{server_path}/refresh-tools", [])
    cf.need(refreshed.status == 303, f"refresh the tool list answered {refreshed.status}, wanted 303")
    tools = owner.get(server_path).values_of("data-catalog-tool")
    cf.need({"echo", DENIED_TOOL} <= set(tools), f"the tool list of {SLUG} holds {tools!r}")
    lines.append(f"PASS server {SLUG} added with its secret header; tool list: {', '.join(tools)}")

    invited = owner.form("/admin/invitations", "/admin/invitations", [("email", BOB_EMAIL), ("role", "user")])
    cf.need(
        invited.kind() == "invitation-created",
        f"the invitation answered {invited.status} without the link page",
    )
    links = invited.values_of("data-invite-link")
    cf.need(len(links) == 1, f"the invitation page shows {len(links)} links, wanted 1")
    invite_path = urlsplit(links[0]).path
    cf.need(invite_path.startswith("/invite/"), "the invitation link is an /invite/ address")
    lines.append(f"PASS invitation for {BOB_EMAIL}: link read from the page (no mail is configured)")

    bob = cf.Client(gw_port)
    bob_password = new_password()
    accepted = bob.form(invite_path, invite_path, [("password", bob_password)])
    cf.need(
        accepted.status == 303 and accepted.location == "/account",
        f"accepting the invitation answered {accepted.status} to {accepted.location!r}",
    )
    lines.append(f"PASS invitation accepted by {BOB_EMAIL} with a password")

    rows = owner.get("/admin/users").find({"data-email": BOB_EMAIL})
    cf.need(len(rows) == 1, f"the users page shows {len(rows)} rows for {BOB_EMAIL}, wanted 1")
    bob_id = rows[0]["data-user-id"]
    user_path = f"/admin/users/{bob_id}"
    assigned = owner.form(user_path, f"{user_path}/servers", [("server_id", server_id)])
    cf.need(assigned.status == 303, f"assign the server answered {assigned.status}, wanted 303")
    lines.append(f"PASS {SLUG} assigned to {BOB_EMAIL}")

    created = owner.form(
        "/admin/rules",
        "/admin/rules",
        [
            ("subject", bob_id),
            ("effect", "deny"),
            ("scope", "tool"),
            ("server_id", server_id),
            ("tool", DENIED_TOOL),
        ],
    )
    cf.need(created.status == 303, f"the rule form answered {created.status}, wanted 303")
    stored = owner.get("/admin/rules").find({"data-effect": "deny", "data-tool": DENIED_TOOL})
    cf.need(len(stored) == 1, f"the rules page shows {len(stored)} deny rules for {DENIED_TOOL}, wanted 1")
    rule = rule_line(stored[0]["data-rule-id"], bob_id)
    lines.append(f"PASS {rule}")
    return owner_password, bob_password, rule, lines


def rule_line(rule_id, bob_id):
    return (
        f"rule id {rule_id}: deny the tool {DENIED_TOOL} on {SLUG} "
        f"for {BOB_EMAIL} (subject: user {bob_id}, scope: one tool)"
    )


def command_up(binary):
    cf.need(os.access(binary, os.X_OK), f"the gateway binary is missing: {rel(binary)}")
    old = read_marker()
    cf.need(not (old and marked_pids(old)), "a stack of an earlier up is still alive; run down first")
    if os.path.isdir(RUN):
        shutil.rmtree(RUN)
    os.makedirs(RUN, mode=0o700)
    os.makedirs(EVIDENCE, exist_ok=True)
    marker = f"prove-clients-{os.getpid()}-{secrets.token_hex(8)}"
    write_private(MARKER_FILE, marker + "\n")
    secret = secrets.token_urlsafe(32)
    gw_port, up_port = int(os.environ.get("PROVE_CLIENTS_GW_PORT") or free_port()), free_port()
    write_config(gw_port)
    up_env = {**os.environ, MARK_KEY: marker, SECRET_KEY: secret}
    up_pid = launch(
        [sys.executable, "-I", os.path.abspath(__file__), "upstream", "--port", str(up_port)], up_env, "upstream"
    )
    gw_pid = launch([binary, "--config", "doorward.toml"], {**os.environ, MARK_KEY: marker}, "gateway")
    try:
        wait_listening(up_port, "the fake upstream")
        wait_listening(gw_port, "the gateway")
        cf.need(healthy(gw_port), "the gateway does not answer /healthz with ok")
        owner_password, bob_password, rule, lines = drive(
            gw_port, up_port, secret, os.path.join(RUN, "gateway.err")
        )
    except Exception as failure:  # The stack is stopped before the failure is reported.
        stop_marked(marker)
        if isinstance(failure, cf.Fail):
            print(f"FAIL up: {failure}")
        else:
            print(f"FAIL up: unexpected {type(failure).__name__}")
        return 1
    addresses = [
        f"gateway: http://127.0.0.1:{gw_port}",
        f"server path: http://127.0.0.1:{gw_port}/{SLUG}",
        f"combined: http://127.0.0.1:{gw_port}/mcp",
        f"upstream: http://127.0.0.1:{up_port}/mcp",
    ]
    stack = addresses + [
        f"owner email: {cf.OWNER_EMAIL}",
        f"owner password: {owner_password}",
        f"bob email: {BOB_EMAIL}",
        f"bob password: {bob_password}",
        f"gateway pid: {gw_pid}",
        f"upstream pid: {up_pid}",
        f"rule: {rule}",
    ]
    write_private(STACK_FILE, "\n".join(stack) + "\n")
    report = lines + addresses + [f"rule: {rule}", f"stack file: {rel(STACK_FILE)}"]
    with open(UP_FILE, "w", encoding="utf-8") as handle:
        handle.write("\n".join(report) + "\n")
    print("\n".join(report))
    return 0


def command_check_free():
    marker = read_marker()
    alive = marked_pids(marker) if marker else []
    cf.need(not alive, f"a stack of an earlier up is still alive: pids {alive}; run down first")
    print("no stack of an earlier up is alive")
    return 0


def command_status():
    if not os.path.isfile(STACK_FILE):
        print("FAIL status: there is no stack file; run up first")
        return 1
    state = read_stack()
    marker = read_marker()
    missing = []
    for role in ("gateway", "upstream"):
        pid = int(state[f"{role} pid"])
        if not (marker and has_marker(pid, marker)):
            missing.append(f"{role} process {pid} is not alive with the stack marker")
    if not healthy(urlsplit(state["gateway"]).port):
        missing.append("the gateway does not answer /healthz with ok")
    for key in ("gateway", "server path", "combined", "upstream"):
        print(f"{key}: {state[key]}")
    if missing:
        for text in missing:
            print(f"MISSING: {text}")
        print("FAIL status: the stack is not complete")
        return 1
    print("PASS status: the gateway answers /healthz and both processes live")
    return 0


class ActivityRows(html.parser.HTMLParser):
    """The rows of the activity page, newest first, with their data attributes and detail text."""

    def __init__(self):
        super().__init__()
        self.rows = []
        self.current = None
        self.in_detail = False

    def handle_starttag(self, tag, attrs):
        values = dict(attrs)
        if tag in ("li", "tr") and "data-kind" in values:
            self.current = {
                "time": values.get("data-time") or "",
                "kind": values.get("data-kind") or "",
                "user": values.get("data-user") or "",
                "server": values.get("data-server") or "",
                "tool": values.get("data-tool") or "",
                "decision": values.get("data-decision") or "",
                "outcome": values.get("data-outcome") or "",
                "detail": "",
            }
            self.rows.append(self.current)
        elif tag == "p" and self.current is not None and "detail" in (values.get("class") or "").split():
            self.in_detail = True

    def handle_endtag(self, tag):
        if tag == "p":
            self.in_detail = False
        elif tag in ("li", "tr"):
            self.current = None

    def handle_data(self, data):
        if self.in_detail and self.current is not None:
            self.current["detail"] += data


class SelectOptions(html.parser.HTMLParser):
    """The options of every select on a page, as (select name, value, text)."""

    def __init__(self):
        super().__init__()
        self.options = []
        self.select = None
        self.value = None
        self.text = ""

    def handle_starttag(self, tag, attrs):
        values = dict(attrs)
        if tag == "select":
            self.select = values.get("name")
        elif tag == "option":
            self.value = values.get("value") or ""
            self.text = ""

    def handle_endtag(self, tag):
        if tag == "select":
            self.select = None
        elif tag == "option" and self.value is not None:
            self.options.append((self.select, self.value, self.text.strip()))
            self.value = None

    def handle_data(self, data):
        if self.value is not None:
            self.text += data


def owner_client(state):
    owner = cf.Client(urlsplit(state["gateway"]).port)
    signed = owner.form("/login", "/login", [("email", cf.OWNER_EMAIL), ("password", state["owner password"])])
    cf.need(signed.status == 303, f"the owner sign-in answered {signed.status}, wanted 303")
    return owner


ACTIVITY_PAGE_LIMIT = 200


def all_activity_rows(owner, path):
    """The rows of every page of the activity list from `path`, newest first.

    Older links are followed on the gateway address; more than ACTIVITY_PAGE_LIMIT pages fail.
    """
    gateway = urlsplit(owner.base)
    rows = []
    for _ in range(ACTIVITY_PAGE_LIMIT):
        page = owner.get(path)
        cf.need(page.status == 200 and page.kind() == "activity", f"the activity page answered {page.status}")
        parser = ActivityRows()
        parser.feed(page.text)
        rows.extend(parser.rows)
        older = page.find({"data-page-link": "older"})
        if not older:
            return rows
        target = urlsplit(urljoin(owner.base + "/", older[0]["href"]))
        cf.need(target.netloc == gateway.netloc, f"an older link leaves the gateway: {older[0]['href']}")
        path = target.path + ("?" + target.query if target.query else "")
    raise cf.Fail(f"the activity list runs past {ACTIVITY_PAGE_LIMIT} pages")


def activity_rows(state, email=None):
    """The activity rows, oldest first, optionally only one user's rows."""
    owner = owner_client(state)
    query = ""
    if email is not None:
        matches = owner.get("/admin/users").find({"data-email": email})
        cf.need(len(matches) == 1, f"there is no user with the email {email}")
        query = "?" + urlencode({"user": matches[0]["data-user-id"]})
    return list(reversed(all_activity_rows(owner, f"/admin/activity{query}")))


def format_row(row):
    fields = [row["time"], row["kind"], row["user"], row["server"], row["tool"], row["decision"], row["outcome"]]
    text = " ".join(value or "-" for value in fields)
    detail = row["detail"].strip()
    return f"{text} {detail}" if detail else text


def command_activity(user, out):
    rows = activity_rows(read_stack(), user)
    lines = [format_row(row) for row in rows] or ["no activity rows"]
    text = "\n".join(lines) + "\n"
    sys.stdout.write(text)
    if out:
        with open(out, "w", encoding="utf-8") as handle:
            handle.write(text)
    return 0


def rule_matches(owner):
    """The rows of the rules page that deny the denied tool on the demo server for bob."""
    return owner.get("/admin/rules").find(
        {"data-subject": BOB_EMAIL, "data-effect": "deny", "data-server": SLUG, "data-tool": DENIED_TOOL}
    )


def rule_targets(owner):
    """Bob's user id and the demo server's id, as the rules page's form lists them."""
    parser = SelectOptions()
    parser.feed(owner.get("/admin/rules").text)
    bob = [value for name, value, text in parser.options if name == "subject" and text == BOB_EMAIL]
    server = [value for name, value, text in parser.options if name == "server_id" and text.endswith(f"({SLUG})")]
    cf.need(len(bob) == 1 and len(server) == 1, f"the rules page lists {BOB_EMAIL} and {SLUG} once each")
    return bob[0], server[0]


def rule_off(owner):
    """Deletes every rule that denies the tool to bob, checks the page, and returns the deleted ids."""
    deleted = [rule["data-rule-id"] for rule in rule_matches(owner)]
    for rule_id in deleted:
        answer = owner.form("/admin/rules", f"/admin/rules/{rule_id}/delete", [])
        cf.need(answer.status == 303, f"deleting rule {rule_id} answered {answer.status}, wanted 303")
    cf.need(not rule_matches(owner), f"the rules page still denies {DENIED_TOOL} for {BOB_EMAIL}")
    return deleted


def rule_on(owner):
    """Creates the deny rule unless it exists; returns the rule line, the creation time (None when it existed)."""
    bob_id, server_id = rule_targets(owner)
    existing = rule_matches(owner)
    cf.need(len(existing) <= 1, f"the rules page shows {len(existing)} deny rules for {DENIED_TOOL}; run rule off first")
    created_at = None
    if not existing:
        created_at = utc_now()
        answer = owner.form(
            "/admin/rules",
            "/admin/rules",
            [("subject", bob_id), ("effect", "deny"), ("scope", "tool"), ("server_id", server_id), ("tool", DENIED_TOOL)],
        )
        cf.need(answer.status == 303, f"the rule form answered {answer.status}, wanted 303")
        existing = rule_matches(owner)
        cf.need(len(existing) == 1, f"the rules page shows {len(existing)} deny rules for {DENIED_TOOL}, wanted 1")
    text = rule_line(existing[0]["data-rule-id"], bob_id)
    set_stack_rule(text)
    return text, created_at


def command_rule(action):
    state = read_stack()
    owner = owner_client(state)
    if action == "off":
        deleted = rule_off(owner)
        if deleted:
            print("deleted rule ids: " + ", ".join(deleted))
        print(f"PASS rule off: {DENIED_TOOL} is allowed for {BOB_EMAIL}")
        return 0
    text, created_at = rule_on(owner)
    if created_at is None:
        print("the rule already existed; no duplicate was created")
    print(f"PASS rule on: {text}")
    return 0


def allowed_call_rows(owner, bob_id, tool):
    """Bob's finished allowed calls of one tool, oldest first; the owner session is reused by the caller."""
    page = owner.get(f"/admin/activity?{urlencode({'user': bob_id})}")
    cf.need(page.status == 200 and page.kind() == "activity", f"the activity page answered {page.status}")
    parser = ActivityRows()
    parser.feed(page.text)
    return [
        row
        for row in reversed(parser.rows)
        if row["kind"] == "tool_call" and row["tool"] == tool and row["outcome"] == "ok"
    ]


def positive_seconds(text):
    value = int(text)
    if value < 1:
        raise argparse.ArgumentTypeError("the timeout is at least 1 second")
    return value


def command_deny_after_first_call(timeout, tool):
    state = read_stack()
    owner = owner_client(state)
    bob_id, _ = rule_targets(owner)
    # Activity times are whole seconds, so a row in the second the command starts counts as newer.
    started = utc_now()
    deadline = time.monotonic() + timeout
    seen = None
    while seen is None:
        newer = [row for row in allowed_call_rows(owner, bob_id, tool) if row["time"] >= started]
        if newer:
            seen = newer[-1]
        elif time.monotonic() >= deadline:
            break
        else:
            time.sleep(POLL_SECONDS)
    if seen is None:
        print(f"FAIL deny-after-first-call: no allowed {tool} call by {BOB_EMAIL} finished within {timeout} seconds")
        return 1
    print(f"row seen: {format_row(seen)}")
    text, created_at = rule_on(owner)
    if created_at is None:
        print("rule creation time: none, the rule already existed")
    else:
        print(f"rule creation time: {created_at}")
    print(f"PASS deny-after-first-call: rule on: {text}")
    return 0


class HeaderRows(html.parser.HTMLParser):
    """The declared header rows of the server page: lower-cased name, Required flag and header id."""

    def __init__(self):
        super().__init__()
        self.rows = []
        self.current = None

    def handle_starttag(self, tag, attrs):
        values = dict(attrs)
        if tag == "tr":
            self.current = None
            if "data-header" in values:
                required = values.get("data-required") == "yes"
                self.current = {"name": values["data-header"], "required": required, "id": None}
                self.rows.append(self.current)
        elif tag == "input" and self.current is not None and (values.get("name") or "").startswith("required_"):
            self.current["id"] = values["name"][len("required_"):]


class ValueFields(html.parser.HTMLParser):
    """The value fields inside one form of the account page, and the header name and state of each hint."""

    def __init__(self, action):
        super().__init__()
        self.action = action
        self.inside = False
        self.fields = []
        self.hints = {}

    def handle_starttag(self, tag, attrs):
        values = dict(attrs)
        if tag == "form":
            self.inside = values.get("action") == self.action
        elif tag == "input" and self.inside and (values.get("name") or "").startswith("value_"):
            self.fields.append((values["name"], values.get("aria-describedby")))
        elif tag == "p" and "data-header" in values:
            self.hints[values.get("id")] = (values["data-header"], values.get("data-value-state"))

    def handle_endtag(self, tag):
        if tag == "form":
            self.inside = False


class ErrorNotice(html.parser.HTMLParser):
    """The text of the first error notice of a page; empty when there is none."""

    def __init__(self):
        super().__init__()
        self.depth = None
        self.found = False
        self.parts = []

    def handle_starttag(self, tag, attrs):
        if tag != "div":
            return
        if self.depth is not None:
            self.depth += 1
        elif not self.found and dict(attrs).get("data-notice") == "error":
            self.found = True
            self.depth = 1

    def handle_endtag(self, tag):
        if tag == "div" and self.depth is not None:
            self.depth -= 1
            if self.depth == 0:
                self.depth = None

    def handle_data(self, data):
        if self.depth is not None:
            self.parts.append(data)

    def text(self):
        return " ".join("".join(self.parts).split())


def header_rows(page):
    parser = HeaderRows()
    parser.feed(page.text)
    return parser.rows


def value_fields(page, action):
    """The value fields of the form posting to action, as (field name, lower-cased header name, hint state)."""
    parser = ValueFields(action)
    parser.feed(page.text)
    fields = []
    for field, hint in parser.fields:
        lower, state = parser.hints.get(hint, (None, None))
        fields.append((field, lower, state))
    return fields


def done_of(answer):
    """The done parameter of a redirect's location, or None."""
    return parse_qs(urlsplit(answer.location or "").query).get("done", [None])[0]


def demo_server_path(owner):
    rows = owner.get("/admin/servers").find({"data-slug": SLUG})
    cf.need(len(rows) == 1, f"the servers page shows {len(rows)} rows for {SLUG}, wanted 1")
    return f"/admin/servers/{rows[0]['data-server-id']}"


def command_headers(passing, storing):
    """Declares each per-user header on demo as required, then sets the two switches; reads both back."""
    names = {}
    for name in fake_upstream.parse_user_headers([], os.environ):
        names.setdefault(name.lower(), name)
    if not names:
        print(f"PROVE-CLIENTS FAIL: {fake_upstream.USER_HEADERS_KEY} is unset or names no header", file=sys.stderr)
        return 2
    owner = owner_client(read_stack())
    server_path = demo_server_path(owner)
    declared = {row["name"] for row in header_rows(owner.get(server_path))}
    for lower, name in names.items():
        if lower in declared:
            continue
        added = owner.form(server_path, f"{server_path}/headers", [("name", name), ("required", "1")])
        cf.need(
            added.status == 303 and done_of(added) == "header-added",
            f"declaring {name} answered {added.status}, wanted 303 with header-added",
        )
        declared.add(lower)
    fields = []
    if passing:
        fields.append(("pass_headers", "1"))
    if storing:
        fields.append(("store_headers", "1"))
    for row in header_rows(owner.get(server_path)):
        cf.need(row["id"] is not None, f"a header row of {SLUG} holds no Required box")
        fields += [(f"listed_{row['id']}", "1"), (f"required_{row['id']}", "1")]
    saved = owner.form(server_path, f"{server_path}/header-switches", fields)
    cf.need(
        saved.status == 303 and done_of(saved) == "headers-saved",
        f"saving the headers answered {saved.status}, wanted 303 with headers-saved",
    )
    page = owner.get(server_path)
    rows = {row["name"]: row for row in header_rows(page)}
    lines = []
    for lower, name in names.items():
        cf.need(lower in rows and rows[lower]["required"], f"header {name} is not declared and required on {SLUG}")
        lines.append(f"header {name}: declared, required")
    states = {}
    for key, want in (("pass_headers", passing), ("store_headers", storing)):
        boxes = page.find({"name": key})
        cf.need(len(boxes) == 1, f"the server page shows {len(boxes)} {key} boxes, wanted 1")
        checked = "checked" in boxes[0]
        cf.need(checked == want, f"the server page shows {key} {'on' if checked else 'off'}, wanted the switch as set")
        states[key] = "on" if checked else "off"
    lines.append(f"switches: pass {states['pass_headers']}, store {states['store_headers']}")
    print("\n".join(lines))
    return 0


def read_value(path):
    """A generated value, or the content of the file without one trailing newline; never printed."""
    if path is None:
        return secrets.token_hex(16)
    try:
        with open(path, encoding="utf-8") as handle:
            text = handle.read()
    except (OSError, UnicodeDecodeError) as error:
        raise cf.Fail(f"the value file cannot be read: {type(error).__name__}") from None
    value = text[:-1] if text.endswith("\n") else text
    cf.need(value != "", "the value file holds no value")
    return value


def command_store_value(name, value_file):
    """Stores one value of a header of demo for bob, through the account page, and reads the state back."""
    state = read_stack()
    bob = cf.Client(urlsplit(state["gateway"]).port)
    signed = bob.form("/login", "/login", [("email", BOB_EMAIL), ("password", state["bob password"])])
    cf.need(signed.status == 303, f"bob's sign-in answered {signed.status}, wanted 303")
    action = f"/account/values/{SLUG}"
    page = bob.get("/account")
    cf.need(page.status == 200 and page.kind() == "account", f"the account page answered {page.status}")
    matches = [field for field, lower, _ in value_fields(page, action) if lower == name.lower()]
    cf.need(len(matches) == 1, f"the account page has {len(matches)} fields for {name} on {SLUG}, wanted 1")
    field = matches[0]
    token = page.csrf()
    cf.need(token is not None, "the account page carries a csrf token")
    value = read_value(value_file)
    answer = bob.post_form(action, [("csrf", token), (field, value)])
    location = urlsplit(answer.location or "")
    saved = (
        answer.status == 303
        and location.path == "/account"
        and parse_qs(location.query).get("done") == ["credentials-saved"]
    )
    if not saved:
        notice = ErrorNotice()
        notice.feed(answer.text)
        detail = f": {notice.text()}" if notice.text() else ""
        raise cf.Fail(f"the post answered {answer.status}{detail}")
    after = bob.get("/account")
    stored = [hint_state for key, _, hint_state in value_fields(after, action) if key == field]
    cf.need(stored == ["set"], f"the account page does not show {name} stored on {SLUG}")
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]
    print(f"stored {name} for bob: digest {digest}")
    if value_file is None:
        path = os.path.join(RUN, f"value-{name.lower()}.txt")
        write_private(path, value + "\n")
        print(f"value file: {rel(path)}")
    return 0


def mcp_post(port, token, body, session=None, timeout=60):
    """One POST to the server path with the bearer token; a slow answer may take up to timeout seconds."""
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
    }
    if session is not None:
        headers["Mcp-Session-Id"] = session
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    try:
        conn.request("POST", f"/{SLUG}", body=json.dumps(body).encode(), headers=headers)
        response = conn.getresponse()
        data = response.read()
        pairs = response.getheaders()
    except (OSError, http.client.HTTPException) as error:
        cf.need(False, f"the request to /{SLUG} failed: {type(error).__name__}")
    finally:
        conn.close()
    return cf.Page(response.status, pairs, data)


def header_value(page, name):
    for key, value in page.headers:
        if key.lower() == name.lower():
            return value
    return None


def reply_of(page):
    """The JSON-RPC message of an answer, from a JSON body or the data line of an event stream."""
    if (header_value(page, "Content-Type") or "").startswith("text/event-stream"):
        data = [line[5:].strip() for line in page.text.splitlines() if line.startswith("data:")]
        cf.need(bool(data), "the event-stream answer holds no data line")
        text = data[-1]
    else:
        text = page.text
    try:
        return json.loads(text)
    except ValueError:
        cf.need(False, "an answer is not JSON")


def open_session(port, token, passed):
    """Initialize and notifications/initialized on a new session; returns the session id."""
    init = mcp_post(
        port,
        token,
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "prove-clients", "version": "1"},
            },
        },
    )
    cf.need(init.status == 200 and "result" in reply_of(init), f"initialize answered {init.status}")
    session = header_value(init, "Mcp-Session-Id")
    cf.need(session is not None, "initialize answered no Mcp-Session-Id")
    passed("initialize answered 200 with a session")
    notified = mcp_post(port, token, {"jsonrpc": "2.0", "method": "notifications/initialized"}, session)
    cf.need(notified.status == 202, f"notifications/initialized answered {notified.status}, wanted 202")
    passed("notifications/initialized answered 202")
    return session


def list_names(port, token, session):
    listed = mcp_post(port, token, {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}, session)
    cf.need(listed.status == 200, f"tools/list answered {listed.status}, wanted 200")
    return [tool["name"] for tool in reply_of(listed)["result"]["tools"]]


def call_slow(port, token, session):
    return mcp_post(
        port,
        token,
        {"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {"name": DENIED_TOOL, "arguments": {}}},
        session,
        timeout=SLOW_TIMEOUT_SECONDS,
    )


def toggle_phase(state, port, token, passed, show):
    """Allows the slow tool, calls it, denies it, and calls it again on the same session."""
    owner = owner_client(state)
    rule_off(owner)
    passed(f"rule off: {DENIED_TOOL} is allowed for {BOB_EMAIL}")
    session = open_session(port, token, passed)
    names = list_names(port, token, session)
    cf.need(
        "echo" in names and DENIED_TOOL in names,
        f"the fresh session's tools/list does not show both tools: {names!r}",
    )
    passed(f"fresh session tools/list shows {', '.join(names)}")
    allowed = call_slow(port, token, session)
    cf.need(allowed.status == 200, f"tools/call {DENIED_TOOL} answered {allowed.status}, wanted 200")
    result = reply_of(allowed).get("result") or {}
    cf.need(
        bool(result.get("content")) and result["content"][0].get("text") == "slow done",
        f"tools/call {DENIED_TOOL} while allowed returned {result!r}",
    )
    passed(f"tools/call {DENIED_TOOL} succeeded while allowed: {result['content'][0]['text']}")
    text, _ = rule_on(owner)
    passed(f"rule on: {text}")
    refused = mcp_post(
        port,
        token,
        {"jsonrpc": "2.0", "id": 6, "method": "tools/call", "params": {"name": DENIED_TOOL, "arguments": {}}},
        session,
    )
    error = reply_of(refused).get("error") or {}
    cf.need(
        error.get("code") == -32602 and error.get("message") == f"Unknown tool: {DENIED_TOOL}",
        f"tools/call {DENIED_TOOL} on the same session was not refused as expected: {error!r}",
    )
    passed(f"tools/call {DENIED_TOOL} on the same session refused: {error['code']} {error['message']}")
    rows = activity_rows(state, BOB_EMAIL)
    allow_index = max(
        (i for i, r in enumerate(rows) if r["tool"] == DENIED_TOOL and r["decision"] == "allow" and r["outcome"] == "ok"),
        default=None,
    )
    cf.need(allow_index is not None, f"the activity log has no allowed {DENIED_TOOL} row for {BOB_EMAIL}")
    deny_index = next(
        (
            i
            for i in range(allow_index + 1, len(rows))
            if rows[i]["tool"] == DENIED_TOOL and rows[i]["decision"] == "deny" and rows[i]["outcome"] == "refused"
        ),
        None,
    )
    cf.need(deny_index is not None, f"no refused {DENIED_TOOL} row follows the allowed one")
    show(format_row(rows[allow_index]))
    show(format_row(rows[deny_index]))
    passed(f"activity shows the {DENIED_TOOL} allow ok row, then the {DENIED_TOOL} deny refused row; the rule is on")


def command_selfcheck(toggle):
    state = read_stack()
    port = urlsplit(state["gateway"]).port
    lines = []

    def passed(text):
        lines.append(f"PASS {text}")
        print(lines[-1], flush=True)

    def show(text):
        lines.append(text)
        print(text, flush=True)

    try:
        anonymous = cf.Client(port)
        client_id = cf.register_client(anonymous)
        passed("registered a throwaway OAuth client")
        bob = cf.Client(port)
        signed = bob.form("/login", "/login", [("email", BOB_EMAIL), ("password", state["bob password"])])
        cf.need(signed.status == 303, f"bob's sign-in answered {signed.status}, wanted 303")
        passed(f"signed in as {BOB_EMAIL} over HTTP")
        token = cf.issue_token(bob, anonymous, client_id, f"http://127.0.0.1:{port}/{SLUG}")
        passed(f"authorization code flow for /{SLUG} as {BOB_EMAIL}: access token issued (not printed)")

        session = open_session(port, token, passed)
        names = list_names(port, token, session)
        cf.need("echo" in names, f"tools/list does not show echo: {names!r}")
        cf.need(DENIED_TOOL not in names, f"tools/list shows the denied tool {DENIED_TOOL}")
        passed(f"tools/list shows {', '.join(names)}; {DENIED_TOOL} is left out (denied tools are not listed)")

        called = mcp_post(
            port,
            token,
            {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "echo", "arguments": {"text": "hello"}}},
            session,
        )
        cf.need(called.status == 200, f"tools/call echo answered {called.status}, wanted 200")
        result = reply_of(called)["result"]
        cf.need(result["content"][0]["text"] == "echo: hello", f"tools/call echo returned {result!r}")
        passed("tools/call echo returned its text: echo: hello")

        refused = mcp_post(
            port,
            token,
            {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": DENIED_TOOL, "arguments": {}}},
            session,
        )
        error = reply_of(refused).get("error") or {}
        cf.need(
            error.get("code") == -32602 and error.get("message") == f"Unknown tool: {DENIED_TOOL}",
            f"tools/call {DENIED_TOOL} was not refused as expected: {error!r}",
        )
        passed(f"tools/call {DENIED_TOOL} refused by the gateway: {error['code']} {error['message']}")

        rows = activity_rows(state, BOB_EMAIL)
        cf.need(
            any(r["tool"] == "echo" and r["decision"] == "allow" and r["outcome"] == "ok" for r in rows),
            f"the activity log has no allowed echo row for {BOB_EMAIL}",
        )
        cf.need(
            any(r["tool"] == DENIED_TOOL and r["decision"] == "deny" and r["outcome"] == "refused" for r in rows),
            f"the activity log has no refused {DENIED_TOOL} row for {BOB_EMAIL}",
        )
        passed(f"activity --user {BOB_EMAIL} shows the echo row allowed and the {DENIED_TOOL} row refused")
        if toggle:
            toggle_phase(state, port, token, passed, show)
        status = 0
    except cf.Fail as failure:
        print(f"FAIL selfcheck: {failure}", flush=True)
        status = 1
    with open(SELFCHECK_FILE, "w", encoding="utf-8") as handle:
        handle.write("\n".join(lines) + "\n")
    return status


def command_down(wipe):
    marker = read_marker()
    if marker is None:
        print("PASS down: no stack marker, nothing to stop")
    else:
        survivors = stop_marked(marker)
        if survivors:
            print(f"FAIL down: processes of this stack survive: {survivors}")
            return 1
        print("PASS down: no process of this stack survives")
    if wipe and os.path.isdir(RUN):
        shutil.rmtree(RUN)
        print("work directory removed")
    return 0


def build_parser():
    parser = argparse.ArgumentParser(description="Local stack for the hand-driven real-client runs.")
    sub = parser.add_subparsers(dest="cmd", required=True)
    up = sub.add_parser("up", help="start the stack detached and drive it")
    up.add_argument("--binary", required=True)
    sub.add_parser("check-free", help="fail when a stack of an earlier up is alive")
    sub.add_parser("status", help="exit 0 when the stack is complete")
    activity = sub.add_parser("activity", help="print the activity rows")
    activity.add_argument("--user")
    activity.add_argument("--out")
    selfcheck = sub.add_parser("selfcheck", help="prove the stack as bob over OAuth and MCP")
    selfcheck.add_argument("--toggle", action="store_true", help="also allow, call, deny and call slow")
    rule = sub.add_parser("rule", help="delete (off) or create (on) the deny rule for slow")
    rule.add_argument("action", choices=["off", "on"])
    first = sub.add_parser("deny-after-first-call", help="deny slow once bob's first allowed call of a tool finishes")
    first.add_argument("--timeout", type=positive_seconds, default=300)
    first.add_argument("--tool", default=DENIED_TOOL, help="the tool whose first finished allowed call triggers rule on")
    headers = sub.add_parser("headers", help="declare the per-user headers on demo and set its two switches")
    headers.add_argument("--pass", dest="passing", required=True, choices=["on", "off"])
    headers.add_argument("--store", dest="storing", required=True, choices=["on", "off"])
    store = sub.add_parser("store-value", help="store one value of a header of demo for bob")
    store.add_argument("--header", required=True)
    store.add_argument("--value-file")
    down = sub.add_parser("down", help="stop this stack by its marker")
    down.add_argument("--wipe", action="store_true")
    serve = sub.add_parser("upstream", help="serve the fake upstream on loopback (used by up)")
    serve.add_argument("--port", type=int, required=True)
    return parser


def work_directory_allowed():
    """True when RUN is a strict subdirectory of BASE and not a symlink; rmtree only ever sees such a path."""
    if os.path.islink(RUN):
        return False
    real = os.path.realpath(RUN)
    return real != BASE and os.path.commonpath([BASE, real]) == BASE


def main(argv):
    if not work_directory_allowed():
        print(WORK_REFUSED, file=sys.stderr)
        return 2
    args = build_parser().parse_args(argv)
    try:
        if args.cmd == "up":
            return command_up(args.binary)
        if args.cmd == "check-free":
            return command_check_free()
        if args.cmd == "status":
            return command_status()
        if args.cmd == "activity":
            return command_activity(args.user, args.out)
        if args.cmd == "selfcheck":
            return command_selfcheck(args.toggle)
        if args.cmd == "rule":
            return command_rule(args.action)
        if args.cmd == "deny-after-first-call":
            return command_deny_after_first_call(args.timeout, args.tool)
        if args.cmd == "headers":
            return command_headers(args.passing == "on", args.storing == "on")
        if args.cmd == "store-value":
            return command_store_value(args.header, args.value_file)
        if args.cmd == "down":
            return command_down(args.wipe)
        return run_upstream(args.port)
    except cf.Fail as failure:
        print(f"FAIL {args.cmd}: {failure}")
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
