"""Gateway driver, loopback token forwarder and report for scripts/prove-conformance.sh."""

import argparse
import base64
import copy
import hashlib
import html.parser
import http.client
import io
import json
import os
import re
import secrets
import socket
import socketserver
import sys
import time
import traceback
from urllib.parse import parse_qs, urlencode, urljoin, urlsplit

OWNER_EMAIL = "owner@example.com"
SLUG = "everything"
COMBINED = "mcp"
SWITCHES = {"pass_resources": "on", "pass_prompts": "on"}
LIMIT_NAMES = ("general_burst", "general_per_minute", "mcp_burst", "mcp_per_minute")
REDIRECT = "http://127.0.0.1:53535/callback"
CLIENT_NAME = "conformance client"
SETUP_MARK = "doorward setup code:"
FORWARDED = ("/everything", "/mcp")
COMBINED_PATH = f"/{COMBINED}"
TOOL_PREFIX = f"{SLUG}__"
TOOL_NAME_RE = re.compile(rb'"name"(\s*:\s*)"' + re.escape(TOOL_PREFIX.encode("ascii")) + rb'([A-Za-z0-9_.-]+)"')
REVISIONS = ("2025-11-25", "2026-07-28")
RUN_NAMES = [f"{kind}-{rev}" for kind in ("direct", "gateway", "combined") for rev in REVISIONS]
STREAMED = ("tools-call-with-progress", "server-sse-multiple-streams")
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DIR_RE = re.compile(r"^server-(?P<name>.+)-\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}-\d{3}Z$")
NOT_SCORED_RE = re.compile(r"^\s+[✓✗] (\S+) \(")
HEADER_TOKEN_RE = re.compile(r"[A-Za-z0-9._~+/=-]{1,512}")
DIGITS_RE = re.compile(r"[0-9]+")
STATUS_RE = re.compile(r"[0-9]{3}")
LINE_LIMIT = 65536
HEADER_LINE_LIMIT = 1000
CHUNK = 65536
PROVE_DIR = os.path.join(ROOT, "scripts", "prove")
SCOPE_FILE = os.path.join(PROVE_DIR, "conformance-combined-scope.txt")
SIDECAR_FILE = os.path.join(PROVE_DIR, "conformance-expected.tsv")
SIDECAR_HEADER = ["revision", "target", "scenario", "check", "class", "substring", "approval", "reason"]
SIDECAR_CLASSES = ("scope decision", "reference quirk")
APPROVAL_RE = re.compile(r"pending|approved by the owner(?:'s reviewer)? on [0-9]{4}-[0-9]{2}-[0-9]{2}")
YAML_ENTRY_RE = re.compile(r"  - ([A-Za-z0-9._/-]+):([A-Za-z0-9._-]+)")
STATUSES = ("SUCCESS", "FAILURE", "WARNING", "SKIPPED", "INFO")
# The run name prefix of each target, and the sidecar's name for it.
TARGET_KINDS = {"gateway": "server-path", "combined": "combined"}


class Fail(Exception):
    """A driver step or argument that does not match what the gateway documents."""


def need(condition, text):
    if not condition:
        raise Fail(text)


def note(text):
    print(f"forward: {text}", file=sys.stderr, flush=True)


def expires_now(attributes):
    for part in attributes.split(";"):
        key, _, value = part.strip().partition("=")
        if key.lower() == "max-age":
            try:
                return int(value) <= 0
            except ValueError:
                return False
    return False


class DocParser(html.parser.HTMLParser):
    def __init__(self):
        super().__init__()
        self.tags = []

    def handle_starttag(self, tag, attrs):
        self.tags.append((tag, {name: value or "" for name, value in attrs}))


class Page:
    def __init__(self, status, headers, body):
        self.status = status
        self.headers = headers
        self.text = body.decode("utf-8", "replace")
        self.parsed = None

    @property
    def location(self):
        for key, value in self.headers:
            if key.lower() == "location":
                return value
        return None

    def tags(self):
        if self.parsed is None:
            parser = DocParser()
            parser.feed(self.text)
            self.parsed = parser.tags
        return self.parsed

    def kind(self):
        for tag, attrs in self.tags():
            if tag == "main":
                return attrs.get("data-page")
        return None

    def csrf(self):
        for tag, attrs in self.tags():
            if tag == "input" and attrs.get("name") == "csrf":
                return attrs.get("value")
        return None

    def find(self, want):
        return [attrs for _, attrs in self.tags() if all(attrs.get(k) == v for k, v in want.items())]

    def values_of(self, attribute):
        return [attrs[attribute] for _, attrs in self.tags() if attribute in attrs]


class Client:
    """One cookie jar speaking plain HTTP to the forwarder on loopback."""

    def __init__(self, port):
        self.port = port
        self.base = os.environ.get("PROVE_CLIENTS_PUBLIC_URL") or f"http://127.0.0.1:{port}"
        self.jar = {}

    def send(self, method, path, body=None, headers=None, cookies=True):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=60)
        try:
            sent = dict(headers or {})
            if cookies and self.jar:
                sent["Cookie"] = "; ".join(f"{k}={v}" for k, v in self.jar.items())
            conn.request(method, path, body=body, headers=sent)
            response = conn.getresponse()
            data = response.read()
            pairs = response.getheaders()
        finally:
            conn.close()
        self.keep_cookies(pairs)
        return Page(response.status, pairs, data)

    def keep_cookies(self, pairs):
        for key, value in pairs:
            if key.lower() != "set-cookie":
                continue
            pair, _, attributes = value.partition(";")
            name, _, cookie_value = pair.partition("=")
            name, cookie_value = name.strip(), cookie_value.strip()
            if not name:
                continue
            if not cookie_value or expires_now(attributes):
                self.jar.pop(name, None)
            else:
                self.jar[name] = cookie_value

    def get(self, path):
        return self.send("GET", path)

    def post_form(self, path, fields):
        headers = {"Content-Type": "application/x-www-form-urlencoded", "Origin": self.base}
        return self.send("POST", path, body=urlencode(fields).encode(), headers=headers)

    def form(self, page_path, action, fields):
        """GETs the form page, then posts the fields with its csrf token."""
        page = self.get(page_path)
        token = page.csrf()
        need(token is not None, f"GET {page_path} carries a csrf token, answered {page.status}")
        return self.post_form(action, [("csrf", token), *fields])


def json_body(page):
    try:
        return json.loads(page.text)
    except ValueError:
        return None


def random_verifier():
    unreserved = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
    return "".join(secrets.choice(unreserved) for _ in range(43))


def read_setup_code(path):
    """The one setup code line the gateway wrote to its standard error."""
    deadline = time.monotonic() + 30
    while True:
        try:
            with open(path, encoding="utf-8", errors="replace") as handle:
                lines = [line for line in handle if SETUP_MARK in line]
        except FileNotFoundError:
            lines = []
        if lines:
            break
        need(time.monotonic() < deadline, "the gateway log holds no setup code line within 30 seconds")
        time.sleep(0.2)
    need(len(lines) == 1, f"the gateway log holds {len(lines)} setup code lines, wanted 1")
    return lines[0].split(SETUP_MARK, 1)[1].strip()


def setup_owner(owner, code, password):
    setup_page = owner.get("/setup")
    need(setup_page.status == 200, f"GET /setup answered {setup_page.status}, wanted 200")
    token = setup_page.csrf()
    need(token is not None, "the setup form carries a csrf token")
    signed = owner.post_form(
        "/setup",
        [("csrf", token), ("setup_code", code), ("email", OWNER_EMAIL), ("password", password)],
    )
    need(
        signed.status == 303 and signed.location == "/admin",
        f"POST /setup answered {signed.status} to {signed.location!r}, wanted 303 to /admin",
    )
    account = owner.get("/account")
    need(account.status == 200, f"GET /account answered {account.status}, wanted 200")
    need(account.kind() == "account", f"the account page has kind {account.kind()!r}")


def add_server(owner, upstream):
    added = owner.form(
        "/admin/servers",
        "/admin/servers",
        [
            ("name", SLUG),
            ("slug", SLUG),
            ("upstream_url", upstream),
            ("secret_header_name", ""),
            ("secret_header_value", ""),
            *SWITCHES.items(),
        ],
    )
    need(added.status == 303, f"POST /admin/servers answered {added.status}, wanted 303")
    prefix = "/admin/servers/"
    need(
        added.location is not None and added.location.startswith(prefix),
        f"the new server has a page, location {added.location!r}",
    )
    server_id = added.location[len(prefix):]
    server_path = f"{prefix}{server_id}"
    refreshed = owner.form(server_path, f"{server_path}/refresh-tools", [])
    need(refreshed.status == 303, f"refresh the tool list answered {refreshed.status}, wanted 303")
    page = owner.get(server_path)
    for name in SWITCHES:
        boxes = page.find({"name": name})
        need(len(boxes) == 1 and "checked" in boxes[0], f"the server page shows {name} checked")
    tools = page.values_of("data-catalog-tool")
    return server_id, len(tools)


def assign_server(owner, server_id):
    rows = owner.get("/admin/users").find({"data-email": OWNER_EMAIL})
    need(len(rows) == 1, f"the owner is on the users page once, found {len(rows)} rows")
    user_path = f"/admin/users/{rows[0]['data-user-id']}"
    assigned = owner.form(user_path, f"{user_path}/servers", [("server_id", server_id)])
    need(assigned.status == 303, f"assign the server answered {assigned.status}, wanted 303")


def register_client(anonymous):
    registered = anonymous.send(
        "POST",
        "/oauth/register",
        body=json.dumps({"client_name": CLIENT_NAME, "redirect_uris": [REDIRECT]}).encode(),
        headers={"Content-Type": "application/json"},
        cookies=False,
    )
    need(registered.status == 201, f"POST /oauth/register answered {registered.status}, wanted 201")
    client_id = (json_body(registered) or {}).get("client_id", "")
    need(client_id.startswith("dcr_"), "registration returns a dcr_ client id")
    return client_id


def issue_token(owner, anonymous, client_id, resource):
    """Authorize with PKCE, approve consent, exchange the code; returns the access token."""
    verifier = random_verifier()
    digest = hashlib.sha256(verifier.encode()).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
    oauth_state = secrets.token_urlsafe(12)
    query = urlencode(
        [
            ("response_type", "code"),
            ("client_id", client_id),
            ("redirect_uri", REDIRECT),
            ("code_challenge", challenge),
            ("code_challenge_method", "S256"),
            ("resource", resource),
            ("state", oauth_state),
            ("scope", "mcp"),
        ]
    )
    authorized = owner.get(f"/oauth/authorize?{query}")
    need(authorized.status == 303, f"GET /oauth/authorize answered {authorized.status}, wanted 303")
    target = urlsplit(urljoin(owner.base + "/", authorized.location or ""))
    need(target.path == "/oauth/consent", f"authorize leads to the consent page, found {target.path!r}")
    req = parse_qs(target.query).get("req", [""])[0]
    need(bool(req), "the consent page has a request id")
    granted = owner.form(
        f"/oauth/consent?{urlencode({'req': req})}",
        "/oauth/consent",
        [("req", req), ("decision", "approve")],
    )
    need(granted.status == 303, f"POST /oauth/consent answered {granted.status}, wanted 303")
    back = urlsplit(granted.location or "")
    need(
        f"{back.scheme}://{back.netloc}{back.path}" == REDIRECT,
        "consent redirects to the registered address (the location is not printed: it holds a code)",
    )
    answer = parse_qs(back.query)
    need(answer.get("state") == [oauth_state], "consent returns the state")
    need(answer.get("iss") == [owner.base], "consent returns iss equal to the public address")
    code = answer.get("code", [""])[0]
    need(bool(code), "consent returns a code")
    issued = anonymous.send(
        "POST",
        "/oauth/token",
        body=urlencode(
            [
                ("grant_type", "authorization_code"),
                ("code", code),
                ("client_id", client_id),
                ("code_verifier", verifier),
                ("redirect_uri", REDIRECT),
                ("resource", resource),
            ]
        ).encode(),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        cookies=False,
    )
    need(issued.status == 200, f"POST /oauth/token answered {issued.status}, wanted 200")
    tokens = json_body(issued) or {}
    access = tokens.get("access_token", "")
    need(access.startswith("dw_at_"), "the token answer holds an access token")
    need(tokens.get("token_type") == "Bearer", f"the token type is {tokens.get('token_type')!r}")
    need(tokens.get("scope") == "mcp", f"the scope is {tokens.get('scope')!r}")
    return access


def write_tokens(path, tokens):
    """Writes the token file with mode 600, replacing any earlier one in one step."""
    temp = f"{path}.tmp"
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        json.dump(tokens, handle)
    os.replace(temp, path)


def drive(args):
    code = read_setup_code(args.setup_log)
    password = secrets.token_urlsafe(24)
    owner = Client(args.port)
    setup_owner(owner, code, password)
    print("PASS D1 owner set up with the setup code; account page loads signed in", flush=True)

    server_id, catalog = add_server(owner, args.upstream)
    print(
        f"PASS D2 server {SLUG} added with pass_resources and pass_prompts on (checked on the edit page); "
        f"tool list refreshed, catalog holds {catalog} tools",
        flush=True,
    )
    assign_server(owner, server_id)
    print("PASS D3 server assigned to the owner", flush=True)

    anonymous = Client(args.port)
    client_id = register_client(anonymous)
    print("PASS D4 public client registered", flush=True)

    tokens = {
        f"/{SLUG}": issue_token(owner, anonymous, client_id, f"{owner.base}/{SLUG}"),
        f"/{COMBINED}": issue_token(owner, anonymous, client_id, f"{owner.base}/{COMBINED}"),
    }
    write_tokens(args.token_file, tokens)
    print(f"PASS D5 PKCE authorize and consent approved; tokens for /{SLUG} and /{COMBINED} written", flush=True)


def failures(checks):
    return [check for check in checks if check.get("status") == "FAILURE"]


def load_run(directory):
    """Scenario name -> its checks, from every checks.json under one run directory; None if absent."""
    if not os.path.isdir(directory):
        return None
    scenarios = {}
    for entry in sorted(os.listdir(directory)):
        path = os.path.join(directory, entry, "checks.json")
        if not os.path.isfile(path):
            continue
        match = DIR_RE.match(entry)
        name = match.group("name") if match else entry
        with open(path, encoding="utf-8") as handle:
            checks = json.load(handle)
        scenarios.setdefault(name, []).extend(checks)
    return scenarios


def read_console(path):
    """The Total line and the names listed under Not scored in one run's console output."""
    info = {"total": None, "not_scored": set()}
    if not os.path.isfile(path):
        return info
    block = False
    with open(path, encoding="utf-8", errors="replace") as handle:
        for line in handle:
            line = line.rstrip("\n")
            if line.startswith("Total: "):
                info["total"] = line
            elif line.startswith("Not scored for "):
                block = True
            elif block:
                match = NOT_SCORED_RE.match(line)
                if match:
                    info["not_scored"].add(match.group(1))
    return info


def read_exits(path):
    exits = {}
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            name, _, code = line.rstrip("\n").partition("\t")
            if name:
                exits[name] = code
    return exits


def read_tokens(work):
    path = os.path.join(work, "tokens.json")
    if not os.path.isfile(path):
        return []
    with open(path, encoding="utf-8") as handle:
        data = json.load(handle)
    return [value for value in data.values() if isinstance(value, str) and value]


def scan_outputs(work, tokens):
    """Names of the suite output files that hold a token; the contents are never printed."""
    hits = []
    targets = []
    for root, _, files in os.walk(os.path.join(work, "results")):
        targets.extend(os.path.join(root, name) for name in files)
    targets.extend(os.path.join(work, name) for name in os.listdir(work) if name.endswith(".txt"))
    for path in targets:
        with open(path, "rb") as handle:
            data = handle.read()
        if any(token.encode("utf-8") in data for token in tokens):
            hits.append(os.path.relpath(path, work))
    return hits


def signature(checks):
    if checks is None:
        return None
    pairs = [[check.get("id"), check.get("errorMessage")] for check in failures(checks)]
    return sorted(pairs, key=lambda pair: json.dumps(pair))


def describe(checks):
    if checks is None:
        return "absent"
    count = len(failures(checks))
    if count == 0:
        return "pass"
    return f"FAIL ({count} check{'s' if count != 1 else ''})"


def check_line(check):
    """The check id and its message, verbatim; a check without errorMessage shows its description."""
    message = check.get("errorMessage")
    if message is None:
        message = f"(no errorMessage) {check.get('description', '')}"
    return f"{check.get('id')}: {message}"


def failure_lines(side, checks):
    if checks is None:
        return []
    return [f"    {side} {line}" for check in failures(checks) for line in check_line(check).split("\n")]


def read_limits(path):
    """The name = number lines of the generated config, as the values the runs used."""
    values = {}
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            match = re.fullmatch(r"([a-z_]+) = ([0-9]+)", line.strip())
            if match:
                values[match.group(1)] = int(match.group(2))
    return values


def comparison_table(left_name, left, right_name, right, not_scored):
    """Rows for the scenarios whose failing checks or presence differ between two runs."""
    lines = [f"scenario | {left_name} | {right_name}"]
    differing = 0
    for name in sorted(set(left) | set(right)):
        a, b = left.get(name), right.get(name)
        if signature(a) == signature(b):
            continue
        differing += 1
        tag = " (not scored)" if name in not_scored else ""
        lines.append(f"{name}{tag} | {describe(a)} | {describe(b)}")
        lines.extend(failure_lines(left_name, a))
        lines.extend(failure_lines(right_name, b))
    if differing == 0:
        lines.append("no scenario differs")
    return differing, lines


def rel(path):
    return os.path.relpath(path, ROOT)


def read_scope(path):
    """Scenario names of the combined scope list in file order; comment and blank lines are skipped."""
    names = []
    with open(path, encoding="utf-8") as handle:
        for raw in handle:
            line = raw.strip()
            if line and not line.startswith("#"):
                names.append(line)
    return names


def expected_path(rev):
    return os.path.join(PROVE_DIR, f"conformance-expected-{rev}.yaml")


def read_expected(path):
    """The (scenario, check id) pairs under the server key of one suite expected-failures file."""
    pairs = []
    in_server = False
    with open(path, encoding="utf-8") as handle:
        for raw in handle:
            line = raw.rstrip("\n")
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            if line == "server:":
                in_server = True
                continue
            match = YAML_ENTRY_RE.fullmatch(line)
            if not in_server or match is None:
                raise Fail(f"{os.path.basename(path)} has a line this reader does not take: {line.strip()[:60]!r}")
            pairs.append((match.group(1), match.group(2)))
    return pairs


def read_sidecar(path, problems):
    """The rows of the sidecar as dicts keyed by its header, each with its raw line."""
    rows = []
    if not os.path.isfile(path):
        return rows
    with open(path, encoding="utf-8") as handle:
        for number, raw in enumerate(handle, 1):
            line = raw.rstrip("\n")
            if not line.strip() or line.startswith("#"):
                continue
            fields = line.split("\t")
            if fields == SIDECAR_HEADER:
                continue
            if len(fields) != len(SIDECAR_HEADER):
                problems.append(f"sidecar line {number} has {len(fields)} columns, not {len(SIDECAR_HEADER)}")
                continue
            row = dict(zip(SIDECAR_HEADER, fields))
            row["line"] = line
            rows.append(row)
    return rows


def target_fail_ids(checks):
    return {check.get("id") for check in failures(checks or [])}


def status_sets(checks):
    table = {}
    for check in checks or []:
        table.setdefault(check.get("id"), set()).add(check.get("status"))
    return table


def deciding_pairs(direct, target, names):
    """(scenario, check id) pairs failing through the target in these scenarios and not failing directly."""
    pairs = set()
    for name in names:
        if name in target:
            for check_id in target_fail_ids(target[name]) - target_fail_ids(direct.get(name)):
                pairs.add((name, check_id))
    return pairs


def sidecar_lines(runs, problems):
    """Checks the sidecar against the yaml files and this run; returns the entry lines, active rows and listed pairs."""
    expected = set()
    for rev in REVISIONS:
        if not os.path.isfile(expected_path(rev)):
            continue
        try:
            pairs = read_expected(expected_path(rev))
        except Fail as failure:
            problems.append(str(failure))
            continue
        for scenario, check_id in pairs:
            for label in TARGET_KINDS:
                expected.add((rev, TARGET_KINDS[label], scenario, check_id))
    rows = {}
    for row in read_sidecar(SIDECAR_FILE, problems):
        key = (row["revision"], row["target"], row["scenario"], row["check"])
        if key in rows:
            problems.append(f"sidecar row repeated for {key[1]} {key[2]}:{key[3]} at {key[0]}")
        rows[key] = row
    for key in sorted(expected - set(rows)):
        problems.append(f"yaml entry without a sidecar row: {key[0]} {key[1]} {key[2]}:{key[3]}")
    for key in sorted(set(rows) - expected):
        problems.append(f"sidecar row without a yaml entry: {key[0]} {key[1]} {key[2]}:{key[3]}")

    labels = {kind: label for label, kind in TARGET_KINDS.items()}
    lines, active = [], []
    listed = {}
    for key in sorted(rows):
        row = rows[key]
        rev, kind, scenario, check_id = key
        label = labels.get(kind)
        if label is None:
            continue
        listed.setdefault((rev, label), set()).add((scenario, check_id))
        name = f"{label}-{rev}"
        if row["class"] not in SIDECAR_CLASSES:
            problems.append(f"sidecar row {scenario}:{check_id} has class {row['class']!r}")
        if not APPROVAL_RE.fullmatch(row["approval"]):
            problems.append(f"sidecar row {scenario}:{check_id} has approval {row['approval']!r}")
        if not row["substring"] or not row["reason"]:
            problems.append(f"sidecar row {scenario}:{check_id} has an empty substring or reason")
        run = runs.get(name)
        lines.append(f"entry: {rev} {kind} {scenario}:{check_id} (class {row['class']}, approval {row['approval']})")
        lines.append(f"  sidecar row: {row['line']}")
        if run is None:
            problems.append(f"no results to check the sidecar row against: {name}")
            continue
        checks = run.get(scenario)
        matching = [check for check in failures(checks or []) if check.get("id") == check_id]
        messages = [check.get("errorMessage") or "" for check in matching]
        if not messages:
            state = ", ".join(sorted(status_sets(checks).get(check_id, {"absent"})))
            lines.append(f"  this run: not FAILURE ({state})")
            continue
        lines.append("  this run's message:")
        for message in messages:
            lines.extend(f"    {text}" for text in message.split("\n"))
        if not all(row["substring"] in message for message in messages):
            problems.append(f"pinned substring {row['substring']!r} is missing from a message of {name} {scenario}:{check_id}")
            continue
        active.append(row)
    return lines, active, listed


def target_gate(label, direct, target, names, listed):
    """Deciding checks of one target against its listed entries; returns the lines and the problems found."""
    deciding = deciding_pairs(direct, target, names)
    unlisted = sorted(deciding - listed)
    stale = sorted(pair for pair in listed if pair[1] not in target_fail_ids(target.get(pair[0])))
    problems = [f"{label}: {name}:{check_id} fails through {label} and is not listed" for name, check_id in unlisted]
    problems += [f"{label}: listed entry {name}:{check_id} is stale, not FAILURE through {label}" for name, check_id in stale]
    lines = [f"  deciding checks (FAILURE through {label}, not FAILURE directly): {len(deciding)}"]
    lines.extend(f"    {name} {check_id}: {'listed' if (name, check_id) in listed else 'NOT LISTED'}" for name, check_id in sorted(deciding))
    lines.append(f"  listed entries that are stale: {len(stale)}")
    lines.extend(f"    {name} {check_id}" for name, check_id in stale)
    return lines, problems


def failing_lines(names, target, deciding, listed):
    lines = []
    for name in names:
        checks = failures(target.get(name) or [])
        if not checks:
            continue
        lines.append(f"  {name}")
        for check in checks:
            pair = (name, check.get("id"))
            if pair in deciding:
                state = "deciding, listed" if pair in listed else "deciding, NOT LISTED"
            else:
                state = "not deciding, also FAILURE directly"
            text = check_line(check).split("\n")
            lines.append(f"    [{state}] {text[0]}")
            lines.extend(f"      {more}" for more in text[1:])
    return lines or ["  none"]


def passed_directly_lines(names, direct, target, label):
    """Checks that pass directly and are skipped or absent through the target."""
    lines = []
    for name in names:
        direct_status = status_sets(direct.get(name))
        target_status = status_sets(target.get(name))
        for check_id in sorted(key for key, value in direct_status.items() if "SUCCESS" in value):
            if check_id not in target_status:
                state = "absent"
            elif target_status[check_id] == {"SKIPPED"}:
                state = "SKIPPED"
            else:
                continue
            lines.append(f"    {name} {check_id}: {label} {state}")
    return lines or ["    none"]


def count_line(run):
    counts = {status: 0 for status in STATUSES}
    for checks in run.values():
        for check in checks:
            if check.get("status") in counts:
                counts[check["status"]] += 1
    return ", ".join(f"{status} {counts[status]}" for status in STATUSES)


SELFTEST_LINE_RE = re.compile(r"forwarder self-test: ([0-9]+) checks passed")


def read_selftest(path):
    """N from the last `forwarder self-test: N checks passed` line of the self-test output; None when absent."""
    if not os.path.isfile(path):
        return None
    with open(path, encoding="utf-8") as handle:
        found = SELFTEST_LINE_RE.findall(handle.read())
    return int(found[-1]) if found else None


def exercise_detail(direct, checks):
    """How many checks pass directly, and the ones that do not all succeed through the target, as (id, state)."""
    direct_status = status_sets(direct)
    target_status = status_sets(checks)
    passing = [check_id for check_id, statuses in direct_status.items() if "SUCCESS" in statuses]
    missed = []
    for check_id in sorted(passing):
        statuses = target_status.get(check_id)
        if statuses is None:
            missed.append((check_id, "absent"))
        elif statuses != {"SUCCESS"}:
            missed.append((check_id, "/".join(sorted(statuses))))
    return len(passing), missed


def result_lines(label, shown, direct, target, not_scored, scored):
    """One result line per shown scenario with its explanation; also the scored scenarios not fully exercised."""
    lines, partial = [], []
    for name in shown:
        tag = " (not scored)" if name in not_scored else ""
        if name not in direct and name not in target:
            lines.append(f"  {name}{tag}: not in the suite for this revision")
            continue
        checks = target.get(name)
        passing, missed = exercise_detail(direct.get(name), checks)
        failing = failures(checks or [])
        not_run = f"not exercised: {len(missed)} of {passing} checks that pass directly did not run here"
        if checks is None:
            result = "absent"
        elif failing:
            result = describe(checks)
        elif missed:
            result = not_run
        else:
            result = "pass"
        if failing and missed:
            result += "; " + not_run
        lines.append(f"  {name}{tag}: {result}")
        lines.extend(f"    {check_id}: {state} through {label}" for check_id, state in missed)
        lines.extend(failure_lines(label, checks))
        if missed and name in scored:
            partial.append(name)
    return lines, partial


def report(args):
    work = args.work
    exits = read_exits(args.exits)
    tokens = read_tokens(work)
    runs = {name: load_run(os.path.join(work, "results", name)) for name in RUN_NAMES}
    consoles = {name: read_console(os.path.join(work, f"{name}.txt")) for name in RUN_NAMES}
    limits = read_limits(args.config)
    selftest = read_selftest(args.selftest)
    problems = []
    if selftest is None:
        problems.append("the forwarder self-test result is missing")
    try:
        scope = read_scope(SCOPE_FILE)
    except OSError:
        scope = []
        problems.append(f"the combined scope list cannot be read: {rel(SCOPE_FILE)}")

    body = ["", "RUNS (suite exit code, then the suite's Total line)"]
    for name in RUN_NAMES:
        body.append(f"{name}: exit {exits.get(name, 'not run')}; {consoles[name]['total'] or 'no Total line'}")
        if runs[name] is None:
            problems.append(f"{name} has no results directory")

    entry_lines, active, listed = sidecar_lines(runs, problems)
    body += ["", "EXPECTED FAILURES (one block per sidecar row)"]
    body += entry_lines or ["  none"]

    partial_total = 0
    for rev in REVISIONS:
        direct = runs[f"direct-{rev}"]
        body += ["", f"REVISION {rev}"]
        has_file = os.path.isfile(expected_path(rev))
        body.append(f"expected-failures file: {rel(expected_path(rev)) if has_file else 'none'}")
        for label in TARGET_KINDS:
            target = runs[f"{label}-{rev}"]
            body.append("")
            body.append(f"{label} target ({TARGET_KINDS[label]}) at {rev}")
            if direct is None or target is None:
                problems.append(f"{label} {rev}: cannot compare, a direct or {label} run has no results")
                body.append("  cannot compare: a run has no results")
                continue
            not_scored = consoles[f"direct-{rev}"]["not_scored"] | consoles[f"{label}-{rev}"]["not_scored"]
            scored = (set(direct) | set(target)) - not_scored
            if label == "combined":
                scored &= set(scope)
                names = [name for name in scope if name in scored]
                shown = scope
            else:
                names = sorted(scored)
                shown = names
            pairs = listed.get((rev, label), set())
            gate, gate_problems = target_gate(label, direct, target, names, pairs)
            problems.extend(f"{rev} {problem}" for problem in gate_problems)
            deciding = deciding_pairs(direct, target, names)
            body.append(f"  scored scenarios: {len(names)}" + (" (scope list)" if label == "combined" else ""))
            body.extend(gate)
            body.append(f"  failing through {label}, scored scenarios, one check per line:")
            body.extend(failing_lines(names, target, deciding, pairs))
            body.append(f"  scenario results through {label}:")
            results, partial = result_lines(label, shown, direct, target, not_scored, scored)
            body.extend(results)
            body.append(f"  scored scenarios not fully exercised: {len(partial)}")
            body.extend(f"    {name}" for name in partial)
            partial_total += len(partial)
            body.append(f"  passed directly, skipped or absent through {label}:")
            body.extend(passed_directly_lines(names, direct, target, label))
            body.append(f"  status counts, direct: {count_line(direct)}")
            body.append(f"  status counts, {label}: {count_line(target)}")
            if label == "gateway":
                count, table = comparison_table("direct", direct, "gateway", target, not_scored)
                body.append(f"  scenarios where direct and gateway differ: {count}")
                body.extend(f"  {line}" for line in table)
            else:
                outside = sorted(set(target) - set(scope))
                body.append("  out of scope on the combined endpoint (not scored):")
                for name in outside:
                    body.append(f"    {name}: {describe(target[name])}")
                    body.extend(failure_lines("combined", target[name]))
                if not outside:
                    body.append("    none")

    body += ["", "STREAMED SCENARIOS (status in each run)"]
    for name in STREAMED:
        for rev in REVISIONS:
            cells = []
            for kind in ("direct", "gateway", "combined"):
                run = runs[f"{kind}-{rev}"]
                cells.append(f"{kind} {describe(None if run is None else run.get(name))}")
            body.append(f"{name} {rev}: " + "; ".join(cells))

    body += ["", "Harness deviations"]
    body.append("- the forwarder adds the owner's bearer token to a /everything or /mcp request that has no Authorization header")
    body.append("- rate limits raised in the generated config: " + ", ".join(f"{name}={limits.get(name, 'default')}" for name in LIMIT_NAMES))
    body.append("- server switches turned on when the server is added: " + ", ".join(f"{name}={value}" for name, value in SWITCHES.items()))
    body.append("- the reference server is bound to 127.0.0.1 by a preload shim (its source listens on all interfaces)")
    body.append("- combined endpoint only: tools/list answers lose the everything__ prefix from tool names; tools/call requests gain it in params.name and in Mcp-Name; no other bytes change")
    body.append("- gateway and combined runs pass --expected-failures for a revision with a yaml file; the suite's own exit code is recorded and does not decide the verdict")

    leaked = scan_outputs(work, tokens) if tokens else []
    if leaked:
        problems.append(f"a bearer token value appears in suite output files: {', '.join(sorted(leaked))}")
    pending = sum(1 for row in active if row["approval"] == "pending")
    if problems:
        verdict = "FAIL"
    elif not active:
        verdict = "PASS"
    else:
        verdict = f"PASS WITH {len(active)} EXPECTED FAILURES ({pending} awaiting owner approval)"
    exit_code = 1 if verdict == "FAIL" else 0

    header = [f"VERDICT: {verdict}"]
    if partial_total:
        header.append(f"not fully exercised: {partial_total} scored scenario(s), listed below")
    header += [
        "PROVE-CONFORMANCE REPORT",
        f"suite: @modelcontextprotocol/conformance {args.suite_version}",
        f"reference server commit: {args.ref_sha}",
        "forwarder self-test: " + (f"{selftest} checks passed" if selftest is not None else "not recorded"),
        "server switches (set when the server is added): "
        + ", ".join(f"{name}={value}" for name, value in SWITCHES.items()),
        "rate limits in the generated config: "
        + ", ".join(f"{name}={limits.get(name, 'default')}" for name in LIMIT_NAMES),
    ]
    tail = ["", "RESULT"]
    tail += [f"problem: {problem}" for problem in problems]
    tail.append(f"expected-failure rows active: {len(active)} ({pending} awaiting owner approval)")
    tail.append(f"scored scenarios not fully exercised: {partial_total}")
    tail.append(f"exit {exit_code}")
    text = "\n".join(header + body + tail) + "\n"
    for token in tokens:
        text = text.replace(token, "<redacted>")
    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as handle:
        handle.write(text)
    sys.stdout.write(text)
    return exit_code


def read_head(reader):
    """A start line and its raw header lines, or None at a clean end of stream."""
    first = reader.readline(LINE_LIMIT)
    if not first:
        return None
    if not first.endswith(b"\n"):
        raise ProtocolError("start line cut off")
    lines = []
    while True:
        line = reader.readline(LINE_LIMIT)
        if not line.endswith(b"\n"):
            raise ProtocolError("header line cut off")
        if line in (b"\r\n", b"\n"):
            return first, lines
        lines.append(line)
        if len(lines) > HEADER_LINE_LIMIT:
            raise ProtocolError("too many header lines")


def request_parts(first):
    parts = first.split()
    if len(parts) != 3 or not parts[2].startswith(b"HTTP/1."):
        raise ProtocolError("request line is not HTTP/1")
    try:
        path = urlsplit(parts[1].decode("latin-1")).path
    except ValueError:
        raise ProtocolError("request target does not parse") from None
    return parts[0].decode("ascii", "replace"), path, parts[2]


def header_values(lines, name):
    wanted = name.encode("ascii")
    values = []
    for line in lines:
        key, colon, value = line.partition(b":")
        if colon and key.strip().lower() == wanted:
            values.append(value.strip().decode("latin-1"))
    return values


def is_chunked(lines):
    codings = [part.strip().lower() for value in header_values(lines, "transfer-encoding") for part in value.split(",")]
    return bool(codings) and codings[-1] == "chunked"


def wants_close(lines):
    tokens = [part.strip().lower() for value in header_values(lines, "connection") for part in value.split(",")]
    return "close" in tokens


def content_length(lines):
    values = header_values(lines, "content-length")
    if not values:
        return None
    if len(values) != 1 or not DIGITS_RE.fullmatch(values[0]):
        raise ProtocolError("Content-Length is not one number")
    return int(values[0])


def status_code(first):
    parts = first.split(None, 2)
    if len(parts) < 2 or not parts[0].startswith(b"HTTP/1.") or not STATUS_RE.fullmatch(parts[1].decode("latin-1")):
        raise ProtocolError("status line is not HTTP/1")
    return int(parts[1])


def relay_fixed(source, target, remaining):
    while remaining:
        piece = source.read1(min(remaining, CHUNK))
        if not piece:
            raise ProtocolError("connection closed inside a body")
        target.sendall(piece)
        remaining -= len(piece)


def chunk_pieces(source):
    """Yields the pieces of a chunked body as they arrive; returns the trailer lines at its end."""
    while True:
        size_line = source.readline(LINE_LIMIT)
        if not size_line.endswith(b"\n"):
            raise ProtocolError("chunk size line cut off")
        try:
            size = int(size_line.split(b";", 1)[0].strip(), 16)
        except ValueError:
            raise ProtocolError("chunk size is not hex") from None
        if size == 0:
            trailers = []
            while True:
                line = source.readline(LINE_LIMIT)
                if not line.endswith(b"\n"):
                    raise ProtocolError("trailer line cut off")
                trailers.append(line)
                if line in (b"\r\n", b"\n"):
                    return trailers
        remaining = size
        while remaining:
            piece = source.read1(min(remaining, CHUNK))
            if not piece:
                raise ProtocolError("connection closed inside a chunk")
            yield piece
            remaining -= len(piece)
        if source.readline(LINE_LIMIT) not in (b"\r\n", b"\n"):
            raise ProtocolError("chunk not followed by a line end")


def relay_chunked(source, target):
    """Copies a chunked body piece by piece, each piece as one chunk, as it arrives."""
    pieces = chunk_pieces(source)
    while True:
        try:
            piece = next(pieces)
        except StopIteration as done:
            target.sendall(b"0\r\n" + b"".join(done.value))
            return
        target.sendall(b"%x\r\n" % len(piece) + piece + b"\r\n")


def relay_until_close(source, target):
    while True:
        piece = source.read1(CHUNK)
        if not piece:
            return
        target.sendall(piece)


def read_chunked(source):
    """The whole body of a chunked message; its trailer lines are dropped."""
    body = bytearray()
    for piece in chunk_pieces(source):
        body += piece
    return bytes(body)


def read_exact(source, length):
    body = bytearray()
    while len(body) < length:
        piece = source.read1(min(length - len(body), CHUNK))
        if not piece:
            raise ProtocolError("connection closed inside a body")
        body += piece
    return bytes(body)


def read_until_close(source):
    body = bytearray()
    while True:
        piece = source.read1(CHUNK)
        if not piece:
            return bytes(body)
        body += piece


def read_request_body(source, lines):
    """The whole request body as its headers frame it; None when the request has none."""
    if is_chunked(lines):
        return read_chunked(source)
    length = content_length(lines)
    return None if length is None else read_exact(source, length)


def reframed(lines, length):
    """The header lines with one Content-Length of this length in place of any framing headers."""
    framed = []
    placed = False
    for line in lines:
        key, _, value = line.partition(b":")
        key = key.strip().lower()
        if key == b"transfer-encoding":
            continue
        if key == b"content-length":
            if not placed:
                placed = True
                same = value.strip() == b"%d" % length
                framed.append(line if same else b"Content-Length: %d\r\n" % length)
            continue
        framed.append(line)
    if not placed:
        framed.append(b"Content-Length: %d\r\n" % length)
    return framed


def is_event_stream(lines):
    return any(value.lower().startswith("text/event-stream") for value in header_values(lines, "content-type"))


def json_messages(raw, event_stream):
    """The JSON messages of an answer, parsed in order; empty event data is skipped."""
    messages = []
    texts = [line[5:].strip() for line in raw.split(b"\n") if line.startswith(b"data:")] if event_stream else [raw]
    for text in texts:
        if not text.strip():
            continue
        try:
            messages.append(json.loads(text))
        except ValueError:
            raise ProtocolError("an answer holds a payload that is not JSON") from None
    return messages


def tool_list(message):
    result = message.get("result") if isinstance(message, dict) else None
    tools = result.get("tools") if isinstance(result, dict) else None
    return tools if isinstance(tools, list) else []


def without_prefix(message):
    """A copy of the message with the combined prefix taken off each of its tool names."""
    copied = copy.deepcopy(message)
    for tool in tool_list(copied):
        if isinstance(tool, dict) and isinstance(tool.get("name"), str) and tool["name"].startswith(TOOL_PREFIX):
            tool["name"] = tool["name"][len(TOOL_PREFIX):]
    return copied


def unprefix_answer(raw, event_stream):
    """A tools/list answer with the prefix taken off its tool names; every other byte is kept."""
    expected = [without_prefix(message) for message in json_messages(raw, event_stream)]
    rewritten = TOOL_NAME_RE.sub(rb'"name"\1"\2"', raw)
    if json_messages(rewritten, event_stream) != expected:
        raise ProtocolError("the tool names of an answer cannot be rewritten")
    return rewritten


def call_with_prefix(body):
    """The tools/call body with the combined prefix added to params.name; None for any other body."""
    try:
        message = json.loads(body)
    except ValueError:
        return None
    if not isinstance(message, dict) or message.get("method") != "tools/call":
        return None
    params = message.get("params")
    if not isinstance(params, dict) or not isinstance(params.get("name"), str):
        return None
    name = params["name"]
    expected = copy.deepcopy(message)
    expected["params"]["name"] = TOOL_PREFIX + name
    pattern = re.compile(rb'"name"(\s*:\s*)"' + re.escape(name.encode("utf-8")) + rb'"')
    for match in pattern.finditer(body):
        candidate = (
            body[: match.start()] + b'"name"' + match.group(1) + b'"'
            + (TOOL_PREFIX + name).encode("utf-8") + b'"' + body[match.end():]
        )
        try:
            if json.loads(candidate) == expected:
                return candidate
        except ValueError:
            continue
    raise ProtocolError("the tools/call name cannot be rewritten")


def prefix_mcp_name(lines):
    prefixed = []
    for line in lines:
        key, colon, value = line.partition(b":")
        if colon and key.strip().lower() == b"mcp-name":
            line = key + b": " + TOOL_PREFIX.encode("ascii") + value.strip() + b"\r\n"
        prefixed.append(line)
    return prefixed


def is_method(body, method):
    try:
        message = json.loads(body)
    except ValueError:
        return False
    return isinstance(message, dict) and message.get("method") == method


def map_combined_request(body, lines):
    """The combined request body and header lines to send upstream, and its kind: tools/call, tools/list or None."""
    call = call_with_prefix(body)
    if call is not None:
        return call, "tools/call", reframed(prefix_mcp_name(lines), len(call))
    kind = "tools/list" if is_method(body, "tools/list") else None
    return body, kind, reframed(lines, len(body))


def read_token(path, key):
    """The token for one forwarded path, or None when the file or the key is absent."""
    try:
        with open(path, encoding="utf-8") as handle:
            tokens = json.load(handle)
    except FileNotFoundError:
        return None
    except (OSError, ValueError) as error:
        raise TokenError(type(error).__name__) from None
    token = tokens.get(key) if isinstance(tokens, dict) else None
    if token is None:
        return None
    if not isinstance(token, str) or not HEADER_TOKEN_RE.fullmatch(token):
        raise TokenError("the token is not a header-safe string")
    return token


class ProtocolError(Exception):
    """HTTP framing the forwarder cannot relay."""


class TokenError(Exception):
    """The token file cannot be read or holds a value that is not header-safe."""


def send_status(client, status):
    client.sendall(b"HTTP/1.1 " + status + b"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")


class Relay(socketserver.BaseRequestHandler):
    """One client connection; each request goes upstream on its own connection."""

    def handle(self):
        client = self.request
        client.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        reader = client.makefile("rb")
        try:
            while True:
                try:
                    head = read_head(reader)
                    if head is None:
                        return
                    request = (head[0], head[1], *request_parts(head[0]))
                except ProtocolError as error:
                    note(f"refused a request: {error}")
                    send_status(client, b"400 Bad Request")
                    return
                if not self.exchange(reader, client, request):
                    return
        except (OSError, ProtocolError) as error:
            note(f"connection ended: {type(error).__name__}")
        finally:
            reader.close()

    def exchange(self, reader, client, request):
        """Relays one request and its answer; True when the client connection stays open."""
        first, lines, method, path, version = request
        headers = list(lines)
        if path in FORWARDED and not header_values(lines, "authorization"):
            try:
                token = read_token(self.server.token_file, path)
            except TokenError as error:
                note(f"token file unusable: {error}")
                send_status(client, b"500 Internal Server Error")
                return False
            if token is not None:
                headers.append(f"Authorization: Bearer {token}\r\n".encode("ascii"))
        try:
            upstream = socket.create_connection(self.server.target, timeout=30)
        except OSError as error:
            note(f"upstream unreachable: {type(error).__name__}")
            send_status(client, b"502 Bad Gateway")
            return False
        upstream.settimeout(None)
        upstream.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        answer = upstream.makefile("rb")
        try:
            return self.converse(reader, client, upstream, answer, (first, lines, headers, method, version), path)
        finally:
            answer.close()
            upstream.close()

    def converse(self, reader, client, upstream, answer, parts, path):
        first, lines, headers, method, version = parts
        body = read_request_body(reader, lines) if path == COMBINED_PATH and method == "POST" else None
        kind = None
        if body is None:
            upstream.sendall(first + b"".join(headers) + b"\r\n")
            if is_chunked(lines):
                relay_chunked(reader, upstream)
            else:
                length = content_length(lines)
                if length:
                    relay_fixed(reader, upstream, length)
        else:
            body, kind, headers = map_combined_request(body, headers)
            upstream.sendall(first + b"".join(headers) + b"\r\n" + body)
        head = read_head(answer)
        if head is None:
            send_status(client, b"502 Bad Gateway")
            return False
        status_line, response_lines = head
        code = status_code(status_line)
        while 100 <= code < 200 and code != 101:
            client.sendall(status_line + b"".join(response_lines) + b"\r\n")
            head = read_head(answer)
            if head is None:
                raise ProtocolError("upstream closed after an informational status")
            status_line, response_lines = head
            code = status_code(status_line)
        if kind == "tools/list" and code not in (101, 204, 304):
            if is_chunked(response_lines):
                raw = read_chunked(answer)
            elif content_length(response_lines) is None:
                raw = read_until_close(answer)
            else:
                raw = read_exact(answer, content_length(response_lines))
            rewritten = unprefix_answer(raw, is_event_stream(response_lines))
            client.sendall(status_line + b"".join(reframed(response_lines, len(rewritten))) + b"\r\n" + rewritten)
            return not (wants_close(lines) or wants_close(response_lines) or version != b"HTTP/1.1")
        client.sendall(status_line + b"".join(response_lines) + b"\r\n")
        if code == 101:
            return False
        if method == "HEAD" or code in (204, 304):
            pass
        elif is_chunked(response_lines):
            relay_chunked(answer, client)
        else:
            length = content_length(response_lines)
            if length is None:
                relay_until_close(answer, client)
                return False
            relay_fixed(answer, client, length)
        return not (wants_close(lines) or wants_close(response_lines) or version != b"HTTP/1.1")


class Forwarder(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, port, target, token_file):
        super().__init__(("127.0.0.1", port), Relay)
        self.target = target
        self.token_file = token_file


def forward(args):
    target = urlsplit(args.target)
    need(
        target.scheme == "http" and target.hostname == "127.0.0.1" and target.port is not None,
        "the target is http://127.0.0.1:<port>",
    )
    server = Forwarder(args.listen, (target.hostname, target.port), args.token_file)
    print(f"FORWARD listening on 127.0.0.1:{args.listen}", flush=True)
    server.serve_forever()
    return 0


class Sink:
    """Stands in for a socket: keeps what is sent to it."""

    def __init__(self):
        self.data = bytearray()

    def sendall(self, piece):
        self.data += piece


def relay_in_memory(request, answer):
    """One request and its answer through the forwarder's relay, in memory: what went upstream, what the client got, and any refusal."""
    upstream, client = Sink(), Sink()
    reader = io.BytesIO(request)
    first, lines = read_head(reader)
    method, path, version = request_parts(first)
    refusal = None
    try:
        Relay.__new__(Relay).converse(
            reader, client, upstream, io.BytesIO(answer), (first, lines, list(lines), method, version), path
        )
    except ProtocolError as error:
        refusal = error
    return bytes(upstream.data), bytes(client.data), refusal


def st_request(path, body, extra=b"", chunked=False, method=b"POST"):
    head = method + b" " + path + b" HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n" + extra
    if chunked:
        framed = b"".join(b"%x\r\n" % len(piece) + piece + b"\r\n" for piece in (body[:7], body[7:]))
        return head + b"Transfer-Encoding: chunked\r\n\r\n" + framed + b"0\r\n\r\n"
    if body is None:
        return head + b"\r\n"
    return head + b"Content-Length: %d\r\n\r\n" % len(body) + body


def st_answer(body, kind="json", chunked=False, status=b"200 OK"):
    ctype = {"json": b"Content-Type: application/json\r\n", "sse": b"Content-Type: text/event-stream\r\n"}.get(kind, b"")
    if chunked:
        framed = b"".join(b"%x\r\n" % len(piece) + piece + b"\r\n" for piece in (body[:20], body[20:]))
        return b"HTTP/1.1 " + status + b"\r\n" + ctype + b"Transfer-Encoding: chunked\r\n\r\n" + framed + b"0\r\n\r\n"
    return b"HTTP/1.1 " + status + b"\r\n" + ctype + b"Content-Length: %d\r\n\r\n" % len(body) + body


ST_AUTH = b"Authorization: Bearer client-token\r\n"
ST_LIST_REQ = json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}).encode()
ST_LIST_ANS = json.dumps({"jsonrpc": "2.0", "id": 2, "result": {"tools": [
    {"name": "everything__echo", "description": "calls everything__echo", "inputSchema": {"type": "object"}},
    {"name": "everything__add", "description": "plain", "inputSchema": {"type": "object"}}]}}).encode()
ST_LIST_OUT = ST_LIST_ANS.replace(b'"name": "everything__', b'"name": "')
ST_CALL = b'{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"arguments":{"name":"echo"},"name":"echo"}}'
ST_CALL_OUT = ST_CALL.replace(b'"name":"echo"}}', b'"name":"everything__echo"}}')
ST_NOTE = b'{"jsonrpc":"2.0","method":"notifications/initialized"}'
ST_ACCEPTED = b"HTTP/1.1 202 Accepted\r\nContent-Type: text/plain\r\nContent-Length: 0\r\n\r\n"
ST_EMPTY_202 = b"HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\n\r\n"
ST_METHOD_405 = b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n"


def st_list_json():
    sent = st_request(b"/mcp", ST_LIST_REQ, ST_AUTH)
    up, cl, _ = relay_in_memory(sent, st_answer(ST_LIST_ANS))
    return [
        ("tools/list JSON on /mcp: upstream request bytes unchanged", up == sent),
        ("tools/list JSON on /mcp: upstream receives the request body unchanged", up.endswith(ST_LIST_REQ)),
        ("tools/list JSON on /mcp: prefix removed from tool names, other bytes kept", cl == st_answer(ST_LIST_OUT)),
        ("tools/list JSON on /mcp: one Content-Length in the answer", cl.count(b"Content-Length:") == 1),
    ]


def st_list_chunked():
    _, cl, _ = relay_in_memory(st_request(b"/mcp", ST_LIST_REQ, ST_AUTH), st_answer(ST_LIST_ANS, chunked=True))
    return [("tools/list chunked answer on /mcp: re-framed with the prefix removed", cl == st_answer(ST_LIST_OUT))]


def st_list_event_stream():
    priming = b"data:\n\n"
    answer = priming + b"event: message\ndata: " + ST_LIST_ANS + b"\n\n"
    expected = priming + b"event: message\ndata: " + ST_LIST_OUT + b"\n\n"
    _, cl, _ = relay_in_memory(st_request(b"/mcp", ST_LIST_REQ, ST_AUTH), st_answer(answer, kind="sse"))
    return [
        ("tools/list event-stream answer on /mcp: prefix removed, priming event kept",
         cl == st_answer(expected, kind="sse")),
    ]


def st_list_unrewritable():
    nested = json.dumps({"jsonrpc": "2.0", "id": 2, "result": {"tools": [], "meta": {"name": "everything__x"}}}).encode()
    _, cl, refusal = relay_in_memory(st_request(b"/mcp", ST_LIST_REQ, ST_AUTH), st_answer(nested))
    return [("tools/list answer that cannot be rewritten: nothing sent to the client", refusal is not None and cl == b"")]


def st_call():
    sent = st_request(b"/mcp", ST_CALL, ST_AUTH + b"Mcp-Name: echo\r\n")
    up, _, _ = relay_in_memory(sent, st_answer(b'{"jsonrpc":"2.0","id":3,"result":{}}'))
    head, _, body = up.partition(b"\r\n\r\n")
    head += b"\r\n"
    return [
        ("tools/call on /mcp: only params.name gains the prefix", body == ST_CALL_OUT),
        ("tools/call on /mcp: Mcp-Name gains the prefix", b"Mcp-Name: everything__echo\r\n" in head),
        ("tools/call on /mcp: Content-Length matches the new body", b"Content-Length: %d\r\n" % len(ST_CALL_OUT) in head),
    ]


def st_call_chunked():
    up, _, _ = relay_in_memory(st_request(b"/mcp", ST_CALL, ST_AUTH, chunked=True), st_answer(b'{"jsonrpc":"2.0","id":3,"result":{}}'))
    head, _, body = up.partition(b"\r\n\r\n")
    head += b"\r\n"
    return [
        ("tools/call with chunked body on /mcp: upstream receives the prefixed body", body == ST_CALL_OUT),
        ("tools/call with chunked body on /mcp: no Transfer-Encoding sent upstream", b"Transfer-Encoding" not in head),
    ]


def st_server_path():
    sent = st_request(b"/everything", ST_LIST_REQ, ST_AUTH)
    up, cl, _ = relay_in_memory(sent, st_answer(ST_LIST_ANS))
    return [
        ("non-/mcp path: request reaches upstream byte for byte", up == sent),
        ("non-/mcp path: tools/list answer keeps the prefix", cl == st_answer(ST_LIST_ANS)),
    ]


def st_notification():
    _, cl, _ = relay_in_memory(st_request(b"/mcp", ST_NOTE, ST_AUTH), ST_ACCEPTED)
    return [("notification on /mcp: 202 answer passes unchanged", cl == ST_ACCEPTED)]


def st_get():
    sent = st_request(b"/mcp", None, ST_AUTH, method=b"GET")
    up, cl, _ = relay_in_memory(sent, ST_METHOD_405)
    return [("GET on /mcp: request and answer pass unchanged", up == sent and cl == ST_METHOD_405)]


def st_empty_answer():
    _, cl, _ = relay_in_memory(st_request(b"/mcp", ST_LIST_REQ, ST_AUTH), ST_EMPTY_202)
    return [("empty 202 answer to tools/list stays empty", cl == ST_EMPTY_202)]


def st_until_close():
    raw = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n" + ST_LIST_ANS
    _, cl, _ = relay_in_memory(st_request(b"/mcp", ST_LIST_REQ, ST_AUTH), raw)
    return [("until-close tools/list answer re-framed with Content-Length", cl == st_answer(ST_LIST_OUT))]


SELFTEST_GROUPS = (
    st_list_json, st_list_chunked, st_list_event_stream, st_list_unrewritable, st_call, st_call_chunked,
    st_server_path, st_notification, st_get, st_empty_answer, st_until_close,
)


def selftest(args):
    """The forwarder's name-mapping checks, in memory: no socket and no gateway."""
    results = []
    for group in SELFTEST_GROUPS:
        try:
            results.extend(group())
        except Exception as error:  # A group that raises is a failed check, reported by name.
            results.append((f"{group.__name__} raised {type(error).__name__}", False))
    passed = 0
    for name, ok in results:
        print(("PASS " if ok else "FAIL ") + name, flush=True)
        passed += 1 if ok else 0
    if passed == len(results):
        print(f"forwarder self-test: {passed} checks passed", flush=True)
        return 0
    print(f"forwarder self-test: {passed} of {len(results)} checks passed", flush=True)
    return 1


def build_parser():
    parser = argparse.ArgumentParser(description="Gateway driver, token forwarder and report for the conformance proof.")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("drive", help="owner setup, server, assignment, client and tokens")
    p.add_argument("--port", type=int, required=True)
    p.add_argument("--setup-log", required=True)
    p.add_argument("--upstream", required=True)
    p.add_argument("--token-file", required=True)
    p.set_defaults(run=drive)

    p = sub.add_parser("forward", help="loopback HTTP/1.1 forwarder that adds the bearer token")
    p.add_argument("--listen", type=int, required=True)
    p.add_argument("--target", required=True)
    p.add_argument("--token-file", required=True)
    p.set_defaults(run=forward)

    p = sub.add_parser("selftest", help="the forwarder's name-mapping checks, in memory")
    p.set_defaults(run=selftest)

    p = sub.add_parser("report", help="compares the suite runs and writes the report")
    p.add_argument("--work", required=True)
    p.add_argument("--exits", required=True)
    p.add_argument("--config", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--suite-version", required=True)
    p.add_argument("--ref-sha", required=True)
    p.add_argument("--selftest", required=True)
    p.set_defaults(run=report)
    return parser


def main(argv):
    args = build_parser().parse_args(argv)
    try:
        return args.run(args)
    except Fail as failure:
        print(f"FAIL {args.cmd}: {failure}", flush=True)
        return 1
    except Exception as error:  # Reported without a traceback: a traceback can print local paths.
        frames = [f for f in traceback.extract_tb(error.__traceback__) if f.filename == __file__]
        line = frames[-1].lineno if frames else 0
        print(f"FAIL {args.cmd}: unexpected {type(error).__name__} at line {line}", flush=True)
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
