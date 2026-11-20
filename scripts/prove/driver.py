"""HTTP and inspection checks for scripts/prove-docker.sh. Standard library only.

Each check prints `PASS <label> <text>`. The first failure prints `FAIL <label> <what>: <evidence>`
and exits 1. Secrets (setup code, passwords, tokens, the upstream secret) are never printed.
"""

import argparse
import base64
import hashlib
import html.parser
import http.client
import json
import os
import secrets
import socket
import ssl
import subprocess
import sys
import time
import traceback
from urllib.parse import parse_qs, urlencode, urljoin, urlsplit

OWNER_EMAIL = "owner@example.com"
SLUG = "proof"
UPSTREAM_URL = "http://upstream:9000/mcp"
UPSTREAM_SECRET_HEADER = "x-upstream-secret"
REDIRECT = "http://127.0.0.1:53535/callback"
CLIENT_NAME = "proof client"
SETUP_MARK = "doorward setup code:"
SESSION_COOKIE = "__Host-doorward_session"
UNRESERVED = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
NOT_FOUND_PATH = "/nothing-here-at-all/x"
SESSION_VERSION = "2025-11-25"


class Fail(Exception):
    def __init__(self, label, what, evidence):
        super().__init__(f"{label} {what}: {evidence}")


def emit(text):
    print(text, flush=True)


def need(cond, label, what, evidence):
    if not cond:
        raise Fail(label, what, evidence)


def expect(page, status, label, what):
    need(
        page.status == status,
        label,
        what,
        f"answered {page.status} (page kind {page.kind()!r}), wanted {status}",
    )


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
        self._tags = None

    def header(self, name):
        for key, value in self.headers:
            if key.lower() == name.lower():
                return value
        return None

    @property
    def location(self):
        return self.header("Location")

    def tags(self):
        if self._tags is None:
            parser = DocParser()
            parser.feed(self.text)
            self._tags = parser.tags
        return self._tags

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


class TlsConnection(http.client.HTTPSConnection):
    """HTTPS to a chosen address, with the name localhost verified against the Caddy root."""

    def __init__(self, connect_host, port, context, timeout):
        super().__init__("localhost", port, timeout=timeout, context=context)
        self.connect_host = connect_host

    def connect(self):
        raw = socket.create_connection((self.connect_host, self.port), self.timeout)
        self.sock = self._context.wrap_socket(raw, server_hostname="localhost")


class Browser:
    """One cookie jar, like one browser. Cookies are kept as name and value pairs."""

    def __init__(self, port, ca, connect_host="127.0.0.1", jar=None, attrs=None):
        self.port = port
        self.base = f"https://localhost:{port}"
        self.connect_host = connect_host
        self.context = ssl.create_default_context(cafile=ca)
        self.jar = dict(jar or {})
        self.attrs = dict(attrs or {})

    def state(self):
        return {"jar": self.jar, "attrs": self.attrs}

    def send(self, method, path, body=None, headers=None, cookies=False, timeout=30):
        conn = TlsConnection(self.connect_host, self.port, self.context, timeout)
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
        self._store_cookies(pairs)
        return Page(response.status, pairs, data)

    def _store_cookies(self, pairs):
        for key, value in pairs:
            if key.lower() != "set-cookie":
                continue
            pair, _, rest = value.partition(";")
            name, _, cookie_value = pair.partition("=")
            name, cookie_value = name.strip(), cookie_value.strip()
            if not name:
                continue
            self.attrs[name] = rest.strip().lower()
            if not cookie_value or expires_now(rest):
                self.jar.pop(name, None)
            else:
                self.jar[name] = cookie_value

    def get(self, path, cookies=True, headers=None):
        return self.send("GET", path, headers=headers, cookies=cookies)

    def post_form(self, path, fields, cookies=True):
        headers = {"Content-Type": "application/x-www-form-urlencoded", "Origin": self.base}
        body = urlencode(fields).encode()
        return self.send("POST", path, body=body, headers=headers, cookies=cookies)

    def form(self, page_path, action, fields):
        """GETs the form page, then posts the fields with its csrf token."""
        page = self.get(page_path)
        token = page.csrf()
        need(token is not None, "form", f"{page_path} carries a csrf token", f"kind {page.kind()!r}")
        return self.post_form(action, [("csrf", token), *fields])


def random_verifier():
    return "".join(secrets.choice(UNRESERVED) for _ in range(43))


def json_body(page):
    try:
        return json.loads(page.text)
    except ValueError:
        return None


def sse_answer(page):
    """The last JSON-RPC answer in an event-stream body, or None."""
    answer = None
    for line in page.text.splitlines():
        if line.startswith("data:"):
            try:
                data = json.loads(line[5:].strip())
            except ValueError:
                continue
            if isinstance(data, dict) and "id" in data and ("result" in data or "error" in data):
                answer = data
    return answer


class McpSession:
    """Session-style MCP client: initialize, notifications/initialized, then requests."""

    def __init__(self, port, ca, token, label):
        self.label = label
        self.token = token
        self.session_id = None
        self.next_id = 1
        self.browser = Browser(port, ca)

    def headers(self):
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/json, text/event-stream",
            "Content-Type": "application/json",
        }
        if self.session_id:
            headers["Mcp-Session-Id"] = self.session_id
            headers["MCP-Protocol-Version"] = SESSION_VERSION
        return headers

    def post(self, message):
        body = json.dumps(message).encode()
        return self.browser.send("POST", f"/{SLUG}", body=body, headers=self.headers())

    def request(self, method, params):
        request_id = self.next_id
        self.next_id += 1
        return self.post({"jsonrpc": "2.0", "id": request_id, "method": method, "params": params})

    def initialize(self):
        page = self.request(
            "initialize",
            {
                "protocolVersion": SESSION_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "proof", "version": "0"},
            },
        )
        expect(page, 200, self.label, "initialize through the gateway")
        self.session_id = page.header("Mcp-Session-Id")
        need(bool(self.session_id), self.label, "initialize returns a session id", "no Mcp-Session-Id")
        note = self.post({"jsonrpc": "2.0", "method": "notifications/initialized"})
        expect(note, 202, self.label, "notifications/initialized through the gateway")

    def tool_names(self):
        page = self.request("tools/list", {})
        expect(page, 200, self.label, "tools/list through the gateway")
        answer = json_body(page)
        need(
            isinstance(answer, dict) and "result" in answer,
            self.label,
            "tools/list answers a result",
            f"no result in {len(page.text)} bytes",
        )
        return sorted(tool["name"] for tool in answer["result"]["tools"])


def load_state(path):
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def save_state(path, state):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        json.dump(state, handle)


def owner_browser(args, state):
    owner = state["owner"]
    return Browser(args.port, args.ca, jar=owner["jar"], attrs=owner["attrs"])


def read_logs(cid):
    done = subprocess.run(["docker", "logs", cid], capture_output=True, check=False)
    need(done.returncode == 0, "A4", "the gateway logs can be read", f"docker logs exit {done.returncode}")
    return (done.stdout + done.stderr).decode("utf-8", "replace")


def cmd_setup(args, state):
    lines = [line for line in read_logs(args.gw_cid).splitlines() if SETUP_MARK in line]
    need(len(lines) == 1, "A4", "exactly one setup code line in the gateway logs", f"found {len(lines)}")
    code = lines[0].split(SETUP_MARK, 1)[1].strip()
    emit("PASS A4 exactly one setup code line in the gateway logs")

    owner = Browser(args.port, args.ca)
    setup_page = owner.get("/setup")
    expect(setup_page, 200, "A5", "GET /setup while no owner exists")
    token = setup_page.csrf()
    need(token is not None, "A5", "the setup form carries a csrf token", "no csrf")
    password = secrets.token_urlsafe(24)
    signed = owner.post_form(
        "/setup",
        [("csrf", token), ("setup_code", code), ("email", OWNER_EMAIL), ("password", password)],
    )
    expect(signed, 303, "A5", "POST /setup with the setup code")
    need(signed.location == "/admin", "A5", "setup redirects to /admin", f"location {signed.location!r}")
    session_attrs = owner.attrs.get(SESSION_COOKIE)
    need(session_attrs is not None, "A5", "setup sets the session cookie", "no session cookie")
    need(
        "secure" in session_attrs and "httponly" in session_attrs,
        "A5",
        "the session cookie is Secure and HttpOnly",
        f"attributes {session_attrs!r}",
    )
    account = owner.get("/account")
    expect(account, 200, "A5", "GET /account after sign-up")
    need(account.kind() == "account", "A5", "the account page loads signed in", f"kind {account.kind()!r}")
    emit(
        "PASS A5 owner signed up through HTTPS with the setup code; "
        "account page loads signed in; session cookie Secure and HttpOnly"
    )

    login = Browser(args.port, args.ca).get("/login")
    expect(login, 200, "A6", "GET /login through Caddy")
    # Loopback never pins HSTS in a browser: the header must be absent on https://localhost.
    checks = [
        ("Content-Security-Policy", bool(login.header("Content-Security-Policy"))),
        ("X-Content-Type-Options", login.header("X-Content-Type-Options") == "nosniff"),
        ("Strict-Transport-Security", login.header("Strict-Transport-Security") is None),
    ]
    not_as_wanted = [name for name, ok in checks if not ok]
    need(
        not not_as_wanted,
        "A6",
        "/login through Caddy carries CSP and nosniff and no HSTS",
        f"not as wanted: {', '.join(not_as_wanted)}",
    )
    emit(
        "PASS A6 /login through Caddy carries Content-Security-Policy and "
        "X-Content-Type-Options nosniff, and no Strict-Transport-Security on localhost"
    )

    state["password"] = password
    state["owner"] = owner.state()


def cmd_app(args, state):
    owner = owner_browser(args, state)
    secret = os.environ.get("PROOF_UPSTREAM_SECRET", "")
    need(bool(secret), "A7", "the upstream secret is set for the proof", "PROOF_UPSTREAM_SECRET is empty")

    added = owner.form(
        "/admin/servers",
        "/admin/servers",
        [
            ("name", SLUG),
            ("slug", SLUG),
            ("upstream_url", UPSTREAM_URL),
            ("secret_header_name", UPSTREAM_SECRET_HEADER),
            ("secret_header_value", secret),
        ],
    )
    expect(added, 303, "A7", "add the server")
    prefix = "/admin/servers/"
    need(
        added.location is not None and added.location.startswith(prefix),
        "A7",
        "the new server has a page",
        f"location {added.location!r}",
    )
    server_id = added.location[len(prefix):]
    server_path = f"{prefix}{server_id}"

    refreshed = owner.form(server_path, f"{server_path}/refresh-tools", [])
    expect(refreshed, 303, "A7", "refresh the tool list")
    tools = sorted(owner.get(server_path).values_of("data-catalog-tool"))
    need(tools == ["echo", "slow"], "A7", "the cached tool list has echo and slow", f"tools {tools!r}")

    rows = owner.get("/admin/users").find({"data-email": OWNER_EMAIL})
    need(len(rows) == 1, "A7", "the owner is on the users page", f"{len(rows)} rows")
    user_path = f"/admin/users/{rows[0]['data-user-id']}"
    assigned = owner.form(user_path, f"{user_path}/servers", [("server_id", server_id)])
    expect(assigned, 303, "A7", "assign the server to the owner")

    anonymous = Browser(args.port, args.ca)
    registered = anonymous.send(
        "POST",
        "/oauth/register",
        body=json.dumps({"client_name": CLIENT_NAME, "redirect_uris": [REDIRECT]}).encode(),
        headers={"Content-Type": "application/json"},
    )
    expect(registered, 201, "A7", "POST /oauth/register")
    client_id = (json_body(registered) or {}).get("client_id", "")
    need(client_id.startswith("dcr_"), "A7", "registration returns a client id", "no dcr_ client id")

    verifier = random_verifier()
    digest = hashlib.sha256(verifier.encode()).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
    oauth_state = secrets.token_urlsafe(12)
    resource = f"{owner.base}/{SLUG}"
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
    expect(authorized, 303, "A7", "GET /oauth/authorize for the signed-in owner")
    target = urlsplit(urljoin(owner.base + "/", authorized.location or ""))
    need(target.path == "/oauth/consent", "A7", "authorize leads to the consent page", f"path {target.path!r}")
    req = parse_qs(target.query).get("req", [""])[0]
    need(bool(req), "A7", "the consent page has a request id", "no req")

    granted = owner.form(f"/oauth/consent?req={req}", "/oauth/consent", [("req", req), ("decision", "approve")])
    expect(granted, 303, "A7", "POST /oauth/consent approve")
    back = urlsplit(granted.location or "")
    need(
        f"{back.scheme}://{back.netloc}{back.path}" == REDIRECT,
        "A7",
        "consent redirects to the registered address",
        f"location {granted.location!r}",
    )
    answer = parse_qs(back.query)
    need(answer.get("state") == [oauth_state], "A7", "consent returns the state", "state differs")
    need(answer.get("iss") == [owner.base], "A7", "consent returns iss equal to the public address", "iss differs")
    code = answer.get("code", [""])[0]
    need(bool(code), "A7", "consent returns a code", "no code")

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
    )
    expect(issued, 200, "A7", "POST /oauth/token with the code and the verifier")
    tokens = json_body(issued) or {}
    access = tokens.get("access_token", "")
    need(access.startswith("dw_at_"), "A7", "the token answer holds an access token", "no dw_at_ token")
    need(tokens.get("token_type") == "Bearer", "A7", "the token type is Bearer", f"type {tokens.get('token_type')!r}")
    need(tokens.get("scope") == "mcp", "A7", "the scope is mcp", f"scope {tokens.get('scope')!r}")

    state["server_id"] = server_id
    state["client_id"] = client_id
    state["access_token"] = access
    state["owner"] = owner.state()
    emit("PASS A7 owner added and assigned the server, client registered, PKCE consent approved, access token issued")


def cmd_mcp(args, state):
    session = McpSession(args.port, args.ca, state["access_token"], "A8")
    session.initialize()
    names = session.tool_names()
    need(names == ["echo", "slow"], "A8", "tools/list answers the upstream tools", f"names {names!r}")
    emit("PASS A8 tools/list through https on the server path answers echo and slow")

    body = json.dumps(
        {"jsonrpc": "2.0", "id": 900, "method": "tools/call", "params": {"name": "slow", "arguments": {}}}
    ).encode()
    conn = TlsConnection("127.0.0.1", args.port, session.browser.context, 150)
    events = []
    try:
        started = time.monotonic()
        conn.request("POST", f"/{SLUG}", body=body, headers=session.headers())
        response = conn.getresponse()
        need(response.status == 200, "A9", "the streamed call is answered 200", f"answered {response.status}")
        content_type = response.getheader("Content-Type") or ""
        need(content_type.startswith("text/event-stream"), "A9", "the streamed call is an event stream", "not an event stream")
        buffer = b""
        while True:
            chunk = response.read1(65536)
            if not chunk:
                break
            now = time.monotonic()
            buffer += chunk
            while b"\n\n" in buffer:
                raw, buffer = buffer.split(b"\n\n", 1)
                for line in raw.split(b"\n"):
                    if line.startswith(b"data:"):
                        events.append((now, json.loads(line[5:].strip())))
    except socket.timeout:
        raise Fail("A9", "the streamed call finishes", "the stream was quiet for more than 150 s")
    finally:
        conn.close()
    need(len(events) == 2, "A9", "the stream holds one progress event and one result", f"{len(events)} events")
    first_at, first = events[0]
    final_at, final = events[-1]
    need(first.get("method") == "notifications/progress", "A9", "the first event is progress", "it is not progress")
    first_delay = first_at - started
    need(first_delay < 5, "A9", "the first event arrives within 5 s", f"after {first_delay:.1f} s")
    need(
        "result" in final and "error" not in final and final.get("id") == 900,
        "A9",
        "the final event is the result",
        "no result",
    )
    silence = final_at - first_at
    need(silence >= 89, "A9", "the upstream stays silent for 90 s before the result", f"silence {silence:.1f} s")
    emit(
        f"PASS A9 streamed tools/call: first event {first_delay:.1f} s after the request, "
        f"result {silence:.1f} s later, call succeeded"
    )


def early_post(port, ca, path, body, headers):
    """POSTs a body and returns (status, body, headers); an answer is read even if the send closes early."""
    context = ssl.create_default_context(cafile=ca)
    conn = TlsConnection("127.0.0.1", port, context, 60)
    try:
        try:
            conn.request("POST", path, body=body, headers=headers)
        except OSError:
            pass
        response = conn.getresponse()
        return response.status, response.read(), response.getheaders()
    except (OSError, http.client.HTTPException) as error:
        raise Fail("A10", "the body is answered", f"no answer ({type(error).__name__})")
    finally:
        conn.close()


def raw_token_post(port, ca, body):
    return early_post(
        port,
        ca,
        "/oauth/token",
        body,
        {"Content-Type": "application/x-www-form-urlencoded"},
    )


def cmd_limits(args, state):
    exact = b"x=" + b"a" * (1048576 - 2)
    need(len(exact) == 1048576, "A10", "the first body is 1048576 bytes", f"{len(exact)} bytes")
    for number in range(1, 31):
        status, body, headers = raw_token_post(args.port, args.ca, exact)
        if status != 400 or b"temporarily_unavailable" in body:
            raise Fail(
                "A10",
                "every 1048576-byte body is answered by the gateway with 400",
                f"{number - 1} of 30 answered 400 before this one; request {number} answered {status}; "
                f"headers {headers!r}; first 200 bytes of body {body[:200]!r}",
            )
    over = b"x=" + b"a" * (2097152 - 2)
    need(len(over) == 2097152, "A10", "the second body is 2097152 bytes", f"{len(over)} bytes")
    second, _, _ = raw_token_post(args.port, args.ca, over)
    need(second == 413, "A10", "a 2097152-byte body is answered 413", f"answered {second}")
    emit("PASS A10 body limit: 30 of 30 1048576-byte token POSTs answered 400 by the gateway through Caddy, 2097152 bytes answered 413")

    early = b"y" * 524288
    for number in range(1, 31):
        status, body, headers = early_post(
            args.port,
            args.ca,
            f"/{SLUG}",
            early,
            {"Authorization": "Bearer dw_at_not-a-real-token", "Content-Type": "application/json"},
        )
        names = [key for key, _ in headers]
        if status != 401 or not any(name.lower() == "www-authenticate" for name in names):
            raise Fail(
                "A10b",
                "every early refusal keeps its status through Caddy: 401 with WWW-Authenticate",
                f"{number - 1} of 30 answered 401 before this one; request {number} answered {status}; "
                f"headers {headers!r}; first 200 bytes of body {body[:200]!r}",
            )
    emit("PASS A10b early refusal keeps its status through Caddy: 30 of 30 524288-byte requests with a wrong bearer answered 401 with WWW-Authenticate")

    raw = (
        f"POST /oauth/token HTTP/1.1\r\nHost: localhost:{args.port}\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: 5\r\n"
        "Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n0\r\n\r\n"
    ).encode()
    context = ssl.create_default_context(cafile=args.ca)
    tls = context.wrap_socket(socket.create_connection(("127.0.0.1", args.port), 30), server_hostname="localhost")
    tls.settimeout(30)
    answer = b""
    try:
        tls.sendall(raw)
        while True:
            chunk = tls.recv(4096)
            if not chunk:
                break
            answer += chunk
    except (ConnectionResetError, BrokenPipeError):
        pass
    except socket.timeout:
        raise Fail("A11", "the request is refused", "no answer and no close within 30 s")
    finally:
        tls.close()
    if not answer:
        emit("PASS A11 request with Content-Length and Transfer-Encoding is refused: the connection closed without an answer")
        return
    status_line = answer.split(b"\r\n", 1)[0].decode("latin-1", "replace")
    parts = status_line.split(" ")
    code = parts[1] if len(parts) > 1 else ""
    need(code == "400", "A11", "the request is refused with 400", f"status line {status_line[:40]!r}")
    emit("PASS A11 request with Content-Length and Transfer-Encoding is refused with 400")


def cmd_caller(args):
    caller = Browser(args.port, args.ca, connect_host=args.connect)
    if args.role == 1:
        for number in (1, 2, 3):
            page = caller.get(NOT_FOUND_PATH, cookies=False)
            expect(page, 404, "A12", f"caller one request {number}")
        limited = caller.get(NOT_FOUND_PATH, cookies=False)
        expect(limited, 429, "A12", "caller one's fourth request")
        retry = limited.header("Retry-After") or ""
        need(retry.isdigit() and int(retry) >= 1, "A12", "the 429 has an integer Retry-After of at least 1", f"value {retry!r}")
        need(limited.header("Cache-Control") == "no-store", "A12", "the 429 is Cache-Control no-store", "header differs")
        forged = caller.get(NOT_FOUND_PATH, cookies=False, headers={"X-Forwarded-For": "203.0.113.50"})
        expect(forged, 429, "A12", "caller one with a forged X-Forwarded-For")
        health = caller.get("/healthz", cookies=False)
        expect(health, 200, "A12", "GET /healthz for the limited caller")
        emit(
            f"PASS A12 caller one: three answers 404, fourth 429 with Retry-After {retry} and "
            "Cache-Control no-store, forged X-Forwarded-For still 429, /healthz 200"
        )
    else:
        first = caller.get(NOT_FOUND_PATH, cookies=False)
        expect(first, 404, "A12", "caller two's first request")
        emit("PASS A12 caller two: first request answered 404 in its own bucket")


def cmd_signin(args, state, label):
    browser = Browser(args.port, args.ca)
    login = browser.get("/login")
    expect(login, 200, label, "GET /login")
    token = login.csrf()
    need(token is not None, label, "the login form carries a csrf token", "no csrf")
    page = browser.post_form(
        "/login",
        [("csrf", token), ("email", OWNER_EMAIL), ("password", state["password"])],
    )
    expect(page, 303, label, "sign in with the owner's password")
    need(page.location == "/account", label, "sign-in redirects to /account", f"location {page.location!r}")
    account = browser.get("/account")
    expect(account, 200, label, "GET /account after sign-in")
    need(account.kind() == "account", label, "the account page loads", f"kind {account.kind()!r}")


def cmd_signin_a13(args, state):
    cmd_signin(args, state, "A13")
    emit("PASS A13 the owner signs in after the recreate; the data survived")


def cmd_signin_a14(args, state):
    cmd_signin(args, state, "A14")
    session = McpSession(args.port, args.ca, state["access_token"], "A14")
    session.initialize()
    names = session.tool_names()
    need(names == ["echo", "slow"], "A14", "tools/list answers after the restore", f"names {names!r}")
    emit("PASS A14 after the restore the owner signs in with the old password; tools/list answers echo and slow")


def plain_get(port, path, forwarded=None):
    """GET over plain HTTP on loopback; returns the status, the Retry-After and the headers."""
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=30)
    headers = {} if forwarded is None else {"X-Forwarded-For": forwarded}
    try:
        conn.request("GET", path, headers=headers)
        response = conn.getresponse()
        response.read()
        return response.status, response.getheader("Retry-After"), response.getheaders()
    finally:
        conn.close()


def cmd_forward(args):
    for number in (1, 2, 3):
        status, _, _ = plain_get(args.port, NOT_FOUND_PATH, "198.51.100.7")
        need(status == 404, "B2", f"request {number} for 198.51.100.7", f"answered {status}, wanted 404")
    status, retry, _ = plain_get(args.port, NOT_FOUND_PATH, "198.51.100.7")
    need(status == 429, "B2", "the fourth request for 198.51.100.7 is limited", f"answered {status}, wanted 429")
    need(retry is not None and retry.isdigit(), "B2", "the 429 carries an integer Retry-After", f"value {retry!r}")
    status, _, _ = plain_get(args.port, NOT_FOUND_PATH, "198.51.100.8")
    need(status == 404, "B2", "198.51.100.8 has its own bucket", f"answered {status}, wanted 404")
    emit("PASS B2 forwarded address counted: 198.51.100.7 answered 3 times then 429, 198.51.100.8 answered 404")


def cmd_hsts(args):
    status, _, headers = plain_get(args.port, "/login", "198.51.100.9")
    need(status == 200, "B5", "GET /login on the plain stack is answered 200", f"answered {status}")
    values = [value for key, value in headers if key.lower() == "strict-transport-security"]
    need(values == ["max-age=31536000"], "B5", "/login carries Strict-Transport-Security max-age=31536000", f"values {len(values)}")
    emit("PASS B5 plain stack with an https public address: /login answered 200 with Strict-Transport-Security max-age=31536000")


def cmd_wait_healthz(args):
    deadline = time.monotonic() + args.deadline
    last = "no answer"
    while True:
        try:
            page = Browser(args.port, args.ca).get("/healthz", cookies=False)
            if page.status == 200:
                return
            last = f"status {page.status}"
        except (OSError, http.client.HTTPException) as error:
            last = type(error).__name__
        if time.monotonic() >= deadline:
            raise Fail(args.label, "the gateway answers /healthz 200 through Caddy", f"last answer {last}")
        time.sleep(1)


def docker_json(argv, label, what):
    done = subprocess.run(["docker", *argv], capture_output=True, check=False)
    need(done.returncode == 0, label, what, f"docker exit {done.returncode}")
    return json.loads(done.stdout)


def cmd_addresses(args):
    """A3b: on the proxy network Caddy and the gateway hold their fixed addresses."""
    for role, cid, wanted in (("caddy", args.caddy_cid, "10.213.87.2"), ("gateway", args.gw_cid, "10.213.87.3")):
        info = docker_json(["inspect", cid], "A3b", "the container can be inspected")[0]
        network = info["NetworkSettings"]["Networks"].get(args.network) or {}
        dynamic = network.get("IPAddress")
        fixed = (network.get("IPAMConfig") or {}).get("IPv4Address")
        need(
            dynamic == wanted and fixed == wanted,
            "A3b",
            f"the {role} has the fixed address {wanted} on the proxy network",
            f"address {dynamic!r}, fixed {fixed!r}",
        )
    emit("PASS A3b on the proxy network Caddy holds the fixed address 10.213.87.2 and the gateway 10.213.87.3")


def cmd_image(args):
    config = docker_json(["image", "inspect", args.image], "A1", "the image can be inspected")[0]["Config"]
    need(config.get("User") == "65532:65532", "A1", "the image runs as 65532:65532", f"user {config.get('User')!r}")
    names = [item.split("=", 1)[0] for item in config.get("Env") or []]
    need(not any(n.startswith("DOORWARD_") for n in names), "A1", "the image sets no DOORWARD_ variable", "one is set")
    emit("PASS A1 image built from the repository runs as 65532:65532 and sets no DOORWARD_ variable")


def cmd_inspect(args):
    info = docker_json(["inspect", args.cid], args.label, "the container can be inspected")[0]
    host = info["HostConfig"]
    label = args.label
    need(host.get("ReadonlyRootfs") is True, label, f"{args.role} root file system is read-only", f"ReadonlyRootfs {host.get('ReadonlyRootfs')!r}")
    need(host.get("CapDrop") == ["ALL"], label, f"{args.role} drops all capabilities", f"CapDrop {host.get('CapDrop')!r}")
    options = host.get("SecurityOpt") or []
    need("no-new-privileges:true" in options, label, f"{args.role} sets no-new-privileges", f"SecurityOpt {options!r}")
    need(host.get("PidsLimit") == 1024, label, f"{args.role} limits processes to 1024", f"PidsLimit {host.get('PidsLimit')!r}")
    need(bool(host.get("Memory")), label, f"{args.role} has a memory limit", f"Memory {host.get('Memory')!r}")
    ports = info["NetworkSettings"].get("Ports") or {}
    if args.role == "caddy":
        emit(f"PASS {label} caddy: read-only root, all capabilities dropped, no-new-privileges, 1024 processes, memory limit")
        return
    user = info["Config"].get("User")
    need(user == "65532:65532", label, "the gateway runs as 65532:65532", f"user {user!r}")
    if args.role == "gateway":
        published = [key for key, value in ports.items() if value]
        need(not published, label, "the gateway publishes no host port", f"published {len(published)} ports")
        emit(f"PASS {label} gateway: user 65532:65532, read-only root, all capabilities dropped, no-new-privileges, 1024 processes, memory limit, no host port")
    else:
        expected = {"8717/tcp": [{"HostIp": "127.0.0.1", "HostPort": str(args.port)}]}
        need(ports == expected, label, "the gateway port is bound to 127.0.0.1 only", f"ports {ports!r}")
        emit(f"PASS {label} gateway: user 65532:65532, read-only root, all capabilities dropped, no-new-privileges, 1024 processes, memory limit, port bound to 127.0.0.1 only")


def build_parser():
    parser = argparse.ArgumentParser(description="Proof checks for scripts/prove-docker.sh.")
    parser.add_argument("--state", default=None)
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("image")
    p.add_argument("--image", required=True)

    p = sub.add_parser("inspect")
    p.add_argument("--cid", required=True)
    p.add_argument("--role", choices=["gateway", "caddy", "plain"], required=True)
    p.add_argument("--label", required=True)
    p.add_argument("--port", type=int, default=0)

    p = sub.add_parser("addresses")
    p.add_argument("--caddy-cid", required=True)
    p.add_argument("--gw-cid", required=True)
    p.add_argument("--network", required=True)

    p = sub.add_parser("wait-healthz")
    p.add_argument("--port", type=int, required=True)
    p.add_argument("--ca", required=True)
    p.add_argument("--deadline", type=int, default=90)
    p.add_argument("--label", required=True)

    for name in ("setup", "app", "mcp", "limits", "signin-a13", "signin-a14"):
        p = sub.add_parser(name)
        p.add_argument("--port", type=int, required=True)
        p.add_argument("--ca", required=True)
        if name == "setup":
            p.add_argument("--gw-cid", required=True)

    p = sub.add_parser("caller")
    p.add_argument("--port", type=int, required=True)
    p.add_argument("--ca", required=True)
    p.add_argument("--connect", required=True)
    p.add_argument("--role", type=int, choices=[1, 2], required=True)

    p = sub.add_parser("forward")
    p.add_argument("--port", type=int, required=True)

    p = sub.add_parser("hsts")
    p.add_argument("--port", type=int, required=True)
    return parser


STATE_COMMANDS = {
    "setup": cmd_setup,
    "app": cmd_app,
    "mcp": cmd_mcp,
    "limits": cmd_limits,
    "signin-a13": cmd_signin_a13,
    "signin-a14": cmd_signin_a14,
}


def run(args):
    if args.cmd == "image":
        return cmd_image(args)
    if args.cmd == "inspect":
        return cmd_inspect(args)
    if args.cmd == "wait-healthz":
        return cmd_wait_healthz(args)
    if args.cmd == "addresses":
        return cmd_addresses(args)
    if args.cmd == "caller":
        return cmd_caller(args)
    if args.cmd == "forward":
        return cmd_forward(args)
    if args.cmd == "hsts":
        return cmd_hsts(args)
    need(args.state is not None, args.cmd, "has a state file", "--state is missing")
    state = load_state(args.state)
    STATE_COMMANDS[args.cmd](args, state)
    save_state(args.state, state)
    return None


def main(argv):
    args = build_parser().parse_args(argv)
    try:
        run(args)
    except Fail as failure:
        print(f"FAIL {failure}", flush=True)
        return 1
    except Exception as error:  # Reported, never a traceback: a traceback can print local paths.
        frames = [f for f in traceback.extract_tb(error.__traceback__) if f.filename == __file__]
        line = frames[-1].lineno if frames else 0
        print(f"FAIL {args.cmd} unexpected {type(error).__name__} at driver line {line}", flush=True)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
