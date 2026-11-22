"""Checks that the fake upstream reads every request body, so a refused request leaves the connection in step.

Standard library only. Run from the repository root: python3 -I scripts/prove/test_fake_upstream.py
"""

import http.client
import http.server
import importlib.util
import json
import os
import secrets
import sys
import threading

HERE = os.path.dirname(os.path.abspath(__file__))
FAKE_UPSTREAM = os.path.join(HERE, "fake_upstream.py")
SECRET_KEY = "PROOF_UPSTREAM_SECRET"
SECRET_HEADER = "x-upstream-secret"
PATH = "/mcp"
PROTOCOL_VERSION = "2025-06-18"
TIMEOUT_SECONDS = 10
LARGE_BODY_BYTES = 64 * 1024


class Fail(Exception):
    pass


def need(condition, message):
    if not condition:
        raise Fail(message)


def load_upstream(secret):
    """The module as the proof scripts load it; it reads its secret from the environment when imported."""
    os.environ[SECRET_KEY] = secret
    spec = importlib.util.spec_from_file_location("fake_upstream", FAKE_UPSTREAM)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def start_upstream(secret):
    """Serves the module's handler on a free loopback port, as clients.py run_upstream does."""
    module = load_upstream(secret)
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), module.Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def notification(pad):
    return json.dumps({"jsonrpc": "2.0", "method": "notifications/test", "params": {"pad": pad}}).encode()


def large_body():
    body = notification("x" * (LARGE_BODY_BYTES - len(notification(""))))
    need(len(body) == LARGE_BODY_BYTES, f"the large body is {len(body)} bytes, wanted {LARGE_BODY_BYTES}")
    return body


def initialize_body(request_id):
    params = {"protocolVersion": PROTOCOL_VERSION, "capabilities": {}, "clientInfo": {"name": "test", "version": "1"}}
    return json.dumps({"jsonrpc": "2.0", "id": request_id, "method": "initialize", "params": params}).encode()


def send(conn, method, body, secret=None):
    """Sends one request; a body of None sends no Content-Length header at all."""
    conn.putrequest(method, PATH)
    conn.putheader("Content-Type", "application/json")
    if secret is not None:
        conn.putheader(SECRET_HEADER, secret)
    if body is not None:
        conn.putheader("Content-Length", str(len(body)))
    conn.endheaders(message_body=body)
    response = conn.getresponse()
    return response, response.read()


def check_initialized(response, data, request_id):
    need(response.status == 200, f"the valid request answered {response.status}, wanted 200")
    need(response.getheader("Content-Type") == "application/json", "the valid answer is not application/json")
    need(response.getheader("Mcp-Session-Id", "").startswith("sess-"), "the valid answer has no Mcp-Session-Id")
    try:
        answer = json.loads(data)
    except ValueError as error:
        raise Fail(f"the valid answer is not JSON ({error}): {data[:200]!r}") from None
    expected = {
        "jsonrpc": "2.0",
        "id": request_id,
        "result": {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": "fake-upstream", "version": "1"},
        },
    }
    need(answer == expected, f"the valid answer is {answer!r}, wanted {expected!r}")


def run_refused(port, secret, label, method, body, refused_status):
    """One kept-alive connection: a refused request without the secret, then a valid one with it."""
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=TIMEOUT_SECONDS)
    try:
        response, data = send(conn, method, body)
        need(response.status == refused_status, f"{label}: the refused request answered {response.status}, wanted {refused_status}")
        need(data == b"", f"{label}: the refused request answered a body {data[:200]!r}")
        response, data = send(conn, "POST", initialize_body(7), secret)
        check_initialized(response, data, 7)
    finally:
        conn.close()


USER_HEADERS_KEY = "FAKE_UPSTREAM_USER_HEADERS"
SESSION_HEADER = "Mcp-Session-Id"
OPTION_NAMES = "X-Api-Key,X-Tenant"
API_KEY_VALUE = "key-value-one"
TENANT_VALUE = "tenant-value-two"
# The first 12 hex characters of the SHA-256 of each value above, computed with hashlib outside this file.
API_KEY_DIGEST = "d3db7c62b201"
TENANT_DIGEST = "0266dbeee780"


def post(conn, secret, message, headers):
    """One JSON-RPC POST with the secret header and the given extra headers."""
    body = json.dumps(message).encode()
    fields = {"Content-Type": "application/json", SECRET_HEADER: secret, **headers}
    conn.request("POST", PATH, body=body, headers=fields)
    response = conn.getresponse()
    return response, response.read()


def call(conn, secret, message, headers):
    """One POST: the status, and the answer parsed as JSON when it is JSON."""
    response, data = post(conn, secret, message, headers)
    try:
        return response.status, json.loads(data)
    except ValueError:
        return response.status, data


def rpc(request_id, method, params):
    return {"jsonrpc": "2.0", "id": request_id, "method": method, "params": params}


def echo_answer(request_id, text):
    result = {"content": [{"type": "text", "text": f"echo: {text}"}], "isError": False}
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def missing_answer(request_id, name):
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": -32600, "message": f"missing header: {name}"}}


def open_session(conn, secret):
    """Initializes one session and returns its Mcp-Session-Id."""
    response, _ = post(conn, secret, json.loads(initialize_body(1)), {})
    need(response.status == 200, f"initialize answered {response.status}, wanted 200")
    session = response.getheader(SESSION_HEADER, "")
    need(session.startswith("sess-"), "initialize gave no Mcp-Session-Id")
    return session


def expect(actual, wanted, label):
    need(actual == wanted, f"{label} is {actual!r}, wanted {wanted!r}")


def listed_names(answer):
    """The tool names of a tools/list answer; any other shape fails the check."""
    result = answer.get("result") if isinstance(answer, dict) else None
    need(isinstance(result, dict) and "tools" in result, f"tools/list answered {answer!r}")
    return [tool["name"] for tool in result["tools"]]


def without_option_checks(conn, secret):
    """With no user header named, the tool list is unchanged and echo needs no header."""
    session = open_session(conn, secret)
    headers = {SESSION_HEADER: session}
    status, answer = call(conn, secret, rpc(2, "tools/list", {}), headers)
    expect(status, 200, "tools/list status without the option")
    expect(listed_names(answer), ["echo", "slow"], "the tool names without the option")
    echo = {"name": "echo", "arguments": {"text": "hi"}}
    status, answer = call(conn, secret, rpc(3, "tools/call", echo), headers)
    expect((status, answer), (200, echo_answer(3, "hi")), "echo without the option")
    whoami = {"name": "whoami", "arguments": {}}
    status, answer = call(conn, secret, rpc(4, "tools/call", whoami), headers)
    unknown = {"jsonrpc": "2.0", "id": 4, "error": {"code": -32602, "message": "Unknown tool: whoami"}}
    expect((status, answer), (200, unknown), "whoami without the option")


def with_option_checks(conn, secret):
    """With two user headers named, every tools/call needs both, and whoami reports their digests."""
    session = open_session(conn, secret)
    bare = {SESSION_HEADER: session}
    status, answer = call(conn, secret, rpc(2, "tools/list", {}), bare)
    expect(status, 200, "tools/list status with the option")
    expect(listed_names(answer), ["echo", "slow", "whoami"], "the tool names with the option")
    echo = {"name": "echo", "arguments": {"text": "hi"}}
    status, answer = call(conn, secret, rpc(3, "tools/call", echo), bare)
    expect((status, answer), (400, missing_answer(3, "X-Api-Key")), "echo without any user header")
    with_key = {**bare, "X-Api-Key": API_KEY_VALUE}
    status, answer = call(conn, secret, rpc(4, "tools/call", echo), with_key)
    expect((status, answer), (400, missing_answer(4, "X-Tenant")), "echo without X-Tenant")
    both = {**with_key, "X-Tenant": TENANT_VALUE}
    status, answer = call(conn, secret, rpc(5, "tools/call", echo), both)
    expect((status, answer), (200, echo_answer(5, "hi")), "echo with both headers")
    lower = {**bare, "x-api-key": API_KEY_VALUE, "X-Tenant": TENANT_VALUE}
    status, answer = call(conn, secret, rpc(6, "tools/call", {"name": "whoami", "arguments": {}}), lower)
    text = f"X-Api-Key: {API_KEY_DIGEST}\nX-Tenant: {TENANT_DIGEST}"
    whoami = {"jsonrpc": "2.0", "id": 6, "result": {"content": [{"type": "text", "text": text}], "isError": False}}
    expect((status, answer), (200, whoami), "whoami with both headers")
    status, answer = call(conn, secret, rpc(7, "ping", {}), bare)
    ping = {"jsonrpc": "2.0", "id": 7, "error": {"code": -32601, "message": "Method not found"}}
    expect((status, answer), (200, ping), "ping without the headers")
    notice = {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}}
    status, answer = call(conn, secret, notice, bare)
    expect((status, answer), (202, b""), "a notification without the headers")


def run_check(secret, names, check):
    """Serves the module with the user headers named as `names` (None: variable unset) and runs `check` on one connection."""
    if names is None:
        os.environ.pop(USER_HEADERS_KEY, None)
    else:
        os.environ[USER_HEADERS_KEY] = names
    server = start_upstream(secret)
    try:
        conn = http.client.HTTPConnection("127.0.0.1", server.server_address[1], timeout=TIMEOUT_SECONDS)
        try:
            check(conn, secret)
        finally:
            conn.close()
    finally:
        server.shutdown()
        server.server_close()


def names_from_arguments_and_environment(secret):
    """--user-header wins over the variable; the variable is split on commas and blanks are dropped."""
    module = load_upstream(secret)
    expect(module.parse_user_headers([], {}), [], "the names with nothing given")
    expect(module.parse_user_headers(["--user-header", "X-A", "--user-header", "X-B"], {}), ["X-A", "X-B"], "two --user-header arguments")
    expect(module.parse_user_headers([], {USER_HEADERS_KEY: " X-A, ,X-B "}), ["X-A", "X-B"], "the names from the variable")
    expect(module.parse_user_headers(["--user-header", "X-C"], {USER_HEADERS_KEY: "X-A"}), ["X-C"], "arguments before the variable")


def main():
    os.environ.pop(USER_HEADERS_KEY, None)
    secret = secrets.token_urlsafe(24)
    server = start_upstream(secret)
    scenarios = [
        ("POST with a small body", "POST", notification("x"), 401),
        ("POST with a 64 KiB body", "POST", large_body(), 401),
        ("POST with a zero length", "POST", b"", 401),
        ("POST with no Content-Length", "POST", None, 401),
        ("GET with a body", "GET", notification("x"), 405),
        ("DELETE with a body", "DELETE", notification("x"), 405),
    ]
    try:
        port = server.server_address[1]
        for label, method, body, refused_status in scenarios:
            run_refused(port, secret, label, method, body, refused_status)
        run_check(secret, None, without_option_checks)
        run_check(secret, OPTION_NAMES, with_option_checks)
        names_from_arguments_and_environment(secret)
    except Fail as failure:
        print(f"FAKE UPSTREAM FAIL: {failure}")
        return 1
    except (OSError, http.client.HTTPException) as failure:
        print(f"FAKE UPSTREAM FAIL: {type(failure).__name__}: {failure}")
        return 1
    finally:
        server.shutdown()
        server.server_close()
    print("FAKE UPSTREAM PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
