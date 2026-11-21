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


def main():
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
