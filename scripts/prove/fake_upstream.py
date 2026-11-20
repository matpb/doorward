"""Fake Streamable HTTP MCP upstream for scripts/prove-docker.sh. Standard library only.

Session rules only: initialize, notifications (202), tools/list, and tools/call for
`echo` (JSON) and `slow` (event stream: one progress event, 90 s of silence, the result).
Every POST needs the secret header named in SECRET_HEADER, else 401.
"""

import json
import os
import secrets
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SECRET_HEADER = "x-upstream-secret"
SECRET = os.environ.get("PROOF_UPSTREAM_SECRET", "")
SLOW_SILENCE_SECONDS = 90
SESSION_VERSIONS = ("2025-03-26", "2025-06-18", "2025-11-25")
TOOLS = [
    {
        "name": "echo",
        "description": "Returns a fixed text.",
        "inputSchema": {"type": "object", "properties": {"text": {"type": "string"}}},
    },
    {
        "name": "slow",
        "description": "Sends progress, then answers after a silence.",
        "inputSchema": {"type": "object", "properties": {}},
    },
]
SESSIONS = set()
SESSIONS_LOCK = threading.Lock()


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        return

    def _reply(self, status, body=b"", headers=()):
        self.send_response(status)
        for name, value in headers:
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)
        self.wfile.flush()

    def _json(self, status, message, headers=()):
        body = json.dumps(message).encode()
        self._reply(status, body, [("Content-Type", "application/json"), *headers])

    def _rpc_error(self, status, request_id, code, text):
        error = {"code": code, "message": text}
        self._json(status, {"jsonrpc": "2.0", "id": request_id, "error": error})

    def do_GET(self):
        self._reply(405)

    def do_DELETE(self):
        self._reply(405)

    def do_POST(self):
        if self.headers.get(SECRET_HEADER) != SECRET:
            self._reply(401)
            return
        length = int(self.headers.get("Content-Length", "0"))
        try:
            message = json.loads(self.rfile.read(length))
        except ValueError:
            self._rpc_error(400, None, -32700, "Parse error")
            return
        if not isinstance(message, dict):
            self._rpc_error(400, None, -32600, "Invalid Request")
            return
        method = message.get("method")
        request_id = message.get("id")
        if request_id is None:
            self._reply(202)
            return
        if method == "initialize":
            self._initialize(request_id, message.get("params") or {})
            return
        session = self.headers.get("Mcp-Session-Id")
        if session is None:
            self._reply(400)
            return
        with SESSIONS_LOCK:
            known = session in SESSIONS
        if not known:
            self._reply(404)
            return
        if method == "tools/list":
            self._json(200, {"jsonrpc": "2.0", "id": request_id, "result": {"tools": TOOLS}})
        elif method == "tools/call":
            self._call(request_id, message.get("params") or {})
        else:
            self._rpc_error(200, request_id, -32601, "Method not found")

    def _initialize(self, request_id, params):
        requested = params.get("protocolVersion")
        version = requested if requested in SESSION_VERSIONS else "2025-11-25"
        session = "sess-" + secrets.token_hex(16)
        with SESSIONS_LOCK:
            SESSIONS.add(session)
        result = {
            "protocolVersion": version,
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": "fake-upstream", "version": "1"},
        }
        self._json(
            200,
            {"jsonrpc": "2.0", "id": request_id, "result": result},
            [("Mcp-Session-Id", session)],
        )

    def _call(self, request_id, params):
        name = params.get("name")
        if name == "echo":
            text = (params.get("arguments") or {}).get("text", "")
            result = {"content": [{"type": "text", "text": f"echo: {text}"}], "isError": False}
            self._json(200, {"jsonrpc": "2.0", "id": request_id, "result": result})
        elif name == "slow":
            self._slow(request_id)
        else:
            self._rpc_error(200, request_id, -32602, f"Unknown tool: {name}")

    def _chunk(self, data):
        self.wfile.write(f"{len(data):x}\r\n".encode() + data + b"\r\n")
        self.wfile.flush()

    def _slow(self, request_id):
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Transfer-Encoding", "chunked")
        self.end_headers()
        progress = {
            "jsonrpc": "2.0",
            "method": "notifications/progress",
            "params": {"progressToken": "p1", "progress": 1, "total": 2},
        }
        self._chunk(b"data: " + json.dumps(progress).encode() + b"\n\n")
        time.sleep(SLOW_SILENCE_SECONDS)
        result = {"content": [{"type": "text", "text": "slow done"}], "isError": False}
        final = {"jsonrpc": "2.0", "id": request_id, "result": result}
        self._chunk(b"data: " + json.dumps(final).encode() + b"\n\n")
        self.wfile.write(b"0\r\n\r\n")
        self.wfile.flush()


if __name__ == "__main__":
    if not SECRET:
        raise SystemExit("PROOF_UPSTREAM_SECRET is not set")
    server = ThreadingHTTPServer(("0.0.0.0", 9000), Handler)
    server.serve_forever()
