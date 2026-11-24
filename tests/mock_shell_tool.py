#!/usr/bin/env python3
"""Mock OpenAI-compatible server that asks to run a shell command.

Usage: mock_shell_tool.py PORT MARKER_PATH

The first request answers with a shell tool call that would create
MARKER_PATH. The e2e test runs emerag in ask mode with stdin at EOF and
checks the marker does NOT exist: closed input must never approve a tool.
"""
import json, sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(sys.argv[1])
MARKER = sys.argv[2]


class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        sys.stderr.write("mock: " + (fmt % args) + "\n")

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        req = json.loads(self.rfile.read(n) or b"{}")
        msgs = req.get("messages", [])
        has_tool_result = any(m.get("role") == "tool" for m in msgs)
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Connection", "close")
        self.end_headers()

        def send(delta, finish=None):
            chunk = {"id": "m", "object": "chat.completion.chunk", "created": 1, "model": "m",
                     "choices": [{"index": 0, "delta": delta, "finish_reason": finish}]}
            self.wfile.write(b"data: " + json.dumps(chunk).encode() + b"\n\n")

        if not has_tool_result:
            args = json.dumps({"command": "touch " + MARKER})
            send({"role": "assistant", "tool_calls": [{"index": 0, "id": "call_1", "type": "function",
                                                       "function": {"name": "shell", "arguments": args}}]})
            send({}, "tool_calls")
        else:
            send({"content": "done"})
            send({}, "stop")
        self.wfile.write(b"data: [DONE]\n\n")
        self.wfile.flush()


if __name__ == "__main__":
    ThreadingHTTPServer(("127.0.0.1", PORT), H).serve_forever()
