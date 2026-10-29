#!/usr/bin/env python3
"""Mock OpenAI-compatible server for emerag end-to-end tests.

First request: asks to read a file with a tool call.
Second request: answers with the tool result.
Streams SSE like a real provider.
"""
import json, sys, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 18080
SEEN_TOOL = False


def peer(handler, payload):
    return {**payload, "id": "mock-1", "object": "chat.completion.chunk", "created": 1, "model": "mock-model"}


class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        sys.stderr.write("mock: " + (fmt % args) + "\n")
        sys.stderr.flush()

    def do_GET(self):
        if self.path.endswith("/models"):
            body = json.dumps({"object": "list", "data": [{"id": "mock-model"}, {"id": "mock-2"}]}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404); self.send_header("Content-Length", "0"); self.end_headers()

    def do_POST(self):
        global SEEN_TOOL
        n = int(self.headers.get("Content-Length", 0))
        req = json.loads(self.rfile.read(n) or b"{}")
        msgs = req.get("messages", [])
        has_tool_result = any(m.get("role") == "tool" for m in msgs)
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "close")
        self.end_headers()
        def send(obj):
            self.wfile.write(b"data: " + json.dumps(obj).encode() + b"\n\n")
            self.wfile.flush()
        if not has_tool_result:
            send(peer(self, {"choices": [{"index": 0, "delta": {"role": "assistant", "content": "Let me read that file."}}]}))
            args = json.dumps({"path": "tests/data/hello.txt"})
            send(peer(self, {"choices": [{"index": 0, "delta": {"tool_calls": [{"index": 0, "id": "call_1", "type": "function", "function": {"name": "read_file", "arguments": args}}]}}]}))
            send(peer(self, {"choices": [{"index": 0, "delta": {}, "finish_reason": "tool_calls"}]}))
            send({"choices": [], "usage": {"prompt_tokens": 20, "completion_tokens": 5, "total_tokens": 25}})
        else:
            tool = next(m for m in msgs if m.get("role") == "tool")
            content = "The file says: " + tool["content"][:200]
            for word in content.split(" "):
                send(peer(self, {"choices": [{"index": 0, "delta": {"content": word + " "}}]}))
            send(peer(self, {"choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]}))
            send({"choices": [], "usage": {"prompt_tokens": 30, "completion_tokens": 10, "total_tokens": 40}})
        self.wfile.write(b"data: [DONE]\n\n")
        self.wfile.flush()


if __name__ == "__main__":
    srv = ThreadingHTTPServer(("127.0.0.1", PORT), H)
    print("ready", flush=True)
    srv.serve_forever()
