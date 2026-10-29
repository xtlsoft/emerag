#!/usr/bin/env python3
"""Mock provider that exercises the subagent (task) tool."""
import json, sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 18231

class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def log_message(self, fmt, *a): sys.stderr.write("mock: " + (fmt % a) + "\n")
    def do_GET(self):
        body = json.dumps({"data": [{"id": "mock-model"}]}).encode()
        self.send_response(200); self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0)); req = json.loads(self.rfile.read(n) or b"{}")
        self.send_response(200); self.send_header("Content-Type", "text/event-stream"); self.end_headers()
        def chunk(o):
            self.wfile.write(b"data: " + json.dumps({"id":"m","object":"chat.completion.chunk","created":1,"model":"mock","choices":[o]}).encode() + b"\n\n"); self.wfile.flush()
        msgs = req.get("messages", [])
        tool_msgs = [m for m in msgs if m.get("role") == "tool"]
        system = next((m.get("content", "") for m in msgs if m.get("role") == "system"), "")
        is_child = "You are a subagent" in system
        if is_child and not tool_msgs:
            chunk({"index":0,"delta":{"content":"child finished its job"},"finish_reason":None})
            chunk({"index":0,"delta":{},"finish_reason":"stop"})
        elif tool_msgs and tool_msgs[-1].get("tool_call_id", "").startswith("call_task"):
            text = "parent saw the subagent report: " + tool_msgs[-1]["content"][:120]
            for w in text.split(" "):
                chunk({"index":0,"delta":{"content":w+" "},"finish_reason":None})
            chunk({"index":0,"delta":{},"finish_reason":"stop"})
        elif tool_msgs:
            text = "child finished its job"
            for w in text.split(" "):
                chunk({"index":0,"delta":{"content":w+" "},"finish_reason":None})
            chunk({"index":0,"delta":{},"finish_reason":"stop"})
        else:
            chunk({"index":0,"delta":{"content":"delegating"},"finish_reason":None})
            chunk({"index":0,"delta":{"tool_calls":[{"index":0,"id":"call_task","type":"function","function":{"name":"task","arguments":json.dumps({"description":"scan","prompt":"look around and report"})}}]},"finish_reason":None})
            chunk({"index":0,"delta":{},"finish_reason":"tool_calls"})
        self.wfile.write(b"data: [DONE]\n\n"); self.wfile.flush()

if __name__ == "__main__":
    ThreadingHTTPServer(("127.0.0.1", PORT), H).serve_forever()
