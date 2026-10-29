#!/usr/bin/env python3
"""Mock provider that requests one write_file tool call."""
import json, sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 18121

class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def log_message(self, fmt, *a): sys.stderr.write("mock: " + (fmt % a) + "\n")
    def do_GET(self):
        body = json.dumps({"data": [{"id": "mock-model"}]}).encode()
        self.send_response(200); self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0)); req = json.loads(self.rfile.read(n) or b"{}")
        has_tool = any(m.get("role") == "tool" for m in req.get("messages", []))
        self.send_response(200); self.send_header("Content-Type", "text/event-stream"); self.end_headers()
        def ev(o):
            self.wfile.write(b"data: " + json.dumps(o).encode() + b"\n\n"); self.wfile.flush()
        def chunk(o):
            ev({"id":"m","object":"chat.completion.chunk","created":1,"model":"mock","choices":[o]})
        if not has_tool:
            chunk({"index":0,"delta":{"content":"I will write a file."},"finish_reason":None})
            chunk({"index":0,"delta":{"tool_calls":[{"index":0,"id":"call_w","type":"function","function":{"name":"write_file","arguments":json.dumps({"path":"approved.txt","content":"approved\n"})}}]},"finish_reason":None})
            chunk({"index":0,"delta":{},"finish_reason":"tool_calls"})
        else:
            chunk({"index":0,"delta":{"content":"File written after approval."},"finish_reason":None})
            chunk({"index":0,"delta":{},"finish_reason":"stop"})
        self.wfile.write(b"data: [DONE]\n\n"); self.wfile.flush()

if __name__ == "__main__":
    ThreadingHTTPServer(("127.0.0.1", PORT), H).serve_forever()
