#!/usr/bin/env python3
"""Mock Anthropic Messages streaming server for emerag adapter tests."""
import json, sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 18093

class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def log_message(self, fmt, *a): sys.stderr.write("mock: " + (fmt % a) + "\n")
    def do_GET(self):
        body = json.dumps({"data": [{"id": "claude-mock", "type": "model"}]}).encode()
        self.send_response(200); self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0)); req = json.loads(self.rfile.read(n) or b"{}")
        self.send_response(200); self.send_header("Content-Type", "text/event-stream"); self.end_headers()
        def ev(name, obj):
            self.wfile.write(("event: " + name + "\ndata: " + json.dumps(obj) + "\n\n").encode()); self.wfile.flush()
        ev("message_start", {"type":"message_start","message":{"id":"msg_1","type":"message","role":"assistant","content":[],"usage":{"input_tokens":12,"output_tokens":0}}})
        ev("content_block_start", {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}})
        for w in ["Anthropic ", "mock ", "replies."]:
            ev("content_block_delta", {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":w}})
        ev("content_block_stop", {"type":"content_block_stop","index":0})
        ev("message_delta", {"type":"message_delta","delta":{"stop_reason":"end_turn","stop_sequence":None},"usage":{"output_tokens":7}})
        ev("message_stop", {"type":"message_stop"})

if __name__ == "__main__":
    srv = ThreadingHTTPServer(("127.0.0.1", PORT), H)
    print("ready", flush=True)
    srv.serve_forever()
