#!/usr/bin/env python3
"""Mock OpenAI Responses streaming server for emerag adapter tests."""
import json, sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 18094

class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def log_message(self, fmt, *a): sys.stderr.write("mock: " + (fmt % a) + "\n")
    def do_GET(self):
        body = json.dumps({"data": [{"id": "resp-mock", "object": "model"}]}).encode()
        self.send_response(200); self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0)); req = json.loads(self.rfile.read(n) or b"{}")
        self.send_response(200); self.send_header("Content-Type", "text/event-stream"); self.end_headers()
        def ev(obj):
            self.wfile.write(("event: " + obj["type"] + "\ndata: " + json.dumps(obj) + "\n\n").encode()); self.wfile.flush()
        ev({"type":"response.created","response":{"id":"resp_1","status":"in_progress"}})
        ev({"type":"response.output_text.delta","item_id":"msg_1","delta":"Responses "})
        ev({"type":"response.output_text.delta","item_id":"msg_1","delta":"mock writes back."})
        ev({"type":"response.completed","response":{"id":"resp_1","status":"completed","usage":{"input_tokens":9,"output_tokens":5,"input_tokens_details":{"cached_tokens":0},"output_tokens_details":{"reasoning_tokens":0}}}})

if __name__ == "__main__":
    srv = ThreadingHTTPServer(("127.0.0.1", PORT), H)
    print("ready", flush=True)
    srv.serve_forever()
