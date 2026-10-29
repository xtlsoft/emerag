#!/usr/bin/env python3
"""Mock OpenAI provider over HTTPS for TLS integration tests."""
import json, ssl, sys
from http.server import ThreadingHTTPServer
sys.path.insert(0, sys.path[0])
from mock_provider import H

port = int(sys.argv[1]); cert = sys.argv[2]; key = sys.argv[3]
srv = ThreadingHTTPServer(("127.0.0.1", port), H)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(cert, key)
srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
print("ready", flush=True)
srv.serve_forever()
