import socket, ssl, sys, threading
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain('/tmp/nano-cert.pem','/tmp/nano-key.pem')
ctx.minimum_version = ssl.TLSVersion.TLSv1_3
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('127.0.0.1',8444)); s.listen(1)
print('listening', flush=True)
conn, addr = s.accept()
print('accepted', flush=True)
try:
    c = ctx.wrap_socket(conn, server_side=True)
    print('tls', c.version(), c.cipher(), flush=True)
    data = c.recv(65536)
    print('request bytes', len(data), flush=True)
    print(repr(data[:1000]), flush=True)
    body = b'{"choices":[{"message":{"role":"assistant","content":"hello from nano"}}]}'
    resp = b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: '+str(len(body)).encode()+b'\r\nConnection: close\r\n\r\n'+body
    c.sendall(resp)
    c.close()
except Exception as e:
    print('error', repr(e), flush=True)
