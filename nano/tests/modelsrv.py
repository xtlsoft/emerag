import socket, ssl, json, re
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain('/tmp/nano-cert.pem','/tmp/nano-key.pem')
ctx.minimum_version = ssl.TLSVersion.TLSv1_3
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('127.0.0.1',8447)); s.listen(2)
print('listening', flush=True)
for n in range(2):
    conn, addr = s.accept()
    c = ctx.wrap_socket(conn, server_side=True)
    print('tls', n, c.version(), flush=True)
    buf=b''
    while b'\r\n\r\n' not in buf: buf += c.recv(65536)
    head, rest = buf.split(b'\r\n\r\n',1)
    m=re.search(br'Content-Length: (\d+)', head, re.I); clen=int(m.group(1)) if m else 0
    while len(rest)<clen: rest += c.recv(65536)
    body=rest[:clen]
    print('request', n, len(body), body[:80], flush=True)
    payload=json.dumps({'choices':[{'message':{'role':'assistant','content':'model-ok'}}]}).encode()
    c.sendall(b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: '+str(len(payload)).encode()+b'\r\nConnection: close\r\n\r\n'+payload)
    c.close()
