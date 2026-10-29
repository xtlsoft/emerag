import socket, ssl, json, re
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain('/tmp/nano-cert.pem','/tmp/nano-key.pem')
ctx.minimum_version = ssl.TLSVersion.TLSv1_3
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('127.0.0.1',8445)); s.listen(1)
print('listening', flush=True)
conn, addr = s.accept()
c = ctx.wrap_socket(conn, server_side=True)
print('tls', c.version(), flush=True)
buf = b''
count = 0
while count < 2:
    while b'\r\n\r\n' not in buf:
        chunk = c.recv(65536)
        if not chunk: raise SystemExit('eof')
        buf += chunk
    head, rest = buf.split(b'\r\n\r\n', 1)
    m = re.search(br'Content-Length: (\d+)', head, re.I)
    clen = int(m.group(1)) if m else 0
    while len(rest) < clen:
        rest += c.recv(65536)
    body, buf = rest[:clen], rest[clen:]
    count += 1
    print('request', count, len(body), body[:120], flush=True)
    text = 'SHELL: echo nano-shell-ok' if count == 1 else 'done'
    payload = json.dumps({'choices':[{'message':{'role':'assistant','content':text}}]}).encode()
    resp = b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: '+str(len(payload)).encode()+b'\r\nConnection: keep-alive\r\n\r\n'+payload
    c.sendall(resp)
c.close()
