import socket, ssl, json
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain('/tmp/nano-cert.pem','/tmp/nano-key.pem')
ctx.minimum_version = ssl.TLSVersion.TLSv1_3
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); s.bind(('127.0.0.1',8446)); s.listen(1)
c=ctx.wrap_socket(s.accept()[0],server_side=True)
buf=b''
while b'\r\n\r\n' not in buf: buf+=c.recv(65536)
body=json.dumps({'choices':[{'message':{'role':'assistant','content':'chunk-ok'}}]}).encode()
resp=b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n'+format(len(body),'x').encode()+b'\r\n'+body+b'\r\n0\r\n\r\n'
c.sendall(resp); c.close()
