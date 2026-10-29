# Nano tests

Crypto vectors:

    make test_crypto

TLS/HTTP mock (needs a certificate):

    openssl req -x509 -newkey rsa:2048 -nodes -keyout /tmp/nano-key.pem         -out /tmp/nano-cert.pem -days 1 -subj /CN=localhost
    python3 tests/shellsrv.py &
    ./emerag-nano --host 127.0.0.1 --port 8445 --path /chat --key x -p hi

shellsrv.py returns a SHELL command on the first request and a final answer
on the second. tlssrv.py is a single request/response server. chunksrv.py
tests chunked HTTP. All three use TLS 1.3 and a self-signed certificate;
nano deliberately does not verify it.

The C client was also tested against api.deepseek.com with an invalid key
(HTTP 401), which proves the TLS handshake and HTTP path without requiring a
real key.
