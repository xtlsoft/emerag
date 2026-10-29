#!/bin/sh
# End-to-end tests for emerag using the mock providers in tests/.
# Requires: bash, python3, openssl, curl. No network, no API keys.
set -eu
cd "$(dirname "$0")/.."
BIN="${BIN:-./target/debug/emerag}"
PASS=0
FAIL=0
PIDS=""

cleanup() {
  for p in $PIDS; do kill "$p" 2>/dev/null || true; done
}
trap cleanup EXIT

start() { # start <script> <port> [args...]
  script="$1"; port="$2"; shift 2
  python3 "$script" "$port" "$@" >/tmp/emerag-e2e-"$port".log 2>&1 &
  PIDS="$PIDS $!"
  i=0
  while [ $i -lt 50 ]; do
    if python3 -c "import socket,sys; s=socket.socket(); s.settimeout(0.2); sys.exit(0 if s.connect_ex(('127.0.0.1',$port))==0 else 1)"; then return 0; fi
    sleep 0.1; i=$((i+1))
  done
  echo "server $script on $port did not start"; cat /tmp/emerag-e2e-"$port".log; exit 1
}

check() { # check <name> <haystack-file> <needle>
  if grep -q "$3" "$2"; then PASS=$((PASS+1)); echo "ok   $1";
  else FAIL=$((FAIL+1)); echo "FAIL $1 (wanted: $3)"; sed -n '1,40p' "$2"; fi
}

printf 'hello from the fixture\n' > tests/data/hello.txt 2>/dev/null || { mkdir -p tests/data; printf 'hello from the fixture\n' > tests/data/hello.txt; }

echo "== chat completions =="
start tests/mock_provider.py 18201
"$BIN" --base-url http://127.0.0.1:18201/v1 --api chat --model mock-model \
  --mode auto --no-write -p "read tests/data/hello.txt" > /tmp/e2e-chat.out 2>&1
check "chat stream + tool call" /tmp/e2e-chat.out "The file says"

echo "== anthropic messages =="
start tests/mock_anthropic.py 18202
"$BIN" --base-url http://127.0.0.1:18202 --api anthropic --model claude-mock \
  --mode auto --no-write -p "hi" > /tmp/e2e-anth.out 2>&1
check "anthropic stream" /tmp/e2e-anth.out "Anthropic mock replies"

echo "== responses =="
start tests/mock_responses.py 18203
"$BIN" --base-url http://127.0.0.1:18203/v1 --api responses --model resp-mock \
  --mode auto --no-write -p "hi" > /tmp/e2e-resp.out 2>&1
check "responses stream" /tmp/e2e-resp.out "Responses mock writes back"

echo "== models discovery =="
"$BIN" --base-url http://127.0.0.1:18201/v1 --api chat --model x --models --no-write > /tmp/e2e-models.out 2>&1
check "model list" /tmp/e2e-models.out "mock-model"

echo "== https with custom CA =="
TMP="$(mktemp -d)"
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$TMP/ca.key" -out "$TMP/ca.pem" -days 2 -subj "/CN=emerag-test-ca" >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes -keyout "$TMP/srv.key" -out "$TMP/srv.csr" -subj "/CN=localhost" >/dev/null 2>&1
printf 'subjectAltName=DNS:localhost,IP:127.0.0.1\n' > "$TMP/ext.cnf"
openssl x509 -req -in "$TMP/srv.csr" -CA "$TMP/ca.pem" -CAkey "$TMP/ca.key" -CAcreateserial -out "$TMP/srv.pem" -days 2 -extfile "$TMP/ext.cnf" >/dev/null 2>&1
start tests/mock_https.py 18204 "$TMP/srv.pem" "$TMP/srv.key"
"$BIN" --base-url https://localhost:18204/v1 --api chat --model mock-model \
  --cacert "$TMP/ca.pem" --mode auto --no-write -p "read tests/data/hello.txt" > /tmp/e2e-https.out 2>&1
check "https + CA validation" /tmp/e2e-https.out "The file says"
set +e
"$BIN" --base-url https://localhost:18204/v1 --api chat --model mock-model \
  --mode auto --no-write -p "hi" > /tmp/e2e-https-bad.out 2>&1
set -e
check "untrusted CA rejected" /tmp/e2e-https-bad.out "no trusted root"

echo "== json output =="
"$BIN" --base-url http://127.0.0.1:18201/v1 --api chat --model mock-model \
  --mode auto --no-write --json -p "read tests/data/hello.txt" > /tmp/e2e-json.out 2>&1
check "json content field" /tmp/e2e-json.out '"content"'

echo "== doctor =="
"$BIN" --doctor --no-write > /tmp/e2e-doctor.out 2>&1
check "doctor runs" /tmp/e2e-doctor.out "emerag"

rm -rf "$TMP"
echo
echo "passed: $PASS  failed: $FAIL"
[ "$FAIL" -eq 0 ]
