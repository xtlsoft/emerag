#!/bin/sh
# Build a single-file offline emerag release: the emerag binary with a
# llama-server binary, a GGUF model and optional sidecar files appended.
#
# Usage:
#   ./scripts/make-offline.sh --server ./llama-server --model model.gguf \
#       --out dist/emerag-offline-x86_64 [--binary target/x86_64-unknown-linux-musl/release/emerag]
#
# The result is a normal executable. Appending data is safe for ELF/PE/Mach-O;
# sign the bundled file afterwards. See docs/LOCAL-MODELS.md.
set -eu

SERVER=""
MODEL=""
OUT=""
BINARY=""
EXTRAS=""

while [ $# -gt 0 ]; do
  case "$1" in
    --server) SERVER="$2"; shift 2 ;;
    --model) MODEL="$2"; shift 2 ;;
    --out) OUT="$2"; shift 2 ;;
    --binary) BINARY="$2"; shift 2 ;;
    --extra) EXTRAS="$EXTRAS $2"; shift 2 ;;
    -h|--help) sed -n '2,12p' "$0"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

[ -n "$SERVER" ] && [ -f "$SERVER" ] || { echo "--server must point to a llama-server binary" >&2; exit 2; }
[ -n "$MODEL" ] && [ -f "$MODEL" ] || { echo "--model must point to a .gguf file" >&2; exit 2; }
[ -n "$OUT" ] || { echo "--out is required" >&2; exit 2; }

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
if [ -z "$BINARY" ]; then
  for cand in "$ROOT/target/x86_64-unknown-linux-musl/release/emerag" "$ROOT/target/release/emerag"; do
    [ -f "$cand" ] && BINARY="$cand" && break
  done
fi
[ -n "$BINARY" ] && [ -f "$BINARY" ] || { echo "no emerag binary; build first" >&2; exit 2; }

mkdir -p "$(dirname "$OUT")"
cp "$BINARY" "$OUT"
chmod +x "$OUT"

python3 - "$OUT" "$SERVER" "$MODEL" $EXTRAS <<'PYEOF'
import hashlib, os, struct, sys

out, server, model, *extras = sys.argv[1:]

def read(p):
    with open(p, "rb") as f:
        return f.read()

entries = []
entries.append(("llama-server", 0o755, read(server)))
entries.append((os.path.basename(model), 0o644, read(model)))
for extra in extras:
    entries.append((os.path.basename(extra), 0o644, read(extra)))

payload = bytearray()
payload += b"EMERAGBD"
payload += struct.pack("<I", 1)
payload += struct.pack("<I", len(entries))
for name, mode, data in entries:
    nb = name.encode()
    payload += struct.pack("<H", len(nb)) + nb
    payload += struct.pack("<I", mode)
    payload += struct.pack("<Q", len(data)) + data

with open(out, "ab") as f:
    offset = f.tell()
    f.write(payload)
    trailer = b"EMERAGPK" + struct.pack("<QQ", offset, len(payload)) + hashlib.sha256(payload).digest() + b"\0" * 8
    assert len(trailer) == 64
    f.write(trailer)

print(f"bundled {len(entries)} files, payload {len(payload)} bytes -> {out}")
PYEOF

echo "size: $(wc -c < "$OUT") bytes"
echo
echo "Test it with:"
echo "  $OUT local status"
echo "  $OUT local up"
