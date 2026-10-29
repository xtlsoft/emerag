#!/bin/sh
# Build the full-feature lite binary: no embedded CA bundle, no certificate
# verification, size profile, UPX. Everything else is the normal agent.
#
# Usage: ./scripts/build-lite.sh [target ...]
# Default: x86_64 musl, aarch64 musl, armv7 musl.

set -eu

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DIST="$ROOT/dist"
mkdir -p "$DIST"
VERSION="$(sed -n 's/^version = "\(.*\)"/\1/p' "$ROOT/Cargo.toml" | head -1)"
TARGETS="${*:-x86_64-unknown-linux-musl aarch64-unknown-linux-musl armv7-unknown-linux-musleabihf}"

for t in $TARGETS; do
  echo "==> $t"
  cargo build --manifest-path "$ROOT/Cargo.toml" --profile size --features lite \
      --bin emerag --target "$t" 2>&1 | tail -2
  BIN="$ROOT/target/$t/size/emerag"
  if [ ! -f "$BIN" ]; then BIN="$BIN.exe"; fi
  [ -f "$BIN" ] || { echo "    missing $ROOT/target/$t/size/emerag"; continue; }
  OUT="$DIST/emerag-lite-$VERSION-$t"
  case "$t" in *windows*) OUT="$OUT.exe" ;; esac
  cp "$BIN" "$OUT"
  if command -v upx >/dev/null 2>&1; then
    if upx --best --lzma "$OUT" >/dev/null 2>&1; then
      echo "    packed: $(wc -c < "$OUT") bytes"
    else
      echo "    UPX failed; raw: $(wc -c < "$OUT") bytes"
    fi
  else
    echo "    raw: $(wc -c < "$OUT") bytes"
  fi
done

echo
ls -l "$DIST"/emerag-lite-* 2>/dev/null || true
