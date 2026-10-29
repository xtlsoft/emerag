#!/bin/sh
# Build the ROM-constrained "mini" variant.
#
# Differences from the normal build:
#   * curated 17-CA trust bundle instead of the full Mozilla bundle
#   * profile "size" (opt-level=z, fat LTO, one codegen unit, strip)
#   * optional UPX packing (about 36% of the raw size)
#
# Usage: ./scripts/build-mini.sh [target ...]
# Default targets: x86_64 musl, aarch64 musl, armv7 musl.

set -eu

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DIST="$ROOT/dist"
mkdir -p "$DIST"
VERSION="$(sed -n 's/^version = "\(.*\)"/\1/p' "$ROOT/Cargo.toml" | head -1)"
TARGETS="${*:-x86_64-unknown-linux-musl aarch64-unknown-linux-musl armv7-unknown-linux-musleabihf}"

for t in $TARGETS; do
  echo "==> $t"
  cargo build --manifest-path "$ROOT/Cargo.toml" --profile size --features mini --target "$t" 2>&1 | tail -2
  BIN="$ROOT/target/$t/size/emerag"
  [ -f "$BIN" ] || { echo "    missing $BIN"; continue; }
  OUT="$DIST/emerag-mini-$VERSION-$t"
  cp "$BIN" "$OUT"
  if command -v upx >/dev/null 2>&1; then
    if upx --best --lzma "$OUT" >/dev/null 2>&1; then
      echo "    packed: $(wc -c < "$OUT") bytes"
    else
      echo "    UPX failed; kept raw: $(wc -c < "$OUT") bytes"
    fi
  else
    echo "    upx not installed; raw: $(wc -c < "$OUT") bytes"
  fi
done

echo
ls -l "$DIST"/emerag-mini-* 2>/dev/null || true
