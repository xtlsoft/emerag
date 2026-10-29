#!/bin/sh
# Build emerag for every target that is installed locally.
# Usage: ./scripts/build-cross.sh [release|size]
set -eu

PROFILE="${1:-release}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DIST="$ROOT/dist"
mkdir -p "$DIST"

TARGETS="
x86_64-unknown-linux-musl
aarch64-unknown-linux-musl
i686-unknown-linux-musl
armv7-unknown-linux-musleabihf
riscv64gc-unknown-linux-musl
s390x-unknown-linux-gnu
loongarch64-unknown-linux-musl
x86_64-pc-windows-gnu
i686-pc-windows-gnu
aarch64-pc-windows-gnullvm
x86_64-apple-darwin
aarch64-apple-darwin
"

INSTALLED="$(rustup target list --installed 2>/dev/null || true)"
VERSION="$(sed -n 's/^version = "\(.*\)"/\1/p' "$ROOT/Cargo.toml" | head -1)"

for t in $TARGETS; do
  case "$INSTALLED" in
    *"$t"*) ;;
    *) echo "skip $t (not installed: rustup target add $t)"; continue ;;
  esac
  case "$t" in
    loongarch64-*) command -v loongarch64-linux-gnu-gcc >/dev/null 2>&1 || {
      echo "skip $t (no loongarch64-linux-gnu-gcc linker)"; continue; } ;;
  esac
  echo "==> $t"
  if cargo build --manifest-path "$ROOT/Cargo.toml" --profile "$PROFILE" --target "$t" 2>&1 | tail -3; then
    BIN="$ROOT/target/$t/$PROFILE/emerag"
    [ -f "$BIN" ] || BIN="$BIN.exe"
    if [ -f "$BIN" ]; then
      cp "$BIN" "$DIST/emerag-full-$VERSION-$t$(printf '%s' "$BIN" | grep -q '\.exe$' && echo .exe || true)"
      echo "    $(wc -c < "$BIN") bytes"
    fi
  else
    echo "    FAILED $t (continuing)"
  fi
done

echo
echo "Artifacts in $DIST:"
ls -l "$DIST" 2>/dev/null || true
