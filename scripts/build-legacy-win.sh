#!/bin/sh
# Build Windows 7-compatible binaries with Rust 1.77.2 (the last toolchain that
# supports Windows 7). The current Rust std requires Windows 10.
set -eu
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VERSION="$(sed -n 's/^version = "\(.*\)"/\1/p' "$ROOT/Cargo.toml" | head -1)"
mkdir -p "$ROOT/dist"

rustup toolchain install 1.77.2 --profile minimal \
  --target x86_64-pc-windows-gnu,i686-pc-windows-gnu || true

for t in x86_64-pc-windows-gnu i686-pc-windows-gnu; do
  echo "==> $t (legacy)"
  cargo +1.77.2 build --release --target "$t" --manifest-path "$ROOT/Cargo.toml"
  cp "$ROOT/target/$t/release/emerag.exe" "$ROOT/dist/emerag-$VERSION-legacy-$t.exe"
done

echo
echo "Legacy artifacts:"
ls -l "$ROOT/dist"/*legacy* 2>/dev/null || true
echo
echo "Check imports with: ./scripts/compat-report.sh dist/*legacy*"
