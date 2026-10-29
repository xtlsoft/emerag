#!/bin/sh
# Build the Rust full/lite agents for legacy Windows (98/ME/NT4/2000/XP).
#
# Requires the third-party rust9x toolchain:
#   rustup toolchain link rust9x /path/to/rust9x
# and an MSVC-compatible linker (see docs/LEGACY.md).
#
# Targets:
#   i586-rust9x-windows-msvc  - 486/Pentium, Windows 95/98/ME/NT4/2000/XP
#   i686-rust9x-windows-msvc  - Pentium 4 / SSE2, Windows 2000/XP
#
# Usage: ./scripts/build-legacy.sh [target ...]
set -eu

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DIST="$ROOT/dist"
mkdir -p "$DIST"
VERSION="$(sed -n 's/^version = "\(.*\)"/\1/p' "$ROOT/Cargo.toml" | head -1)"
if [ "$#" -eq 0 ]; then
    TARGETS="i586-rust9x-windows-msvc i686-rust9x-windows-msvc"
else
    TARGETS="$*"
fi

if ! cargo +rust9x --version >/dev/null 2>&1; then
    echo "rust9x toolchain not found." >&2
    echo "Install the precompiled toolchain from the rust9x releases page and run:" >&2
    echo "  rustup toolchain link rust9x /path/to/extracted/rust9x" >&2
    exit 2
fi

for t in $TARGETS; do
    for mode in full lite; do
        echo "==> $mode / $t"
        if [ "$mode" = "lite" ]; then
            FEATURES="--features lite"
        else
            FEATURES=""
        fi
        cargo +rust9x build --manifest-path "$ROOT/Cargo.toml" --profile size \
            $FEATURES --bin emerag --target "$t" 2>&1 | tail -3
        BIN="$ROOT/target/$t/size/emerag.exe"
        [ -f "$BIN" ] || { echo "    missing $BIN"; continue; }
        OUT="$DIST/emerag-$mode-legacy-$VERSION-$t.exe"
        cp "$BIN" "$OUT"
        echo "    $(wc -c < "$OUT") bytes"
    done
done

echo
ls -l "$DIST"/*legacy*.exe 2>/dev/null || true
