#!/bin/sh
# Build emerag-nano. Linux uses musl-static when musl-gcc exists; Windows
# cross-builds use MinGW for verification. VC6 uses build-vc6.bat.
set -eu
ROOT="$(cd "$(dirname "$0")" && pwd)"
DIST="$ROOT/../dist"
mkdir -p "$DIST"

cd "$ROOT"
if command -v musl-gcc >/dev/null 2>&1; then
    musl-gcc -std=gnu89 -Os -static -Wall -Wextra \
        -o "$DIST/emerag-nano-linux-x86_64" \
        common.c crypto.c tls.c emerag.c
else
    cc -std=gnu89 -Os -static -Wall -Wextra \
        -o "$DIST/emerag-nano-linux-x86_64" \
        common.c crypto.c tls.c emerag.c
fi
echo "linux: $(wc -c < "$DIST/emerag-nano-linux-x86_64") bytes"

if command -v i686-w64-mingw32-gcc >/dev/null 2>&1; then
    i686-w64-mingw32-gcc -std=gnu89 -Os -Wall -Wextra \
        -o "$DIST/emerag-nano-windows-x86.exe" \
        common.c crypto.c tls.c emerag.c -lws2_32 -ladvapi32
    echo "win32: $(wc -c < "$DIST/emerag-nano-windows-x86.exe") bytes"
fi
if command -v x86_64-w64-mingw32-gcc >/dev/null 2>&1; then
    x86_64-w64-mingw32-gcc -std=gnu89 -Os -Wall -Wextra \
        -o "$DIST/emerag-nano-windows-x86_64.exe" \
        common.c crypto.c tls.c emerag.c -lws2_32 -ladvapi32
    echo "win64: $(wc -c < "$DIST/emerag-nano-windows-x86_64.exe") bytes"
fi

if command -v upx >/dev/null 2>&1; then
    for f in "$DIST"/emerag-nano-*; do
        upx --best --lzma "$f" >/dev/null 2>&1 || true
    done
fi
ls -l "$DIST"/emerag-nano-* 2>/dev/null || true
