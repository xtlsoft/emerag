#!/bin/sh
# Assemble the exact set of files GitHub Pages serves from dist/.
# Usage: ./scripts/package-site.sh [dist-dir] [site-dir]
set -eu

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DIST="${1:-$ROOT/dist}"
SITE="${2:-$ROOT/site}"

rm -rf "$SITE"
mkdir -p "$SITE/docs"

cp "$ROOT/www/index.html" "$SITE/index.html"
cp "$ROOT/docs/LEGACY.md" "$SITE/docs/LEGACY.md"
cp "$ROOT/scripts/install.sh" "$SITE/install.sh"
chmod +x "$SITE/install.sh"

for f in "$DIST"/emerag-*; do
    [ -f "$f" ] || continue
    base="${f##*/}"
    case "$base" in
        emerag-full-*) tier=full ;;
        emerag-lite-*) tier=lite ;;
        emerag-nano-*) tier=nano ;;
        *) continue ;;
    esac
    case "$base" in
        *-x86_64-unknown-linux-musl) plat=linux-x86_64 ;;
        *-i686-unknown-linux-musl) plat=linux-i686 ;;
        *-aarch64-unknown-linux-musl) plat=linux-aarch64 ;;
        *-armv7-unknown-linux-musleabihf) plat=linux-armv7 ;;
        *-riscv64gc-unknown-linux-musl) plat=linux-riscv64 ;;
        *-s390x-unknown-linux-gnu) plat=linux-s390x ;;
        *-x86_64-pc-windows-gnu.exe) plat=windows-x86_64.exe ;;
        *-i686-pc-windows-gnu.exe) plat=windows-x86.exe ;;
        *-legacy-windows-x86.exe) plat=legacy-windows-x86.exe ;;
        *-legacy-windows-pentium.exe) plat=legacy-windows-pentium.exe ;;
        *-x86_64-apple-darwin) plat=macos-x86_64 ;;
        *-aarch64-apple-darwin) plat=macos-arm64 ;;
        *-linux-x86_64) plat=linux-x86_64 ;;
        *-linux-aarch64) plat=linux-aarch64 ;;
        *-linux-armv7) plat=linux-armv7 ;;
        *-linux-i686) plat=linux-i686 ;;
        *-linux-riscv64) plat=linux-riscv64 ;;
        *-windows-x86_64.exe) plat=windows-x86_64.exe ;;
        *-windows-x86.exe) plat=windows-x86.exe ;;
        *) continue ;;
    esac
    cp "$f" "$SITE/emerag-$tier-$plat"
done

chmod +x "$SITE"/emerag-* 2>/dev/null || true
(cd "$SITE" && sha256sum emerag-* install.sh > SHA256SUMS)
echo "site: $SITE"
ls -l "$SITE"/emerag-* "$SITE/install.sh" | awk '{print $5, $9}'
