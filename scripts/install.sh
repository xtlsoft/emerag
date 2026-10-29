#!/bin/sh
# emerag one-liner installer and temporary runner.
#
# Install:
#   wget -qO- http://10.20.2.226:8899/install.sh | sh
#
# Run without installing (uses tmpfs, works on a read-only root):
#   wget -qO- http://10.20.2.226:8899/install.sh | sh -s -- --run
#   wget -qO- http://10.20.2.226:8899/install.sh | sh -s -- --run --doctor
#
# Works with busybox sh/ash, curl, wget or busybox wget. Verified with SHA-256
# when a checksum tool is available.

set -eu

BASE="${EMERAG_BASE:-http://10.20.2.226:8899}"
MODE=install
DIR=""
MINI=0

die() {
    echo "emerag installer: $*" >&2
    exit 1
}

usage() {
    cat <<'EOF'
emerag installer

Usage:
  install.sh [--install] [--dir DIR] [--base URL]
  install.sh --run [emerag arguments...] [--base URL before --run]

Options:
  --install       install to a writable bin directory (default)
  --run           download to a temp filesystem and execute immediately
  --mini          smaller build (curated CA bundle, UPX packed)
  --dir DIR       install directory (default: ~/.local/bin or /usr/local/bin)
  --base URL      download origin (default: http://10.20.2.226:8899)
  -h, --help      this text

Environment:
  EMERAG_BASE     same as --base
  EMERAG_NO_VERIFY=1  skip SHA-256 verification (not recommended)
  TMPDIR          preferred temporary directory for --run
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --run) MODE=run; shift ;;
        --install) MODE=install; shift ;;
        --mini) MINI=1; shift ;;
        --dir)
            [ $# -ge 2 ] || die "--dir needs a value"
            DIR="$2"; shift 2 ;;
        --base)
            [ $# -ge 2 ] || die "--base needs a value"
            BASE="$2"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        --) shift; break ;;
        -*) if [ "$MODE" = "run" ]; then break; fi; die "unknown option '$1' (try --help)" ;;
        *) break ;;
    esac
done

BASE="${BASE%/}"

case "$(uname -m)" in
    x86_64|amd64) FILE=emerag-linux-x86_64 ;;
    aarch64|arm64) FILE=emerag-linux-aarch64 ;;
    armv7l|armv7*|armv8l) FILE=emerag-linux-armv7 ;;
    i386|i486|i586|i686) FILE=emerag-linux-i686 ;;
    riscv64) FILE=emerag-linux-riscv64 ;;
    s390x) FILE=emerag-linux-s390x ;;
    *) die "unsupported architecture: $(uname -m)" ;;
esac

if [ "$MINI" = "1" ]; then
    FILE="emerag-mini-${FILE#emerag-}"
fi

fetch() {
    url="$1"
    out="$2"
    if command -v curl >/dev/null 2>&1; then
        if curl -fsSL --connect-timeout 15 -o "$out" "$url"; then return 0; fi
    fi
    if command -v wget >/dev/null 2>&1; then
        if wget -q -O "$out" "$url"; then return 0; fi
    fi
    if command -v busybox >/dev/null 2>&1; then
        if busybox wget -q -O "$out" "$url"; then return 0; fi
    fi
    return 1
}

sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    elif command -v openssl >/dev/null 2>&1; then
        openssl dgst -sha256 "$1" | awk '{print $NF}'
    elif command -v busybox >/dev/null 2>&1; then
        busybox sha256sum "$1" | awk '{print $1}'
    else
        echo ""
    fi
}

choose_tmp() {
    for d in "${TMPDIR:-/tmp}" /tmp /dev/shm "${HOME:-/nonexistent}/.cache" "${HOME:-/nonexistent}"; do
        if [ -d "$d" ] && [ -w "$d" ]; then
            echo "$d"
            return 0
        fi
    done
    return 1
}

tmpdir=$(choose_tmp) || die "no writable temporary directory (set TMPDIR)"
BIN="$tmpdir/emerag.$$"
SUMS="$tmpdir/emerag-sums.$$"
cleanup() {
    rm -f "$BIN" "$SUMS"
}
trap cleanup EXIT INT TERM

echo "downloading $FILE for $(uname -m) ..."
fetch "$BASE/$FILE" "$BIN" || die "download failed: $BASE/$FILE (try --base, or curl/wget/busybox wget)"

if [ "${EMERAG_NO_VERIFY:-0}" != "1" ]; then
    if fetch "$BASE/SHA256SUMS" "$SUMS"; then
        expected=$(awk -v f="$FILE" '$2==f {print $1; exit}' "$SUMS")
        if [ -n "$expected" ]; then
            actual=$(sha256_of "$BIN")
            if [ -z "$actual" ]; then
                die "no sha256sum/openssl/busybox available to verify the download"
            fi
            [ "$actual" = "$expected" ] || die "SHA-256 mismatch for $FILE"
            echo "sha256 ok"
        else
            echo "warning: no checksum entry for $FILE" >&2
        fi
    else
        die "cannot download SHA256SUMS (set EMERAG_NO_VERIFY=1 to override)"
    fi
fi

chmod +x "$BIN" 2>/dev/null || true

if [ "$MODE" = "run" ]; then
    # A read-only root is fine as long as some writable filesystem allows
    # execution (/tmp and /dev/shm usually do). Try the requested TMPDIR first,
    # then common tmpfs locations.
    ran=0
    tried=""
    for d in "$tmpdir" /dev/shm /run "$tmpdir/.." "${HOME:-/nonexistent}/.cache" "${HOME:-/nonexistent}" .; do
        [ -d "$d" ] && [ -w "$d" ] || continue
        case ":$tried:" in *":$d:"*) continue ;; esac
        tried="$tried:$d"
        cand="$d/emerag-run.$$"
        cp "$BIN" "$cand" 2>/dev/null || continue
        chmod +x "$cand" 2>/dev/null || true
        if "$cand" --version >/dev/null 2>&1; then
            rm -f "$BIN" "$SUMS"
            trap - EXIT INT TERM
            # Open, unlink and exec through the fd so no temporary file is
            # left behind and the running image is already anonymous.
            exec 9<"$cand" || exec "$cand" "$@"
            rm -f "$cand"
            exec /proc/self/fd/9 "$@"
        fi
        rm -f "$cand"
    done

    # If every filesystem is noexec, use a memfd through Python when present.
    if command -v python3 >/dev/null 2>&1; then
        if python3 - "$BIN" "$@" <<'PY'
import os, sys
path = sys.argv[1]
args = sys.argv[2:]
with open(path, "rb") as f:
    data = f.read()
fd = os.memfd_create("emerag", 0)
os.write(fd, data)
os.fchmod(fd, 0o755)
exe = "/proc/self/fd/%d" % fd
os.execve(exe, [exe] + args, os.environ)
PY
        then
            :
        fi
    fi
    rm -f "$BIN" "$SUMS"
    trap - EXIT INT TERM
    die "no exec-capable writable filesystem found (try --dir with a writable partition, or set TMPDIR=/dev/shm)"
fi

if [ -z "$DIR" ]; then
    if mkdir -p "${HOME:-/nonexistent}/.local/bin" 2>/dev/null && [ -w "${HOME:-/nonexistent}/.local/bin" ]; then
        DIR="${HOME}/.local/bin"
    elif mkdir -p /usr/local/bin 2>/dev/null && [ -w /usr/local/bin ]; then
        DIR=/usr/local/bin
    else
        DIR="${HOME:-/tmp}"
    fi
fi
mkdir -p "$DIR" || die "cannot create $DIR"
cp "$BIN" "$DIR/emerag" || die "cannot write $DIR/emerag (use --run for a read-only system)"
chmod +x "$DIR/emerag" 2>/dev/null || true
echo "installed: $DIR/emerag"
case ":${PATH:-}:" in
    *":$DIR:"*) ;;
    *) echo "note: $DIR is not in PATH; run $DIR/emerag or add it" ;;
esac
