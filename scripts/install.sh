#!/bin/sh
# emerag one-liner installer and temporary runner.
#
# Install:
#   wget -qO- https://xtlsoft.github.io/emerag/install.sh | sh
#
# Run without installing (uses tmpfs, works on a read-only root):
#   wget -qO- https://xtlsoft.github.io/emerag/install.sh | sh -s -- --run
#   wget -qO- https://xtlsoft.github.io/emerag/install.sh | sh -s -- --run --doctor
#
# Works with busybox sh/ash, curl, wget or busybox wget. Verified with SHA-256
# when a checksum tool is available.

set -eu

BASE="${EMERAG_BASE:-https://xtlsoft.github.io/emerag}"
MODE=install
DIR=""
BUILD=full

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
  --full          full agent, embedded CA bundle (default)
  --lite          almost full agent, no CA bundle, no certificate checks
  --nano          tiny C agent, Chat Completions only, no certificate checks
  --mini          deprecated alias for --lite
  --dir DIR       install directory (default: ~/.local/bin or /usr/local/bin)
  --base URL      download origin (default: https://xtlsoft.github.io/emerag)
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
        --full) BUILD=full; shift ;;
        --lite) BUILD=lite; shift ;;
        --nano) BUILD=nano; shift ;;
        --mini) BUILD=lite; echo "note: --mini is now --lite (no CA bundle, no checks)" >&2; shift ;;
        --dir)
            [ $# -ge 2 ] || die "--dir needs a value"
            DIR="$2"; shift 2 ;;
        --base)
            [ $# -ge 2 ] || die "--base needs a value"
            BASE="$2"; shift 2 ;;
        -h|--help)
            if [ "$MODE" = "run" ]; then break; fi
            usage; exit 0 ;;
        --) shift; break ;;
        -*) if [ "$MODE" = "run" ]; then break; fi; die "unknown option '$1' (try --help)" ;;
        *) break ;;
    esac
done

BASE="${BASE%/}"

case "$(uname -s)" in
    Linux*) OS=linux ;;
    Darwin*) OS=macos ;;
    *) die "unsupported operating system: $(uname -s)" ;;
esac

case "$(uname -m)" in
    x86_64|amd64) ARCH=x86_64 ;;
    aarch64|arm64) ARCH=aarch64 ;;
    armv7l|armv7*|armv8l) ARCH=armv7 ;;
    i386|i486|i586|i686) ARCH=i686 ;;
    riscv64) ARCH=riscv64 ;;
    s390x) ARCH=s390x ;;
    mips|mipsel|mips64|mips64el)
        die "MIPS is not built by this release; use a MIPS C cross-compiler for nano, or an ARM/x86 router" ;;
    armv6l)
        die "ARMv6 is not built; use --lite on ARMv7/ARM64 or build nano from source" ;;
    *) die "unsupported architecture: $(uname -m)" ;;
esac

if [ "$OS" = "macos" ] && [ "$ARCH" != "x86_64" ] && [ "$ARCH" != "aarch64" ]; then
    die "macOS is built for x86_64 and arm64 only"
fi
if [ "$BUILD" = "nano" ]; then
    if [ "$OS" != "linux" ]; then
        die "nano is built for Linux and Windows; use --lite on this platform"
    fi
    case "$ARCH" in
        x86_64|aarch64|armv7|i686|riscv64) ;;
        *) die "nano has no Linux build for $ARCH; use --lite" ;;
    esac
fi

FILE="emerag-$OS-$ARCH"

case "$BUILD" in
    full) FILE="emerag-full-${FILE#emerag-}" ;;
    lite) FILE="emerag-lite-${FILE#emerag-}" ;;
    nano) FILE="emerag-nano-${FILE#emerag-}" ;;
esac

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
    tried=""
    fd9_ok=0
    cand=""

    run_exec() {
        # The script is usually fed through a pipe: stdin is the script, not
        # the terminal. Reattach the interactive program to /dev/tty.
        if [ -r /dev/tty ] && [ ! -t 0 ]; then
            if [ "$fd9_ok" = 1 ] && [ -e /proc/self/fd/9 ]; then
                exec /proc/self/fd/9 "$@" </dev/tty
            fi
            exec "$cand" "$@" </dev/tty
        fi
        if [ "$fd9_ok" = 1 ] && [ -e /proc/self/fd/9 ]; then
            exec /proc/self/fd/9 "$@"
        fi
        exec "$cand" "$@"
    }

    if [ "$#" -eq 0 ] && [ ! -t 0 ] && [ ! -r /dev/tty ]; then
        rm -f "$BIN" "$SUMS"
        trap - EXIT INT TERM
        die "no terminal available for interactive input; use -p PROMPT"
    fi

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
            if exec 9<"$cand"; then
                # Termux and some Android kernels refuse exec of a deleted
                # /proc/self/fd path. Prove it before unlinking the file.
                if /proc/self/fd/9 --version >/dev/null 2>&1; then
                    fd9_ok=1
                fi
            fi
            if [ "$fd9_ok" = 1 ] && [ -e /proc/self/fd/9 ]; then
                rm -f "$cand"
            fi
            run_exec "$@"
        fi
        rm -f "$cand"
    done

    # If every filesystem is noexec, use a memfd through Python when present.
    if command -v python3 >/dev/null 2>&1; then
        if python3 - "$BIN" "$@" <<'PY'
import os, sys
path = sys.argv[1]
args = sys.argv[2:]
try:
    if not os.isatty(0) and os.path.exists("/dev/tty"):
        tty = os.open("/dev/tty", os.O_RDONLY)
        os.dup2(tty, 0)
except OSError:
    pass
with open(path, "rb") as f:
    data = f.read()
os.unlink(path)
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
    die "no exec-capable writable filesystem found (tried:$tried; arch $(uname -m)); set TMPDIR to an exec-capable directory or install with --dir"
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
