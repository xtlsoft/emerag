#!/bin/sh
# Run smoke tests on foreign-architecture Linux binaries via qemu-user.
set -eu
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
run() {
  qemu="$1"; bin="$2"
  if command -v "$qemu" >/dev/null 2>&1 && [ -f "$bin" ]; then
    echo "==> $qemu $bin"
    "$qemu" "$bin" --version || echo "FAILED"
    "$qemu" "$bin" --doctor --no-write 2>&1 | head -20 || true
  fi
}
run qemu-aarch64 "$ROOT/dist/"*aarch64-unknown-linux-musl
run qemu-arm "$ROOT/dist/"*armv7-unknown-linux-musleabihf
run qemu-riscv64 "$ROOT/dist/"*riscv64gc-unknown-linux-musl
run qemu-s390x "$ROOT/dist/"*s390x-unknown-linux-musl
run qemu-i386 "$ROOT/dist/"*i686-unknown-linux-musl
