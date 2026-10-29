# Compatibility matrix

Every claim below was measured on the artifacts produced by
`scripts/build-cross.sh` and `scripts/compat-report.sh`. "Tested" means the
binary was executed (natively or under qemu-user) and answered `--version`,
`--keys` and `--doctor`.

## Linux (static, musl)

| target | size | link | tested | notes |
| --- | --- | --- | --- | --- |
| x86_64-unknown-linux-musl | 1.70 MiB | static-pie, 0 DT_NEEDED, 0 GLIBC refs | native | reference build |
| i686-unknown-linux-musl | 1.55 MiB | static-pie | qemu-i386 | 32-bit x86 |
| aarch64-unknown-linux-musl | 1.44 MiB | static-pie | qemu-aarch64 | |
| armv7-unknown-linux-musleabihf | 1.40 MiB | static-pie | qemu-arm | hard-float ABI |
| riscv64gc-unknown-linux-musl | 1.40 MiB | static-pie | qemu-riscv64 | |
| s390x-unknown-linux-gnu | 1.70 MiB | dynamic (glibc) | not executed | no upstream musl target |
| loongarch64-unknown-linux-musl | - | static-pie | not built | needs a loongarch linker |

Verification commands:

    file target/x86_64-unknown-linux-musl/release/emerag
    # ELF 64-bit LSB pie executable, static-pie linked, stripped
    readelf -d ...   # no NEEDED
    readelf -l ...   # no INTERP
    objdump -T ...   # no GLIBC_ symbols

### Kernel floor

The static musl builds target **Linux 2.6.39 or newer**. This is the floor of
the musl libc we link (1.2.x), not a guess:

- threads use `clone` + futex (2.6.0),
- timers use `clock_gettime` (2.6.12) with a vDSO fallback,
- randomness uses `getrandom` when available (3.17) and `/dev/urandom`
  otherwise,
- networking uses ordinary BSD sockets,
- no epoll, no io_uring, no pidfd, no statx-dependent paths.

Kernels older than 2.6.39 are untested. If you need 2.4, that is a different
libc and is out of scope.

The binary is static-pie; on kernels that predate static-pie support in the
toolchain's crt, convert with `-C relocation-model=static` at build time.
Nothing in the code requires PIE.

## Windows

The x86_64 binary was smoke-tested under Wine 9.0 (--version, --keys,
--doctor): it starts, detects cmd/PowerShell, and resolves Windows config
paths. It has not been executed on a real Windows installation.

| target | size | imports | minimum OS |
| --- | --- | --- | --- |
| x86_64-pc-windows-gnu | 1.44 MiB | KERNEL32, msvcrt, ntdll, WS2_32, api-ms-win-core-synch-l1-2-0 | Windows 8 (see below) |
| i686-pc-windows-gnu | 1.40 MiB | same | Windows 8 |
| legacy 1.77 x64/x86 | ~1.4 MiB | see legacy section | Windows 7 |

Current Rust (1.78+) only supports Windows 10 and newer as a platform, and
the standard library imports four APIs that do not exist on older systems:

    GetFileInformationByHandleEx   Vista
    SetFileInformationByHandle     Vista
    GetSystemTimePreciseAsFileTime Windows 8
    WaitOnAddress / WakeByAddressSingle  Windows 8

Those come from `std::fs`, `std::time` and the thread parking used by
`std::sync::mpsc`; they appear in the import table even when the corresponding
feature is barely used. Practical minimum for the current build is therefore
**Windows 8/10**, which matches Rust's own support statement.

### Windows 7

A legacy build with Rust 1.77.2 (the last toolchain supporting Windows 7)
removes the Windows 8 imports. Run:

    ./scripts/build-legacy-win.sh

and use the resulting `dist/emerag-legacy-*.exe`. Windows 7 SP1 with the UCRT
update is the realistic floor.

### Windows 2000 and XP

The Rust standard library requires Windows 7; it uses Vista+ APIs for basic
file metadata and synchronization. Supporting Windows 2000/XP would require a
no_std port with hand-written kernel32/winsock bindings, a custom allocator,
and a replacement for threads and time. That is a separate project, not a
build flag. emerag does not claim Windows 2000 support; `--doctor` on such a
system will fail to start the binary at all with a missing-import error.

What *is* provided for old Windows:

- a 32-bit build that runs on 32-bit Windows 7+,
- a static link (no Visual C++ redistributable, only msvcrt.dll which ships
  with the OS),
- `scripts/compat-report.sh` so you can see exactly which import blocks a
  given Windows version before deploying,
- console fallbacks that do not require ANSI/VT support (legacy conhost).

## macOS

Not built in this environment (needs an Apple SDK). The code has no
platform-specific dependency beyond termios/console APIs already implemented
for macOS:

    rustup target add aarch64-apple-darwin x86_64-apple-darwin
    cargo build --release --target aarch64-apple-darwin

The CI workflow builds both targets on macOS runners. Appending an offline
payload invalidates code signatures; sign after bundling (see LOCAL-MODELS.md).

## Architectures not shipped here

- **loongarch64**: `loongarch64-unknown-linux-musl` is a valid Rust target, but
  Ubuntu does not ship a loongarch linker. On a loongarch host:
  `rustup target add loongarch64-unknown-linux-musl && cargo build --release`.
- **s390x**: no musl std is published, so the build uses glibc. It is still a
  single binary, but it needs the system libc. A musl s390x build would need
  `-Z build-std` with a custom target and musl's s390x support.
- **aarch64 Windows**: `aarch64-pc-windows-gnullvm` is buildable with clang/lld;
  not part of the tested matrix.

## Byte order and word size

s390x is big-endian, and i686/armv7 are 32-bit. All binary formats (TLS,
X.509 DER, GGUF) are parsed explicitly little/big-endian as required by their
specifications; no `transmute` of multi-byte integers is used. This is
exercised by the s390x build compiling, and by endian-explicit parsers in the
test suite.
