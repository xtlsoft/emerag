# Legacy Windows: 98, ME, NT 4.0, 2000, XP

There are two independent legacy paths.

## 1. Nano (C, native)

emerag-nano is a small C program built with Visual C++ 6.0. It uses WinSock 2,
TLS 1.3 with one cipher suite, and plain Chat Completions. It does not verify
certificates and has no CA store.

    cd nano
    build-vc6.bat

The result is a 32-bit PE executable for Windows 98/ME/NT4/2000/XP. It does
not need a runtime, a package manager, or a modern CPU. Windows 95 needs the
WinSock 2 update.

## 2. Lite and Full (Rust, rust9x)

The Rust agents can be built for legacy Windows using the third-party
rust9x toolchain (github.com/rust9x/rust). It ports the Rust standard library
to Windows 95, 98, ME, NT 3.51+, 2000 and XP.

    rustup toolchain link rust9x /path/to/rust9x
    ./scripts/build-legacy.sh

Targets:

| target | CPU | systems |
|---|---|---|
| i586-rust9x-windows-msvc | 486/Pentium | 95/98/ME/NT4/2000/XP |
| i686-rust9x-windows-msvc | Pentium 4 / SSE2 | 2000/XP |

The script builds both:

- emerag-full-legacy-...exe - embedded full CA bundle, certificate
  verification enabled.
- emerag-lite-legacy-...exe - no embedded CA bundle, certificate verification
  disabled, otherwise almost the full agent.

### Limitations

- The rust9x toolchain is third-party and beta-quality. GitHub Actions builds
  i586/i686 full and lite artifacts with rust-lld and the MSVC SDK import
  libraries from `xwin`; see `.github/workflows/build.yml`. They have not
  been runtime-tested on 98/2000 hardware here.
- Windows 95/98/ME have no system CSPRNG. The Rust port falls back to a mixed
  clock/process source and prints a warning. Windows 2000+ uses RtlGenRandom
  and does not take this path.
- The full build verifies certificates, but the lite build does not. On a
  legacy machine without a correct clock, even full verification may fail.
- A Rust9x build needs an MSVC-compatible linker and Windows import libraries.
  The CI recipe downloads the rust9x 1.99.1 toolchain and uses `rust-lld` plus
  `xwin` MSVC CRT/SDK import libraries. `-Zunicows=no` is used, so Windows
  2000/XP is the tested target class; Windows 9x may need MSLU.

The native C nano build is the recommended path for a genuinely old machine:
it has no Rust runtime, no TLS library, and no CA bundle at all.
