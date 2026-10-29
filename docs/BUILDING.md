# Building emerag

## Requirements

- Rust stable 1.74 or newer (1.90 tested).
- That is it for the host build. There are no third-party crates, no C
  compiler, and no network access needed after the toolchain is installed.

    cargo build --release
    ./target/release/emerag --version

Release profile: `opt-level = z`, fat LTO, `panic = abort`, symbols stripped,
single codegen unit. The binary is a few MiB including TLS, the LLM adapters,
the script engine and an embedded root CA bundle.

## ROM-constrained (mini) builds

    ./scripts/build-mini.sh x86_64-unknown-linux-musl \
        aarch64-unknown-linux-musl armv7-unknown-linux-musleabihf

The mini variant:

- enables the `mini` cargo feature, which selects a curated 17-CA trust bundle
  (`assets/roots-mini.pem`) instead of the full 118-cert Mozilla bundle;
- builds with the `size` profile (opt-level=z, fat LTO, one codegen unit,
  panic=abort, strip);
- runs `upx --best --lzma` when UPX is installed.

Measured packed sizes: x86_64 0.61 MiB, aarch64 0.54 MiB, armv7 0.54 MiB.
Unpacked is about 1.7 MiB. Use `--cacert` for a CA outside the curated set.

A binary with TLS, HTTP, JSON, the provider adapters and the tool loop cannot
fit in a few kilobytes. When ROM is nearly full, do not install it: the
installer's `--run --mini` downloads into /dev/shm or another writable tmpfs
and executes it there, so only RAM is consumed.

Other size levers (not used for the shipped artifacts): nightly `build-std`
with `panic_immediate_abort`, `-Z location-detail=none`, and dropping the
script/MCP features at compile time. Each trades capability or toolchain
stability for a few tens of kilobytes.

## Static Linux builds (musl)

    rustup target add x86_64-unknown-linux-musl aarch64-unknown-linux-musl
    cargo build --release --target x86_64-unknown-linux-musl

The result has no interpreter and no shared library dependencies:

    file target/x86_64-unknown-linux-musl/release/emerag
    # ELF 64-bit LSB executable, statically linked, stripped
    readelf -d target/x86_64-unknown-linux-musl/release/emerag
    # no NEEDED entries

Cross-compiling the other architectures only needs the Rust target plus a
linker. For aarch64/armv7/riscv64/s390x/loong64, install `gcc-<target>` or use
`clang -target` with `-C linker=`.

    rustup target add aarch64-unknown-linux-musl armv7-unknown-linux-musleabihf
    cargo build --release --target aarch64-unknown-linux-musl

Test foreign binaries with qemu-user:

    ./scripts/smoke-qemu.sh

## Windows

Tier 1 is `x86_64-pc-windows-gnu` and `i686-pc-windows-gnu` (static mingw,
msvcrt only). Install `mingw-w64` and the Rust target, then:

    cargo build --release --target x86_64-pc-windows-gnu

Windows ARM64 can be attempted with `aarch64-pc-windows-gnullvm` (clang + lld)
but is not part of the supported matrix yet.

Windows 2000/XP: the Rust standard library requires Windows 7 or newer; a
literal Windows 2000 build would need a no_std port. `scripts/compat-report.sh`
prints the DLL imports and flags APIs newer than XP/7 so the claim is measured
rather than assumed.

## macOS

    rustup target add aarch64-apple-darwin x86_64-apple-darwin
    cargo build --release --target aarch64-apple-darwin

Building on Linux requires an SDK (osxcross). The code itself is portable; the
CI matrix builds macOS on macOS runners.

## Compatibility reports

    ./scripts/compat-report.sh dist/*

Prints, for each artifact: static/dynamic, DT_NEEDED count, GLIBC symbol
references, and for PE files the imported DLLs plus any APIs newer than XP or
Windows 7. This is how the compatibility matrix in COMPAT.md is produced.

## Tests

    cargo test --workspace

467 unit and integration tests as of this writing, including:

- cryptographic test vectors (NIST/RFC/Wycheproof-style negatives),
- X.509 chain validation against real captured chains,
- HTTP framing, redirects, SSE and DNS overrides with in-process servers,
- script engine semantics and limits,
- terminal key decoding and line editing,
- TLS interop with openssl s_server and live hosts (`--ignored` network tests).

An end-to-end mock provider is included:

    python3 tests/mock_provider.py 18080 &
    ./target/debug/emerag --base-url http://127.0.0.1:18080/v1 \
        --model mock --mode auto --no-write -p "read hello.txt"

## Offline bundle

    ./scripts/make-offline.sh --server /path/llama-server \
        --model model.gguf --out dist/emerag-offline

See LOCAL-MODELS.md for the payload format and signing notes.

## Repository layout

    crates/util      errors, encodings, text width, sys, glob, time
    crates/json      JSON parser/serializer
    crates/crypto    SHA-2, HMAC, HKDF, AES-GCM, ChaCha20, X25519, P-256/384, RSA, X.509
    crates/tls       TLS 1.2/1.3 client
    crates/http      HTTP/1.1, DNS overrides, proxies, SSE
    crates/term      raw mode, keys, line editor, screen, prompts
    crates/script    emera script engine (Lua subset)
    crates/llm       provider adapters and catalog
    crates/agent     loop, tools, permissions, jobs, subagents, skills
    crates/mcp       MCP stdio client
    crates/infer     reserved for the native GGUF engine
    crates/cli       the emerag binary
