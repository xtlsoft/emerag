# Status and roadmap

emerag 0.1 is a complete, working emergency agent. This page records what is
intentionally finished, what is experimental, and what is not built yet, so
nobody has to reverse-engineer a claim from the README.

## Finished and tested

- **Transport**: HTTP/1.1 client, TLS 1.2 + 1.3 (AES-GCM, ChaCha20, X25519,
  P-256), embedded CA store, SPKI pinning, DNS overrides, an internal UDP
  resolver for hosts without /etc/resolv.conf (Android/Termux), HTTP proxies,
  redirects, SSE, cancellation, retryable timeouts.
- **Providers**: Chat Completions, Responses, Anthropic Messages, DeepSeek
  API keys, DeepSeek account OAuth (PKCE browser login, x-dsh-auth-token,
  /models discovery), OpenAI, OpenCode Console/Go, ollama/llama.cpp/LM Studio,
  custom endpoints. Streaming tool calls and reasoning fields are normalized.
- **Liveness**: reasoning traces stream by default, waiting/status lines and
  tool durations are shown, and the system prompt carries a measured
  environment probe (OS, shells, tools, DNS, writability, memory).
- **Agent**: tool loop, per-call approvals, four permission modes, subagents,
  background jobs, compaction, JSONL transcripts, usage accounting.
- **Tools**: shell (bash/zsh/fish/sh/cmd/pwsh/python/php), file read/write/edit,
  list/glob/grep, script engine, ask-user, task, job_*, skill, run_elevated.
- **Script engine**: Lua 5.4 subset with a deterministic instruction budget,
  forkless fs/sys host functions (descriptors, read_at/write_at, stat, chmod,
  symlink, kill, pid/limit/load/memory readers), plus proc/time/json/hash/base64.
  The sys namespace is registered now, so sys.os/sys.arch/sys.cwd work too.
- **Skills**: SKILL.md discovery, catalog in the system prompt, on-demand load.
- **MCP**: stdio client (initialize, tools/list, tools/call), namespaced tools,
  timeouts, stderr diagnostics.
- **Interfaces**: interactive TUI, Ctrl+X chords, slash commands, cooked-mode
  and ASCII fallbacks, one-shot, JSON output, automatic first-run wizard,
  DeepSeek account login/logout, doctor, guide, key card.
- **Sessions**: /new, /session, /fork, persisted 0600 JSON (or memory with
  --no-write), background turns via " &" or /bg with /wait and /kill; each
  background turn gets its own Agent and MCP/job state.
- **Named providers**: /p lists configured endpoints only, custom endpoints
  get names, and the catalog is shown only through "Configure another
  provider..."; wizard selections are remembered.
- **Distribution**: POSIX/busybox installer with SHA-256 verification and
  tmpfs/noexec fallbacks; three tiers: nano C (58-82 KB), lite Rust
  (530-630 KB, no CA bundle), full Rust (1.6-2.0 MB, 118-CA bundle).
- **Platforms**: Linux static musl on x86_64/i686/aarch64/armv7/riscv64
  (qemu-smoke-tested), Windows x64/x86, s390x glibc.
- **Offline release**: self-extracting bundle with SHA-256 trailer, extraction,
  local up/status/stop/models, packaging script.

## Experimental

- **DeepSeek account end-to-end**: `auth_init` is verified live against
  platform.deepseek.com and the invalid-grant shape on both chat and messages
  routes is verified, but a real grant could not be completed here (no
  account). Inference uses the OpenAI-compatible route so reasoning_content is
  replayed; confirm on first real login.
- **Termux on a physical device**: the empty-resolv.conf failure and the
  --dns fallback were reproduced in WSL, not on Android hardware.
- **Background sessions**: output is deliberately buffered while you are at
  the prompt, and approvals wait until that session is foreground. They are
  tested through the TUI, not with a formal concurrency test.
- **Lite build**: no CA bundle and no certificate verification. It is the
  full feature set otherwise, but it is not a security equivalent of full.
  UPX-packed binaries can be flagged by some scanners. The installer cannot
  execute from a noexec filesystem unless /dev/shm, another exec tmpfs, or
  Python memfd is available.
- **Session files**: concurrent emerag processes writing the same
  sessions.json are not locked; the last writer wins.
- **Nano**: C89/VC6 source. Linux x86_64 musl and Windows x64/x86 PE builds
  are produced. DeepSeek TLS 1.3 and the mock shell loop were tested; Windows
  x64 runs under Wine. The VC6 build and Windows 98/2000/XP execution were not
  available in this environment.
- **Legacy Rust**: rust9x build script and a legacy RNG fallback are present,
  but the rust9x toolchain/MSVC linker was not installed, so no lite/full
  9x/2000 artifact was produced or tested.

- **Windows 7**: scripts/build-legacy-win.sh builds with Rust 1.77.2, the last
  toolchain supporting Windows 7. It was not verifiable in this environment
  (rustup interrupted the 1.77 installation), so treat it as untested. The
  default build needs Windows 8+ because Rust's std imports WaitOnAddress and
  GetSystemTimePreciseAsFileTime.
- **macOS**: source is portable and CI builds both architectures on macOS
  runners, but no artifact was produced here (no Apple SDK).
- **s390x**: builds against glibc; musl std is not published upstream.
- **loongarch64**: target exists in Rust, but no loongarch linker is installed
  here. Build on a loongarch host.

## Not implemented

- A native GGUF inference engine. crates/infer is reserved. The offline
  bundle currently carries llama.cpp instead; the payload format is designed
  so the engine can replace it without changing the CLI.
- MCP server mode (emerag exposing its tools *to* another agent). MCP client
  mode is complete.
- Session resume. Transcripts are written; loading them back into a fresh
  process is manual today.
- TLS: no client certificates, no resumption, no TLS 1.0/1.1, no RSA key
  exchange (ECDHE only), no OCSP/CRL checking.
- Windows 2000/XP. Rust's std requires Windows 7; a no_std port would be a
  separate project.

## Known deviations from the original brief

- The offline release is one file, but it bundles a small llama.cpp server and
  a GGUF model rather than embedding a Rust inference engine. A 0.5B model
  would otherwise multiply the agent's 3.2 MiB RSS by 200x.
- Windows 2000 is not reachable with the Rust standard library. The measured
  floor is Windows 8 for the default build and Windows 7 for the legacy build.
- Local models below ~0.5B parameters are included as options but tool-calling
  reliability is poor; the docs say so instead of pretending otherwise.
