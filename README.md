# emerag

**A tiny, statically linked coding agent for emergencies.**

When a machine is broken, freshly installed, air-gapped, or running on a CPU
architecture no Node.js runtime supports, you still need an assistant that can
read files, run commands, and help you put the system back together. emerag is
that assistant: one binary, no runtime, no installer, no daemon.

    cp emerag /usr/local/bin/       # or carry it on a USB stick
    emerag

That is the whole installation.

## Measured, not promised

| property | value (Linux x86_64, release build) |
| --- | --- |
| binary size | **1.87 MiB** (1.96 MB) static-pie, 0 DT_NEEDED, 0 GLIBC symbols |
| resident memory | **3.2 MB** (3.1 MiB) maximum RSS for a full one-shot tool-using session |
| dependencies | **zero** Rust crates, zero shared libraries |
| tests | 480 unit/integration tests + 10 end-to-end scenarios |
| startup | milliseconds; no config file required |

Other targets: aarch64 1.57 MiB, armv7 1.53 MiB, riscv64 1.52 MiB,
i686 1.69 MiB, Windows x64 1.58 MiB, Windows x86 1.52 MiB, s390x 1.88 MiB. See
[docs/COMPAT.md](docs/COMPAT.md).

## Why

Full coding agents assume a healthy host: glibc, Node.js, working DNS, an
editor, a modern terminal, and plenty of RAM. Those assumptions fail exactly
when you need help most. emerag makes the opposite trade:

- **One static binary.** Linux/musl builds need no shared libraries at all.
  Windows builds need only the OS. No Node, no Python, no OpenSSL.
- **Zero third-party crates.** The whole agent is Rust plus std, with
  hand-written TLS, HTTP, JSON, crypto, X.509 and a Lua-subset interpreter.
  Builds work offline and cross-compile to unusual targets.
- **Small.** 1.6-2.0 MiB full, 530-630 KB lite, 58-82 KB nano; 3.2 MB RSS
  in normal use; no background
  threads when idle; no model weights in the agent process.
- **Terminal-first.** VT100, serial consoles, 40-column windows, legacy
  Windows consoles, no Unicode, no color, no arrow keys: all supported.
- **Broken-network aware.** DNS is optional: pin any endpoint with
  --resolve host:443:IP or --ip, or supply a nameserver with --dns. On
  Android/Termux, where a static binary cannot see the platform resolver,
  emerag discovers nameservers or falls back to public DNS automatically.
  Certificates still verify against the hostname, and a Mozilla-derived root
  bundle is embedded.
- **DeepSeek account sign-in.** A DeepSeek account can be used through the
  browser OAuth flow (PKCE, loopback callback), with no API key. Model names
  come from the account's /models endpoint, and the grant is sent as
  x-dsh-auth-token.
- **Live, not stuck.** Reasoning traces stream while the model thinks, each
  request shows a waiting status, and tool calls report their duration.
- **Many conversations.** /new, /session and /fork keep independent histories.
  A turn started with " &" or /bg keeps running while you switch and work in
  another session; /wait and /kill control it. Sessions persist as 0600 JSON,
  or stay in memory with --no-write.
- **Named providers.** Configured endpoints are remembered under a name;
  /p lists only those, with a separate "Configure another provider..." entry
  instead of dumping the whole catalog.
- **One-liner and RAM-only runs.** A POSIX/busybox installer downloads,
  verifies and installs, or executes from /dev/shm when the root filesystem is
  read-only.
- **Three tiers.** Nano is a 58-82 KB C client (VC6, Windows 98/2000/XP,
  Chat Completions only, no certificates). Lite is the full Rust agent with
  no CA bundle and no certificate checks at **530-630 KB**. Full is the
  reference build with the 118-CA bundle at **1.6-2.0 MB**.
- **Broken-shell and PID-limit aware.** bash, zsh, fish, sh, cmd, PowerShell,
  Python and PHP are supported; when none works, or RLIMIT_NPROC blocks fork,
  the built-in script engine exposes forkless filesystem and syscall-level
  primitives: open/read/write/seek/fsync, read_at/write_at, stat, chmod,
  symlink, kill, pid/limits and memory/load readers. proc.run and the shell
  tool still need a child process.
- **Offline-capable.** 'emerag local up' runs a local model; the offline
  release is a single file containing the agent, a GGUF model and a static
  llama.cpp server (see [docs/LOCAL-MODELS.md](docs/LOCAL-MODELS.md)).

## Quick start

    emerag --wizard        # choose provider, endpoint, key, model (numbered menu)
    emerag login deepseek  # browser sign-in with a DeepSeek account (no key)
    emerag                 # interactive session
    emerag "fix the nginx config"        # one-shot turn
    emerag --doctor        # terminal, shells, TLS, DNS, disk diagnosis
    emerag --keys          # printable key card
    emerag --guide         # offline tutorial

The wizard needs only digits and Enter. Nothing needs an editor, a mouse or a
clipboard. If DNS is broken it offers to pin an IP address.

### Install or run without installing

    # install (curl, wget or busybox wget)
    wget -qO- http://10.20.2.226:8899/install.sh | sh

    # temporary run; uses tmpfs/RAM and works with a read-only root
    wget -qO- http://10.20.2.226:8899/install.sh | sh -s -- --run

    # 58 KB C client, no certificates
    wget -qO- http://10.20.2.226:8899/install.sh | sh -s -- --run --nano

    # 530-630 KB Rust agent, no CA bundle
    wget -qO- http://10.20.2.226:8899/install.sh | sh -s -- --run --lite

The installer tries curl, wget and busybox wget, verifies SHA-256 when a
checksum tool exists, and falls back from a noexec TMPDIR to /dev/shm.
Installer options may follow --run; unknown options after it go to emerag.

Nano is the floor: a C client with one TLS 1.3 cipher suite and Chat
Completions, not a full HTTPS stack. Lite and full keep every agent feature.
If ROM is nearly full, use --run --nano or --run --lite: the download lives
in RAM and nothing is installed.

For scripts and automation:

    emerag --json -p "summarize /etc/fstab"
    echo "why is nginx failing" | emerag --stdin

## What works today

| area | status |
| --- | --- |
| Chat Completions, Responses, Anthropic Messages | working, streaming, tool calls, usage, reasoning |
| DeepSeek account (OAuth), DeepSeek/OpenAI/Anthropic keys, OpenCode, custom, local | browser sign-in, embedded catalog, /models discovery, key handling |
| agent loop | tools, approvals, retries, cancellation, compaction, transcripts (JSONL) |
| tools | shell (8 shells), read/write/edit/list/glob/grep, script, ask-user, subagents, background jobs, elevation |
| skills (SKILL.md) and MCP client (stdio) | working |
| TUI / serial / dumb terminals | working, ASCII fallback, cooked-mode fallback |
| providers without DNS | --resolve / --ip / --dns, Android fallback, embedded CA, --cacert |
| local models | external ollama/llama.cpp/LM Studio; self-extracting offline bundle |
| cross builds | Linux musl x86_64/i686/aarch64/armv7/riscv64, Windows x64/x86, s390x (glibc) |

Not implemented yet (tracked in [docs/STATUS.md](docs/STATUS.md)):

- a native Rust GGUF inference engine (the offline release bundles llama.cpp),
- MCP *server* mode (client mode works),
- session resume (--transcript writes, resume is manual),
- Windows 7 legacy build (script provided, not verified in this environment),
- macOS artifacts built here (CI builds them on macOS),
- musl s390x and a loongarch64 build (no upstream std / no linker here).

## Interfaces for hard-to-input situations

- Every control has a **typed slash command**: /model, /mode, /jobs, /quit.
  Prefix matching works (/m).
- Fast controls use a **Ctrl+X chord** that does not collide with shells or
  tmux: Ctrl+X H help, M model, A auth, P mode, J jobs, Q quit.
- Menus are **numbered** and accept a digit or Enter.
- Approvals accept **one key**: y once, a session, n deny.
- If the terminal cannot do raw mode, emerag silently falls back to **cooked
  line input**; everything still works.
- --ascii --width 40 is a supported, tested configuration.
- 'emerag local status' and --doctor work without a model or a network.

## Security

emerag executes commands and edits files. Defaults are conservative:
'ask' mode approves every write/command, full-build TLS verification is on
unless you pass --insecure, keys are redacted from logs and transcripts, and
elevation asks for a password over the TTY without storing it. Read
[docs/SECURITY.md](docs/SECURITY.md) before running as root or with --mode
yolo.

**Lite and nano do not verify TLS certificates.** Lite has no CA bytes at all;
nano has no CA store and no verification code. Use the full build on any
network you do not control.

## Build

    cargo build --release                 # host
    ./scripts/build-cross.sh              # every installed target
    ./scripts/compat-report.sh            # minimum OS/static-link report
    ./tests/e2e.sh                        # mock providers, no network

There is nothing to fetch: 'cargo build --offline' works on a machine with a
Rust toolchain and nothing else. See [docs/BUILDING.md](docs/BUILDING.md).

## Documentation

- [Quick start card](docs/QUICKSTART.md) - printable, 60 columns
- [Emergency playbooks](docs/EMERGENCY.md) - broken DNS, broken shell, read-only disk
- [Manual](docs/MANUAL.md) - every command, flag, config key and tool
- [Keys and slash commands](docs/KEYMAP.md)
- [Providers and API quirks](docs/PROVIDERS.md)
- [Local models and offline release](docs/LOCAL-MODELS.md)
- [Scripting engine](docs/SCRIPTING.md)
- [Skills and MCP](docs/SKILLS.md)
- [Security model](docs/SECURITY.md)
- [Building and cross-compiling](docs/BUILDING.md)
- [Legacy Windows, 98/2000/XP](docs/LEGACY.md)
- [Compatibility matrix](docs/COMPAT.md)
- [Architecture](docs/DESIGN.md) and [status/roadmap](docs/STATUS.md)

## License

MIT.
