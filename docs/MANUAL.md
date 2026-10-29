# emerag manual

## Starting

    emerag                    interactive session
    emerag "prompt"           one-shot turn
    emerag -p "prompt"        same
    emerag --stdin            read the prompt from stdin
    emerag --wizard           provider/model setup
    emerag --doctor           diagnostics
    emerag --keys             key card
    emerag --guide            offline tutorial
    emerag --models           list models for the current provider
    emerag login deepseek     sign in with a DeepSeek account (no API key)
    emerag --dns 1.1.1.1      nameserver for broken/absent DNS (repeatable)
    emerag local status|up    local model runtime
    emerag --version | --help

Exit codes: 0 success, 1 runtime failure, 2 usage/config error, 130 cancelled.

## First run

If no endpoint and model are configured, emerag starts the wizard. It asks:

1. **Provider** - numbered list (DeepSeek API key, DeepSeek account sign-in,
   OpenAI, Anthropic, OpenCode, local servers, Custom).
2. **Endpoint** - defaults to the provider's; paste or type an override. If
   DNS fails, it offers to pin an IP or use --dns.
3. **API key** - hidden input; leave empty for local servers. The DeepSeek
   account option opens a browser sign-in instead.
4. **Model** - discovered from the provider's /models, or typed by hand.
5. **Test** - a tiny completion proves the key and endpoint work.
6. **Mode** - ask, auto, or read-only.
7. **Save** - writes `~/.config/emerag/config.json` (0600) unless you say no.

Nothing needs an editor, a mouse, or a clipboard.

## Configuration

Priority: CLI flags > environment > config file > defaults.

Environment variables:

    EMERAG_PROVIDER EMERAG_MODEL EMERAG_BASE_URL EMERAG_API
    EMERAG_API_KEY EMERAG_MODE EMERAG_NO_WRITE EMERAG_CONFIG
    EMERAG_RESOLVE EMERAG_IP EMERAG_INSECURE EMERAG_CACERT
    EMERAG_TIMEOUT EMERAG_SHELL EMERAG_ASCII EMERAG_SKILLS
    HTTPS_PROXY / HTTP_PROXY / ALL_PROXY / NO_PROXY
    DEEPSEEK_API_KEY OPENAI_API_KEY ANTHROPIC_API_KEY OPENCODE_API_KEY

The config file is JSON; `/config` prints the effective values with secrets
redacted. `--no-write` means nothing is ever written.

## Providers

Embedded profiles (see PROVIDERS.md for wire details):

| id | API | notes |
| --- | --- | --- |
| deepseek | Chat Completions | deepseek-flash, deepseek-v4-pro; also serves Anthropic/Responses paths |
| openai | Chat Completions | |
| openai-responses | Responses | stateless (`store: false`) |
| anthropic | Anthropic Messages | Bearer + anthropic-version; max_tokens required |
| opencode-zen | Chat Completions | OpenCode Console, https://opencode.ai/inference |
| opencode-go | Chat Completions | requires a session header, handled automatically |
| ollama / llamacpp / lmstudio | Chat Completions | localhost, no key |
| custom | choose | any OpenAI-compatible endpoint |

Adding an endpoint is data, not code: pick **Custom**, give the base URL, the
API style and the key. A new embedded profile is a single struct entry in
`crates/llm/src/catalog.rs`.

## Using the agent

Type plain language. The model decides which tools to call; you approve them
according to the mode.

    > the machine booted into emergency mode, diagnose it
    > why does nginx fail to start
    > read /etc/fstab and check for a missing mount
    > fix the ssh config and restart it

Tool calls are shown as they happen, with a one-line result. The final answer
is printed after the loop ends. Reasoning text (DeepSeek, o-series, Claude
thinking) is shown only with `--verbose`.

### Permission modes

    /mode ask         every write/command needs y/n (default)
    /mode auto        run tools without prompts
    /mode read-only   inspect only
    /mode yolo        everything, including elevation

Approval options: `y` once, `a` always for this exact call in this session,
`n` deny (the model sees the denial and can adapt).

### Tools

| tool | purpose |
| --- | --- |
| shell | run a command in the detected shell (bash/zsh/fish/sh/cmd/pwsh/python/php) |
| read_file / write_file / edit_file | line-numbered reads, atomic writes, exact replacements |
| list_dir / glob / grep | tree listing, glob search, literal substring search |
| script | emera script (Lua subset) for shell-less operation |
| ask_user | ask you a question with optional choices |
| task | subagent with a fresh context |
| job_start / job_output / job_list / job_kill | background commands with bounded output |
| skill | load a skill body |
| run_elevated | sudo/doas with an explicit prompt |
| mcp__server__tool | tools from configured MCP servers |

File tools are size-limited (2 MiB reads, 2 MiB writes) and never dump binary
files. The shell tool has a 120s default timeout, no stdin, and a bounded
output buffer.

### Jobs

    > start the backup in the background
    [tool] job_start: ...
    > check on it
    [tool] job_output: ...

`/jobs` lists them; `/jobs output j1`, `/jobs kill j1`.

### Subagents

The model can call `task` to run a bounded sub-run with a fresh conversation,
its own tool loop, and a report back. This keeps the main context small for
large searches. Subagents cannot spawn subagents.

### Compact

Long sessions are compacted automatically at ~75% of the context budget: tool
outputs are elided, then older turns are summarized by the model. `/compact`
forces a pass. If compaction fails (no model), the oldest turns are dropped.

## Keys and commands

Type `/help` for the inline list, `/keys` for the printable card. Ctrl+X is a
prefix chord: `Ctrl+X H` help, `M` model, `A` auth, `P` mode, `J` jobs,
`G` agents, `S` skills, `T` transcript, `C` compact, `L` redraw, `Q` quit.

Slash commands: `/help /wizard /model /provider /auth /login /logout /new
/session /fork /bg /wait /kill /mode /config /keys /skills /mcp /jobs /agents
/transcript /clear /compact /script /local /doctor /cost /quit`. Prefix
matching works (`/m` = `/model`).

`/auth` offers a DeepSeek account sign-in or an API key; `/login deepseek` is
the direct form and `/logout` removes the local grant.

## Multiple sessions

    /new [name]        start a fresh conversation
    /session           list sessions (name, messages, model, busy)
    /session N|name    switch
    /fork [name]       copy the current conversation into a new one

`/new` and `/fork` never touch the other histories. With a writable config
directory, sessions are saved to `sessions.json` (0600) next to the config
file and reloaded on the next start. With --no-write, or on a read-only
filesystem, they stay in memory for the run.

A prompt ending in ` &` starts a background turn; `/bg PROMPT` does the same:

    examine the logs &      # returns to the prompt immediately
    /session 2             # work elsewhere while it runs
    /wait                  # wait, show buffered output and approvals
    /kill 1                # cancel background id 1

Output from a background session is buffered until you switch to it or
`/wait`, so it cannot corrupt the line editor. Approvals for a background turn
wait until that session is foreground. Each background turn has its own Agent,
while jobs and MCP clients are isolated per session.

## Named providers

`/p` lists only providers you have configured (the active one plus saved
entries) and offers "Configure another provider...". Choosing that shows the
embedded catalog or a custom endpoint. Custom endpoints ask for a display name;
the id is derived from it (`custom-router`). Named entries are saved in
`sessions.json`/config metadata (never an API key). `/wizard` also records the
selected endpoint, so it appears under `/p` next time.

## One-liner and mini builds

    wget -qO- http://10.20.2.226:8899/install.sh | sh
    wget -qO- http://10.20.2.226:8899/install.sh | sh -s -- --run
    wget -qO- http://10.20.2.226:8899/install.sh | sh -s -- --run --mini
    wget -qO- http://10.20.2.226:8899/install.sh | sh -s -- --run --lite

The installer needs one of curl, wget or busybox wget. It verifies SHA-256,
installs to `~/.local/bin` or `/usr/local/bin`, and for --run tries TMPDIR,
/dev/shm and other writable filesystems. A noexec filesystem is skipped; if all
are noexec it tries a Python memfd, then reports the limitation.

`scripts/build-mini.sh` builds a ROM-oriented variant (17 major CA roots
instead of the full bundle, size profile, UPX). It is 0.54-0.64 MiB on disk,
not a few kilobytes: TLS, HTTP, JSON, provider protocols and tools have a
floor. On a router with almost no free ROM, use `--run --mini` (full agent) or
`--run --lite` (306-369 KB core) so the binary lives in RAM.

The lite core is a separate binary: Chat Completions only, with shell,
read_file, write_file, edit_file and list_dir. It has no sessions, MCP, Lua,
OAuth, skills or subagents. Use it when the machine cannot spare another
megabyte; use the full build when you need the rest.

## Broken networks

    # DNS works, proxy needed
    export HTTPS_PROXY=http://10.0.0.1:3128

    # DNS broken, you know the IP
    emerag --resolve api.deepseek.com:443:203.0.113.10 --wizard

    # DNS resolver itself is missing/broken (common on Termux/Android)
    emerag --dns 223.5.5.5 --dns 1.1.1.1 --doctor

    # Termux: the phone's DNS works but a static binary cannot see it;
    # emerag tries Android properties and a public fallback automatically.

    # shortcut for the configured endpoint
    emerag --ip 203.0.113.10 -p "hi"

    # verify the chain yourself
    emerag --cacert /etc/ssl/my-ca.pem ...

    # last resort (warns loudly)
    emerag --insecure ...

Certificates always verify against the hostname, even when the address is
pinned. Doctor checks DNS, TCP and TLS separately so you can see which layer
is broken.

## Minimal terminals

    emerag --ascii --width 40

- No raw mode? Input falls back to cooked lines; slash commands still work.
- No colors? `--no-color` or `NO_COLOR=1`.
- No Unicode? `--ascii` and the glyph table switches to ASCII.
- Serial console? Keep the default (no alternate screen); output is appended,
  never repainted.
- Arrow keys missing? History is optional; type commands.

## Windows

cmd.exe, PowerShell, and Python/PHP are detected as shells. Legacy consoles
without ANSI are detected and rendered without escape sequences. The binary is
statically linked against msvcrt, so no runtime DLL install is needed beyond
what the OS ships.

## Data

- Config: `~/.config/emerag/config.json` (0600).
- Sessions/transcripts: only with `--transcript`.
- No telemetry, no update check, no phone-home beyond the configured LLM
  endpoint.

## Reasoning, progress and probes

Reasoning/thinking traces stream by default (dim, indented), so a model that is
thinking does not look hung. Each model request prints a "waiting for ..."
status and the reply time; each tool call reports its duration. `--verbose`
adds more diagnostics. ANSI is optional: `--ascii` and `--no-color` work on
serial consoles.

The system prompt includes a measured environment probe: OS and version,
kernel/init, architecture, user/root, available shells, package managers,
common tools, whether the cwd is writable, DNS servers, memory and whether
sudo/doas exists. The model therefore knows it is on Termux, a rescue shell or
a container without guessing.

## DeepSeek account sign-in

    emerag login deepseek

emerag generates a PKCE verifier, asks platform.deepseek.com for an authorize
URL, starts a loopback listener and opens a browser (or prints the URL). On
Termux, open the URL in the phone's browser; the callback to 127.0.0.1 reaches
emerag. The token is stored in config (0600) and sent as `x-dsh-auth-token`;
no `Authorization` header is used. Model names come from
`https://api.deepseek.com/models`, and inference uses the OpenAI-compatible
chat route so `reasoning_content` is replayed across tool calls.

## Troubleshooting

| symptom | fix |
| --- | --- |
| "no endpoint configured" | `emerag --wizard` |
| 401/403 | `/auth` for a key, `/login deepseek` for an account |
| "not signed in" | `/login deepseek` |
| DNS error | `--dns 1.1.1.1`, `--resolve host:443:IP`, or `--ip` |
| TLS certificate error | check clock, `--cacert`, or `--insecure` knowingly |
| Termux: DNS works in apps, emerag fails | `--dns` (auto fallback usually fixes it) |
| "stream stalled" | proxy/idle timeout; retry or switch model |
| tools denied | `/mode auto` or answer the prompt |
| no models listed | type the model name; some gateways hide /models |
| terminal garbage | `--ascii`, `--width 80`, or set `TERM=dumb` |
| too much context | `/compact` or `/clear` |

`emerag --doctor` automates most of this.
