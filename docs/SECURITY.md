# Security model

emerag is a tool that runs commands and edits files on your behalf. It is
designed to make the dangerous parts explicit, not invisible.

## Threat model

In scope:

- A malicious or confused model proposing destructive commands.
- A prompt injection inside a file, web page, skill, or MCP tool result.
- A hostile network (wrong certificate, DNS hijack, captive portal).
- A compromised or malicious MCP server.
- Accidental disclosure of API keys in logs, transcripts, or terminal output.
- Running from a rescue shell as root.

Out of scope:

- A compromised kernel, hypervisor, or emerag binary.
- An attacker who can already write to emerag's config or executable.
- Side-channel attacks on the host CPU (emerag's AES is table-based).

## Execution

- Every tool call is classified as read / write / destructive and checked
  against the permission mode.
- `ask` (default) prompts before anything that writes, executes, or modifies.
  The prompt shows the exact command or file operation.
- `auto` runs tools without prompts but still asks for elevation.
- `read-only` permits only reads, listings and searches; writes, shell
  commands, scripts, jobs and MCP calls are denied.
- `yolo` runs everything. Use only in a throwaway container; it exists because
  a rescue console sometimes has nobody to answer prompts.
- Deny rules in the config (`"deny": ["shell:rm -rf *"]`) are checked first and
  cannot be overridden interactively.

Commands are spawned directly, without a shell wrapper, except for the shell
tool where a shell is the point. The child gets a clean environment
(`TERM=dumb`, `PAGER=cat`, `NO_COLOR=1`) and no stdin, so a command cannot
silently consume your keystrokes.

## Privilege elevation

`run_elevated` never happens implicitly:

1. It tries `sudo -n` / `doas` (passwordless, common in containers).
2. Otherwise it asks for the password over the terminal, feeds it to
   `sudo -S` via a pipe, and never stores or logs it.
3. Cancelling the password prompt cancels the command.

There is no setuid helper, no persistent daemon, and no cached credential.
If you are already root, elevation is a no-op.

## Network and TLS

- TLS verification is on by default, against a Mozilla-derived root bundle
  embedded in the binary. A broken system CA store cannot silently weaken you.
- `--cacert` replaces the trust anchors; `SSL_CERT_FILE` is honoured.
- `--insecure` disables verification and prints a warning at startup. It is
  for a captive-portal LLM proxy you control, nothing else.
- `--resolve host:443:IP` / `--ip` pin the address but still verify the
  certificate against the hostname. This is the correct fix for broken DNS.
- Only HTTP/1.1, no compression, one request per connection. There is no
  HTTP/2, no cookies, no redirect to a different origin with credentials.

## Secrets

- API keys are redacted as `sk-1...cdef` in `/config`, doctor output, verbose
  HTTP logs and transcripts.
- The key is written to disk only if you save it in the wizard; the file is
  created with mode 0600 on Unix.
- `--no-write` keeps keys, config and sessions in memory only. Nothing is
  created in the working directory, including temp files.
- `--verbose` prints request headers but replaces Authorization and x-api-key
  values.

## Transcripts

Transcripts are JSONL and opt-in (`--transcript PATH`). They contain model
output, tool calls and tool results, i.e. potentially sensitive file contents.
They are never uploaded anywhere by emerag. Delete them like you would a shell
history.

## Supply chain

- The binary has no third-party Rust crates. `cargo build --offline` works.
- Skills are local text you can read; MCP servers are executables you install.
  Both are trust decisions you make explicitly.
- The embedded CA bundle is a pinned snapshot from curl.se; refresh it by
  rebuilding with a new `crates/crypto/assets/roots.pem`.

## Root and rescue environments

Running emerag as root is supported and sometimes necessary (a rescue shell is
root). The permission prompts still apply. Prefer `--mode ask` and
`--no-write`, and remember that a model with root can do anything you can:
the approval prompt is the last line of defense, so read it.

## Reporting

This is a young project. If you find a vulnerability, please open a private
security report rather than a public issue, and include the emerag version and
the exact command sequence.
