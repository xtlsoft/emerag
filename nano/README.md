# emerag-nano

A deliberately tiny C client for Chat Completions. This is the Windows 98 /
NT4 / 2000 / XP tier. It is not a replacement for the Rust agent.

- One TLS 1.3 cipher suite: TLS_AES_128_GCM_SHA256.
- X25519 key exchange, SHA-256, AES-128-GCM, all local C.
- HTTP/1.1, JSON, one shell-command protocol.
- **No certificate verification and no CA store.** There is nothing to
  validate certificates with in the binary.
- No MCP, no scripting engine, no sessions, no tools JSON.

## Build

Linux/musl:

    ./build.sh

Visual C++ 6.0 (Windows 98/2000/XP):

    build-vc6.bat

MinGW cross builds are also produced by build.sh when available; those
are what the release page hosts. Run build-vc6.bat for the actual VC6 /
Windows 98-2000 artifact.

## Run

    emerag-nano --key KEY --model deepseek-chat -p "inspect the machine"

Interactive:

    emerag-nano --key KEY

The model can ask for a command by replying with a line:

    SHELL: uname -a

The controller prints the command, runs it, and sends the output back. This
is prompt-based, not OpenAI tool JSON. Use --ask to confirm each command or
--no-shell to disable execution.

Environment: EMERAG_API_KEY, EMERAG_MODEL, EMERAG_HOST.

## Why it exists

For machines where a Rust binary is too large or the OS is too old for the
Rust standard library. VC6 produces a small 32-bit PE that runs on Windows
98/2000/XP without a runtime or TLS library.
