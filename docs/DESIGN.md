# emerag design

emerag is a tiny, statically linked, zero-dependency coding agent for emergencies:
broken machines, fresh installs, serial consoles, air-gapped networks, musl
distros, Termux, and hardware where a Node.js runtime is simply not an option.

The name is "emergency agent". One binary, no installer, no runtime, no daemon.

## Non-negotiable constraints

1. **Zero third-party crates.** The workspace has no dependencies. Everything is
   std plus hand-written FFI declarations. This makes offline builds, audits and
   exotic-target builds possible. Do not add crates; do not vendor C code.
2. **One static binary.** No shared libraries beyond the OS (and on Linux/musl:
   none at all). No assets that must be installed next to the binary. Embedded
   data goes through include_bytes!.
3. **Small.** Release profile opt-level=z, LTO, panic=abort, strip. Target:
   binary under 3 MiB, RSS under 15 MiB idle, under 40 MiB while streaming.
   Prefer stack/arena reuse over allocation churn; avoid regex engines.
4. **Portable.** Windows (x86, x64; old consoles), Linux (musl static, old
   kernels), macOS (x64/arm64). Arch matrix: x86_64, i686, aarch64, armv7,
   riscv64, s390x, loong64. Code must not assume 64-bit, little-endian or
   x86. No inline asm unless cfg-gated and optional.
5. **TTY-safe.** Must work on VT100, serial console, dumb terminals, Windows
   legacy console. No mouse, no clipboard, no truecolor requirement, no
   alt-screen requirement, no Unicode requirement (ASCII fallback).
6. **No panics on untrusted input.** Parsers return Result. Panic=abort is for
   bugs only; I/O and model output must never trigger one.

## Failure modes we explicitly design for

- DNS is broken: every endpoint can be pinned with a resolve override
  (`host:port:ip`), certificates still verify against the *hostname*.
- No CA store installed: emerag embeds a Mozilla-derived root set and supports
  `--cacert`, `SSL_CERT_FILE`, and `--insecure` (loudly warned).
- Read-only filesystem: all config and session state can live in memory
  (`--no-write`), never required to start.
- Shells are broken: tools use direct process spawn when possible, and the
  built-in script engine exposes filesystem/process/env/time primitives.
- Terminal is 40 columns: every screen must render at 40x16, with an
  `ascii` mode and line-oriented fallback.

## Crate graph

    util  -> (std only)
    json  -> util
    crypto-> util
    tls   -> util, crypto
    http  -> util, tls
    term  -> util
    script-> util, json
    mcp   -> util, json
    llm   -> util, json, http
    agent -> util, json, llm, script, mcp
    infer -> util
    cli (bin emerag) -> all

No cycles. `agent` must not depend on `term`: the UI talks to the agent through
an event sink trait defined in `agent`, so the same core can be reused by the
one-shot CLI, the TUI, and tests.

## Error convention

Each crate defines:

    pub struct Error { ... }
    pub type Result<T> = core::result::Result<T, Error>;

with Display + std::error::Error. Context is prepended as text. No panics for
recoverable conditions; no `unwrap()` on I/O or parsed data.

## Interfaces (frozen for parallel work)

### emerag-http

    pub struct Url { pub scheme: String, pub host: String, pub port: u16,
                     pub path: String, pub query: String }
    impl Url {
        pub fn parse(s: &str) -> Result<Url>;
        pub fn host_header(&self) -> String;      // includes non-default port
        pub fn path_and_query(&self) -> String;
        pub fn origin(&self) -> String;
    }

    pub enum TlsVerify { EmbeddedCa, SystemCa, CaFile(Vec<u8>), PinnedSpki([u8; 32]), Insecure }

    pub struct TlsOptions {
        pub verify: TlsVerify,
        pub sni: Option<String>,          // defaults to Url.host
        pub alpn: Vec<String>,            // default ["http/1.1"]
        pub client_cert_pem: Option<Vec<u8>>,
        pub client_key_pem: Option<Vec<u8>>,
    }

    pub struct Client {
        pub resolve: ResolveTable,
        pub tls: TlsOptions,
        pub proxy: Option<ProxyConfig>,
        pub connect_timeout: Duration,
        pub read_timeout: Duration,
        pub max_redirects: u8,
        pub user_agent: String,
        pub verbose: bool,
        pub cancel: CancelToken,
    }

    impl Client {
        pub fn send(&self, req: Request) -> Result<Response>;   // no redirects
        pub fn send_follow(&self, req: Request) -> Result<Response>; // redirects
    }

    pub struct Request { pub method: String, pub url: Url,
                         pub headers: Vec<(String, String)>, pub body: Vec<u8> }
    pub struct Response { pub status: u16, pub reason: String,
                          pub headers: Vec<(String, String)>, pub url: Url,
                          body: Box<dyn Read + Send> }
    impl Response {
        pub fn header(&self, name: &str) -> Option<&str>;
        pub fn read_some(&mut self, buf: &mut [u8]) -> io::Result<usize>;
        pub fn read_to_end_limited(&mut self, limit: usize) -> Result<Vec<u8>>;
        pub fn into_body(self) -> Box<dyn Read + Send>;
    }
    impl Read for Response;

    pub struct SseDecoder { ... }
    impl SseDecoder {
        pub fn new() -> Self;
        pub fn feed(&mut self, bytes: &[u8]) -> Vec<SseEvent>;
    }
    pub struct SseEvent { pub event: String, pub data: String, pub id: String }

ResolveTable supports entries `host:port:ip`, `host:ip` (default port 443 when
scheme is https), IPv6 in brackets. Lookup order: exact host:port, host, then
the system resolver via std ToSocketAddrs. When all addresses fail, return an
error mentioning --resolve and --ip.

### emerag-tls

    pub struct TlsConfig {
        pub server_name: String,
        pub verify: TlsVerify,            // from http, defined in tls to avoid cycle
        pub ca_pem: Option<Vec<u8>>,
        pub alpn: Vec<String>,
        pub min_version: TlsVersion,      // Tls12 or Tls13
        pub client_cert_pem: Option<Vec<u8>>,
        pub client_key_pem: Option<Vec<u8>>,
        pub pinned_spki: Option<[u8; 32]>,
        pub insecure_skip_verify: bool,
    }
    impl TlsStream {
        pub fn connect(tcp: TcpStream, cfg: &TlsConfig) -> Result<TlsStream>;
        pub fn version(&self) -> TlsVersion;
        pub fn alpn(&self) -> Option<&str>;
        pub fn peer_spki_sha256(&self) -> Option<[u8; 32]>;
    }
    impl Read for TlsStream; impl Write for TlsStream;

TLS 1.2 and 1.3 clients, HTTP/1.1 ALPN only. Cipher suites:
TLS1.3 AES-128-GCM, AES-256-GCM, CHACHA20-POLY1305; groups X25519, P-256.
TLS1.2 ECDHE-{RSA,ECDSA}-{AES128-GCM,AES256-GCM,CHACHA20} with
signature_algorithms RSA-PSS/PKCS1 and ECDSA-P256. No renegotiation, no
resumption, no compression, no client auth in v1 (API reserved).

### emerag-term

    pub struct Capabilities { pub width: u16, pub height: u16, pub ansi: bool,
        pub color: bool, pub unicode: bool, pub tty: bool }
    pub fn detect() -> Capabilities;

    pub enum KeyCode { Char(char), Enter, Tab, Backspace, Esc,
        Up, Down, Left, Right, Home, End, PageUp, PageDown, Delete, Insert,
        F(u8), Unknown }
    pub struct Key { pub code: KeyCode, pub ctrl: bool, pub alt: bool, pub shift: bool }
    pub fn read_key() -> Result<Key>;      // blocking, raw mode expected

    pub struct RawMode { ... }             // Drop restores the terminal
    pub fn raw_mode() -> Result<RawMode>;

    pub struct LineEditor { ... }          // history, cursor, paste, completion
    impl LineEditor {
        pub fn new(caps: Capabilities) -> Self;
        pub fn read_line(&mut self, prompt: &str) -> Result<Option<String>>;
        pub fn set_completer(&mut self, f: Box<dyn Fn(&str) -> Vec<String>>);
    }

    pub struct Screen { ... }              // ANSI painter with dumb fallback
    impl Screen {
        pub fn new(caps: Capabilities) -> Self;
        pub fn begin_frame(&mut self);     // cursor home + clear-to-end
        pub fn line(&mut self, text: &str);
        pub fn end_frame(&mut self);
        pub fn write_raw(&mut self, s: &str);
    }

A cooked-mode fallback must exist: when !tty or TERM=dumb, read_line uses
stdin lines and prints a numbered menu instead of interactive selection.

### emerag-script

Lua 5.4 subset ("emera script"). Host API injected by the agent crate.

    pub enum Value { Nil, Bool(bool), Number(f64), Str(String),
                     Table(Rc<RefCell<Table>>), Function(Rc<Function>) }
    pub trait Host {
        fn call(&mut self, name: &str, args: Vec<Value>) -> Result<Value>;
        fn print(&mut self, text: &str);
    }
    pub struct Limits { pub max_instructions: u64, pub max_output_bytes: usize,
                        pub wall_clock_ms: u64 }
    pub fn run(source: &str, host: &mut dyn Host, limits: Limits) -> Result<Value>;

Language: local/function/if/elseif/else/while/repeat/for numeric and pairs/
return/break; tables, metatables not required; closures; varargs; string
escapes; `--` comments. Stdlib: print, type, tostring, tonumber, pairs, ipairs,
next, select, error, pcall, assert, string.{format,sub,gsub,find,match,rep,len,
byte,char,upper,lower}, table.{insert,remove,concat,sort}, math.*, os.{time,
clock,getenv}, plus host calls. Deterministic instruction budget; memory caps.

### emerag-llm

    pub enum ApiKind { ChatCompletions, Responses, AnthropicMessages }
    pub struct ProviderProfile { pub id: String, pub label: String,
        pub base_url: String, pub api: ApiKind, pub auth: AuthKind,
        pub default_models: Vec<String>, pub headers: Vec<(String, String)>, ... }
    pub struct ModelInfo { pub id: String, pub context: Option<u32>, pub max_out: Option<u32> }
    pub trait Provider {
        fn list_models(&self) -> Result<Vec<ModelInfo>>;
        fn stream(&self, req: ChatRequest, sink: &mut dyn FnMut(StreamEvent)) -> Result<()>;
    }
    pub enum StreamEvent { Text(String), Reasoning(String), ToolCall(ToolCall),
        Usage(Usage), Done(StopReason), Error(String) }

Internal canonical message format is OpenAI-ish; adapters translate.

### emerag-agent

    pub trait Ui { fn event(&mut self, ev: UiEvent); fn ask(&mut self, q: &Question) -> Answer; }
    pub struct Agent { ... }
    impl Agent {
        pub fn run_turn(&mut self, user_input: &str, ui: &mut dyn Ui) -> Result<TurnResult>;
    }

Tools: shell, read, write, edit, list, glob, grep, script, ask_user, task
(subagent), job_start/job_output/job_list/job_kill, skill, mcp tool passthrough,
run_elevated. Permission modes: ask (default), auto, read-only, yolo. Approval
is a Ui callback; denied tools return an error string to the model.

## Provider catalog (embedded, extensible)

The catalog is data, not code. Each entry is a small struct literal compiled in:

- openai (Chat Completions, https://api.openai.com/v1)
- openai-responses (Responses API)
- anthropic (Messages, https://api.anthropic.com/v1)
- deepseek (Chat Completions, https://api.deepseek.com, models: deepseek-flash,
  deepseek-v4-pro; the same host also serves /anthropic and /responses paths)
- opencode-zen (OpenCode Console, https://opencode.ai/inference)
- opencode-go (Go plan gateway, https://opencode.ai/inference/go, needs a session header)
- ollama (http://127.0.0.1:11434/v1)
- llama.cpp server (http://127.0.0.1:9931/v1)
- lmstudio (http://127.0.0.1:1234/v1)
- custom (user-supplied endpoint, API kind selectable)

Discovery: GET /models with the profile's auth headers, parse OpenAI-style
data[].id or Anthropic data[].id; fall back to the embedded default_models if
the endpoint returns 404. Wizard verifies with a 1-token chat call.

## Security posture

- API keys never written to transcripts or logs; redact Authorization and
  x-api-key values in verbose output.
- Config file mode 0600 on Unix, created atomically.
- TLS verification on by default; --insecure prints a red warning every session.
- Tool execution is confined by permission mode; destructive commands are
  surfaced verbatim in the approval prompt and never auto-run in ask mode.
- Elevation is explicit per command: sudo -n first, then an interactive password
  prompt over /dev/tty (never echoed, never stored), with a timeout.

## Build matrix

Tier 1 (CI must produce): x86_64-unknown-linux-musl, aarch64-unknown-linux-musl,
x86_64-pc-windows-gnu, i686-pc-windows-gnu.
Tier 2 (best effort): i686/armv7/riscv64/s390x/loongarch64 musl,
aarch64-pc-windows-gnullvm, x86_64/aarch64-apple-darwin.

Old-OS support is measured, not assumed: scripts/compat-report.sh inspects the
import table and syscalls and prints the minimum OS/kernel.

## Working agreements for parallel work

- Each crate is owned by one author at a time. Do not edit other crates.
- Add tests in the crate you own. Run `cargo test -p <crate>`.
- Never add a dependency to Cargo.toml (the workspace has none on purpose).
- Keep public APIs as specified above; propose changes in your report instead
  of diverging silently.
- Format with `cargo fmt` if available; keep comments factual.
- Do not commit; the integrator handles git.
