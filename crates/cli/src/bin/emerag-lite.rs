//! emerag-lite: the emergency core.
//!
//! This binary deliberately does not use emerag-llm or emerag-agent. It reuses
//! only the portable substrate (TLS, HTTP, JSON, crypto) and implements one
//! Chat Completions tool loop with four tools:
//!
//!   shell, read_file, write_file, edit_file, list_dir
//!
//! It is built with the "lite" cargo feature (curated CA roots) and is meant
//! for ROM-constrained routers or for temporary RAM-only execution. No config
//! wizard, no MCP, no skills, no subagents, no sessions, no scripting.

use std::io::{BufRead, IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use emerag_http::{Client, Request, ResolveTable, SseDecoder, TlsOptions, TlsVerify, Url};
use emerag_json::{json, Map, Value};

const VERSION: &str = env!("CARGO_PKG_VERSION");
const MAX_TOOL_OUTPUT: usize = 32 * 1024;
const DEFAULT_MAX_TURNS: u32 = 8;

struct Opts {
    base_url: String,
    model: String,
    api_key: String,
    account_token: String,
    auto: bool,
    max_turns: u32,
    system_extra: String,
    config: Option<PathBuf>,
    dns: Vec<std::net::IpAddr>,
    resolve: Vec<String>,
    insecure: bool,
    cacert: Option<Vec<u8>>,
    prompt: String,
    doctor: bool,
}

impl Default for Opts {
    fn default() -> Self {
        Opts {
            base_url: String::new(),
            model: String::new(),
            api_key: String::new(),
            account_token: String::new(),
            auto: false,
            max_turns: DEFAULT_MAX_TURNS,
            system_extra: String::new(),
            config: None,
            dns: Vec::new(),
            resolve: Vec::new(),
            insecure: false,
            cacert: None,
            prompt: String::new(),
            doctor: false,
        }
    }
}

fn main() {
    let mut opts = Opts::default();
    if let Err(e) = parse_args(&mut opts) {
        eprintln!("emerag-lite: {e}");
        std::process::exit(2);
    }
    load_config(&mut opts);
    apply_env(&mut opts);
    if opts.doctor {
        doctor(&opts);
        return;
    }
    if opts.base_url.is_empty() || opts.model.is_empty() {
        eprintln!("emerag-lite: --base-url and --model are required");
        eprintln!(
            "  emerag-lite --base-url https://api.deepseek.com --model deepseek-flash -p \"hi\""
        );
        std::process::exit(2);
    }
    if opts.prompt.trim().is_empty() {
        if !std::io::stdin().is_terminal() {
            let mut s = String::new();
            if std::io::stdin().read_to_string(&mut s).is_ok() {
                opts.prompt = s;
            }
        }
    }
    let auto = opts.auto
        || std::env::var("EMERAG_YES")
            .map(|v| v == "1")
            .unwrap_or(false);
    opts.auto = auto;

    if opts.prompt.trim().is_empty() {
        interactive(&mut opts);
    } else {
        let prompt = opts.prompt.clone();
        match run(&mut opts, prompt.trim()) {
            Ok(()) => {}
            Err(e) => {
                eprintln!("emerag-lite: {e}");
                std::process::exit(1);
            }
        }
    }
}

fn parse_args(opts: &mut Opts) -> Result<(), String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    let mut words: Vec<String> = Vec::new();
    while i < args.len() {
        match args[i].as_str() {
            "-h" | "--help" => {
                print_help();
                std::process::exit(0);
            }
            "--version" | "-V" => {
                println!("emerag-lite {VERSION} (emergency core)");
                std::process::exit(0);
            }
            "--doctor" => opts.doctor = true,
            "--base-url" => {
                i += 1;
                opts.base_url = args.get(i).cloned().ok_or("--base-url needs a value")?;
            }
            "--model" => {
                i += 1;
                opts.model = args.get(i).cloned().ok_or("--model needs a value")?;
            }
            "--api-key" | "-k" => {
                i += 1;
                opts.api_key = args.get(i).cloned().ok_or("--api-key needs a value")?;
            }
            "--system" => {
                i += 1;
                opts.system_extra = args.get(i).cloned().ok_or("--system needs a value")?;
            }
            "--config" => {
                i += 1;
                opts.config = Some(PathBuf::from(
                    args.get(i).cloned().ok_or("--config needs a value")?,
                ));
            }
            "--dns" => {
                i += 1;
                let v = args.get(i).cloned().ok_or("--dns needs a value")?;
                let ip = v
                    .trim()
                    .trim_start_matches('[')
                    .trim_end_matches(']')
                    .parse()
                    .map_err(|_| format!("bad --dns '{v}'"))?;
                opts.dns.push(ip);
            }
            "--resolve" => {
                i += 1;
                opts.resolve
                    .push(args.get(i).cloned().ok_or("--resolve needs host:port:ip")?);
            }
            "--cacert" => {
                i += 1;
                let p = args.get(i).cloned().ok_or("--cacert needs a value")?;
                opts.cacert = Some(std::fs::read(&p).map_err(|e| format!("{p}: {e}"))?);
            }
            "--insecure" => opts.insecure = true,
            "--yes" | "-y" => opts.auto = true,
            "--ask" => opts.auto = false,
            "--max-turns" => {
                i += 1;
                opts.max_turns = args
                    .get(i)
                    .ok_or("--max-turns needs a value")?
                    .parse()
                    .map_err(|_| "bad --max-turns")?;
            }
            "-p" => {
                i += 1;
                let p = args.get(i).cloned().ok_or("-p needs a value")?;
                if !opts.prompt.is_empty() {
                    opts.prompt.push(' ');
                }
                opts.prompt.push_str(&p);
            }
            "--" => {
                i += 1;
                while i < args.len() {
                    words.push(args[i].clone());
                    i += 1;
                }
                break;
            }
            a if a.starts_with('-') => return Err(format!("unknown option '{a}'")),
            a => words.push(a.to_string()),
        }
        i += 1;
    }
    if !words.is_empty() {
        if !opts.prompt.is_empty() {
            opts.prompt.push(' ');
        }
        opts.prompt.push_str(&words.join(" "));
    }
    Ok(())
}

fn print_help() {
    println!(
        "emerag-lite {VERSION} - emergency core\n\
\n\
USAGE\n\
  emerag-lite --base-url URL --model ID [options] [prompt...]\n\
  emerag-lite -p \"prompt\"\n\
\n\
OPTIONS\n\
  --base-url URL       Chat Completions base (https://api.deepseek.com)\n\
  --model ID           model name\n\
  --api-key KEY, -k    API key (or EMERAG_API_KEY)\n\
  --yes, -y            run tools without asking (also EMERAG_YES=1)\n\
  --ask                ask before shell/write/edit\n\
  --max-turns N        tool loop limit (default {DEFAULT_MAX_TURNS})\n\
  --system TEXT        extra system instruction\n\
  --dns IP             nameserver fallback (repeatable)\n\
  --resolve H:P:IP     pin a host to an address (repeatable)\n\
  --cacert PATH        extra CA bundle\n\
  --insecure           disable TLS verification (dangerous)\n\
  --config PATH        read base/model/key from a JSON config\n\
  --doctor             print configuration and exit\n\
  --version, --help\n\
\n\
ENVIRONMENT\n\
  EMERAG_BASE_URL, EMERAG_MODEL, EMERAG_API_KEY, EMERAG_ACCOUNT_TOKEN\n\
"
    );
}

fn load_config(opts: &mut Opts) {
    let path = opts.config.clone().unwrap_or_else(default_config);
    let Ok(text) = std::fs::read_to_string(&path) else {
        return;
    };
    let Ok(v) = emerag_json::parse(&text) else {
        return;
    };
    let get = |k: &str| v.get(k).and_then(|x| x.as_str()).unwrap_or("").to_string();
    if opts.base_url.is_empty() {
        opts.base_url = get("base_url");
    }
    if opts.model.is_empty() {
        opts.model = get("model");
    }
    if opts.api_key.is_empty() {
        opts.api_key = get("api_key");
    }
    if opts.account_token.is_empty() {
        opts.account_token = get("account_token");
    }
    if opts.dns.is_empty() {
        if let Some(arr) = v
            .get("network")
            .and_then(|n| n.get("dns"))
            .and_then(|d| d.as_array())
        {
            for item in arr {
                if let Some(ip) = item.as_str().and_then(|s| s.parse().ok()) {
                    opts.dns.push(ip);
                }
            }
        }
    }
}

fn apply_env(opts: &mut Opts) {
    if opts.base_url.is_empty() {
        opts.base_url = std::env::var("EMERAG_BASE_URL").unwrap_or_default();
    }
    if opts.model.is_empty() {
        opts.model = std::env::var("EMERAG_MODEL").unwrap_or_default();
    }
    if opts.api_key.is_empty() {
        opts.api_key = std::env::var("EMERAG_API_KEY").unwrap_or_default();
    }
    if opts.account_token.is_empty() {
        opts.account_token = std::env::var("EMERAG_ACCOUNT_TOKEN").unwrap_or_default();
    }
}

fn default_config() -> PathBuf {
    if let Ok(p) = std::env::var("EMERAG_CONFIG") {
        return PathBuf::from(p);
    }
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .unwrap_or_else(|_| ".".into());
    PathBuf::from(home).join(".config/emerag/config.json")
}

fn doctor(opts: &Opts) {
    println!("emerag-lite {VERSION}");
    println!(
        "os:      {} {}",
        std::env::consts::OS,
        std::env::consts::ARCH
    );
    println!(
        "cwd:     {}",
        std::env::current_dir().unwrap_or_default().display()
    );
    println!(
        "endpoint:{}",
        if opts.base_url.is_empty() {
            "(unset)"
        } else {
            &opts.base_url
        }
    );
    println!(
        "model:   {}",
        if opts.model.is_empty() {
            "(unset)"
        } else {
            &opts.model
        }
    );
    println!(
        "auth:    {}",
        if !opts.account_token.is_empty() {
            "account grant"
        } else if !opts.api_key.is_empty() {
            "api key"
        } else {
            "(none)"
        }
    );
    let d = emerag_http::dns::discover();
    println!(
        "dns:     {} ({})",
        d.servers
            .iter()
            .map(|i| i.to_string())
            .collect::<Vec<_>>()
            .join(", "),
        d.source
    );
    println!("tools:   shell, read_file, write_file, edit_file, list_dir");
}

fn interactive(opts: &mut Opts) {
    println!("emerag-lite {VERSION} - type /quit to exit, /clear to reset");
    let mut history: Vec<Value> = Vec::new();
    loop {
        print!("emerag-lite> ");
        let _ = std::io::stdout().flush();
        let mut line = String::new();
        match std::io::stdin().lock().read_line(&mut line) {
            Ok(0) => break,
            Ok(_) => {}
            Err(e) => {
                eprintln!("input: {e}");
                break;
            }
        }
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        match line {
            "/quit" | "/exit" | "/q" => break,
            "/clear" => {
                history.clear();
                println!("conversation cleared");
            }
            "/help" => print_help(),
            _ => {
                if let Err(e) = run_with_history(opts, line, &mut history) {
                    eprintln!("emerag-lite: {e}");
                }
            }
        }
    }
}

fn run(opts: &mut Opts, prompt: &str) -> Result<(), String> {
    let mut history = Vec::new();
    run_with_history(opts, prompt, &mut history)
}

fn run_with_history(opts: &mut Opts, prompt: &str, history: &mut Vec<Value>) -> Result<(), String> {
    let client = make_client(opts)?;
    let url = endpoint(&opts.base_url)?;
    let mut system = system_prompt();
    if !opts.system_extra.is_empty() {
        system.push_str("\n");
        system.push_str(&opts.system_extra);
    }
    if history.is_empty() {
        history.push(obj([("role", vstr("system")), ("content", vstr(&system))]));
    }
    history.push(obj([("role", vstr("user")), ("content", vstr(prompt))]));

    for _ in 0..opts.max_turns {
        let out = chat(&client, &url, opts, history)?;
        let mut assistant = Map::new();
        assistant.insert("role".into(), vstr("assistant"));
        assistant.insert(
            "content".into(),
            if out.content.is_empty() {
                Value::Null
            } else {
                vstr(&out.content)
            },
        );
        if !out.calls.is_empty() {
            let calls = out
                .calls
                .iter()
                .map(|c| {
                    obj([
                        ("id", vstr(&c.id)),
                        ("type", vstr("function")),
                        (
                            "function",
                            obj([("name", vstr(&c.name)), ("arguments", vstr(&c.args))]),
                        ),
                    ])
                })
                .collect();
            assistant.insert("tool_calls".into(), Value::Array(calls));
        }
        if !out.reasoning.is_empty() && is_deepseek(&opts.base_url) {
            assistant.insert("reasoning_content".into(), vstr(&out.reasoning));
        }
        history.push(Value::Object(assistant));

        if out.calls.is_empty() {
            return Ok(());
        }
        for call in &out.calls {
            eprintln!("[tool] {} {}", call.name, call.args);
            let result = execute(opts, call)?;
            history.push(obj([
                ("role", vstr("tool")),
                ("tool_call_id", vstr(&call.id)),
                ("content", vstr(&result)),
            ]));
        }
    }
    Err(format!("tool loop exceeded {} turns", opts.max_turns))
}

fn make_client(opts: &Opts) -> Result<Client, String> {
    let mut c = Client::default();
    if opts.resolve.is_empty() {
        c.resolve = ResolveTable::new();
    } else {
        c.resolve = ResolveTable::parse(&opts.resolve.join(",")).map_err(|e| e.to_string())?;
    }
    c.connect_timeout = Duration::from_secs(20);
    c.read_timeout = Duration::from_secs(300);
    c.user_agent = format!("emerag-lite/{VERSION}");
    if let Some(pem) = &opts.cacert {
        c.tls = TlsOptions {
            verify: TlsVerify::CaFile(pem.clone()),
            ..TlsOptions::new()
        };
    } else if opts.insecure {
        c.tls = TlsOptions {
            verify: TlsVerify::Insecure,
            ..TlsOptions::new()
        };
    }
    c.proxy = Some(emerag_http::ProxyConfig::from_env());
    if opts.dns.is_empty() {
        c.dns_servers = emerag_http::dns::discover().servers;
    } else {
        c.dns_servers = opts.dns.clone();
        c.dns_first = true;
    }
    Ok(c)
}

fn endpoint(base: &str) -> Result<Url, String> {
    let base = base.trim().trim_end_matches('/');
    let url = if base.ends_with("/chat/completions") {
        base.to_string()
    } else {
        format!("{base}/chat/completions")
    };
    Url::parse(&url).map_err(|e| format!("bad endpoint: {e}"))
}

fn is_deepseek(base: &str) -> bool {
    base.contains("deepseek.com")
}

struct Call {
    id: String,
    name: String,
    args: String,
}

struct ChatOut {
    content: String,
    reasoning: String,
    calls: Vec<Call>,
}

fn chat(client: &Client, url: &Url, opts: &Opts, messages: &[Value]) -> Result<ChatOut, String> {
    let mut body = Map::new();
    body.insert("model".into(), vstr(&opts.model));
    body.insert("messages".into(), Value::Array(messages.to_vec()));
    body.insert("stream".into(), Value::Bool(true));
    body.insert(
        "max_tokens".into(),
        Value::Number(emerag_json::Number::Int(4096)),
    );
    body.insert("tools".into(), tool_specs());
    body.insert("tool_choice".into(), vstr("auto"));
    let body = Value::Object(body);
    let bytes = emerag_json::to_string(&body).into_bytes();
    let mut req = Request::json(url.clone(), bytes);
    req = req.header("accept", "text/event-stream");
    if !opts.account_token.is_empty() {
        req = req.header("x-dsh-auth-token", opts.account_token.clone());
    } else if !opts.api_key.is_empty() {
        req = req.bearer(&opts.api_key);
    }
    let mut resp = client.send(req).map_err(|e| e.to_string())?;
    if !resp.is_success() {
        let text = resp.read_to_string_limited(64 * 1024).unwrap_or_default();
        return Err(format!("HTTP {}: {}", resp.status, first_line(&text)));
    }
    let ctype = resp.header("content-type").unwrap_or("").to_string();
    if ctype.contains("application/json") && !ctype.contains("event-stream") {
        let text = resp
            .read_to_string_limited(16 * 1024 * 1024)
            .map_err(|e| e.to_string())?;
        return parse_full(&text);
    }
    stream_response(&mut resp, opts)
}

fn stream_response(resp: &mut emerag_http::Response, _opts: &Opts) -> Result<ChatOut, String> {
    let mut decoder = SseDecoder::new();
    let mut buf = [0u8; 8192];
    let mut out = ChatOut {
        content: String::new(),
        reasoning: String::new(),
        calls: Vec::new(),
    };
    let mut reasoning_started = false;
    let mut content_started = false;
    loop {
        let n = resp.read_some(&mut buf).map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        for ev in decoder.feed(&buf[..n]) {
            if ev.data == "[DONE]" {
                return finish(out);
            }
            let Ok(v) = emerag_json::parse(&ev.data) else {
                continue;
            };
            let Some(choice) = v
                .get("choices")
                .and_then(|c| c.as_array())
                .and_then(|a| a.first())
            else {
                continue;
            };
            let Some(delta) = choice.get("delta") else {
                continue;
            };
            if let Some(r) = delta.get("reasoning_content").and_then(|x| x.as_str()) {
                if !reasoning_started {
                    eprintln!("[thinking]");
                    reasoning_started = true;
                }
                eprint!("{r}");
                let _ = std::io::stderr().flush();
                out.reasoning.push_str(r);
            }
            if let Some(c) = delta.get("content").and_then(|x| x.as_str()) {
                if !content_started {
                    if reasoning_started {
                        eprintln!();
                    }
                    content_started = true;
                }
                print!("{c}");
                let _ = std::io::stdout().flush();
                out.content.push_str(c);
            }
            if let Some(calls) = delta.get("tool_calls").and_then(|x| x.as_array()) {
                for tc in calls {
                    let idx = tc.get("index").and_then(|x| x.as_u64()).unwrap_or(0) as usize;
                    while out.calls.len() <= idx {
                        out.calls.push(Call {
                            id: String::new(),
                            name: String::new(),
                            args: String::new(),
                        });
                    }
                    let slot = &mut out.calls[idx];
                    if let Some(id) = tc.get("id").and_then(|x| x.as_str()) {
                        slot.id = id.to_string();
                    }
                    if let Some(f) = tc.get("function") {
                        if let Some(name) = f.get("name").and_then(|x| x.as_str()) {
                            if !name.is_empty() {
                                slot.name = name.to_string();
                            }
                        }
                        if let Some(args) = f.get("arguments").and_then(|x| x.as_str()) {
                            slot.args.push_str(args);
                        }
                    }
                }
            }
        }
    }
    finish(out)
}

fn finish(mut out: ChatOut) -> Result<ChatOut, String> {
    if out.content.is_empty() && out.calls.is_empty() {
        return Err("provider returned an empty response".into());
    }
    if out.content.starts_with('\n') {
        out.content.remove(0);
    }
    if !out.content.is_empty() {
        println!();
    }
    for (i, c) in out.calls.iter_mut().enumerate() {
        if c.id.is_empty() {
            c.id = format!("call_{i}");
        }
    }
    Ok(out)
}

fn parse_full(text: &str) -> Result<ChatOut, String> {
    let v = emerag_json::parse(text).map_err(|e| format!("bad JSON: {e}"))?;
    let msg = v
        .get("choices")
        .and_then(|c| c.as_array())
        .and_then(|a| a.first())
        .and_then(|c| c.get("message"))
        .ok_or("response has no message")?;
    let content = msg
        .get("content")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string();
    let reasoning = msg
        .get("reasoning_content")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string();
    let mut calls = Vec::new();
    if let Some(arr) = msg.get("tool_calls").and_then(|x| x.as_array()) {
        for c in arr {
            let f = c.get("function").unwrap_or(&Value::Null);
            calls.push(Call {
                id: c.get("id").and_then(|x| x.as_str()).unwrap_or("").into(),
                name: f.get("name").and_then(|x| x.as_str()).unwrap_or("").into(),
                args: f
                    .get("arguments")
                    .and_then(|x| x.as_str())
                    .unwrap_or("{}")
                    .into(),
            });
        }
    }
    if !content.is_empty() {
        println!("{content}");
    }
    Ok(ChatOut {
        content,
        reasoning,
        calls,
    })
}

fn system_prompt() -> String {
    let cwd = std::env::current_dir().unwrap_or_default();
    let os = std::env::consts::OS;
    let arch = std::env::consts::ARCH;
    format!(
        "You are emerag-lite, a tiny emergency coding agent.\n\
You operate a real machine through tools: shell, read_file, write_file, edit_file, list_dir.\n\
Inspect before changing. Keep answers short; the user may be on a serial console.\n\
Do not print secrets. If a command fails, read the error and adapt.\n\
Environment: {os} {arch}, cwd {}, shell {}.\n",
        cwd.display(),
        if cfg!(windows) { "cmd" } else { "sh" }
    )
}

fn tool_specs() -> Value {
    Value::Array(vec![
        tool(
            "shell",
            "Run a shell command and return stdout/stderr.",
            json!({
                "type": "object",
                "properties": {
                    "command": {"type": "string"},
                    "timeout_ms": {"type": "integer"}
                },
                "required": ["command"],
                "additionalProperties": false
            }),
        ),
        tool(
            "read_file",
            "Read a UTF-8 text file.",
            json!({
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    "offset": {"type": "integer"},
                    "limit": {"type": "integer"}
                },
                "required": ["path"],
                "additionalProperties": false
            }),
        ),
        tool(
            "write_file",
            "Create or overwrite a file.",
            json!({
                "type": "object",
                "properties": {"path": {"type": "string"}, "content": {"type": "string"}},
                "required": ["path", "content"],
                "additionalProperties": false
            }),
        ),
        tool(
            "edit_file",
            "Replace an exact string in a file.",
            json!({
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    "old_string": {"type": "string"},
                    "new_string": {"type": "string"},
                    "replace_all": {"type": "boolean"}
                },
                "required": ["path", "old_string", "new_string"],
                "additionalProperties": false
            }),
        ),
        tool(
            "list_dir",
            "List a directory.",
            json!({
                "type": "object",
                "properties": {"path": {"type": "string"}},
                "required": ["path"],
                "additionalProperties": false
            }),
        ),
    ])
}

fn tool(name: &str, desc: &str, params: Value) -> Value {
    obj([
        ("type", vstr("function")),
        (
            "function",
            obj([
                ("name", vstr(name)),
                ("description", vstr(desc)),
                ("parameters", params),
            ]),
        ),
    ])
}

fn execute(opts: &Opts, call: &Call) -> Result<String, String> {
    let args = emerag_json::parse(&call.args).unwrap_or_else(|_| Value::Object(Map::new()));
    let path = args.get("path").and_then(|x| x.as_str()).unwrap_or("");
    match call.name.as_str() {
        "shell" => {
            let cmd = args.get("command").and_then(|x| x.as_str()).unwrap_or("");
            if cmd.trim().is_empty() {
                return Err("empty command".into());
            }
            if !approve(opts, &format!("run: {cmd}"))? {
                return Ok("denied by user".into());
            }
            let timeout = args
                .get("timeout_ms")
                .and_then(|x| x.as_u64())
                .unwrap_or(120_000);
            run_shell(cmd, Duration::from_millis(timeout))
        }
        "read_file" => {
            let offset = args.get("offset").and_then(|x| x.as_u64()).unwrap_or(0) as usize;
            let limit = args.get("limit").and_then(|x| x.as_u64()).unwrap_or(400) as usize;
            let content = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
            let mut out = String::new();
            for (i, line) in content.lines().skip(offset).take(limit).enumerate() {
                out.push_str(&format!("{:5} {}\n", offset + i + 1, line));
            }
            Ok(truncate(out))
        }
        "write_file" => {
            let content = args.get("content").and_then(|x| x.as_str()).unwrap_or("");
            if !approve(opts, &format!("write {path} ({} bytes)", content.len()))? {
                return Ok("denied by user".into());
            }
            if let Some(parent) = Path::new(path).parent() {
                std::fs::create_dir_all(parent)
                    .map_err(|e| format!("{}: {e}", parent.display()))?;
            }
            std::fs::write(path, content).map_err(|e| format!("{path}: {e}"))?;
            Ok(format!("wrote {} bytes to {path}", content.len()))
        }
        "edit_file" => {
            let old = args
                .get("old_string")
                .and_then(|x| x.as_str())
                .unwrap_or("");
            let new = args
                .get("new_string")
                .and_then(|x| x.as_str())
                .unwrap_or("");
            let all = args
                .get("replace_all")
                .and_then(|x| x.as_bool())
                .unwrap_or(false);
            if !approve(opts, &format!("edit {path}"))? {
                return Ok("denied by user".into());
            }
            let text = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
            if !text.contains(old) {
                return Err("old_string not found".into());
            }
            let out = if all {
                text.replace(old, new)
            } else {
                text.replacen(old, new, 1)
            };
            std::fs::write(path, out).map_err(|e| format!("{path}: {e}"))?;
            Ok(format!("edited {path}"))
        }
        "list_dir" => {
            let dir = if path.is_empty() { "." } else { path };
            let mut entries: Vec<String> = std::fs::read_dir(dir)
                .map_err(|e| format!("{dir}: {e}"))?
                .filter_map(|e| e.ok())
                .map(|e| {
                    let mut name = e.file_name().to_string_lossy().into_owned();
                    if e.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                        name.push('/');
                    }
                    name
                })
                .collect();
            entries.sort();
            entries.truncate(300);
            Ok(truncate(entries.join("\n")))
        }
        other => Err(format!("unknown tool '{other}'")),
    }
}

fn approve(opts: &Opts, what: &str) -> Result<bool, String> {
    if opts.auto {
        return Ok(true);
    }
    if !std::io::stdin().is_terminal() {
        return Ok(false);
    }
    print!("{what}? [y/N] ");
    let _ = std::io::stdout().flush();
    let mut line = String::new();
    std::io::stdin()
        .lock()
        .read_line(&mut line)
        .map_err(|e| e.to_string())?;
    Ok(matches!(
        line.trim().to_ascii_lowercase().as_str(),
        "y" | "yes"
    ))
}

fn run_shell(command: &str, timeout: Duration) -> Result<String, String> {
    let mut cmd = if cfg!(windows) {
        let mut c = Command::new("cmd");
        c.arg("/C").arg(command);
        c
    } else {
        let mut c = Command::new("sh");
        c.arg("-c").arg(command);
        c
    };
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = cmd.spawn().map_err(|e| format!("spawn: {e}"))?;
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) => {
                if start.elapsed() > timeout {
                    let _ = child.kill();
                    break;
                }
                std::thread::sleep(Duration::from_millis(30));
            }
            Err(e) => return Err(format!("wait: {e}")),
        }
    }
    let out = child.wait_with_output().map_err(|e| e.to_string())?;
    let mut text = String::new();
    if !out.stdout.is_empty() {
        text.push_str(&String::from_utf8_lossy(&out.stdout));
    }
    if !out.stderr.is_empty() {
        if !text.is_empty() {
            text.push('\n');
        }
        text.push_str(&String::from_utf8_lossy(&out.stderr));
    }
    if text.trim().is_empty() {
        text = format!("(exit {})", out.status.code().unwrap_or(-1));
    }
    Ok(truncate(text))
}

fn truncate(mut s: String) -> String {
    if s.len() > MAX_TOOL_OUTPUT {
        s.truncate(MAX_TOOL_OUTPUT);
        s.push_str("\n[output truncated]");
    }
    s
}

fn first_line(s: &str) -> String {
    s.lines().next().unwrap_or("").chars().take(500).collect()
}

fn obj<const N: usize>(pairs: [(&str, Value); N]) -> Value {
    let mut m = Map::new();
    for (k, v) in pairs {
        m.insert(k.into(), v);
    }
    Value::Object(m)
}

fn vstr(s: impl Into<String>) -> Value {
    Value::String(s.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chat_endpoint_is_appended_once() {
        let a = endpoint("https://api.deepseek.com").unwrap();
        assert_eq!(a.host, "api.deepseek.com");
        assert_eq!(a.path, "/chat/completions");
        let b = endpoint("https://example.test/v1").unwrap();
        assert_eq!(b.path, "/v1/chat/completions");
        let c = endpoint("https://example.test/v1/chat/completions/").unwrap();
        assert_eq!(c.path, "/v1/chat/completions");
    }

    #[test]
    fn first_line_is_bounded() {
        let s = "a".repeat(2000)
            + "
second";
        assert!(first_line(&s).len() <= 500);
    }
}
