//! Diagnostics that answer: can this machine reach a model, and can emerag
//! actually run tools here?

use crate::config::Config;
use emerag_json::{Map, Value};
use emerag_util::sys;
use std::net::ToSocketAddrs;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Ok,
    Warn,
    Fail,
    Info,
}

impl Status {
    fn mark(self, ascii: bool) -> &'static str {
        match (self, ascii) {
            (Status::Ok, false) => "✓",
            (Status::Warn, false) => "!",
            (Status::Fail, false) => "✗",
            (Status::Info, false) => "·",
            (Status::Ok, true) => "OK",
            (Status::Warn, true) => "!",
            (Status::Fail, true) => "FAIL",
            (Status::Info, true) => "-",
        }
    }
    fn color(self) -> &'static str {
        match self {
            Status::Ok => "32",
            Status::Warn => "33",
            Status::Fail => "31",
            Status::Info => "2",
        }
    }
}

pub struct Check {
    pub status: Status,
    pub name: String,
    pub detail: String,
    pub hint: Option<String>,
}

pub struct Report {
    pub checks: Vec<Check>,
}

impl Report {
    fn add(&mut self, status: Status, name: impl Into<String>, detail: impl Into<String>) {
        self.checks.push(Check {
            status,
            name: name.into(),
            detail: detail.into(),
            hint: None,
        });
    }
    fn add_hint(
        &mut self,
        status: Status,
        name: impl Into<String>,
        detail: impl Into<String>,
        hint: impl Into<String>,
    ) {
        self.checks.push(Check {
            status,
            name: name.into(),
            detail: detail.into(),
            hint: Some(hint.into()),
        });
    }

    pub fn to_json(&self) -> Value {
        let mut m = Map::new();
        let mut arr = Vec::new();
        for c in &self.checks {
            let mut e = Map::new();
            e.insert(
                "status".into(),
                Value::String(
                    match c.status {
                        Status::Ok => "ok",
                        Status::Warn => "warn",
                        Status::Fail => "fail",
                        Status::Info => "info",
                    }
                    .into(),
                ),
            );
            e.insert("name".into(), Value::String(c.name.clone()));
            e.insert("detail".into(), Value::String(c.detail.clone()));
            if let Some(h) = &c.hint {
                e.insert("hint".into(), Value::String(h.clone()));
            }
            arr.push(Value::Object(e));
        }
        m.insert("checks".into(), Value::Array(arr));
        Value::Object(m)
    }

    pub fn failures(&self) -> usize {
        self.checks
            .iter()
            .filter(|c| c.status == Status::Fail)
            .count()
    }
}

pub fn run(cfg: &Config, ascii: bool, color: bool) -> Report {
    let mut r = Report { checks: Vec::new() };
    r.add(
        Status::Info,
        "emerag",
        format!("{} ({})", env!("CARGO_PKG_VERSION"), std::env::consts::ARCH),
    );
    r.add(
        Status::Info,
        "os",
        format!("{} {}", sys::os_name(), sys::hostname()),
    );
    r.add(
        Status::Info,
        "user",
        format!("{} (uid info unavailable)", sys::username()),
    );
    r.add(
        Status::Info,
        "cwd",
        sys::current_dir().display().to_string(),
    );

    // Terminal
    let caps = emerag_term::detect();
    let term = sys::env_var("TERM").unwrap_or_else(|| "(unset)".into());
    if caps.tty {
        r.add(
            Status::Ok,
            "terminal",
            format!(
                "{}x{} TERM={} ansi={} color={} unicode={}",
                caps.width, caps.height, term, caps.ansi, caps.color, caps.unicode
            ),
        );
    } else {
        r.add_hint(
            Status::Warn,
            "terminal",
            format!("not a TTY (TERM={term}); cooked line mode will be used"),
            "run from an interactive terminal for best experience",
        );
    }
    if term == "dumb" {
        r.add_hint(
            Status::Warn,
            "TERM=dumb",
            "no colors or cursor control",
            "use --ascii; slash commands still work",
        );
    }

    // Shells
    let shells = emerag_agent::tools::shell::available_shells();
    if shells.is_empty() {
        r.add_hint(
            Status::Fail,
            "shells",
            "no supported shell found",
            "the script tool still works; check PATH",
        );
    } else {
        let names: Vec<String> = shells.iter().map(|s| s.kind.name().to_string()).collect();
        r.add(Status::Ok, "shells", names.join(", "));
    }
    let chosen = emerag_agent::tools::shell::detect(cfg.shell.as_deref());
    r.add(Status::Info, "default shell", chosen.label());

    // Config / disk
    let path = Config::config_path();
    r.add(Status::Info, "config", path.display().to_string());
    if path.exists() {
        r.add(Status::Ok, "config file", "present");
    } else {
        r.add(
            Status::Info,
            "config file",
            "not written yet (wizard will create it)",
        );
    }
    let test_dir = cfg.workdir.clone().unwrap_or_else(sys::current_dir);
    if cfg.no_write {
        r.add(
            Status::Info,
            "writes",
            "disabled (--no-write): config and sessions stay in memory",
        );
    } else {
        let probe = test_dir.join(format!(".emerag-write-test-{}", std::process::id()));
        match std::fs::write(&probe, b"ok") {
            Ok(()) => {
                let _ = std::fs::remove_file(&probe);
                r.add(
                    Status::Ok,
                    "disk",
                    format!("writable: {}", test_dir.display()),
                );
            }
            Err(e) => r.add_hint(
                Status::Warn,
                "disk",
                format!("not writable: {test_dir:?}: {e}"),
                "use --no-write to keep state in memory",
            ),
        }
    }
    if !cfg.api_key.is_empty() {
        r.add(Status::Ok, "api key", emerag_llm::redact(&cfg.api_key));
    } else {
        r.add_hint(
            Status::Warn,
            "api key",
            "not set",
            "run --wizard or set EMERAG_API_KEY",
        );
    }
    r.add(
        Status::Info,
        "endpoint",
        if cfg.base_url.is_empty() {
            "(none)".into()
        } else {
            cfg.base_url.clone()
        },
    );
    r.add(
        Status::Info,
        "model",
        if cfg.model.is_empty() {
            "(none)".into()
        } else {
            cfg.model.clone()
        },
    );

    // Resolve overrides
    let mut overrides = emerag_http::ResolveTable::new();
    for spec in &cfg.network.resolve {
        match overrides.parse_entry(spec) {
            Ok(()) => r.add(Status::Ok, "resolve override", spec.clone()),
            Err(e) => r.add(Status::Fail, "resolve override", format!("{spec}: {e}")),
        }
    }

    // Network
    if cfg.base_url.is_empty() {
        r.add(
            Status::Info,
            "network",
            "no endpoint configured; skipping checks",
        );
    } else {
        match emerag_http::Url::parse(&cfg.base_url) {
            Err(e) => r.add_hint(
                Status::Fail,
                "endpoint url",
                e.to_string(),
                "endpoint must look like https://host/v1",
            ),
            Ok(url) => {
                let port = url.port;
                let mut addrs: Vec<std::net::SocketAddr> = Vec::new();
                let mut from_override = false;
                if let Some(ip) = cfg
                    .network
                    .ip
                    .as_deref()
                    .and_then(|s| s.parse::<std::net::IpAddr>().ok())
                {
                    addrs.push(std::net::SocketAddr::new(ip, port));
                    from_override = true;
                }
                if let Some(ip) = overrides.lookup(&url.host, port) {
                    addrs.push(std::net::SocketAddr::new(ip, port));
                    from_override = true;
                }
                if addrs.is_empty() && !cfg.network.no_dns {
                    let host = url.host.clone();
                    let (tx, rx) = std::sync::mpsc::channel();
                    std::thread::spawn(move || {
                        let res = (host.as_str(), port)
                            .to_socket_addrs()
                            .map(|it| it.collect::<Vec<_>>());
                        let _ = tx.send(res);
                    });
                    match rx.recv_timeout(Duration::from_secs(5)) {
                        Ok(Ok(list)) if !list.is_empty() => {
                            addrs = list;
                            r.add(
                                Status::Ok,
                                "dns",
                                format!(
                                    "{} -> {}",
                                    url.host,
                                    addrs
                                        .iter()
                                        .map(|a| a.ip().to_string())
                                        .collect::<Vec<_>>()
                                        .join(", ")
                                ),
                            );
                        }
                        Ok(Ok(_)) => r.add_hint(
                            Status::Fail,
                            "dns",
                            format!("{} resolved to nothing", url.host),
                            "use --resolve host:443:IP",
                        ),
                        Ok(Err(e)) => r.add_hint(
                            Status::Fail,
                            "dns",
                            format!("{}: {e}", url.host),
                            "use --resolve host:443:IP or --ip",
                        ),
                        Err(_) => r.add_hint(
                            Status::Fail,
                            "dns",
                            format!("resolver timed out for {}", url.host),
                            "use --resolve host:443:IP",
                        ),
                    }
                } else if cfg.network.no_dns {
                    r.add(
                        Status::Info,
                        "dns",
                        "disabled (--no-dns); only explicit addresses are used",
                    );
                }
                if from_override {
                    r.add(
                        Status::Ok,
                        "address",
                        addrs
                            .iter()
                            .map(|a| a.to_string())
                            .collect::<Vec<_>>()
                            .join(", "),
                    );
                }
                if let Some(addr) = addrs.first().copied() {
                    let start = Instant::now();
                    match std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(5)) {
                        Ok(stream) => {
                            r.add(
                                Status::Ok,
                                "tcp",
                                format!("{addr} connected in {}ms", start.elapsed().as_millis()),
                            );
                            if url.scheme == "https" {
                                let tls_cfg = emerag_tls::TlsConfig::new(url.host.clone());
                                match emerag_tls::TlsStream::connect(stream, &tls_cfg) {
                                    Ok(tls) => r.add(Status::Ok, "tls", format!("{:?} alpn={:?}", tls.version(), tls.alpn())),
                                    Err(e) => r.add_hint(Status::Fail, "tls", e.to_string(), "check --cacert, system time, or --insecure (not recommended)"),
                                }
                            }
                        }
                        Err(e) => r.add_hint(
                            Status::Fail,
                            "tcp",
                            format!("{addr}: {e}"),
                            "check firewall/proxy, or pin a different IP",
                        ),
                    }
                } else {
                    r.add_hint(
                        Status::Fail,
                        "tcp",
                        "no address to connect to",
                        "use --resolve host:443:IP",
                    );
                }
            }
        }
    }

    // Proxy env
    for var in ["HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY", "NO_PROXY"] {
        if let Some(v) = sys::env_var(var) {
            r.add(Status::Info, var, emerag_llm::redact(&v));
        }
    }

    report_summary(&r, ascii, color);
    r
}

fn report_summary(r: &Report, ascii: bool, color: bool) {
    let fails = r.failures();
    let summary = if fails == 0 {
        "all checks passed"
    } else {
        "some checks failed; see hints above"
    };
    let status = if fails == 0 { Status::Ok } else { Status::Fail };
    let mark = status.mark(ascii);
    if color {
        println!("\n\x1b[{}m{mark} {summary}\x1b[0m", status.color());
    } else {
        println!("\n{mark} {summary}");
    }
}

pub fn render(report: &Report, ascii: bool, color: bool) {
    for c in &report.checks {
        let mark = c.status.mark(ascii);
        let line = format!("{mark:>4}  {:<16} {}", c.name, c.detail);
        if color {
            println!("\x1b[{}m{}\x1b[0m", c.status.color(), line);
        } else {
            println!("{line}");
        }
        if let Some(h) = &c.hint {
            println!("          -> {h}");
        }
    }
}
