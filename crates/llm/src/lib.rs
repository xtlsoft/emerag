//! emerag-llm - provider abstraction and wire adapters.
//!
//! The agent speaks one canonical message format. Adapters translate it to:
//!   - OpenAI Chat Completions
//!   - OpenAI Responses
//!   - Anthropic Messages
//!   - any OpenAI-compatible local server (ollama, llama.cpp, lmstudio)
//!
//! The provider catalog is embedded data, not code: adding a provider means
//! adding one Profile entry (or shipping a JSON override at runtime).

pub mod catalog;
pub mod client;
pub mod deepseek_auth;
pub mod types;

pub use catalog::{Profile, Quirk};
pub use types::*;

use core::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error {
    pub kind: ErrorKind,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    Network,
    Auth,
    RateLimit,
    BadRequest,
    Server,
    Protocol,
    Cancelled,
    Config,
}

impl Error {
    pub fn new(kind: ErrorKind, message: impl Into<String>) -> Self {
        Error {
            kind,
            message: message.into(),
        }
    }

    pub fn network(msg: impl Into<String>) -> Self {
        Error::new(ErrorKind::Network, msg)
    }

    pub fn protocol(msg: impl Into<String>) -> Self {
        Error::new(ErrorKind::Protocol, msg)
    }

    pub fn config(msg: impl Into<String>) -> Self {
        Error::new(ErrorKind::Config, msg)
    }

    pub fn cancelled() -> Self {
        Error::new(ErrorKind::Cancelled, "cancelled")
    }

    /// True when the request can be retried after a delay.
    pub fn retryable(&self) -> bool {
        matches!(
            self.kind,
            ErrorKind::RateLimit | ErrorKind::Network | ErrorKind::Server
        )
    }

    /// Short hint for the UI, e.g. what the user should do next.
    pub fn hint(&self) -> &'static str {
        let m = self.message.to_ascii_lowercase();
        if m.contains("not signed in") || m.contains("dsh token") {
            return "the DeepSeek account grant was rejected; run /login deepseek";
        }
        if m.contains("certificate")
            || m.contains("no trusted root")
            || m.contains("handshake")
            || m.contains("tls:")
        {
            return "TLS failed: check the system clock, --cacert, or the endpoint hostname";
        }
        if m.contains("dns") || m.contains("resolve") || m.contains("lookup") {
            return "DNS failed: use --dns <ip>, --resolve host:443:IP or --ip <ip>";
        }
        if m.contains("connect") || m.contains("timed out") || m.contains("timeout") {
            return "cannot reach the endpoint: check host/port, proxy, firewall or DNS";
        }
        match self.kind {
            ErrorKind::Auth => "check the API key (/auth) or provider settings",
            ErrorKind::RateLimit => "rate limited: wait a moment or switch models (/model)",
            ErrorKind::Network => {
                "check DNS, endpoint, proxy; use --resolve host:443:IP or --dns <ip> if DNS is broken"
            }
            ErrorKind::BadRequest => "the request was rejected; try /compact or a different model",
            ErrorKind::Server => "provider error; retry or switch models",
            ErrorKind::Protocol => "unexpected provider response; try a different API kind",
            ErrorKind::Cancelled => "cancelled",
            ErrorKind::Config => "run the setup wizard (/wizard) or check /config",
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for Error {}

impl From<emerag_http::Error> for Error {
    fn from(e: emerag_http::Error) -> Self {
        let msg = e.to_string();
        let kind = if msg.contains("cancel") {
            ErrorKind::Cancelled
        } else if msg.contains("URL") || msg.contains("url") || msg.contains("scheme") {
            ErrorKind::Config
        } else if msg.contains("tls")
            || msg.contains("certificate")
            || msg.contains("connect")
            || msg.contains("io:")
        {
            ErrorKind::Network
        } else {
            ErrorKind::Protocol
        };
        Error::new(kind, msg)
    }
}

/// Provider credentials. Never logged.
#[derive(Clone)]
pub struct Credentials {
    pub api_key: String,
    /// DeepSeek account grant (x-dsh-auth-token), when signed in.
    pub account_token: Option<String>,
    pub extra_headers: Vec<(String, String)>,
}

impl Credentials {
    pub fn none() -> Self {
        Credentials {
            api_key: String::new(),
            account_token: None,
            extra_headers: Vec::new(),
        }
    }

    pub fn key(key: impl Into<String>) -> Self {
        Credentials {
            api_key: key.into(),
            account_token: None,
            extra_headers: Vec::new(),
        }
    }

    pub fn account(token: impl Into<String>) -> Self {
        Credentials {
            api_key: String::new(),
            account_token: Some(token.into()),
            extra_headers: Vec::new(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.api_key.is_empty() && self.account_token.is_none() && self.extra_headers.is_empty()
    }

    pub fn redacted(&self) -> String {
        if let Some(t) = &self.account_token {
            format!("account {}", redact(t))
        } else if self.api_key.is_empty() {
            "(none)".to_string()
        } else {
            redact(&self.api_key)
        }
    }
}

/// Show only a recognizable prefix/suffix of a secret.
pub fn redact(secret: &str) -> String {
    let chars: Vec<char> = secret.chars().collect();
    if chars.len() <= 8 {
        return "****".to_string();
    }
    let head: String = chars.iter().take(4).collect();
    let tail: String = chars.iter().skip(chars.len() - 4).collect();
    format!("{head}...{tail}")
}

/// What the client needs to talk to one provider.
#[derive(Clone)]
pub struct ClientConfig {
    pub profile_id: String,
    pub base_url: String,
    pub api: ApiKind,
    pub model: String,
    pub credentials: Credentials,
    pub user_agent: String,
    pub timeout: std::time::Duration,
    pub stream: bool,
    pub verbose: bool,
    /// Extra body fields merged into every request (provider-specific knobs).
    pub extra_body: emerag_json::Map,
    /// Extra headers merged into every request.
    pub extra_headers: Vec<(String, String)>,
    /// DNS override + TLS options are carried by the http client.
    pub resolve: emerag_http::ResolveTable,
    pub tls: emerag_http::TlsOptions,
    pub proxy: Option<emerag_http::ProxyConfig>,
    /// Extra nameservers for systems without a usable resolver (Termux).
    pub dns_servers: Vec<std::net::IpAddr>,
    pub dns_first: bool,
}

impl ClientConfig {
    pub fn new(profile: &Profile, model: impl Into<String>) -> Self {
        ClientConfig {
            profile_id: profile.id.to_string(),
            base_url: profile.base_url.trim_end_matches('/').to_string(),
            api: profile.api,
            model: model.into(),
            credentials: Credentials::none(),
            user_agent: format!("emerag/{}", env!("CARGO_PKG_VERSION")),
            timeout: std::time::Duration::from_secs(120),
            stream: true,
            verbose: false,
            extra_body: emerag_json::Map::new(),
            extra_headers: Vec::new(),
            resolve: emerag_http::ResolveTable::new(),
            tls: emerag_http::TlsOptions::new(),
            proxy: None,
            dns_servers: Vec::new(),
            dns_first: false,
        }
    }

    pub fn endpoint(&self, suffix: &str) -> String {
        format!(
            "{}/{}",
            self.base_url.trim_end_matches('/'),
            suffix.trim_start_matches('/')
        )
    }
}

/// Streaming callback: return false to abort the request.
pub type EventSink<'a> = dyn FnMut(StreamEvent) -> bool + 'a;

/// A client that can list models and stream completions.
pub trait Provider: Send + Sync {
    fn list_models(&self) -> Result<Vec<ModelInfo>, Error>;
    fn stream(&self, req: &ChatRequest, sink: &mut EventSink<'_>) -> Result<ChatResponse, Error>;
    /// Cheap connectivity/auth probe used by the wizard.
    fn probe(&self) -> Result<(), Error> {
        let models = self.list_models()?;
        if models.is_empty() {
            return Err(Error::new(
                ErrorKind::Protocol,
                "provider returned no models",
            ));
        }
        Ok(())
    }
}
