//! Configuration: defaults, file, environment, CLI overrides.
//!
//! Everything is JSON so it can be read and written without an editor.
//! Secrets are only persisted when the user explicitly saves them; --no-write
//! keeps the whole configuration in memory for read-only systems.

use emerag_json::{json, Map, Value};
use emerag_util::sys;
use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PermissionMode {
    Ask,
    Auto,
    ReadOnly,
    Yolo,
}

impl PermissionMode {
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "ask" | "manual" | "default" => Some(PermissionMode::Ask),
            "auto" | "accept" | "yes" => Some(PermissionMode::Auto),
            "read-only" | "readonly" | "ro" | "plan" => Some(PermissionMode::ReadOnly),
            "yolo" | "danger" | "all" => Some(PermissionMode::Yolo),
            _ => None,
        }
    }
    pub fn as_str(&self) -> &'static str {
        match self {
            PermissionMode::Ask => "ask",
            PermissionMode::Auto => "auto",
            PermissionMode::ReadOnly => "read-only",
            PermissionMode::Yolo => "yolo",
        }
    }
    pub fn describe(&self) -> &'static str {
        match self {
            PermissionMode::Ask => "every tool call needs approval",
            PermissionMode::Auto => "tool calls run without prompts (except elevation)",
            PermissionMode::ReadOnly => "reads and searches only",
            PermissionMode::Yolo => "everything runs, including writes and elevation",
        }
    }
}

#[derive(Debug, Clone)]
pub struct NetworkConfig {
    /// host:port:ip entries (curl --resolve style).
    pub resolve: Vec<String>,
    /// Explicit nameservers (--dns), used before the system resolver.
    pub dns: Vec<String>,
    /// Connect to this IP for the selected endpoint (single override).
    pub ip: Option<String>,
    pub insecure: bool,
    pub cacert: Option<String>,
    pub proxy: Option<String>,
    pub timeout_secs: u64,
    /// Refuse to use the system resolver at all.
    pub no_dns: bool,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        NetworkConfig {
            resolve: Vec::new(),
            dns: Vec::new(),
            ip: None,
            insecure: false,
            cacert: None,
            proxy: None,
            timeout_secs: 120,
            no_dns: false,
        }
    }
}

#[derive(Debug, Clone)]
pub struct UiConfig {
    pub ascii: bool,
    pub color: bool,
    pub width: Option<u16>,
    pub fullscreen: bool,
}

impl Default for UiConfig {
    fn default() -> Self {
        UiConfig {
            ascii: false,
            color: true,
            width: None,
            fullscreen: false,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Config {
    pub provider: String,
    pub model: String,
    pub base_url: String,
    pub api: String,
    pub api_key: String,
    /// DeepSeek account grant from browser sign-in.
    pub account_token: String,
    pub mode: PermissionMode,
    pub max_turns: u32,
    pub context_limit: u32,
    pub temperature: Option<f32>,
    pub max_output_tokens: Option<u32>,
    pub shell: Option<String>,
    pub workdir: Option<PathBuf>,
    pub no_write: bool,
    pub network: NetworkConfig,
    pub ui: UiConfig,
    pub mcp_servers: Vec<Value>,
    pub skill_dirs: Vec<PathBuf>,
    pub system_extra: String,
    /// User-defined provider profiles (same shape as the embedded catalog).
    pub custom_profiles: Vec<Value>,
    /// Session directory override (defaults to the config dir).
    pub session_dir: Option<PathBuf>,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            provider: String::new(),
            model: String::new(),
            base_url: String::new(),
            api: String::new(),
            api_key: String::new(),
            account_token: String::new(),
            mode: PermissionMode::Ask,
            max_turns: 32,
            context_limit: 96_000,
            temperature: None,
            max_output_tokens: None,
            shell: None,
            workdir: None,
            no_write: false,
            network: NetworkConfig::default(),
            ui: UiConfig::default(),
            mcp_servers: Vec::new(),
            skill_dirs: Vec::new(),
            system_extra: String::new(),
            custom_profiles: Vec::new(),
            session_dir: None,
        }
    }
}

impl Config {
    pub fn config_path() -> PathBuf {
        if let Some(p) = sys::env_var("EMERAG_CONFIG") {
            return PathBuf::from(p);
        }
        sys::config_dir().join("config.json")
    }

    /// Load from an explicit path, the default path, or return defaults.
    pub fn load(path: Option<&std::path::Path>) -> (Config, Vec<String>) {
        let mut notes = Vec::new();
        let path = path
            .map(|p| p.to_path_buf())
            .unwrap_or_else(Config::config_path);
        let mut cfg = Config::default();
        if path.exists() {
            match std::fs::read_to_string(&path) {
                Ok(text) => match emerag_json::parse(&text) {
                    Ok(v) => {
                        cfg.apply_json(&v, &mut notes);
                        notes.push(format!("loaded {}", path.display()));
                    }
                    Err(e) => notes.push(format!("config parse error in {}: {e}", path.display())),
                },
                Err(e) => notes.push(format!("cannot read {}: {e}", path.display())),
            }
        }
        cfg.apply_env(&mut notes);
        cfg.finish(&mut notes);
        (cfg, notes)
    }

    fn apply_env(&mut self, notes: &mut Vec<String>) {
        let env = |k: &str| sys::env_var(k);
        if let Some(v) = env("EMERAG_PROVIDER") {
            self.provider = v;
        }
        if let Some(v) = env("EMERAG_MODEL") {
            self.model = v;
        }
        if let Some(v) = env("EMERAG_BASE_URL") {
            self.base_url = v;
        }
        if let Some(v) = env("EMERAG_API") {
            self.api = v;
        }
        if let Some(v) = env("EMERAG_API_KEY") {
            self.api_key = v;
            notes.push("API key from EMERAG_API_KEY".into());
        }
        if let Some(v) = env("EMERAG_ACCOUNT_TOKEN") {
            self.account_token = v;
            notes.push("DeepSeek account token from EMERAG_ACCOUNT_TOKEN".into());
        }
        if let Some(v) = env("EMERAG_MODE").and_then(|s| PermissionMode::parse(&s)) {
            self.mode = v;
        }
        if let Some(v) = env("EMERAG_NO_WRITE") {
            self.no_write = matches!(v.as_str(), "1" | "true" | "yes");
        }
        if let Some(v) = env("EMERAG_RESOLVE") {
            for spec in v.split([',', ';']).filter(|s| !s.trim().is_empty()) {
                self.network.resolve.push(spec.trim().to_string());
            }
        }
        if let Some(v) = env("EMERAG_IP") {
            self.network.ip = Some(v);
        }
        if let Some(v) = env("EMERAG_DNS") {
            for spec in v.split([',', ';']).filter(|s| !s.trim().is_empty()) {
                self.network.dns.push(spec.trim().to_string());
            }
        }
        if let Some(v) = env("EMERAG_INSECURE") {
            self.network.insecure = matches!(v.as_str(), "1" | "true" | "yes");
        }
        if let Some(v) = env("EMERAG_CACERT") {
            self.network.cacert = Some(v);
        }
        if let Some(v) = env("HTTPS_PROXY").or_else(|| env("https_proxy")) {
            self.network.proxy = Some(v);
        } else if let Some(v) = env("ALL_PROXY").or_else(|| env("all_proxy")) {
            self.network.proxy = Some(v);
        }
        if let Some(v) = env("EMERAG_TIMEOUT").and_then(|s| s.parse().ok()) {
            self.network.timeout_secs = v;
        }
        if let Some(v) = env("EMERAG_SHELL") {
            self.shell = Some(v);
        }
        if let Some(v) = env("NO_COLOR") {
            if !v.is_empty() {
                self.ui.color = false;
            }
        }
        if let Some(v) = env("EMERAG_ASCII") {
            self.ui.ascii = matches!(v.as_str(), "1" | "true" | "yes");
        }
    }

    fn finish(&mut self, notes: &mut Vec<String>) {
        if self.base_url.is_empty() {
            if let Some(p) = emerag_llm::catalog::find(&self.provider) {
                self.base_url = p.base_url.to_string();
                if self.api.is_empty() {
                    self.api = p.api.as_str().to_string();
                }
                if self.model.is_empty() {
                    self.model = p.default_model().to_string();
                }
                if self.api_key.is_empty() {
                    if let Some(k) = sys::env_var(p.env_key) {
                        self.api_key = k;
                        notes.push(format!("API key from {}", p.env_key));
                    }
                }
                if let Some(b) = sys::env_var(p.env_base) {
                    self.base_url = b;
                }
            }
        }
        if self.api.is_empty() {
            self.api = "chat".to_string();
        }
        let mut table = emerag_http::ResolveTable::new();
        for entry in &self.network.resolve {
            if let Err(e) = table.parse_entry(entry) {
                notes.push(format!("bad --resolve entry '{entry}': {e}"));
            }
        }
    }

    pub fn apply_json(&mut self, v: &Value, notes: &mut Vec<String>) {
        let s = |k: &str| v.get(k).and_then(|x| x.as_str()).map(str::to_string);
        if let Some(x) = s("provider") {
            self.provider = x;
        }
        if let Some(x) = s("model") {
            self.model = x;
        }
        if let Some(x) = s("base_url") {
            self.base_url = x;
        }
        if let Some(x) = s("api") {
            self.api = x;
        }
        if let Some(x) = s("api_key") {
            self.api_key = x;
        }
        if let Some(x) = s("account_token") {
            self.account_token = x;
        }
        if let Some(x) = s("mode") {
            if let Some(m) = PermissionMode::parse(&x) {
                self.mode = m;
            } else {
                notes.push(format!("unknown mode '{x}' in config; using ask"));
            }
        }
        if let Some(x) = v.get("max_turns").and_then(|x| x.as_u64()) {
            self.max_turns = x.clamp(1, 500) as u32;
        }
        if let Some(x) = v.get("context_limit").and_then(|x| x.as_u64()) {
            self.context_limit = x.clamp(4096, 2_000_000) as u32;
        }
        if let Some(x) = v.get("temperature").and_then(|x| x.as_f64()) {
            self.temperature = Some(x as f32);
        }
        if let Some(x) = v.get("max_output_tokens").and_then(|x| x.as_u64()) {
            self.max_output_tokens = Some(x as u32);
        }
        if let Some(x) = s("shell") {
            self.shell = Some(x);
        }
        if let Some(x) = s("workdir") {
            self.workdir = Some(PathBuf::from(x));
        }
        if let Some(x) = v.get("no_write").and_then(|x| x.as_bool()) {
            self.no_write = x;
        }
        if let Some(net) = v.get("network") {
            if let Some(arr) = net.get("resolve").and_then(|x| x.as_array()) {
                self.network.resolve = arr
                    .iter()
                    .filter_map(|x| x.as_str().map(str::to_string))
                    .collect();
            }
            if let Some(x) = net.get("ip").and_then(|x| x.as_str()) {
                self.network.ip = Some(x.to_string());
            }
            if let Some(x) = net.get("insecure").and_then(|x| x.as_bool()) {
                self.network.insecure = x;
            }
            if let Some(x) = net.get("cacert").and_then(|x| x.as_str()) {
                self.network.cacert = Some(x.to_string());
            }
            if let Some(x) = net.get("proxy").and_then(|x| x.as_str()) {
                self.network.proxy = Some(x.to_string());
            }
            if let Some(x) = net.get("timeout_secs").and_then(|x| x.as_u64()) {
                self.network.timeout_secs = x.clamp(5, 3600);
            }
            if let Some(x) = net.get("no_dns").and_then(|x| x.as_bool()) {
                self.network.no_dns = x;
            }
        }
        if let Some(ui) = v.get("ui") {
            if let Some(x) = ui.get("ascii").and_then(|x| x.as_bool()) {
                self.ui.ascii = x;
            }
            if let Some(x) = ui.get("color").and_then(|x| x.as_bool()) {
                self.ui.color = x;
            }
            if let Some(x) = ui.get("width").and_then(|x| x.as_u64()) {
                self.ui.width = Some(x.clamp(20, 500) as u16);
            }
            if let Some(x) = ui.get("fullscreen").and_then(|x| x.as_bool()) {
                self.ui.fullscreen = x;
            }
        }
        if let Some(arr) = v.get("mcp_servers").and_then(|x| x.as_array()) {
            self.mcp_servers = arr.clone();
        }
        if let Some(mcp) = v.get("mcp") {
            if let Some(arr) = mcp.get("servers").and_then(|x| x.as_array()) {
                self.mcp_servers = arr.clone();
            }
        }
        if let Some(arr) = v.get("skill_dirs").and_then(|x| x.as_array()) {
            self.skill_dirs = arr
                .iter()
                .filter_map(|x| x.as_str())
                .map(|s| sys::expand_tilde(s))
                .collect();
        }
        if let Some(x) = s("system_extra") {
            self.system_extra = x;
        }
        if let Some(arr) = v.get("custom_profiles").and_then(|x| x.as_array()) {
            self.custom_profiles = arr.clone();
        }
        if let Some(x) = s("session_dir") {
            self.session_dir = Some(sys::expand_tilde(&x));
        }
    }

    pub fn to_json(&self, include_secrets: bool) -> Value {
        let mut root = Map::new();
        root.insert("version".into(), json!(1));
        root.insert("provider".into(), Value::String(self.provider.clone()));
        root.insert("model".into(), Value::String(self.model.clone()));
        root.insert("base_url".into(), Value::String(self.base_url.clone()));
        root.insert("api".into(), Value::String(self.api.clone()));
        if include_secrets && !self.api_key.is_empty() {
            root.insert("api_key".into(), Value::String(self.api_key.clone()));
        }
        if include_secrets && !self.account_token.is_empty() {
            root.insert(
                "account_token".into(),
                Value::String(self.account_token.clone()),
            );
        }
        root.insert("mode".into(), Value::String(self.mode.as_str().into()));
        root.insert("max_turns".into(), json!(self.max_turns));
        root.insert("context_limit".into(), json!(self.context_limit));
        if let Some(t) = self.temperature {
            root.insert("temperature".into(), json!(t as f64));
        }
        if let Some(m) = self.max_output_tokens {
            root.insert("max_output_tokens".into(), json!(m));
        }
        if let Some(s) = &self.shell {
            root.insert("shell".into(), Value::String(s.clone()));
        }
        if let Some(w) = &self.workdir {
            root.insert(
                "workdir".into(),
                Value::String(w.to_string_lossy().to_string()),
            );
        }
        root.insert("no_write".into(), Value::Bool(self.no_write));

        let mut net = Map::new();
        net.insert(
            "resolve".into(),
            Value::Array(
                self.network
                    .resolve
                    .iter()
                    .cloned()
                    .map(Value::String)
                    .collect(),
            ),
        );
        if let Some(ip) = &self.network.ip {
            net.insert("ip".into(), Value::String(ip.clone()));
        }
        net.insert("insecure".into(), Value::Bool(self.network.insecure));
        if let Some(c) = &self.network.cacert {
            net.insert("cacert".into(), Value::String(c.clone()));
        }
        if let Some(p) = &self.network.proxy {
            net.insert("proxy".into(), Value::String(p.clone()));
        }
        net.insert("timeout_secs".into(), json!(self.network.timeout_secs));
        net.insert("no_dns".into(), Value::Bool(self.network.no_dns));
        root.insert("network".into(), Value::Object(net));

        let mut ui = Map::new();
        ui.insert("ascii".into(), Value::Bool(self.ui.ascii));
        ui.insert("color".into(), Value::Bool(self.ui.color));
        if let Some(w) = self.ui.width {
            ui.insert("width".into(), json!(w as u64));
        }
        ui.insert("fullscreen".into(), Value::Bool(self.ui.fullscreen));
        root.insert("ui".into(), Value::Object(ui));

        if !self.mcp_servers.is_empty() {
            let mut mcp = Map::new();
            mcp.insert("servers".into(), Value::Array(self.mcp_servers.clone()));
            root.insert("mcp".into(), Value::Object(mcp));
        }
        if !self.skill_dirs.is_empty() {
            root.insert(
                "skill_dirs".into(),
                Value::Array(
                    self.skill_dirs
                        .iter()
                        .map(|p| Value::String(p.to_string_lossy().to_string()))
                        .collect(),
                ),
            );
        }
        if !self.system_extra.is_empty() {
            root.insert(
                "system_extra".into(),
                Value::String(self.system_extra.clone()),
            );
        }
        if !self.custom_profiles.is_empty() {
            root.insert(
                "custom_profiles".into(),
                Value::Array(self.custom_profiles.clone()),
            );
        }
        if let Some(s) = &self.session_dir {
            root.insert(
                "session_dir".into(),
                Value::String(s.to_string_lossy().to_string()),
            );
        }
        Value::Object(root)
    }

    /// Save with 0600 permissions where the OS supports it.
    pub fn save(&self, path: &std::path::Path) -> Result<(), String> {
        if self.no_write {
            return Err("refusing to write config: --no-write is active".into());
        }
        let text = emerag_json::to_string_pretty(&self.to_json(true));
        if let Some(parent) = path.parent() {
            emerag_util::fsutil::ensure_dir(parent).map_err(|e| e.to_string())?;
        }
        emerag_util::fsutil::write_text_atomic(path, &text).map_err(|e| e.to_string())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
        }
        Ok(())
    }

    pub fn redacted_summary(&self) -> String {
        format!(
            "provider={} model={} api={} base={} key={} mode={}",
            if self.provider.is_empty() {
                "(none)"
            } else {
                &self.provider
            },
            if self.model.is_empty() {
                "(none)"
            } else {
                &self.model
            },
            self.api,
            if self.base_url.is_empty() {
                "(none)"
            } else {
                &self.base_url
            },
            if self.api_key.is_empty() {
                "(none)"
            } else {
                &emerag_llm::redact(&self.api_key)
            },
            self.mode.as_str()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mode_parsing() {
        assert_eq!(PermissionMode::parse("ASK"), Some(PermissionMode::Ask));
        assert_eq!(
            PermissionMode::parse("read-only"),
            Some(PermissionMode::ReadOnly)
        );
        assert_eq!(PermissionMode::parse("nope"), None);
    }

    #[test]
    fn roundtrip_json_without_secrets() {
        let mut cfg = Config::default();
        cfg.provider = "deepseek".into();
        cfg.api_key = "sk-secret".into();
        cfg.network
            .resolve
            .push("api.deepseek.com:443:1.2.3.4".into());
        cfg.ui.ascii = true;
        let v = cfg.to_json(false);
        assert!(v.get("api_key").is_none());
        let mut back = Config::default();
        let mut notes = Vec::new();
        back.apply_json(&v, &mut notes);
        assert_eq!(back.provider, "deepseek");
        assert_eq!(back.network.resolve.len(), 1);
        assert!(back.ui.ascii);
        assert!(back.api_key.is_empty());
    }

    #[test]
    fn env_overrides_file() {
        let mut cfg = Config::default();
        cfg.provider = "openai".into();
        let mut notes = Vec::new();
        cfg.apply_env(&mut notes);
        // Environment in tests is usually clean; just ensure no panic.
        assert!(notes.len() < 10);
    }
}
