//! Turn configuration into a live provider client.

use crate::args::Cli;
use crate::config::Config;
use emerag_http::{ProxyConfig, ResolveTable, TlsOptions, TlsVerify};
use emerag_llm::{ApiKind, ClientConfig, Credentials, Provider};
use std::time::Duration;

pub fn profile_id(cfg: &Config) -> String {
    if !cfg.provider.is_empty() {
        return cfg.provider.clone();
    }
    if let Some(p) = emerag_llm::catalog::detect_from_url(&cfg.base_url) {
        return p.id.to_string();
    }
    "custom".to_string()
}

pub fn api_kind(cfg: &Config) -> ApiKind {
    if let Some(k) = ApiKind::parse(&cfg.api) {
        return k;
    }
    if let Some(p) = emerag_llm::catalog::find(&profile_id(cfg)) {
        return p.api;
    }
    for entry in &cfg.custom_profiles {
        if entry.get("id").and_then(|x| x.as_str()) == Some(cfg.provider.as_str()) {
            if let Some(api) = entry.get("api").and_then(|x| x.as_str()) {
                if let Some(k) = ApiKind::parse(api) {
                    return k;
                }
            }
        }
    }
    ApiKind::ChatCompletions
}

pub fn client_config(cfg: &Config, _cli: &Cli) -> Result<ClientConfig, String> {
    let profile = emerag_llm::catalog::find(&profile_id(cfg));
    let base_url = if !cfg.base_url.trim().is_empty() {
        cfg.base_url.clone()
    } else if let Some(p) = profile {
        p.base_url.to_string()
    } else {
        cfg.custom_profiles
            .iter()
            .find(|v| v.get("id").and_then(|x| x.as_str()) == Some(cfg.provider.as_str()))
            .and_then(|v| v.get("base_url").and_then(|x| x.as_str()))
            .unwrap_or("")
            .to_string()
    };
    if base_url.trim().is_empty() {
        return Err("no endpoint configured: run --wizard or pass --base-url".into());
    }
    let url = emerag_http::Url::parse(&base_url).map_err(|e| format!("bad endpoint: {e}"))?;
    let api = api_kind(cfg);

    let mut headers = Vec::new();
    if let Some(p) = profile {
        for (k, v) in p.headers {
            headers.push((k.to_string(), v.to_string()));
        }
    }
    headers.extend(cfg_headers(cfg));

    let mut dns_servers: Vec<std::net::IpAddr> = Vec::new();
    for spec in &cfg.network.dns {
        let ip: std::net::IpAddr = spec
            .trim()
            .trim_start_matches('[')
            .trim_end_matches(']')
            .parse()
            .map_err(|_| format!("bad --dns '{spec}' (expected an IP address)"))?;
        if !dns_servers.contains(&ip) {
            dns_servers.push(ip);
        }
    }
    let dns_first = !dns_servers.is_empty();
    if dns_servers.is_empty() {
        dns_servers = emerag_http::dns::discover().servers;
    }

    let mut resolve = ResolveTable::new();
    for spec in &cfg.network.resolve {
        resolve
            .parse_entry(spec)
            .map_err(|e| format!("bad --resolve '{spec}': {e}"))?;
    }
    if let Some(ip) = &cfg.network.ip {
        let ip: std::net::IpAddr = ip
            .trim()
            .trim_start_matches('[')
            .trim_end_matches(']')
            .parse()
            .map_err(|_| format!("bad --ip '{ip}'"))?;
        resolve.add(&url.host, Some(url.port), ip);
    }

    let tls = TlsOptions {
        verify: if cfg.network.insecure {
            TlsVerify::Insecure
        } else if let Some(path) = &cfg.network.cacert {
            let pem =
                std::fs::read(path).map_err(|e| format!("cannot read --cacert {path}: {e}"))?;
            TlsVerify::CaFile(pem)
        } else {
            #[cfg(feature = "lite")]
            {
                TlsVerify::Insecure
            }
            #[cfg(not(feature = "lite"))]
            {
                TlsVerify::EmbeddedCa
            }
        },
        sni: None,
        alpn: vec!["http/1.1".into()],
        client_cert_pem: None,
        client_key_pem: None,
    };

    let proxy = match &cfg.network.proxy {
        Some(p) => {
            let target =
                emerag_http::proxy::parse_proxy(p).map_err(|e| format!("bad proxy: {e}"))?;
            if target.scheme != "http" {
                return Err(format!(
                    "only http:// proxies are supported (got {})",
                    target.scheme
                ));
            }
            Some(ProxyConfig {
                all: Some(p.trim().to_string()),
                ..Default::default()
            })
        }
        None => {
            let env = ProxyConfig::from_env();
            if env.is_empty() {
                None
            } else {
                Some(env)
            }
        }
    };

    let mut cc = match profile {
        Some(p) => ClientConfig::new(p, cfg.model.clone()),
        None => {
            let mut cc = ClientConfig {
                profile_id: "custom".into(),
                base_url: cfg.base_url.trim_end_matches('/').to_string(),
                api,
                model: cfg.model.clone(),
                credentials: Credentials::none(),
                user_agent: format!("emerag/{}", env!("CARGO_PKG_VERSION")),
                timeout: Duration::from_secs(120),
                stream: true,
                verbose: false,
                extra_body: emerag_json::Map::new(),
                extra_headers: Vec::new(),
                resolve: ResolveTable::new(),
                tls: TlsOptions::default(),
                proxy: None,
                dns_servers: Vec::new(),
                dns_first: false,
            };
            cc.api = api;
            cc
        }
    };
    cc.base_url = base_url.trim_end_matches('/').to_string();
    cc.api = api;
    cc.model = cfg.model.clone();
    cc.credentials = Credentials {
        api_key: cfg.api_key.clone(),
        account_token: if cfg.account_token.is_empty() {
            None
        } else {
            Some(cfg.account_token.clone())
        },
        extra_headers: headers.clone(),
    };
    cc.extra_headers = headers;
    cc.resolve = resolve;
    cc.tls = tls;
    cc.proxy = proxy;
    cc.dns_servers = dns_servers;
    cc.dns_first = dns_first;
    cc.timeout = Duration::from_secs(cfg.network.timeout_secs.max(5));
    cc.verbose = cfg.mode == crate::config::PermissionMode::Yolo && false;
    Ok(cc)
}

fn cfg_headers(cfg: &Config) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for p in &cfg.custom_profiles {
        if p.get("id").and_then(|v| v.as_str()) == Some(cfg.provider.as_str()) {
            if let Some(h) = p.get("headers").and_then(|v| v.as_object()) {
                for (k, v) in h.iter() {
                    if let Some(s) = v.as_str() {
                        out.push((k.clone(), s.to_string()));
                    }
                }
            }
        }
    }
    out
}

#[derive(Clone, Debug)]
pub struct ConfiguredProvider {
    pub id: String,
    pub name: String,
    pub base_url: String,
    pub api: String,
    pub model: String,
}

pub fn display_name(cfg: &Config) -> String {
    if cfg.provider.is_empty() {
        return "custom (unconfigured)".to_string();
    }
    if !cfg.provider_name.is_empty() {
        return cfg.provider_name.clone();
    }
    if let Some(entry) = cfg
        .custom_profiles
        .iter()
        .find(|v| v.get("id").and_then(|x| x.as_str()) == Some(cfg.provider.as_str()))
    {
        if let Some(name) = entry.get("name").and_then(|x| x.as_str()) {
            if !name.is_empty() {
                return name.to_string();
            }
        }
    }
    if let Some(p) = emerag_llm::catalog::find(&profile_id(cfg)) {
        return p.label.to_string();
    }
    if cfg.provider.is_empty() {
        "custom".to_string()
    } else {
        cfg.provider.clone()
    }
}

fn saved_entry(cfg: &Config, id: &str) -> Option<ConfiguredProvider> {
    cfg.custom_profiles.iter().find_map(|v| {
        if v.get("id").and_then(|x| x.as_str()) != Some(id) {
            return None;
        }
        Some(ConfiguredProvider {
            id: id.to_string(),
            name: v
                .get("name")
                .and_then(|x| x.as_str())
                .unwrap_or(id)
                .to_string(),
            base_url: v
                .get("base_url")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string(),
            api: v
                .get("api")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string(),
            model: v
                .get("model")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string(),
        })
    })
}

/// Providers the user has actually configured. The embedded catalog is not
/// dumped here; /provider offers a separate "configure another" entry.
pub fn configured(cfg: &Config) -> Vec<ConfiguredProvider> {
    let mut out = Vec::new();
    let current = ConfiguredProvider {
        id: cfg.provider.clone(),
        name: display_name(cfg),
        base_url: cfg.base_url.clone(),
        api: cfg.api.clone(),
        model: cfg.model.clone(),
    };
    if !current.id.is_empty() {
        out.push(current.clone());
    }
    for v in &cfg.custom_profiles {
        let Some(id) = v.get("id").and_then(|x| x.as_str()) else {
            continue;
        };
        if id == current.id || out.iter().any(|p| p.id == id) {
            continue;
        }
        if let Some(p) = saved_entry(cfg, id) {
            out.push(p);
        }
    }
    out
}

pub fn apply(cfg: &mut Config, p: &ConfiguredProvider) {
    cfg.provider = p.id.clone();
    cfg.provider_name = p.name.clone();
    if !p.base_url.is_empty() {
        cfg.base_url = p.base_url.clone();
    } else if let Some(profile) = emerag_llm::catalog::find(&p.id) {
        cfg.base_url = profile.base_url.to_string();
        if cfg.api.is_empty() {
            cfg.api = profile.api.as_str().to_string();
        }
    }
    if !p.api.is_empty() {
        cfg.api = p.api.clone();
    }
    cfg.model = if p.model.is_empty() {
        emerag_llm::catalog::find(&p.id)
            .map(|profile| profile.default_model().to_string())
            .unwrap_or_default()
    } else {
        p.model.clone()
    };
}

pub fn custom_id(cfg: &Config, name: &str) -> String {
    let mut slug: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect();
    while slug.contains("--") {
        slug = slug.replace("--", "-");
    }
    let slug = slug.trim_matches('-');
    let base = if slug.is_empty() {
        format!("custom-{}", cfg.custom_profiles.len() + 1)
    } else {
        format!("custom-{slug}")
    };
    let mut id = base.clone();
    let mut n = 2;
    while emerag_llm::catalog::find(&id).is_some()
        || cfg
            .custom_profiles
            .iter()
            .any(|v| v.get("id").and_then(|x| x.as_str()) == Some(id.as_str()))
    {
        id = format!("{base}-{n}");
        n += 1;
    }
    id
}

/// Persist the active endpoint as a named provider entry (without secrets).
pub fn remember(cfg: &mut Config) {
    if cfg.provider.is_empty() || cfg.base_url.is_empty() {
        return;
    }
    let id = cfg.provider.clone();
    let name = display_name(cfg);
    let mut entry = emerag_json::Map::new();
    entry.insert("id".into(), emerag_json::Value::String(id.clone()));
    entry.insert("name".into(), emerag_json::Value::String(name));
    entry.insert(
        "base_url".into(),
        emerag_json::Value::String(cfg.base_url.clone()),
    );
    entry.insert("api".into(), emerag_json::Value::String(cfg.api.clone()));
    entry.insert(
        "model".into(),
        emerag_json::Value::String(cfg.model.clone()),
    );
    let entry = emerag_json::Value::Object(entry);
    if let Some(slot) = cfg
        .custom_profiles
        .iter_mut()
        .find(|v| v.get("id").and_then(|x| x.as_str()) == Some(id.as_str()))
    {
        *slot = entry;
    } else {
        cfg.custom_profiles.push(entry);
    }
}

pub fn build(cfg: &Config, cli: &Cli) -> Result<Box<dyn Provider>, String> {
    let cc = client_config(cfg, cli)?;
    emerag_llm::client::build(&cc).map_err(|e| format!("{e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_empty_endpoint() {
        let cfg = Config::default();
        let cli = Cli::default();
        assert!(client_config(&cfg, &cli).is_err());
    }

    #[test]
    fn named_custom_provider_is_remembered_and_listed() {
        let mut cfg = Config::default();
        cfg.provider = "custom-router".into();
        cfg.provider_name = "Router".into();
        cfg.base_url = "http://192.168.1.1:8080/v1".into();
        cfg.api = "chat".into();
        cfg.model = "tiny".into();
        remember(&mut cfg);
        let list = configured(&cfg);
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].name, "Router");
        assert_eq!(list[0].base_url, "http://192.168.1.1:8080/v1");
        let id = custom_id(&cfg, "Edge Box");
        assert!(id.starts_with("custom-edge-box"));
        assert_ne!(id, "custom-router");
    }

    #[test]
    fn saved_custom_endpoint_resolves_without_cli_base() {
        let mut cfg = Config::default();
        cfg.provider = "custom-edge".into();
        cfg.custom_profiles.push(emerag_json::json!({
            "id": "custom-edge",
            "name": "Edge",
            "base_url": "http://10.0.0.2:8000/v1",
            "api": "chat",
            "model": "m"
        }));
        let cc = client_config(&cfg, &Cli::default()).unwrap();
        assert_eq!(cc.base_url, "http://10.0.0.2:8000/v1");
        assert_eq!(cc.api, ApiKind::ChatCompletions);
    }

    #[test]
    fn builds_local_config() {
        let mut cfg = Config::default();
        cfg.base_url = "http://127.0.0.1:11434/v1".into();
        cfg.model = "llama3".into();
        let cc = client_config(&cfg, &Cli::default()).unwrap();
        assert_eq!(cc.api, ApiKind::ChatCompletions);
        assert_eq!(cc.model, "llama3");
        assert!(cc.credentials.api_key.is_empty());
    }
}
