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
    ApiKind::ChatCompletions
}

pub fn client_config(cfg: &Config, _cli: &Cli) -> Result<ClientConfig, String> {
    let profile = emerag_llm::catalog::find(&profile_id(cfg));
    let base_url = if !cfg.base_url.trim().is_empty() {
        cfg.base_url.clone()
    } else if let Some(p) = profile {
        p.base_url.to_string()
    } else {
        String::new()
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
            TlsVerify::EmbeddedCa
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
