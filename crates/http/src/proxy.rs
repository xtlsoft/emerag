//! Proxy configuration from the environment (or an explicit value).
//!
//! Supported: plain HTTP forward proxying for http:// targets and CONNECT
//! tunnelling for https:// targets. Only http:// proxies are supported; an
//! https:// proxy is reported as an error rather than silently bypassed.

use emerag_util::base64;

use crate::error::{Error, Result};
use crate::url::Url;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProxyConfig {
    pub http: Option<String>,
    pub https: Option<String>,
    pub all: Option<String>,
    pub no_proxy: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyTarget {
    pub scheme: String,
    pub host: String,
    pub port: u16,
    /// Base64 of user:password, ready for Proxy-Authorization: Basic.
    pub auth: Option<String>,
}

impl ProxyConfig {
    pub fn new() -> Self {
        ProxyConfig::default()
    }

    /// Read HTTP_PROXY, HTTPS_PROXY, ALL_PROXY and NO_PROXY (either case).
    pub fn from_env() -> Self {
        ProxyConfig::from_lookup(|key| std::env::var(key).ok())
    }

    /// Same as from_env but with an injected lookup, for tests.
    pub fn from_lookup<F>(lookup: F) -> Self
    where
        F: Fn(&str) -> Option<String>,
    {
        let get = |names: &[&str]| {
            names
                .iter()
                .filter_map(|n| lookup(n))
                .map(|v| v.trim().to_string())
                .find(|v| !v.is_empty())
        };
        ProxyConfig {
            http: get(&["HTTP_PROXY", "http_proxy"]),
            https: get(&["HTTPS_PROXY", "https_proxy"]),
            all: get(&["ALL_PROXY", "all_proxy"]),
            no_proxy: get(&["NO_PROXY", "no_proxy"])
                .map(|v| {
                    v.split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect()
                })
                .unwrap_or_default(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.http.is_none() && self.https.is_none() && self.all.is_none()
    }

    /// Which proxy (if any) applies to url. Invalid proxy URLs are errors, not
    /// silent bypasses.
    pub fn for_url(&self, url: &Url) -> Result<Option<ProxyTarget>> {
        if self.bypasses(url) {
            return Ok(None);
        }
        let chosen = if url.scheme == "https" {
            self.https.as_deref().or(self.all.as_deref())
        } else {
            self.http.as_deref().or(self.all.as_deref())
        };
        match chosen {
            None => Ok(None),
            Some(spec) => parse_proxy(spec).map(Some),
        }
    }

    pub fn bypasses(&self, url: &Url) -> bool {
        bypasses(&self.no_proxy, &url.host, url.port)
    }
}

pub fn parse_proxy(spec: &str) -> Result<ProxyTarget> {
    let url = Url::parse(spec).map_err(|e| e.context("invalid proxy URL"))?;
    if url.scheme != "http" {
        return Err(Error::new(format!(
            "unsupported proxy scheme {} (only http:// proxies are supported)",
            url.scheme
        )));
    }
    let auth = url.user.as_ref().map(|user| {
        let pass = url.pass.clone().unwrap_or_default();
        base64::encode(format!("{user}:{pass}").as_bytes())
    });
    Ok(ProxyTarget {
        scheme: url.scheme,
        host: url.host,
        port: url.port,
        auth,
    })
}

fn bypasses(no_proxy: &[String], host: &str, port: u16) -> bool {
    let host = host.to_ascii_lowercase();
    for entry in no_proxy {
        let e = entry.trim().to_ascii_lowercase();
        if e.is_empty() {
            continue;
        }
        if e == "*" {
            return true;
        }
        let (ehost, eport) = split_host_port(&e);
        if let Some(p) = eport {
            if p != port {
                continue;
            }
        }
        let ehost = ehost.trim_start_matches('.');
        if ehost.is_empty() {
            continue;
        }
        let suffix = format!(".{ehost}");
        if host == ehost || host.ends_with(&suffix) {
            return true;
        }
    }
    false
}

fn split_host_port(s: &str) -> (&str, Option<u16>) {
    if let Some(rest) = s.strip_prefix('[') {
        if let Some(end) = rest.find(']') {
            let host = &rest[..end];
            let after = &rest[end + 1..];
            let port = after.strip_prefix(':').and_then(|p| p.parse::<u16>().ok());
            return (host, port);
        }
        return (s, None);
    }
    if s.matches(':').count() == 1 {
        if let Some((h, p)) = s.split_once(':') {
            if let Ok(port) = p.parse::<u16>() {
                return (h, Some(port));
            }
        }
    }
    (s, None)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn url(s: &str) -> Url {
        Url::parse(s).unwrap()
    }

    #[test]
    fn env_lookup_prefers_lowercase_fallback() {
        let cfg = ProxyConfig::from_lookup(|key| match key {
            "HTTP_PROXY" => Some("http://proxy.local:3128".to_string()),
            "NO_PROXY" => Some("localhost, .internal, 127.0.0.1:8080".to_string()),
            _ => None,
        });
        assert_eq!(cfg.http.as_deref(), Some("http://proxy.local:3128"));
        assert!(cfg.https.is_none());
        assert_eq!(cfg.no_proxy.len(), 3);
        let target = cfg.for_url(&url("http://example.com/x")).unwrap().unwrap();
        assert_eq!(target.host, "proxy.local");
        assert_eq!(target.port, 3128);
        assert!(target.auth.is_none());
    }

    #[test]
    fn empty_env_var_falls_through_to_lowercase() {
        let cfg = ProxyConfig::from_lookup(|key| match key {
            "HTTP_PROXY" => Some(String::new()),
            "http_proxy" => Some("http://lower:3128".to_string()),
            _ => None,
        });
        assert_eq!(cfg.http.as_deref(), Some("http://lower:3128"));
    }

    #[test]
    fn https_proxy_selection_and_all_fallback() {
        let mut cfg = ProxyConfig::new();
        cfg.all = Some("http://fallback:8080".to_string());
        assert_eq!(
            cfg.for_url(&url("https://api.example.com/"))
                .unwrap()
                .unwrap()
                .host,
            "fallback"
        );
        cfg.https = Some("http://secure-proxy:8443".to_string());
        let t = cfg
            .for_url(&url("https://api.example.com/"))
            .unwrap()
            .unwrap();
        assert_eq!(t.host, "secure-proxy");
        assert_eq!(t.port, 8443);
        // http traffic still uses ALL_PROXY
        assert_eq!(
            cfg.for_url(&url("http://plain.example.com/"))
                .unwrap()
                .unwrap()
                .host,
            "fallback"
        );
    }

    #[test]
    fn no_proxy_matching() {
        let mut cfg = ProxyConfig::new();
        cfg.http = Some("http://proxy:3128".to_string());
        cfg.no_proxy = vec![
            "localhost".into(),
            ".internal.example".into(),
            "127.0.0.1".into(),
            "[::1]".into(),
        ];
        assert!(cfg.for_url(&url("http://localhost/x")).unwrap().is_none());
        assert!(cfg
            .for_url(&url("http://a.internal.example/x"))
            .unwrap()
            .is_none());
        assert!(cfg.for_url(&url("http://127.0.0.1/x")).unwrap().is_none());
        assert!(cfg.for_url(&url("http://[::1]/x")).unwrap().is_none());
        assert!(cfg.for_url(&url("http://example.com/x")).unwrap().is_some());
        // Suffix must be at a label boundary.
        assert!(cfg
            .for_url(&url("http://notinternal.example/x"))
            .unwrap()
            .is_some());
    }

    #[test]
    fn no_proxy_star_disables_all_proxies() {
        let mut cfg = ProxyConfig::new();
        cfg.http = Some("http://proxy:3128".to_string());
        cfg.no_proxy = vec!["*".into()];
        assert!(cfg.for_url(&url("http://example.com/x")).unwrap().is_none());
    }

    #[test]
    fn proxy_credentials_become_basic_auth() {
        let t = parse_proxy("http://user:pass@127.0.0.1:8888").unwrap();
        assert_eq!(t.auth.as_deref(), Some("dXNlcjpwYXNz"));
        let t = parse_proxy("http://127.0.0.1:8888").unwrap();
        assert!(t.auth.is_none());
    }

    #[test]
    fn invalid_proxy_is_an_error_not_a_bypass() {
        let mut cfg = ProxyConfig::new();
        cfg.http = Some("socks5://127.0.0.1:1080".to_string());
        assert!(cfg.for_url(&url("http://example.com/")).is_err());
        cfg.http = Some("not a url".to_string());
        assert!(cfg.for_url(&url("http://example.com/")).is_err());
    }

    #[test]
    fn no_proxy_port_restriction() {
        let mut cfg = ProxyConfig::new();
        cfg.http = Some("http://proxy:3128".to_string());
        cfg.no_proxy = vec!["127.0.0.1:8080".into()];
        assert!(cfg
            .for_url(&url("http://127.0.0.1:8080/x"))
            .unwrap()
            .is_none());
        assert!(cfg
            .for_url(&url("http://127.0.0.1:9090/x"))
            .unwrap()
            .is_some());
    }
}
