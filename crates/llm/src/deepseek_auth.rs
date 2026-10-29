//! DeepSeek account sign-in (browser PKCE), matching the Desktop Harness.
//!
//! Protocol (verified against platform.deepseek.com):
//!   1. POST {platform}/auth-api/v0/dsh/auth_init
//!      {code_challenge, code_challenge_method: S256, state, redirect_uri,
//!       locale, login_source}
//!      -> {code:0, data:{biz_code, biz_data:{authorize_url, authorize_id, expires_in}}}
//!   2. Open authorize_url in a browser. The platform redirects to redirect_uri
//!      with ?code=...&state=...
//!   3. POST {platform}/auth-api/v0/dsh/auth_exchange
//!      {code, code_verifier, redirect_uri, device_id, device_model, os_version}
//!      -> {code:0, data:{biz_data:{token, authorized_url, user}}}
//!   4. Send the token as x-dsh-auth-token to api.deepseek.com for inference
//!      and for GET /models.
//!
//! The token has no expiry or refresh flow in the upstream design; signing out
//! removes it locally and best-effort revokes it remotely.

use std::net::IpAddr;
use std::time::Duration;

use emerag_http::{Client, Request, TlsOptions};
use emerag_json::{json, Map, Value};

use crate::{Error, ErrorKind};

pub const DEFAULT_PLATFORM: &str = "https://platform.deepseek.com";
const CLIENT_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Clone)]
pub struct LoginStart {
    pub platform: String,
    pub authorize_url: String,
    pub authorize_id: String,
    pub state: String,
    pub verifier: String,
    pub redirect_uri: String,
    pub expires_in: u64,
}

#[derive(Debug, Clone)]
pub struct AccountGrant {
    pub token: String,
    pub user: Value,
}

fn client() -> Client {
    let discovered = emerag_http::dns::discover();
    Client {
        resolve: emerag_http::ResolveTable::new(),
        tls: TlsOptions::new(),
        proxy: None,
        connect_timeout: Duration::from_secs(15),
        read_timeout: Duration::from_secs(30),
        max_redirects: 2,
        user_agent: format!("emerag/{CLIENT_VERSION}"),
        verbose: false,
        cancel: emerag_util::sync::CancelToken::new(),
        no_dns: false,
        dns_servers: discovered.servers,
        dns_first: false,
    }
}

fn client_headers() -> Vec<(String, String)> {
    vec![
        ("content-type".into(), "application/json".into()),
        ("accept".into(), "application/json".into()),
        ("x-client-platform".into(), "web".into()),
        ("x-client-version".into(), CLIENT_VERSION.into()),
        ("x-client-locale".into(), "en_US".into()),
        ("x-client-timezone-offset".into(), "0".into()),
        ("x-client-bundle-id".into(), String::new()),
    ]
}

fn platform_base(platform: &str) -> Result<String, Error> {
    let url = emerag_http::Url::parse(platform)
        .map_err(|e| Error::config(format!("bad DeepSeek platform origin: {e}")))?;
    if url.scheme != "https"
        && !(url.scheme == "http"
            && matches!(url.host.as_str(), "127.0.0.1" | "localhost" | "[::1]"))
    {
        return Err(Error::config("DeepSeek account login requires https"));
    }
    Ok(format!("{}://{}{}", url.scheme, url.host_header(), "")
        .trim_end_matches('/')
        .to_string())
}

pub fn start_login(platform: &str, redirect_uri: &str) -> Result<LoginStart, Error> {
    let platform = platform_base(platform)?;
    let verifier = random_b64url(32)?;
    let state = random_b64url(32)?;
    let challenge =
        emerag_util::base64::encode_url(&emerag_crypto::hash::sha256(verifier.as_bytes()));
    let body = json!({
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "state": (state.clone()),
        "redirect_uri": redirect_uri,
        "locale": "en_US",
        "login_source": "desktop"
    });
    let value = post(&platform, "/auth-api/v0/dsh/auth_init", &body, None)?;
    let biz = biz_data(&value)?;
    let authorize_url = biz
        .get("authorize_url")
        .and_then(|v| v.as_str())
        .ok_or_else(|| Error::protocol("auth_init returned no authorize_url"))?
        .to_string();
    let authorize_id = biz
        .get("authorize_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| Error::protocol("auth_init returned no authorize_id"))?
        .to_string();
    let expires_in = biz
        .get("expires_in")
        .and_then(|v| v.as_u64())
        .unwrap_or(600);
    Ok(LoginStart {
        platform,
        authorize_url,
        authorize_id,
        state,
        verifier,
        redirect_uri: redirect_uri.to_string(),
        expires_in,
    })
}

pub fn exchange_code(start: &LoginStart, code: &str) -> Result<AccountGrant, Error> {
    let body = json!({
        "code": (code),
        "code_verifier": (start.verifier.clone()),
        "redirect_uri": (start.redirect_uri.clone()),
        "device_id": (random_uuid()?),
        "device_model": (device_model()),
        "os_version": (os_version())
    });
    let value = post(
        &start.platform,
        "/auth-api/v0/dsh/auth_exchange",
        &body,
        None,
    )?;
    let biz = biz_data(&value)?;
    let token = biz
        .get("token")
        .and_then(|v| v.as_str())
        .filter(|t| !t.is_empty() && t.bytes().all(|b| (0x21..=0x7e).contains(&b)))
        .ok_or_else(|| Error::protocol("auth_exchange returned an invalid token"))?
        .to_string();
    let user = biz.get("user").cloned().unwrap_or(Value::Null);
    Ok(AccountGrant { token, user })
}

/// Best-effort cancellation of an abandoned login attempt.
pub fn cancel_login(start: &LoginStart) {
    let body = json!({
        "authorize_id": (start.authorize_id.clone()),
        "code_verifier": (start.verifier.clone())
    });
    let _ = post(&start.platform, "/auth-api/v0/dsh/auth_cancel", &body, None);
}

/// Revoke the stored grant. Failures are ignored by callers.
pub fn logout(platform: &str, token: &str) -> Result<(), Error> {
    let body = Value::Null;
    let _ = post(platform, "/auth-api/v0/users/logout", &body, Some(token))?;
    Ok(())
}

fn post(platform: &str, path: &str, body: &Value, token: Option<&str>) -> Result<Value, Error> {
    let url = format!("{}{}", platform.trim_end_matches('/'), path);
    let mut req = Request::new(
        "POST",
        emerag_http::Url::parse(&url).map_err(|e| Error::config(format!("bad auth URL: {e}")))?,
    );
    req.headers = client_headers();
    if let Some(t) = token {
        req.headers.push(("x-dsh-auth-token".into(), t.into()));
    }
    req.body = emerag_json::to_string(body).into_bytes();
    let mut resp = client().send(req).map_err(|e| {
        let msg = e.to_string();
        let kind = if msg.contains("dns") || msg.contains("resolve") || msg.contains("connect") {
            ErrorKind::Network
        } else {
            ErrorKind::Protocol
        };
        Error::new(kind, format!("DeepSeek account: {msg}"))
    })?;
    let text = resp
        .read_to_string_limited(256 * 1024)
        .map_err(|e| Error::new(ErrorKind::Network, format!("DeepSeek account: {e}")))?;
    let parsed = emerag_json::parse(&text).unwrap_or(Value::Null);
    if resp.status == 401 || resp.status == 403 {
        return Err(Error::new(
            ErrorKind::Auth,
            "DeepSeek account rejected this sign-in",
        ));
    }
    if resp.status / 100 != 2 {
        let msg = parsed
            .get("data")
            .and_then(|d| d.get("biz_msg"))
            .and_then(|m| m.as_str())
            .or_else(|| parsed.get("msg").and_then(|m| m.as_str()))
            .unwrap_or("request failed");
        return Err(Error::new(
            ErrorKind::Server,
            format!("DeepSeek account: HTTP {} {msg}", resp.status),
        ));
    }
    if parsed.get("code").and_then(|c| c.as_i64()).unwrap_or(-1) != 0 {
        let msg = parsed
            .get("msg")
            .and_then(|m| m.as_str())
            .unwrap_or("unknown error");
        return Err(Error::new(
            ErrorKind::Server,
            format!("DeepSeek account: {msg}"),
        ));
    }
    Ok(parsed)
}

fn biz_data(value: &Value) -> Result<&Value, Error> {
    let data = value
        .get("data")
        .ok_or_else(|| Error::protocol("DeepSeek account: response has no data"))?;
    let code = data.get("biz_code").and_then(|c| c.as_i64()).unwrap_or(-1);
    if code != 0 {
        let msg = data
            .get("biz_msg")
            .and_then(|m| m.as_str())
            .filter(|s| !s.is_empty())
            .unwrap_or("business error");
        return Err(Error::new(
            ErrorKind::Auth,
            format!("DeepSeek account: {msg} (code {code})"),
        ));
    }
    data.get("biz_data")
        .ok_or_else(|| Error::protocol("DeepSeek account: response has no biz_data"))
}

fn random_b64url(n: usize) -> Result<String, Error> {
    let mut bytes = vec![0u8; n];
    emerag_util::rand::fill_bytes(&mut bytes)
        .map_err(|e| Error::network(format!("no OS randomness: {e}")))?;
    Ok(emerag_util::base64::encode_url(&bytes))
}

fn random_uuid() -> Result<String, Error> {
    let mut b = [0u8; 16];
    emerag_util::rand::fill_bytes(&mut b)
        .map_err(|e| Error::network(format!("no OS randomness: {e}")))?;
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let hex = emerag_util::hex::encode(&b);
    Ok(format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    ))
}

fn device_model() -> String {
    let os = if is_termux() || cfg!(target_os = "android") {
        "android"
    } else {
        std::env::consts::OS
    };
    format!("{os}-{}", std::env::consts::ARCH)
}

fn os_version() -> String {
    if let Ok(text) = std::fs::read_to_string("/etc/os-release") {
        for line in text.lines() {
            if let Some(v) = line.strip_prefix("PRETTY_NAME=") {
                return v.trim_matches('"').to_string();
            }
        }
    }
    if let Ok(v) = std::fs::read_to_string("/system/build.prop") {
        for line in v.lines() {
            if let Some(r) = line.strip_prefix("ro.build.version.release=") {
                return format!("Android {r}");
            }
        }
    }
    format!("{} {}", std::env::consts::OS, std::env::consts::ARCH)
}

fn is_termux() -> bool {
    std::env::var("PREFIX")
        .map(|p| p.contains("com.termux"))
        .unwrap_or(false)
}

/// Resolve a DeepSeek origin to its models endpoint (used by diagnostics).
pub fn models_url_for(origin: &str) -> String {
    format!("{}/models", origin.trim_end_matches('/'))
}

/// Expose discovered DNS for callers that build their own HTTP client.
pub fn dns_servers() -> Vec<IpAddr> {
    emerag_http::dns::discover().servers
}

#[allow(dead_code)]
fn _unused(_: &Map) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uuid_has_version_and_variant() {
        let u = random_uuid().unwrap();
        let parts: Vec<&str> = u.split('-').collect();
        assert_eq!(parts.len(), 5);
        assert_eq!(parts[2].len(), 4);
        assert!(parts[2].starts_with('4'));
        assert!(matches!(parts[3].as_bytes()[0], b'8' | b'9' | b'a' | b'b'));
    }

    #[test]
    #[ignore = "network: contacts platform.deepseek.com"]
    fn live_auth_init_returns_authorize_url() {
        let start = start_login(DEFAULT_PLATFORM, "http://127.0.0.1:45678/oauth/callback").unwrap();
        assert!(start
            .authorize_url
            .starts_with("https://platform.deepseek.com/dsh/authorize?"));
        assert!(!start.authorize_id.is_empty());
        cancel_login(&start);
    }
}
