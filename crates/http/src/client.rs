//! The HTTP/1.1 client: connection establishment (including DNS overrides and
//! proxies), request writing, response head parsing and redirect following.

use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs};
use std::time::Duration;

use emerag_util::sync::CancelToken;

use crate::conn::Conn;
use crate::error::{Error, Result};
use crate::proxy::{ProxyConfig, ProxyTarget};
use crate::resolve::ResolveTable;
use crate::response::{BodyMode, BodyReader, Response};
use crate::tlsopts::TlsOptions;
use crate::url::Url;

const MAX_HEAD_BYTES: usize = 64 * 1024;
const MAX_INTERIM_RESPONSES: usize = 16;
const MAX_BODY_LENGTH: u64 = 1 << 40;
const PREVIEW_LIMIT: usize = 8 * 1024;
const PREVIEW_TIMEOUT: Duration = Duration::from_millis(250);
const DEFAULT_USER_AGENT: &str = concat!("emerag/", env!("CARGO_PKG_VERSION"));

#[derive(Debug, Clone)]
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
    /// When true the system resolver is never used; only ResolveTable entries
    /// and IP-literal hosts may be connected to.
    pub no_dns: bool,
}

impl Client {
    pub fn new() -> Self {
        Client::default()
    }

    /// Send one request and return the response. Redirects are not followed.
    pub fn send(&self, req: Request) -> Result<Response> {
        if self.cancel.is_cancelled() {
            return Err(Error::new("cancelled"));
        }
        let url = req.url.clone();
        let proxy = match &self.proxy {
            Some(cfg) => cfg.for_url(&url)?,
            None => None,
        };
        let (conn, absolute_form) = self.open(&url, proxy.as_ref())?;
        let target = if absolute_form {
            url.absolute_uri()
        } else {
            url.path_and_query()
        };
        let proxy_auth = proxy.as_ref().and_then(|p| p.auth.as_deref());
        let head = build_request_head(&req, &target, absolute_form, &self.user_agent, proxy_auth)?;
        if self.verbose {
            eprintln!("> {} {}{}", req.method, url.origin(), url.path_and_query());
        }

        let mut conn = conn;
        conn.write_all(&head)
            .map_err(|e| Error::new(format!("io: {e}")).context("sending request"))?;
        if !req.body.is_empty() {
            conn.write_all(&req.body)
                .map_err(|e| Error::new(format!("io: {e}")).context("sending request body"))?;
        }
        conn.flush()
            .map_err(|e| Error::new(format!("io: {e}")).context("sending request"))?;

        let mut reader = HeadReader::new(conn, Vec::new(), false);
        let head = read_final_head(&mut reader)?;
        if self.verbose {
            eprintln!("< {} {}", head.status, head.reason);
        }
        let (conn, leftover) = reader.into_parts();
        let mode = body_mode(&req.method, head.status, &head.headers)?;
        let mut body = BodyReader::new(conn, mode, self.cancel.clone(), leftover);

        // Grab a short preview of error bodies so callers can surface the
        // server's message without reading the whole thing. The preview is
        // replayed by the body reader, so nothing is lost or duplicated.
        let mut early = Vec::new();
        if head.status >= 400 && !matches!(mode, BodyMode::None) {
            body.set_read_timeout(PREVIEW_TIMEOUT);
            let preview = body.read_preview(PREVIEW_LIMIT);
            body.set_read_timeout(self.read_timeout);
            if !preview.is_empty() {
                early = preview.clone();
                body.set_pushback(&preview);
            }
        }

        Ok(Response {
            status: head.status,
            reason: head.reason,
            headers: head.headers,
            url,
            body: Box::new(body),
            early_body: early,
        })
    }

    /// Send a request, following up to max_redirects redirects.
    ///
    /// 301/302 turn POST into GET; 303 turns everything but HEAD into GET;
    /// 307/308 preserve the method and body. Authorization, Proxy-
    /// Authorization, Cookie and Host are dropped when the redirect leaves the
    /// origin.
    pub fn send_follow(&self, req: Request) -> Result<Response> {
        let mut method = req.method.clone();
        let mut url = req.url.clone();
        let mut headers = req.headers.clone();
        let mut body = req.body.clone();
        let mut visited: Vec<String> = Vec::new();
        let mut redirects: u32 = 0;

        loop {
            if self.cancel.is_cancelled() {
                return Err(Error::new("cancelled"));
            }
            let key = format!("{} {}", url.origin(), url.path_and_query());
            if visited.iter().any(|v| v == &key) {
                return Err(Error::new(format!("redirect loop detected at {key}")));
            }
            visited.push(key);

            let current = Request {
                method: method.clone(),
                url: url.clone(),
                headers: headers.clone(),
                body: body.clone(),
            };
            let resp = self.send(current)?;
            let status = resp.status;
            if !matches!(status, 301 | 302 | 303 | 307 | 308) {
                return Ok(resp);
            }
            let location = match resp.header("location") {
                Some(l) => l.to_string(),
                None => return Ok(resp),
            };
            if redirects >= u32::from(self.max_redirects) {
                return Err(Error::new(format!(
                    "too many redirects (limit {})",
                    self.max_redirects
                )));
            }
            drop(resp);

            let next = url
                .join(&location)
                .map_err(|e| e.context(format!("redirect from {}", url.origin())))?;

            let to_get = status == 303
                || ((status == 301 || status == 302) && method.eq_ignore_ascii_case("POST"));
            if to_get {
                if !method.eq_ignore_ascii_case("HEAD") {
                    method = "GET".to_string();
                }
                body.clear();
                headers.retain(|(k, _)| !is_body_header(k));
            } else if method.eq_ignore_ascii_case("GET") || method.eq_ignore_ascii_case("HEAD") {
                body.clear();
                headers.retain(|(k, _)| !is_body_header(k));
            }

            if !url.same_origin(&next) {
                headers.retain(|(k, _)| !is_sensitive_header(k) && !k.eq_ignore_ascii_case("host"));
            }
            if self.verbose {
                eprintln!("redirect {status} -> {}", next.origin());
            }
            redirects += 1;
            url = next;
        }
    }

    /// Convenience: GET a URL without following redirects.
    pub fn get(&self, url: Url) -> Result<Response> {
        self.send(Request::get(url))
    }

    fn open(&self, url: &Url, proxy: Option<&ProxyTarget>) -> Result<(Conn, bool)> {
        match proxy {
            Some(target) => {
                let tcp = self.connect_tcp(&target.host, target.port, "proxy")?;
                if url.is_https() {
                    let tcp = connect_tunnel(tcp, url, target.auth.as_deref())?;
                    let conn = self.connect_tls(tcp, url)?;
                    Ok((conn, false))
                } else {
                    Ok((Conn::Plain(tcp), true))
                }
            }
            None => {
                let tcp = self.connect_tcp(&url.host, url.port, "host")?;
                if url.is_https() {
                    let conn = self.connect_tls(tcp, url)?;
                    Ok((conn, false))
                } else {
                    Ok((Conn::Plain(tcp), false))
                }
            }
        }
    }

    fn connect_tls(&self, tcp: TcpStream, url: &Url) -> Result<Conn> {
        let cfg = self.tls.to_tls_config(&url.host);
        let stream = emerag_tls::TlsStream::connect(tcp, &cfg)?;
        Ok(Conn::Tls(Box::new(stream)))
    }

    fn connect_tcp(&self, host: &str, port: u16, what: &str) -> Result<TcpStream> {
        if self.cancel.is_cancelled() {
            return Err(Error::new("cancelled"));
        }
        let addresses = self.addresses(host, port)?;
        let timeout = self.effective_connect_timeout();
        let mut last_error: Option<std::io::Error> = None;
        for ip in addresses {
            if self.cancel.is_cancelled() {
                return Err(Error::new("cancelled"));
            }
            let addr = SocketAddr::new(ip, port);
            match TcpStream::connect_timeout(&addr, timeout) {
                Ok(stream) => {
                    let _ = stream.set_nodelay(true);
                    self.apply_timeouts(&stream);
                    return Ok(stream);
                }
                Err(e) => last_error = Some(e),
            }
        }
        let detail = match last_error {
            Some(e) => e.to_string(),
            None => "no usable address".to_string(),
        };
        Err(Error::new(format!(
            "cannot connect to {what} {host}:{port}: {detail}; if DNS is broken or the host is unreachable, pin it with --resolve {host}:{port}:<ip> or --ip <ip>"
        )))
    }

    fn addresses(&self, host: &str, port: u16) -> Result<Vec<IpAddr>> {
        if let Some(ip) = self.resolve.lookup(host, port) {
            return Ok(vec![ip]);
        }
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(vec![ip]);
        }
        if self.no_dns {
            return Err(Error::new(format!(
                "DNS is disabled and {host}:{port} has no address override; use --resolve {host}:{port}:<ip> or --ip <ip>"
            )));
        }
        match (host, port).to_socket_addrs() {
            Ok(iter) => {
                let mut out: Vec<IpAddr> = Vec::new();
                for sa in iter {
                    if !out.contains(&sa.ip()) {
                        out.push(sa.ip());
                    }
                }
                if out.is_empty() {
                    return Err(Error::new(format!(
                        "DNS returned no addresses for {host}:{port}; use --resolve {host}:{port}:<ip> or --ip <ip>"
                    )));
                }
                Ok(out)
            }
            Err(e) => Err(Error::new(format!(
                "cannot resolve {host}: {e}; DNS may be broken: use --resolve {host}:{port}:<ip> or --ip <ip>"
            ))),
        }
    }

    fn effective_connect_timeout(&self) -> Duration {
        if self.connect_timeout.is_zero() {
            Duration::from_secs(10)
        } else {
            self.connect_timeout
        }
    }

    fn apply_timeouts(&self, stream: &TcpStream) {
        if self.read_timeout.is_zero() {
            let _ = stream.set_read_timeout(None);
        } else {
            let _ = stream.set_read_timeout(Some(self.read_timeout));
        }
        let write = if self.connect_timeout.is_zero() {
            None
        } else {
            Some(self.connect_timeout)
        };
        let _ = stream.set_write_timeout(write);
    }
}

impl Default for Client {
    fn default() -> Self {
        Client {
            resolve: ResolveTable::new(),
            tls: TlsOptions::new(),
            proxy: None,
            connect_timeout: Duration::from_secs(10),
            read_timeout: Duration::from_secs(120),
            max_redirects: 10,
            user_agent: DEFAULT_USER_AGENT.to_string(),
            verbose: false,
            cancel: CancelToken::new(),
            no_dns: false,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Request {
    pub method: String,
    pub url: Url,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Request {
    pub fn new(method: impl Into<String>, url: Url) -> Self {
        Request {
            method: method.into(),
            url,
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    pub fn get(url: Url) -> Self {
        Request::new("GET", url)
    }

    pub fn post(url: Url, body: impl Into<Vec<u8>>, content_type: &str) -> Self {
        let mut req = Request::new("POST", url).header("Content-Type", content_type);
        req.body = body.into();
        req
    }

    pub fn json(url: Url, body: impl Into<Vec<u8>>) -> Self {
        Request::post(url, body, "application/json")
    }

    pub fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    pub fn bearer(self, token: &str) -> Self {
        self.header("Authorization", format!("Bearer {token}"))
    }

    pub fn with_body(mut self, body: impl Into<Vec<u8>>) -> Self {
        self.body = body.into();
        self
    }
}

fn connect_tunnel(mut tcp: TcpStream, url: &Url, auth: Option<&str>) -> Result<TcpStream> {
    let authority = url.host_header();
    let mut head = format!(
        "CONNECT {authority} HTTP/1.1
Host: {authority}
Proxy-Connection: keep-alive
"
    );
    if let Some(auth) = auth {
        head.push_str("Proxy-Authorization: Basic ");
        head.push_str(auth);
        head.push_str(
            "
",
        );
    }
    head.push_str(
        "
",
    );
    tcp.write_all(head.as_bytes())
        .map_err(|e| Error::new(format!("io: {e}")).context("proxy CONNECT"))?;
    tcp.flush()
        .map_err(|e| Error::new(format!("io: {e}")).context("proxy CONNECT"))?;

    // Read byte by byte: any bytes after the CONNECT response belong to the
    // tunnelled TLS stream and must not be swallowed into a buffer.
    let mut reader = HeadReader::new(tcp, Vec::new(), true);
    let head = reader.read_head()?;
    if !(200..300).contains(&head.status) {
        return Err(Error::new(format!(
            "proxy CONNECT failed: {} {}",
            head.status, head.reason
        )));
    }
    let (tcp, leftover) = reader.into_parts();
    if !leftover.is_empty() {
        return Err(Error::new(
            "proxy sent unexpected data after the CONNECT response",
        ));
    }
    Ok(tcp)
}

fn is_body_header(name: &str) -> bool {
    name.eq_ignore_ascii_case("content-length")
        || name.eq_ignore_ascii_case("content-type")
        || name.eq_ignore_ascii_case("content-encoding")
        || name.eq_ignore_ascii_case("transfer-encoding")
        || name.eq_ignore_ascii_case("expect")
}

fn is_sensitive_header(name: &str) -> bool {
    name.eq_ignore_ascii_case("authorization")
        || name.eq_ignore_ascii_case("proxy-authorization")
        || name.eq_ignore_ascii_case("cookie")
        || name.eq_ignore_ascii_case("cookie2")
}

fn is_token_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric()
        || matches!(
            b,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

pub(crate) fn valid_header_value(value: &str) -> bool {
    value
        .bytes()
        .all(|b| b == b'\t' || (b >= 0x20 && b != 0x7f))
}

fn build_request_head(
    req: &Request,
    target: &str,
    absolute_form: bool,
    default_ua: &str,
    proxy_auth: Option<&str>,
) -> Result<Vec<u8>> {
    if req.method.is_empty() || !req.method.bytes().all(is_token_byte) {
        return Err(Error::new("invalid HTTP method"));
    }
    if target.is_empty() || target.bytes().any(|b| b <= b' ' || b == 0x7f) {
        return Err(Error::new("invalid HTTP request target"));
    }
    if absolute_form {
        if !(target.starts_with("http://") || target.starts_with("https://")) {
            return Err(Error::new("invalid absolute request target"));
        }
    } else if !target.starts_with('/') {
        return Err(Error::new("invalid origin-form request target"));
    }

    let mut host: Option<String> = None;
    let mut user_agent: Option<String> = None;
    let mut proxy_auth_supplied = false;
    let mut extra: Vec<(String, String)> = Vec::new();
    for (name, value) in &req.headers {
        if name.is_empty() || !name.bytes().all(is_token_byte) {
            return Err(Error::new(format!("invalid header name: {name:?}")));
        }
        if !valid_header_value(value) {
            return Err(Error::new(format!("invalid value for header {name}")));
        }
        if name.eq_ignore_ascii_case("host") {
            host = Some(value.clone());
            continue;
        }
        if name.eq_ignore_ascii_case("content-length")
            || name.eq_ignore_ascii_case("connection")
            || name.eq_ignore_ascii_case("transfer-encoding")
        {
            continue;
        }
        if name.eq_ignore_ascii_case("user-agent") {
            user_agent = Some(value.clone());
            continue;
        }
        if name.eq_ignore_ascii_case("proxy-authorization") {
            proxy_auth_supplied = true;
        }
        extra.push((name.clone(), value.clone()));
    }

    let host = host.unwrap_or_else(|| req.url.host_header());
    let user_agent = match user_agent {
        Some(ua) if !ua.is_empty() => ua,
        _ => {
            if default_ua.is_empty() {
                DEFAULT_USER_AGENT.to_string()
            } else {
                default_ua.to_string()
            }
        }
    };

    let mut out = Vec::with_capacity(256 + target.len());
    out.extend_from_slice(req.method.as_bytes());
    out.push(b' ');
    out.extend_from_slice(target.as_bytes());
    out.extend_from_slice(b" HTTP/1.1\r\nHost: ");
    out.extend_from_slice(host.as_bytes());
    out.extend_from_slice(b"\r\nUser-Agent: ");
    out.extend_from_slice(user_agent.as_bytes());
    out.extend_from_slice(b"\r\nAccept-Encoding: identity\r\nContent-Length: ");
    out.extend_from_slice(req.body.len().to_string().as_bytes());
    out.extend_from_slice(b"\r\nConnection: close\r\n");
    if let Some(auth) = proxy_auth {
        if !proxy_auth_supplied {
            out.extend_from_slice(b"Proxy-Authorization: Basic ");
            out.extend_from_slice(auth.as_bytes());
            out.extend_from_slice(b"\r\n");
        }
    }
    for (name, value) in &extra {
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(value.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"\r\n");
    Ok(out)
}

struct Head {
    status: u16,
    reason: String,
    headers: Vec<(String, String)>,
}

struct HeadReader<R> {
    r: R,
    buf: Vec<u8>,
    pos: usize,
    exact: bool,
}

impl<R: Read> HeadReader<R> {
    fn new(r: R, leftover: Vec<u8>, exact: bool) -> Self {
        HeadReader {
            r,
            buf: leftover,
            pos: 0,
            exact,
        }
    }

    fn read_head(&mut self) -> Result<Head> {
        loop {
            if let Some(end) = find_head_end(&self.buf[self.pos..]) {
                let absolute = self.pos + end;
                let head = parse_head(&self.buf[self.pos..absolute])?;
                self.pos = absolute;
                if self.pos > MAX_HEAD_BYTES {
                    self.buf.drain(..self.pos);
                    self.pos = 0;
                }
                return Ok(head);
            }
            if self.buf.len() - self.pos > MAX_HEAD_BYTES {
                return Err(Error::new("response headers too large"));
            }
            let mut tmp = [0u8; 8192];
            let slice: &mut [u8] = if self.exact {
                &mut tmp[..1]
            } else {
                &mut tmp[..]
            };
            let n = self
                .r
                .read(slice)
                .map_err(|e| Error::new(format!("io: {e}")).context("reading response"))?;
            if n == 0 {
                if self.buf.len() == self.pos {
                    return Err(Error::new(
                        "server closed the connection without sending a response",
                    ));
                }
                return Err(Error::new(
                    "server closed the connection in the middle of the response headers",
                ));
            }
            self.buf.extend_from_slice(&slice[..n]);
        }
    }

    fn into_parts(self) -> (R, Vec<u8>) {
        let leftover = self.buf[self.pos..].to_vec();
        (self.r, leftover)
    }
}

fn read_final_head<R: Read>(reader: &mut HeadReader<R>) -> Result<Head> {
    let mut interim = 0usize;
    loop {
        let head = reader.read_head()?;
        if head.status == 101 {
            return Err(Error::new(
                "server requested a protocol upgrade (101), which this client does not support",
            ));
        }
        if (100..200).contains(&head.status) {
            interim += 1;
            if interim > MAX_INTERIM_RESPONSES {
                return Err(Error::new("too many interim (1xx) responses"));
            }
            continue;
        }
        return Ok(head);
    }
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn find_head_end(buf: &[u8]) -> Option<usize> {
    let crlf = find_subsequence(buf, b"\r\n\r\n").map(|i| i + 4);
    let lf = find_subsequence(buf, b"\n\n").map(|i| i + 2);
    match (crlf, lf) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (Some(a), None) => Some(a),
        (None, Some(b)) => Some(b),
        (None, None) => None,
    }
}

fn parse_head(head: &[u8]) -> Result<Head> {
    let text = String::from_utf8_lossy(head);
    let mut lines = text.split('\n');
    let status_line = lines.next().unwrap_or("");
    let status_line = status_line.strip_suffix('\r').unwrap_or(status_line);
    let mut parts = status_line.splitn(3, ' ');
    let version = parts.next().unwrap_or("");
    if version != "HTTP/1.1" && version != "HTTP/1.0" {
        return Err(Error::new(format!(
            "unsupported HTTP status line: {status_line:?}"
        )));
    }
    let code = parts.next().unwrap_or("");
    if code.len() != 3 || !code.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Error::new(format!(
            "malformed HTTP status line: {status_line:?}"
        )));
    }
    let status: u16 = code
        .parse()
        .map_err(|_| Error::new("malformed HTTP status code"))?;
    if !(100..=599).contains(&status) {
        return Err(Error::new(format!(
            "HTTP status code out of range: {status}"
        )));
    }
    let reason = parts.next().unwrap_or("").to_string();
    if reason.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return Err(Error::new("invalid characters in the HTTP reason phrase"));
    }

    let mut headers = Vec::new();
    for raw in lines {
        let line = raw.strip_suffix('\r').unwrap_or(raw);
        if line.is_empty() {
            continue;
        }
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| Error::new("malformed header line in response"))?;
        if name.is_empty() || !name.bytes().all(is_token_byte) {
            return Err(Error::new("invalid header name in response"));
        }
        let value = value.trim_matches(|c: char| c == ' ' || c == '\t');
        if value.bytes().any(|b| (b < 0x20 && b != b'\t') || b == 0x7f) {
            return Err(Error::new("invalid header value in response"));
        }
        headers.push((name.to_string(), value.to_string()));
    }
    Ok(Head {
        status,
        reason,
        headers,
    })
}

pub(crate) fn body_mode(
    method: &str,
    status: u16,
    headers: &[(String, String)],
) -> Result<BodyMode> {
    if method.eq_ignore_ascii_case("HEAD") {
        return Ok(BodyMode::None);
    }
    if status == 204 || status == 304 || (100..200).contains(&status) {
        return Ok(BodyMode::None);
    }

    let mut codings: Vec<String> = Vec::new();
    for (name, value) in headers {
        if name.eq_ignore_ascii_case("transfer-encoding") {
            for token in value.split(',') {
                let token = token.trim().to_ascii_lowercase();
                if !token.is_empty() {
                    codings.push(token);
                }
            }
        }
    }
    if !codings.is_empty() {
        let chunked_last = codings.last().map(|s| s.as_str()) == Some("chunked");
        let others_identity = codings
            .iter()
            .take(codings.len() - 1)
            .all(|c| c == "identity");
        if !chunked_last || !others_identity {
            return Err(Error::new(format!(
                "unsupported transfer-encoding: {}",
                codings.join(", ")
            )));
        }
        return Ok(BodyMode::Chunked);
    }

    let mut lengths: Vec<&str> = Vec::new();
    for (name, value) in headers {
        if name.eq_ignore_ascii_case("content-length") {
            for part in value.split(',') {
                lengths.push(part.trim());
            }
        }
    }
    if lengths.is_empty() {
        return Ok(BodyMode::Close);
    }
    let first = lengths[0];
    if first.is_empty() || !first.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Error::new(format!(
            "invalid content-length value: {first:?}"
        )));
    }
    if lengths.iter().any(|v| *v != first) {
        return Err(Error::new("conflicting content-length values in response"));
    }
    let length: u64 = first
        .parse()
        .map_err(|_| Error::new("invalid content-length value"))?;
    if length > MAX_BODY_LENGTH {
        return Err(Error::new("content-length is unreasonably large"));
    }
    Ok(BodyMode::Length(length))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(headers: &[(&str, &str)]) -> Request {
        let url = Url::parse("http://example.com:8080/p?q=1").unwrap();
        let mut req = Request::get(url);
        for (k, v) in headers {
            req.headers.push((k.to_string(), v.to_string()));
        }
        req
    }

    fn head_of(req: &Request) -> String {
        let head = build_request_head(req, "/p?q=1", false, "emerag/test", None).unwrap();
        String::from_utf8(head).unwrap()
    }

    #[test]
    fn request_head_has_required_fields() {
        let text = head_of(&request(&[]));
        assert!(text.starts_with("GET /p?q=1 HTTP/1.1\r\n"));
        assert!(text.contains("\r\nHost: example.com:8080\r\n"));
        assert!(text.contains("\r\nUser-Agent: emerag/test\r\n"));
        assert!(text.contains("\r\nContent-Length: 0\r\n"));
        assert!(text.contains("\r\nConnection: close\r\n"));
        assert!(text.ends_with("\r\n\r\n"));
    }

    #[test]
    fn caller_host_and_user_agent_override_defaults() {
        let text = head_of(&request(&[
            ("Host", "virtual.example"),
            ("User-Agent", "custom/1"),
        ]));
        assert!(text.contains("\r\nHost: virtual.example\r\n"));
        assert!(!text.contains("example.com:8080"));
        assert!(text.contains("\r\nUser-Agent: custom/1\r\n"));
        assert_eq!(text.matches("User-Agent:").count(), 1);
    }

    #[test]
    fn caller_content_length_is_replaced_by_body_length() {
        let mut req = request(&[("Content-Length", "999")]);
        req.body = b"abc".to_vec();
        let text = head_of(&req);
        assert!(text.contains("\r\nContent-Length: 3\r\n"));
        assert!(!text.contains("999"));
        assert_eq!(
            text.to_ascii_lowercase().matches("content-length:").count(),
            1
        );
    }

    #[test]
    fn header_injection_is_rejected() {
        let mut req = request(&[]);
        req.headers
            .push(("X-Evil".to_string(), "value\r\nInjected: yes".to_string()));
        assert!(build_request_head(&req, "/", false, "ua", None).is_err());

        let mut req = request(&[]);
        req.headers.push(("Bad Name".to_string(), "v".to_string()));
        assert!(build_request_head(&req, "/", false, "ua", None).is_err());
    }

    #[test]
    fn rejects_absolute_target_in_origin_form() {
        let req = request(&[]);
        assert!(build_request_head(&req, "http://example.com/", false, "ua", None).is_err());
        assert!(build_request_head(&req, "/", true, "ua", None).is_err());
    }

    #[test]
    fn proxy_authorization_is_added_unless_supplied() {
        let req = request(&[]);
        let head = build_request_head(
            &req,
            "http://example.com/",
            true,
            "ua",
            Some("dXNlcjpwYXNz"),
        )
        .unwrap();
        let text = String::from_utf8(head).unwrap();
        assert!(text.contains("\r\nProxy-Authorization: Basic dXNlcjpwYXNz\r\n"));

        let req = request(&[("Proxy-Authorization", "Basic caller")]);
        let head =
            build_request_head(&req, "http://example.com/", true, "ua", Some("server")).unwrap();
        let text = String::from_utf8(head).unwrap();
        assert_eq!(text.matches("Proxy-Authorization:").count(), 1);
        assert!(text.contains("Basic caller"));
    }

    #[test]
    fn body_mode_rules() {
        let empty: Vec<(String, String)> = Vec::new();
        assert_eq!(body_mode("HEAD", 200, &empty).unwrap(), BodyMode::None);
        assert_eq!(body_mode("GET", 204, &empty).unwrap(), BodyMode::None);
        assert_eq!(body_mode("GET", 304, &empty).unwrap(), BodyMode::None);
        assert_eq!(body_mode("GET", 200, &empty).unwrap(), BodyMode::Close);

        let cl = vec![("Content-Length".to_string(), "12".to_string())];
        assert_eq!(body_mode("GET", 200, &cl).unwrap(), BodyMode::Length(12));

        let te = vec![("Transfer-Encoding".to_string(), "chunked".to_string())];
        assert_eq!(body_mode("GET", 200, &te).unwrap(), BodyMode::Chunked);

        let te = vec![(
            "transfer-encoding".to_string(),
            "identity, chunked".to_string(),
        )];
        assert_eq!(body_mode("GET", 200, &te).unwrap(), BodyMode::Chunked);
        assert!(body_mode(
            "GET",
            200,
            &[("Transfer-Encoding".to_string(), "gzip, chunked".to_string())]
        )
        .is_err());
        assert!(body_mode(
            "GET",
            200,
            &[("Transfer-Encoding".to_string(), "gzip".to_string())]
        )
        .is_err());
    }

    #[test]
    fn content_length_validation() {
        let invalid = vec![("Content-Length".to_string(), "12x".to_string())];
        assert!(body_mode("GET", 200, &invalid).is_err());
        let conflicting = vec![
            ("Content-Length".to_string(), "12".to_string()),
            ("Content-Length".to_string(), "13".to_string()),
        ];
        assert!(body_mode("GET", 200, &conflicting).is_err());
        let repeated_same = vec![("Content-Length".to_string(), "12, 12".to_string())];
        assert_eq!(
            body_mode("GET", 200, &repeated_same).unwrap(),
            BodyMode::Length(12)
        );
        let negative = vec![("Content-Length".to_string(), "-1".to_string())];
        assert!(body_mode("GET", 200, &negative).is_err());
    }

    #[test]
    fn head_parsing_rejects_garbage() {
        assert!(parse_head(b"garbage\r\n\r\n").is_err());
        assert!(parse_head(b"HTTP/2 200 OK\r\n\r\n").is_err());
        assert!(parse_head(b"HTTP/1.1 2O0 OK\r\n\r\n").is_err());
        assert!(parse_head(b"HTTP/1.1 20 OK\r\n\r\n").is_err());
        assert!(parse_head(b"HTTP/1.1 200 OK\r\nNoColon\r\n\r\n").is_err());
        assert!(parse_head(b"HTTP/1.1 200 OK\r\nBad Name: v\r\n\r\n").is_err());
        let head = parse_head(b"HTTP/1.1 200 OK\r\nX-A: 1\r\nx-a: 2\r\n\r\n").unwrap();
        assert_eq!(head.status, 200);
        assert_eq!(head.headers.len(), 2);
    }

    #[test]
    fn head_end_detection_handles_both_line_endings() {
        assert_eq!(find_head_end(b"HTTP/1.1 200 OK\r\n\r\nbody"), Some(19));
        assert_eq!(find_head_end(b"HTTP/1.1 200 OK\n\nbody"), Some(17));
        assert_eq!(find_head_end(b"HTTP/1.1 200 OK\r\n"), None);
    }
}
