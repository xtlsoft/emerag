//! HTTP(S) URL parsing.
//!
//! Only absolute http:// and https:// URLs are accepted. Paths and queries are
//! kept byte for byte (no percent-decoding), fragments are dropped because they
//! are never sent to a server. Userinfo is parsed and exposed separately so it
//! can be turned into an Authorization header by the caller.

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::error::{Error, Result};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Url {
    pub scheme: String,
    pub host: String,
    pub port: u16,
    pub path: String,
    pub query: String,
    pub user: Option<String>,
    pub pass: Option<String>,
}

impl Url {
    pub fn parse(input: &str) -> Result<Url> {
        if input.is_empty() {
            return Err(Error::new("empty URL"));
        }
        // Reject whitespace and control characters anywhere: they are never
        // valid in a URL and are how request splitting bugs start.
        for b in input.bytes() {
            if b <= b' ' || b == 0x7f {
                return Err(Error::new("URL contains whitespace or control characters"));
            }
        }
        let scheme_end = input
            .find("://")
            .ok_or_else(|| Error::new("URL is not absolute (missing http:// or https://)"))?;
        let scheme_raw = &input[..scheme_end];
        if scheme_raw.is_empty() {
            return Err(Error::new("URL is missing a scheme"));
        }
        if !scheme_raw
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'-' || b == b'.')
        {
            return Err(Error::new("invalid characters in URL scheme"));
        }
        let scheme = scheme_raw.to_ascii_lowercase();
        let default_port = match scheme.as_str() {
            "http" => 80u16,
            "https" => 443u16,
            _ => return Err(Error::new(format!("unsupported URL scheme: {scheme_raw}"))),
        };

        let rest = &input[scheme_end + 3..];
        let rest = match rest.find('#') {
            Some(i) => &rest[..i],
            None => rest,
        };
        let (authority, path_query) = match rest.find(|c: char| c == '/' || c == '?') {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, ""),
        };
        if authority.is_empty() {
            return Err(Error::new("URL is missing a host"));
        }
        if authority.bytes().any(|b| b > 0x7f) {
            return Err(Error::new("non-ASCII host names are not supported"));
        }

        // rsplit: a password may legally contain an unencoded @ in practice.
        let (userinfo, host_port) = match authority.rsplit_once('@') {
            Some((u, h)) => (Some(u), h),
            None => (None, authority),
        };
        let (user, pass) = match userinfo {
            None => (None, None),
            Some(info) => {
                if info.is_empty() {
                    return Err(Error::new("URL has an empty userinfo section"));
                }
                match info.split_once(':') {
                    Some((u, p)) => (Some(u.to_string()), Some(p.to_string())),
                    None => (Some(info.to_string()), None),
                }
            }
        };

        let (host, port) = parse_host_port(host_port, default_port)?;
        let (path, query) = match path_query.split_once('?') {
            Some((p, q)) => (p, q.to_string()),
            None => (path_query, String::new()),
        };
        let path = if path.is_empty() {
            "/".to_string()
        } else {
            path.to_string()
        };
        if !path.starts_with('/') {
            return Err(Error::new("URL path must start with /"));
        }
        Ok(Url {
            scheme,
            host,
            port,
            path,
            query,
            user,
            pass,
        })
    }

    /// Default port implied by the scheme.
    pub fn default_port(&self) -> u16 {
        if self.scheme == "https" {
            443
        } else {
            80
        }
    }

    pub fn is_https(&self) -> bool {
        self.scheme == "https"
    }

    /// Value for the Host header: brackets around IPv6, port omitted when it
    /// is the scheme default.
    pub fn host_header(&self) -> String {
        let host = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        if self.port == self.default_port() {
            host
        } else {
            format!("{host}:{}", self.port)
        }
    }

    pub fn path_and_query(&self) -> String {
        if self.query.is_empty() {
            self.path.clone()
        } else {
            let mut s = String::with_capacity(self.path.len() + self.query.len() + 1);
            s.push_str(&self.path);
            s.push('?');
            s.push_str(&self.query);
            s
        }
    }

    /// scheme://host[:port] - never includes userinfo.
    pub fn origin(&self) -> String {
        format!("{}://{}", self.scheme, self.host_header())
    }

    /// Absolute request target (used when talking to a forward proxy).
    pub fn absolute_uri(&self) -> String {
        let mut s = self.origin();
        s.push_str(&self.path_and_query());
        s
    }

    pub fn same_origin(&self, other: &Url) -> bool {
        self.scheme.eq_ignore_ascii_case(&other.scheme)
            && self.host.eq_ignore_ascii_case(&other.host)
            && self.port == other.port
    }

    /// Resolve a Location header against this URL (RFC 3986 relative refs).
    pub fn join(&self, location: &str) -> Result<Url> {
        let location = location.trim_matches(|c: char| c == ' ' || c == '\t');
        if location.is_empty() {
            return Err(Error::new("empty redirect location"));
        }
        if location.contains("://") {
            return Url::parse(location);
        }
        if let Some(rest) = location.strip_prefix("//") {
            return Url::parse(&format!("{}://{}", self.scheme, rest));
        }
        if location.starts_with('#') {
            return Ok(self.clone());
        }
        let (loc_path, loc_query) = match location.split_once('?') {
            Some((p, q)) => (p, Some(q)),
            None => (location, None),
        };
        let (path, query) = if loc_path.is_empty() {
            // Query-only reference: keep the path, replace the query.
            (
                self.path.clone(),
                loc_query
                    .map(|q| q.to_string())
                    .unwrap_or_else(|| self.query.clone()),
            )
        } else if loc_path.starts_with('/') {
            (
                normalize_path(loc_path),
                loc_query.unwrap_or("").to_string(),
            )
        } else {
            let dir = match self.path.rfind('/') {
                Some(i) => &self.path[..=i],
                None => "/",
            };
            let joined = format!("{dir}{loc_path}");
            (normalize_path(&joined), loc_query.unwrap_or("").to_string())
        };
        Ok(Url {
            scheme: self.scheme.clone(),
            host: self.host.clone(),
            port: self.port,
            path,
            query,
            user: self.user.clone(),
            pass: self.pass.clone(),
        })
    }
}

fn parse_host_port(authority: &str, default_port: u16) -> Result<(String, u16)> {
    if let Some(rest) = authority.strip_prefix('[') {
        let end = rest
            .find(']')
            .ok_or_else(|| Error::new("unterminated IPv6 literal in URL"))?;
        let inner = &rest[..end];
        let addr: Ipv6Addr = inner
            .parse()
            .map_err(|_| Error::new("invalid IPv6 literal in URL"))?;
        let after = &rest[end + 1..];
        let port = if after.is_empty() {
            default_port
        } else {
            let p = after
                .strip_prefix(':')
                .ok_or_else(|| Error::new("unexpected characters after IPv6 literal"))?;
            parse_port(p)?
        };
        Ok((addr.to_string(), port))
    } else {
        if authority.contains('[') || authority.contains(']') {
            return Err(Error::new("unexpected bracket in URL host"));
        }
        let (host_raw, port) = match authority.split_once(':') {
            Some((h, p)) => (h, Some(parse_port(p)?)),
            None => (authority, None),
        };
        if host_raw.is_empty() {
            return Err(Error::new("URL is missing a host"));
        }
        if host_raw.contains(':') {
            return Err(Error::new("IPv6 addresses must be enclosed in brackets"));
        }
        let host = if let Ok(v4) = host_raw.parse::<Ipv4Addr>() {
            v4.to_string()
        } else {
            for b in host_raw.bytes() {
                if !(b.is_ascii_alphanumeric() || b == b'-' || b == b'.' || b == b'_' || b == b'~')
                {
                    return Err(Error::new("invalid character in URL host"));
                }
            }
            host_raw.to_ascii_lowercase()
        };
        Ok((host, port.unwrap_or(default_port)))
    }
}

fn parse_port(s: &str) -> Result<u16> {
    if s.is_empty() || s.len() > 5 || !s.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Error::new("invalid port in URL"));
    }
    let v: u32 = s.parse().map_err(|_| Error::new("invalid port in URL"))?;
    if v == 0 || v > u16::MAX as u32 {
        return Err(Error::new("port out of range in URL"));
    }
    Ok(v as u16)
}

fn normalize_path(path: &str) -> String {
    let trailing = path.ends_with('/');
    let mut parts: Vec<&str> = Vec::new();
    for seg in path.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            other => parts.push(other),
        }
    }
    let mut out = String::from("/");
    out.push_str(&parts.join("/"));
    if trailing && !out.ends_with('/') {
        out.push('/');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parsed(s: &str) -> Url {
        match Url::parse(s) {
            Ok(u) => u,
            Err(e) => panic!("expected {s} to parse: {e}"),
        }
    }

    #[test]
    fn parses_plain_http() {
        let u = parsed("http://example.com/");
        assert_eq!(u.scheme, "http");
        assert_eq!(u.host, "example.com");
        assert_eq!(u.port, 80);
        assert_eq!(u.path, "/");
        assert_eq!(u.query, "");
        assert_eq!(u.user, None);
        assert_eq!(u.host_header(), "example.com");
        assert_eq!(u.origin(), "http://example.com");
        assert_eq!(u.path_and_query(), "/");
    }

    #[test]
    fn default_path_and_https_port() {
        let u = parsed("https://Example.COM");
        assert_eq!(u.scheme, "https");
        assert_eq!(u.host, "example.com");
        assert_eq!(u.port, 443);
        assert_eq!(u.path, "/");
        assert_eq!(u.host_header(), "example.com");
        assert_eq!(u.origin(), "https://example.com");
    }

    #[test]
    fn preserves_path_and_query_and_drops_fragment() {
        let u = parsed("http://example.com/a%2Fb/c?x=1&y=%20#section");
        assert_eq!(u.path, "/a%2Fb/c");
        assert_eq!(u.query, "x=1&y=%20");
        assert_eq!(u.path_and_query(), "/a%2Fb/c?x=1&y=%20");
        assert_eq!(u.host_header(), "example.com");
    }

    #[test]
    fn empty_query_and_empty_path() {
        let u = parsed("http://example.com?x");
        assert_eq!(u.path, "/");
        assert_eq!(u.query, "x");
        let u = parsed("http://example.com/?");
        assert_eq!(u.path, "/");
        assert_eq!(u.query, "");
        assert_eq!(u.path_and_query(), "/");
    }

    #[test]
    fn keeps_fragment_out_of_query() {
        let u = parsed("http://example.com/p?q=1#frag?not-query");
        assert_eq!(u.query, "q=1");
    }

    #[test]
    fn non_default_port_appears_in_host_header() {
        let u = parsed("http://example.com:8080/x");
        assert_eq!(u.port, 8080);
        assert_eq!(u.host_header(), "example.com:8080");
        assert_eq!(u.origin(), "http://example.com:8080");
        assert_eq!(u.absolute_uri(), "http://example.com:8080/x");
    }

    #[test]
    fn explicit_default_port_is_omitted() {
        let u = parsed("https://example.com:443/x");
        assert_eq!(u.host_header(), "example.com");
        let u = parsed("http://example.com:443/x");
        assert_eq!(u.host_header(), "example.com:443");
    }

    #[test]
    fn userinfo_is_exposed_but_not_in_origin() {
        let u = parsed("http://alice:s3cret@example.com:8080/p?q=1");
        assert_eq!(u.user.as_deref(), Some("alice"));
        assert_eq!(u.pass.as_deref(), Some("s3cret"));
        assert_eq!(u.host, "example.com");
        assert_eq!(u.origin(), "http://example.com:8080");
        assert!(!u.absolute_uri().contains("alice"));
    }

    #[test]
    fn userinfo_without_password() {
        let u = parsed("http://token@example.com/");
        assert_eq!(u.user.as_deref(), Some("token"));
        assert_eq!(u.pass, None);
    }

    #[test]
    fn ipv4_host() {
        let u = parsed("http://127.0.0.1:1234/x");
        assert_eq!(u.host, "127.0.0.1");
        assert_eq!(u.host_header(), "127.0.0.1:1234");
    }

    #[test]
    fn ipv6_host_is_normalized_and_bracketed() {
        let u = parsed("http://[2001:DB8:0:0::1]:8443/x");
        assert_eq!(u.host, "2001:db8::1");
        assert_eq!(u.host_header(), "[2001:db8::1]:8443");
        assert_eq!(u.origin(), "http://[2001:db8::1]:8443");
        assert_eq!(u.absolute_uri(), "http://[2001:db8::1]:8443/x");
    }

    #[test]
    fn ipv6_default_port() {
        let u = parsed("https://[::1]/");
        assert_eq!(u.port, 443);
        assert_eq!(u.host, "::1");
        assert_eq!(u.host_header(), "[::1]");
    }

    #[test]
    fn rejects_relative_and_malformed_urls() {
        let bad = [
            "",
            "example.com/path",
            "/path",
            "//example.com/path",
            "ftp://example.com/",
            "file:///etc/passwd",
            "http://",
            "http:///path",
            "http://example.com:0/",
            "http://example.com:99999/",
            "http://example.com:abc/",
            "http://example.com:/",
            "http://exa mple.com/",
            "http://example.com/a b",
            "http://example.com/a\tb",
            "http://example.com/a\nb",
            "http://[::1/",
            "http://2001:db8::1/",
            "http://user@:80/",
        ];
        for s in bad {
            assert!(Url::parse(s).is_err(), "should reject {s:?}");
        }
    }

    #[test]
    fn rejects_control_chars_in_any_component() {
        assert!(Url::parse("http://example.com/\u{0}").is_err());
        assert!(Url::parse("http://example.com/pa\u{7}th").is_err());
    }

    #[test]
    fn joins_relative_references() {
        let base = parsed("http://example.com/a/b?q=1");
        assert_eq!(base.join("/x").unwrap().path_and_query(), "/x");
        assert_eq!(base.join("x").unwrap().path_and_query(), "/a/x");
        assert_eq!(base.join("../x").unwrap().path_and_query(), "/x");
        assert_eq!(base.join("./x").unwrap().path_and_query(), "/a/x");
        assert_eq!(base.join("?z=2").unwrap().path_and_query(), "/a/b?z=2");
        assert!(base.join("").is_err());
        let other = base.join("//other.example/p?q=2").unwrap();
        assert_eq!(other.origin(), "http://other.example");
        assert_eq!(other.path_and_query(), "/p?q=2");
        let https = base.join("https://secure.example/z").unwrap();
        assert_eq!(https.scheme, "https");
        assert_eq!(https.port, 443);
        assert_eq!(https.path_and_query(), "/z");
    }

    #[test]
    fn join_keeps_authority_for_absolute_paths() {
        let base = parsed("https://user:pw@example.com:8443/a/b");
        let u = base.join("/c").unwrap();
        assert_eq!(u.origin(), "https://example.com:8443");
        assert_eq!(u.path, "/c");
        assert_eq!(u.user.as_deref(), Some("user"));
        assert_eq!(u.pass.as_deref(), Some("pw"));
    }

    #[test]
    fn same_origin_compares_scheme_host_port() {
        let a = parsed("http://example.com/x");
        let b = parsed("http://EXAMPLE.com:80/y");
        let c = parsed("http://example.com:8080/y");
        let d = parsed("https://example.com/x");
        assert!(a.same_origin(&b));
        assert!(!a.same_origin(&c));
        assert!(!a.same_origin(&d));
    }
}
