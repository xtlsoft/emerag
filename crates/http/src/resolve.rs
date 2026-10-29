//! DNS-proof address overrides.
//!
//! A ResolveTable maps host (and optionally port) to a literal IP address,
//! which is what --resolve is built on. Entries are written as:
//!
//!   host:port:ip      pin one host and port
//!   host:ip           pin one host on any port
//!   [2001:db8::1]:443 pin a literal IPv6 host to itself on that port
//!
//! Lookup order is exact host:port first, then the port-less host entry. The
//! system resolver is only consulted by the client after both miss.

use core::str::FromStr;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::error::{Error, Result};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolveEntry {
    pub host: String,
    pub port: Option<u16>,
    pub ip: IpAddr,
}

#[derive(Debug, Clone, Default)]
pub struct ResolveTable {
    entries: Vec<ResolveEntry>,
}

impl ResolveTable {
    pub fn new() -> Self {
        ResolveTable {
            entries: Vec::new(),
        }
    }

    /// Parse a comma/semicolon/whitespace separated list of entries.
    pub fn parse(list: &str) -> Result<ResolveTable> {
        let mut table = ResolveTable::new();
        for token in list.split(|c: char| c == ',' || c == ';' || c.is_whitespace()) {
            if token.is_empty() {
                continue;
            }
            table.parse_entry(token)?;
        }
        Ok(table)
    }

    /// Parse and append one entry.
    pub fn parse_entry(&mut self, raw: &str) -> Result<()> {
        let s = raw.trim();
        if s.is_empty() {
            return Err(Error::new("empty resolve entry"));
        }
        if s.bytes().any(|b| b <= b' ' || b == 0x7f) {
            return Err(Error::new(
                "resolve entry contains whitespace or control characters",
            ));
        }

        let (host, rest) = if let Some(stripped) = s.strip_prefix('[') {
            let end = stripped
                .find(']')
                .ok_or_else(|| Error::new("resolve entry: missing ']' after IPv6 host"))?;
            let inner = &stripped[..end];
            let v6: Ipv6Addr = inner
                .parse()
                .map_err(|_| Error::new("resolve entry: invalid IPv6 host"))?;
            (v6.to_string(), &stripped[end + 1..])
        } else {
            let idx = s
                .find(':')
                .ok_or_else(|| Error::new("resolve entry must be host:ip or host:port:ip"))?;
            let host = &s[..idx];
            if host.is_empty() {
                return Err(Error::new("resolve entry: missing host"));
            }
            if !host.bytes().all(|b| {
                b.is_ascii_alphanumeric() || b == b'-' || b == b'.' || b == b'_' || b == b'~'
            }) {
                return Err(Error::new(
                    "resolve entry: invalid character in host (bracket IPv6 hosts)",
                ));
            }
            (host.to_ascii_lowercase(), &s[idx..])
        };

        let rest = rest
            .strip_prefix(':')
            .filter(|r| !r.is_empty())
            .ok_or_else(|| Error::new("resolve entry: missing address"))?;

        // IPv6 literals must be bracketed everywhere; this keeps host:ip and
        // host:port:ip unambiguous (a bare v6 address contains colons).
        let (port, ip) = if let Some(ip) = parse_bracketed_ip(rest) {
            // host:[ipv6] - port defaults by scheme at lookup time.
            (None, ip)
        } else if let Ok(v4) = rest.parse::<Ipv4Addr>() {
            // host:ipv4
            (None, IpAddr::V4(v4))
        } else if let Some((port_s, ip_s)) = rest.split_once(':') {
            // host:port:ip or host:port:[ipv6]
            let port = parse_port(port_s)?;
            let ip = if let Some(ip) = parse_bracketed_ip(ip_s) {
                ip
            } else if let Ok(v4) = ip_s.parse::<Ipv4Addr>() {
                IpAddr::V4(v4)
            } else {
                return Err(Error::new(
                    "resolve entry: invalid address; bracket IPv6 literals, e.g. host:443:[2001:db8::1]",
                ));
            };
            (Some(port), ip)
        } else if let Ok(port) = parse_port(rest) {
            // [ipv6]:port - a literal address pinned to itself.
            match host.parse::<IpAddr>() {
                Ok(ip) => (Some(port), ip),
                Err(_) => return Err(Error::new(
                    "resolve entry: missing address after the port (use host:ip or host:port:ip)",
                )),
            }
        } else {
            return Err(Error::new(format!(
                "invalid resolve entry {:?}; expected host:port:ip, host:ip or [ipv6]:port",
                raw
            )));
        };
        self.add(host, port, ip);
        Ok(())
    }

    /// Add an entry. host is lowercased and IPv6 literals are canonicalised.
    pub fn add(&mut self, host: impl Into<String>, port: impl Into<Option<u16>>, ip: IpAddr) {
        let host = normalize_host(&host.into());
        let entry = ResolveEntry {
            host,
            port: port.into(),
            ip,
        };
        if let Some(existing) = self
            .entries
            .iter_mut()
            .find(|e| e.host == entry.host && e.port == entry.port)
        {
            existing.ip = ip;
        } else {
            self.entries.push(entry);
        }
    }

    /// Exact host:port first, then a port-less host entry.
    pub fn lookup(&self, host: &str, port: u16) -> Option<IpAddr> {
        let host = normalize_host(host);
        self.entries
            .iter()
            .rev()
            .find(|e| e.host == host && e.port == Some(port))
            .map(|e| e.ip)
            .or_else(|| {
                self.entries
                    .iter()
                    .rev()
                    .find(|e| e.host == host && e.port.is_none())
                    .map(|e| e.ip)
            })
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn entries(&self) -> &[ResolveEntry] {
        &self.entries
    }

    pub fn clear(&mut self) {
        self.entries.clear();
    }
}

impl FromStr for ResolveTable {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        ResolveTable::parse(s)
    }
}

fn normalize_host(host: &str) -> String {
    let h = host.trim().trim_start_matches('[').trim_end_matches(']');
    if let Ok(v6) = h.parse::<Ipv6Addr>() {
        v6.to_string()
    } else if let Ok(v4) = h.parse::<Ipv4Addr>() {
        v4.to_string()
    } else {
        h.to_ascii_lowercase()
    }
}

fn parse_bracketed_ip(token: &str) -> Option<IpAddr> {
    let inner = token.strip_prefix('[')?.strip_suffix(']')?;
    inner.parse::<Ipv6Addr>().ok().map(IpAddr::V6)
}

fn parse_port(s: &str) -> Result<u16> {
    if s.is_empty() || s.len() > 5 || !s.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Error::new("resolve entry: invalid port"));
    }
    let v: u32 = s
        .parse()
        .map_err(|_| Error::new("resolve entry: invalid port"))?;
    if v == 0 || v > u16::MAX as u32 {
        return Err(Error::new("resolve entry: port out of range"));
    }
    Ok(v as u16)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn host_port_ip_entry() {
        let mut t = ResolveTable::new();
        t.parse_entry("example.com:443:10.0.0.1").unwrap();
        assert_eq!(t.lookup("example.com", 443), Some(ip("10.0.0.1")));
        assert_eq!(t.lookup("example.com", 80), None);
        assert_eq!(t.lookup("EXAMPLE.COM", 443), Some(ip("10.0.0.1")));
    }

    #[test]
    fn host_ip_entry_applies_to_every_port() {
        let mut t = ResolveTable::new();
        t.parse_entry("api.example.com:10.0.0.2").unwrap();
        assert_eq!(t.lookup("api.example.com", 443), Some(ip("10.0.0.2")));
        assert_eq!(t.lookup("api.example.com", 80), Some(ip("10.0.0.2")));
        assert_eq!(t.len(), 1);
        assert_eq!(t.entries()[0].port, None);
    }

    #[test]
    fn exact_port_beats_wildcard_regardless_of_insertion_order() {
        let mut t = ResolveTable::new();
        t.parse_entry("example.com:10.0.0.2").unwrap();
        t.parse_entry("example.com:443:10.0.0.1").unwrap();
        assert_eq!(t.lookup("example.com", 443), Some(ip("10.0.0.1")));
        assert_eq!(t.lookup("example.com", 8443), Some(ip("10.0.0.2")));

        let mut t = ResolveTable::new();
        t.parse_entry("example.com:443:10.0.0.1").unwrap();
        t.parse_entry("example.com:10.0.0.2").unwrap();
        assert_eq!(t.lookup("example.com", 443), Some(ip("10.0.0.1")));
        assert_eq!(t.lookup("example.com", 8443), Some(ip("10.0.0.2")));
    }

    #[test]
    fn later_duplicate_replaces_earlier() {
        let mut t = ResolveTable::new();
        t.add("example.com", Some(443), ip("10.0.0.1"));
        t.add("example.com", Some(443), ip("10.0.0.9"));
        assert_eq!(t.lookup("example.com", 443), Some(ip("10.0.0.9")));
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn ipv6_forms() {
        let mut t = ResolveTable::new();
        t.parse_entry("v6.example:443:[2001:db8::1]").unwrap();
        assert_eq!(t.lookup("v6.example", 443), Some(ip("2001:db8::1")));

        t.parse_entry("v6b.example:[2001:db8::2]").unwrap();
        assert_eq!(t.lookup("v6b.example", 80), Some(ip("2001:db8::2")));

        t.parse_entry("[2001:db8::3]:443:[2001:db8::4]").unwrap();
        assert_eq!(t.lookup("2001:db8::3", 443), Some(ip("2001:db8::4")));

        t.parse_entry("[2001:db8::5]:443").unwrap();
        assert_eq!(t.lookup("[2001:db8::5]", 443), Some(ip("2001:db8::5")));
        assert_eq!(t.lookup("2001:db8::5", 80), None);
    }

    #[test]
    fn unbracketed_ipv6_addresses_are_rejected() {
        // Bare IPv6 in the ip position would make host:ip and host:port:ip
        // ambiguous, so it is an error rather than a silent misparse.
        let mut t = ResolveTable::new();
        assert!(t.parse_entry("v6.example:2001:db8::2").is_err());
        assert!(t.parse_entry("v6.example:443:2001:db8::2").is_err());
        assert!(t.parse_entry("2001:db8::1:443:1.2.3.4").is_err());
    }

    #[test]
    fn list_parsing() {
        let t =
            ResolveTable::parse("a.example:443:10.0.0.1, b.example:10.0.0.2\nc.example:8443:[::1]")
                .unwrap();
        assert_eq!(t.len(), 3);
        assert_eq!(t.lookup("a.example", 443), Some(ip("10.0.0.1")));
        assert_eq!(t.lookup("b.example", 1), Some(ip("10.0.0.2")));
        assert_eq!(t.lookup("c.example", 8443), Some(ip("::1")));
    }

    #[test]
    fn rejects_bad_entries() {
        for bad in [
            "",
            "hostonly",
            "example.com:",
            "example.com:abc",
            "example.com:0:10.0.0.1",
            "example.com:70000:10.0.0.1",
            "example.com:443:1.2.3.4:5",
            "[not-v6]:443:1.2.3.4",
            "[::1:443:1.2.3.4",
            "exa mple.com:10.0.0.1",
        ] {
            let mut t = ResolveTable::new();
            assert!(t.parse_entry(bad).is_err(), "should reject {bad:?}");
        }
    }

    #[test]
    fn parses_ipv4_literal_host() {
        let mut t = ResolveTable::new();
        t.parse_entry("127.0.0.1:80:127.0.0.2").unwrap();
        assert_eq!(t.lookup("127.0.0.1", 80), Some(ip("127.0.0.2")));
    }

    #[test]
    fn empty_table() {
        let t = ResolveTable::new();
        assert!(t.is_empty());
        assert_eq!(t.lookup("example.com", 80), None);
        assert_eq!(ResolveTable::parse("").unwrap().len(), 0);
    }

    #[test]
    fn from_str_impl() {
        let t: ResolveTable = "example.com:443:127.0.0.1".parse().unwrap();
        assert_eq!(
            t.lookup("example.com", 443),
            Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)))
        );
    }
}
