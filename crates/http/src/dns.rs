//! A tiny DNS client used when the system resolver is unusable.
//!
//! This matters on Android/Termux: a statically linked musl binary has no
//! access to bionic's netd resolver and there is usually no /etc/resolv.conf,
//! so getaddrinfo() fails even though the device has working DNS. We can query
//! the platform's nameservers directly over UDP.
//!
//! Supported: A and AAAA queries, CNAME following, multiple servers, retries.
//! Not supported: DNSSEC, EDNS, TCP fallback (reported clearly).

use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream, UdpSocket};
use std::time::{Duration, Instant};

use crate::{Error, Result};

const TYPE_A: u16 = 1;
const TYPE_CNAME: u16 = 5;
const TYPE_AAAA: u16 = 28;
const CLASS_IN: u16 = 1;

#[derive(Debug, Clone, Default)]
pub struct Discovery {
    pub servers: Vec<IpAddr>,
    pub source: String,
}

/// Nameservers from /etc/resolv.conf, or Android properties when there is no
/// resolver configuration (Termux).
pub fn discover() -> Discovery {
    let mut servers = Vec::new();
    if let Ok(text) = std::fs::read_to_string("/etc/resolv.conf") {
        for line in text.lines() {
            let line = line.trim();
            if let Some(rest) = line.strip_prefix("nameserver") {
                if let Some(ip) = rest
                    .split_whitespace()
                    .next()
                    .and_then(|s| s.parse::<IpAddr>().ok())
                {
                    if !servers.contains(&ip) {
                        servers.push(ip);
                    }
                }
            }
        }
        if !servers.is_empty() {
            return Discovery {
                servers,
                source: "/etc/resolv.conf".into(),
            };
        }
    }
    #[cfg(unix)]
    {
        for key in ["net.dns1", "net.dns2", "net.dns3", "net.dns4"] {
            if let Some(value) = android_prop(key) {
                if let Ok(ip) = value.trim().parse::<IpAddr>() {
                    if !servers.contains(&ip) {
                        servers.push(ip);
                    }
                }
            }
        }
        if servers.is_empty() {
            // Recent Android versions stopped exporting net.dns*, but some
            // still expose DNS in the property dump.
            if let Ok(output) = std::process::Command::new("getprop").output() {
                let text = String::from_utf8_lossy(&output.stdout);
                for line in text.lines() {
                    let lower = line.to_ascii_lowercase();
                    if !lower.contains("dns") {
                        continue;
                    }
                    if let Some(open) = line.rfind('[') {
                        if let Some(close) = line.rfind(']') {
                            if let Ok(ip) = line[open + 1..close].trim().parse::<IpAddr>() {
                                if !servers.contains(&ip) {
                                    servers.push(ip);
                                }
                            }
                        }
                    }
                }
            }
        }
        if !servers.is_empty() {
            return Discovery {
                servers,
                source: "Android properties".into(),
            };
        }
        if is_android() {
            // No resolver configuration is visible to a static musl binary on
            // Android. Public resolvers are the only remaining option; the
            // user can override with --dns. This unblocks Termux, where the
            // device's own DNS works but /etc/resolv.conf does not exist.
            for ip in ["223.5.5.5", "1.1.1.1", "8.8.8.8"] {
                if let Ok(ip) = ip.parse::<IpAddr>() {
                    servers.push(ip);
                }
            }
            return Discovery {
                servers,
                source: "public fallback (Android; use --dns to override)".into(),
            };
        }
    }
    Discovery {
        servers,
        source: "none".into(),
    }
}

#[cfg(unix)]
fn is_android() -> bool {
    std::env::var("PREFIX")
        .map(|p| p.contains("com.termux"))
        .unwrap_or(false)
        || std::path::Path::new("/system/build.prop").exists()
}

#[cfg(unix)]
fn android_prop(key: &str) -> Option<String> {
    for bin in ["/system/bin/getprop", "getprop"] {
        let output = std::process::Command::new(bin).arg(key).output().ok()?;
        if output.status.success() {
            let text = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !text.is_empty() {
                return Some(text);
            }
        }
    }
    None
}

/// Resolve a hostname using explicit nameservers. Port is used only to build
/// socket addresses; the DNS query itself is port-independent.
pub fn resolve(
    host: &str,
    _port: u16,
    servers: &[IpAddr],
    timeout: Duration,
) -> Result<Vec<IpAddr>> {
    if servers.is_empty() {
        return Err(Error::new("no DNS servers configured"));
    }
    let mut last = String::new();
    for server in servers.iter().take(4) {
        // Prefer A: IPv6 is often unroutable and asking both on every server
        // doubles the worst-case wait on a rescue network.
        match query(host, TYPE_A, *server, timeout) {
            Ok(ips) if !ips.is_empty() => return Ok(ips),
            Ok(_) => {}
            Err(e) => last = format!("{e}"),
        }
        match query(host, TYPE_AAAA, *server, timeout) {
            Ok(ips) if !ips.is_empty() => return Ok(ips),
            Ok(_) => {}
            Err(e) => last = format!("{e}"),
        }
    }
    Err(Error::new(format!(
        "DNS lookup for {host} failed via {}: {}",
        servers
            .iter()
            .map(|s| s.to_string())
            .collect::<Vec<_>>()
            .join(", "),
        if last.is_empty() {
            "no addresses".into()
        } else {
            last
        }
    )))
}

fn query(host: &str, qtype: u16, server: IpAddr, timeout: Duration) -> Result<Vec<IpAddr>> {
    query_depth(host, qtype, server, timeout, 0)
}

fn query_depth(
    host: &str,
    qtype: u16,
    server: IpAddr,
    timeout: Duration,
    depth: u8,
) -> Result<Vec<IpAddr>> {
    let id = (emerag_util::rand::u64().unwrap_or(0) & 0xffff) as u16;
    let packet = build_query(id, host, qtype)?;
    let bind: SocketAddr = if server.is_ipv4() {
        "0.0.0.0:0".parse().unwrap()
    } else {
        "[::]:0".parse().unwrap()
    };
    let socket = UdpSocket::bind(bind).map_err(|e| Error::new(format!("dns: bind: {e}")))?;
    socket
        .set_read_timeout(Some(timeout))
        .map_err(|e| Error::new(format!("dns: timeout: {e}")))?;
    let target = SocketAddr::new(server, 53);
    socket
        .connect(target)
        .map_err(|e| Error::new(format!("dns: connect {target}: {e}")))?;
    socket
        .send(&packet)
        .map_err(|e| Error::new(format!("dns: send to {target}: {e}")))?;
    let mut buf = [0u8; 4096];
    let started = Instant::now();
    loop {
        match socket.recv(&mut buf) {
            Ok(n) => {
                let response = &buf[..n];
                if response.len() < 12 {
                    continue;
                }
                let rid = u16::from_be_bytes([response[0], response[1]]);
                if rid != id {
                    continue;
                }
                let flags = u16::from_be_bytes([response[2], response[3]]);
                if flags & 0x0200 != 0 {
                    return Err(Error::new(
                        "dns: truncated response (TCP fallback unsupported)",
                    ));
                }
                let rcode = flags & 0x000f;
                if rcode == 3 {
                    return Ok(Vec::new());
                }
                if rcode != 0 {
                    return Err(Error::new(format!("dns: server returned rcode {rcode}")));
                }
                let (ips, cname) = parse_answers(response, qtype)?;
                if ips.is_empty() {
                    if let Some(target) = cname {
                        if depth < 3 && target != host {
                            return query_depth(&target, qtype, server, timeout, depth + 1);
                        }
                    }
                }
                return Ok(ips);
            }
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                if started.elapsed() >= timeout * 2 {
                    return Err(Error::new("dns: timeout"));
                }
                continue;
            }
            Err(e) => return Err(Error::new(format!("dns: recv: {e}"))),
        }
    }
}

fn build_query(id: u16, host: &str, qtype: u16) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(32 + host.len());
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&0x0100u16.to_be_bytes()); // recursion desired
    out.extend_from_slice(&1u16.to_be_bytes()); // qdcount
    out.extend_from_slice(&0u16.to_be_bytes()); // ancount
    out.extend_from_slice(&0u16.to_be_bytes()); // nscount
    out.extend_from_slice(&0u16.to_be_bytes()); // arcount
    let labels: Vec<&str> = host.trim_end_matches('.').split('.').collect();
    if labels.iter().any(|l| l.is_empty() || l.len() > 63) {
        return Err(Error::new("dns: invalid hostname"));
    }
    for label in labels {
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    out.extend_from_slice(&qtype.to_be_bytes());
    out.extend_from_slice(&CLASS_IN.to_be_bytes());
    Ok(out)
}

fn parse_answers(packet: &[u8], qtype: u16) -> Result<(Vec<IpAddr>, Option<String>)> {
    if packet.len() < 12 {
        return Err(Error::new("dns: short packet"));
    }
    let qd = u16::from_be_bytes([packet[4], packet[5]]) as usize;
    let an = u16::from_be_bytes([packet[6], packet[7]]) as usize;
    let mut pos = 12usize;
    for _ in 0..qd {
        let _ = read_name(packet, &mut pos)?;
        pos += 4;
        if pos > packet.len() {
            return Err(Error::new("dns: truncated question"));
        }
    }
    let mut out = Vec::new();
    let mut cname: Option<String> = None;
    for _ in 0..an {
        let _ = read_name(packet, &mut pos)?;
        if pos + 10 > packet.len() {
            return Err(Error::new("dns: truncated answer"));
        }
        let rtype = u16::from_be_bytes([packet[pos], packet[pos + 1]]);
        let rdlen = u16::from_be_bytes([packet[pos + 8], packet[pos + 9]]) as usize;
        pos += 10;
        if pos + rdlen > packet.len() {
            return Err(Error::new("dns: truncated rdata"));
        }
        let rdata = &packet[pos..pos + rdlen];
        if rtype == TYPE_CNAME && cname.is_none() {
            let mut name_pos = pos;
            if let Ok(name) = read_name(packet, &mut name_pos) {
                cname = Some(name);
            }
        }
        if rtype == qtype {
            match qtype {
                TYPE_A if rdata.len() == 4 => {
                    out.push(IpAddr::from([rdata[0], rdata[1], rdata[2], rdata[3]]));
                }
                TYPE_AAAA if rdata.len() == 16 => {
                    let mut bytes = [0u8; 16];
                    bytes.copy_from_slice(rdata);
                    out.push(IpAddr::from(bytes));
                }
                _ => {}
            }
        }
        pos += rdlen;
    }
    Ok((out, cname))
}

fn read_name(packet: &[u8], pos: &mut usize) -> Result<String> {
    let mut out = String::new();
    let mut p = *pos;
    let mut jumped = false;
    let mut hops = 0;
    loop {
        if p >= packet.len() {
            return Err(Error::new("dns: name out of bounds"));
        }
        let len = packet[p];
        if len & 0xc0 == 0xc0 {
            if p + 1 >= packet.len() {
                return Err(Error::new("dns: bad compression pointer"));
            }
            let offset = (((len as usize & 0x3f) << 8) | packet[p + 1] as usize) as usize;
            if !jumped {
                *pos = p + 2;
                jumped = true;
            }
            p = offset;
            hops += 1;
            if hops > 16 {
                return Err(Error::new("dns: compression loop"));
            }
            continue;
        }
        if len == 0 {
            if !jumped {
                *pos = p + 1;
            }
            return Ok(out);
        }
        let end = p + 1 + len as usize;
        if end > packet.len() {
            return Err(Error::new("dns: label out of bounds"));
        }
        if !out.is_empty() {
            out.push('.');
        }
        out.push_str(&String::from_utf8_lossy(&packet[p + 1..end]));
        p = end;
    }
}

/// TCP fallback is deliberately not implemented; expose whether it is needed
/// so callers can produce a clear error instead of hanging.
pub fn tcp_fallback_hint() -> &'static str {
    "DNS response was truncated; retry with a different --dns server"
}

#[allow(dead_code)]
fn _tcp_query(host: &str, qtype: u16, server: IpAddr, timeout: Duration) -> Result<Vec<u8>> {
    let id = (emerag_util::rand::u64().unwrap_or(0) & 0xffff) as u16;
    let packet = build_query(id, host, qtype)?;
    let mut stream = TcpStream::connect_timeout(&SocketAddr::new(server, 53), timeout)
        .map_err(|e| Error::new(format!("dns tcp: {e}")))?;
    stream.set_read_timeout(Some(timeout)).ok();
    let len = (packet.len() as u16).to_be_bytes();
    stream
        .write_all(&len)
        .and_then(|_| stream.write_all(&packet))
        .map_err(|e| Error::new(format!("dns tcp: {e}")))?;
    let mut prefix = [0u8; 2];
    stream
        .read_exact(&mut prefix)
        .map_err(|e| Error::new(format!("dns tcp: {e}")))?;
    let n = u16::from_be_bytes(prefix) as usize;
    let mut buf = vec![0u8; n];
    stream
        .read_exact(&mut buf)
        .map_err(|e| Error::new(format!("dns tcp: {e}")))?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_encodes_labels_and_type() {
        let packet = build_query(7, "example.test", TYPE_A).unwrap();
        assert_eq!(&packet[0..2], &7u16.to_be_bytes());
        assert_eq!(&packet[2..4], &0x0100u16.to_be_bytes());
        assert_eq!(&packet[12..13], &[7u8]);
        assert_eq!(&packet[13..20], b"example");
        assert_eq!(&packet[20..21], &[4u8]);
        assert_eq!(&packet[21..25], b"test");
        assert_eq!(&packet[25..26], &[0u8]);
        assert_eq!(&packet[26..28], &TYPE_A.to_be_bytes());
    }

    #[test]
    fn parses_a_response_with_compression() {
        let query = build_query(7, "example.test", TYPE_A).unwrap();
        let mut response = Vec::new();
        response.extend_from_slice(&7u16.to_be_bytes());
        response.extend_from_slice(&0x8180u16.to_be_bytes());
        response.extend_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&0u16.to_be_bytes());
        response.extend_from_slice(&0u16.to_be_bytes());
        response.extend_from_slice(&query[12..]);
        response.extend_from_slice(&[
            0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04, 192, 0, 2, 7,
        ]);
        let (ips, cname) = parse_answers(&response, TYPE_A).unwrap();
        assert!(cname.is_none());
        assert_eq!(ips, vec!["192.0.2.7".parse::<IpAddr>().unwrap()]);
    }

    #[test]
    fn compression_loop_is_rejected() {
        let mut packet = vec![0u8; 12];
        packet[0..2].copy_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&[0xc0, 0x0c]);
        let mut pos = 12;
        assert!(read_name(&packet, &mut pos).is_err());
    }

    #[test]
    fn discover_never_panics() {
        let d = discover();
        assert!(!d.source.is_empty());
    }
}
