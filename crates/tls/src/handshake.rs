//! Handshake message framing, ClientHello construction and ServerHello parsing.

use std::net::{IpAddr, TcpStream};

use emerag_crypto::curve::{P256Private, X25519Private};

use crate::bytes::{Reader, Writer};
use crate::key::HashId;
use crate::record::{RecordLayer, MAX_PLAINTEXT};
use crate::{Error, TlsConfig, TlsVersion};

/// Largest handshake message we accept (certificate chains included).
const MAX_HANDSHAKE_MSG: usize = 1 << 20;
/// Largest buffered transcript. Handshake hashing needs every message.
const MAX_TRANSCRIPT: usize = 2 << 20;

pub(crate) const EXT_SERVER_NAME: u16 = 0x0000;
pub(crate) const EXT_SUPPORTED_GROUPS: u16 = 0x000a;
pub(crate) const EXT_EC_POINT_FORMATS: u16 = 0x000b;
pub(crate) const EXT_SIGNATURE_ALGORITHMS: u16 = 0x000d;
pub(crate) const EXT_ALPN: u16 = 0x0010;
pub(crate) const EXT_SESSION_TICKET: u16 = 0x0023;
pub(crate) const EXT_SUPPORTED_VERSIONS: u16 = 0x002b;
pub(crate) const EXT_KEY_SHARE: u16 = 0x0033;
pub(crate) const EXT_RENEGOTIATION_INFO: u16 = 0xff01;
pub(crate) const EXT_EXTENDED_MASTER_SECRET: u16 = 0x0017;

pub(crate) const GROUP_X25519: u16 = 0x001d;
pub(crate) const GROUP_P256: u16 = 0x0017;

pub(crate) const HS_CLIENT_HELLO: u8 = 1;
pub(crate) const HS_SERVER_HELLO: u8 = 2;
pub(crate) const HS_NEW_SESSION_TICKET: u8 = 4;
pub(crate) const HS_ENCRYPTED_EXTENSIONS: u8 = 8;
pub(crate) const HS_CERTIFICATE: u8 = 11;
pub(crate) const HS_SERVER_KEY_EXCHANGE: u8 = 12;
pub(crate) const HS_CERTIFICATE_REQUEST: u8 = 13;
pub(crate) const HS_SERVER_HELLO_DONE: u8 = 14;
pub(crate) const HS_CERTIFICATE_VERIFY: u8 = 15;
pub(crate) const HS_FINISHED: u8 = 20;
pub(crate) const HS_KEY_UPDATE: u8 = 24;

/// The HelloRetryRequest random from RFC 8446 section 4.1.3.
pub(crate) const HRR_RANDOM: [u8; 32] = [
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
];

pub(crate) fn encode_handshake(typ: u8, body: &[u8]) -> Result<Vec<u8>, Error> {
    if body.len() > MAX_HANDSHAKE_MSG {
        return Err(Error::new(format!(
            "tls: handshake: message of {} bytes exceeds the {MAX_HANDSHAKE_MSG}-byte limit",
            body.len()
        )));
    }
    let mut out = Vec::with_capacity(4 + body.len());
    out.push(typ);
    out.push((body.len() >> 16) as u8);
    out.push((body.len() >> 8) as u8);
    out.push(body.len() as u8);
    out.extend_from_slice(body);
    Ok(out)
}

#[derive(Debug)]
pub(crate) struct HandshakeMessage {
    pub(crate) typ: u8,
    pub(crate) body: Vec<u8>,
    pub(crate) raw: Vec<u8>,
}

pub(crate) struct HandshakeBuffer {
    buf: Vec<u8>,
}

impl HandshakeBuffer {
    pub(crate) fn new() -> Self {
        HandshakeBuffer { buf: Vec::new() }
    }

    pub(crate) fn push(&mut self, data: &[u8]) -> Result<(), Error> {
        if self.buf.len().saturating_add(data.len()) > MAX_HANDSHAKE_MSG + 4 {
            return Err(Error::new(
                "tls: handshake: reassembly buffer exceeds the handshake size limit",
            ));
        }
        self.buf.extend_from_slice(data);
        Ok(())
    }

    pub(crate) fn next(&mut self) -> Result<Option<HandshakeMessage>, Error> {
        if self.buf.len() < 4 {
            return Ok(None);
        }
        let len =
            ((self.buf[1] as usize) << 16) | ((self.buf[2] as usize) << 8) | (self.buf[3] as usize);
        if len > MAX_HANDSHAKE_MSG {
            return Err(Error::new(format!(
                "tls: handshake: message of {len} bytes exceeds the {MAX_HANDSHAKE_MSG}-byte limit"
            )));
        }
        if self.buf.len() < 4 + len {
            return Ok(None);
        }
        let raw: Vec<u8> = self.buf.drain(..4 + len).collect();
        let typ = raw[0];
        let body = raw[4..].to_vec();
        Ok(Some(HandshakeMessage { typ, body, raw }))
    }
}

pub(crate) struct Transcript {
    buf: Vec<u8>,
}

impl Transcript {
    pub(crate) fn new() -> Self {
        Transcript { buf: Vec::new() }
    }

    pub(crate) fn add(&mut self, raw: &[u8]) -> Result<(), Error> {
        if self.buf.len().saturating_add(raw.len()) > MAX_TRANSCRIPT {
            return Err(Error::new(
                "tls: handshake: transcript exceeds the handshake size limit",
            ));
        }
        self.buf.extend_from_slice(raw);
        Ok(())
    }

    pub(crate) fn hash(&self, hash_id: HashId) -> Vec<u8> {
        hash_id.digest(&self.buf)
    }
}

/// Handshake-time connection: record layer plus reassembly and transcript.
pub(crate) struct HsConn {
    pub(crate) io: RecordLayer,
    pub(crate) hs: HandshakeBuffer,
    pub(crate) transcript: Transcript,
    /// When true (TLS 1.3), a ChangeCipherSpec record is ignored.
    pub(crate) compat_ccs: bool,
}

impl HsConn {
    pub(crate) fn new(tcp: TcpStream) -> Self {
        HsConn {
            io: RecordLayer::new(tcp),
            hs: HandshakeBuffer::new(),
            transcript: Transcript::new(),
            compat_ccs: false,
        }
    }

    /// Write a complete handshake message as one record and add it to the
    /// transcript.
    pub(crate) fn send_message(&mut self, raw: &[u8]) -> Result<(), Error> {
        if raw.len() > MAX_PLAINTEXT {
            return Err(Error::new(
                "tls: handshake: handshake message does not fit in one record",
            ));
        }
        self.io
            .write_record(22, raw)
            .map_err(|e| Error::new(format!("tls: handshake: write failed: {e}")))?;
        self.transcript.add(raw)
    }

    pub(crate) fn read_record(&mut self) -> Result<(u8, Vec<u8>), Error> {
        self.io
            .read_record()
            .map_err(|e| Error::new(format!("tls: handshake: {e}")))
    }

    /// Read the next complete handshake message, skipping compatibility CCS
    /// records in TLS 1.3 and reporting alerts as errors.
    pub(crate) fn read_msg(&mut self) -> Result<HandshakeMessage, Error> {
        loop {
            if let Some(msg) = self.hs.next()? {
                return Ok(msg);
            }
            let (typ, payload) = self.read_record()?;
            match typ {
                22 => self.hs.push(&payload)?,
                20 if self.compat_ccs => continue,
                20 => {
                    return Err(Error::new(
                        "tls: handshake: unexpected ChangeCipherSpec message",
                    ))
                }
                21 => return Err(alert_error("handshake", &payload)),
                other => {
                    return Err(Error::new(format!(
                    "tls: handshake: unexpected record content type {other} (expected handshake)"
                )))
                }
            }
        }
    }

    /// Read records until a ChangeCipherSpec arrives. A TLS 1.2 server may put
    /// a NewSessionTicket before it; other handshake messages are errors.
    pub(crate) fn read_ccs(&mut self) -> Result<(), Error> {
        loop {
            if let Some(msg) = self.hs.next()? {
                if msg.typ == HS_NEW_SESSION_TICKET {
                    // A TLS 1.2 ticket is sent before the server's CCS and is
                    // part of the transcript the server Finished covers.
                    self.transcript.add(&msg.raw)?;
                    continue;
                }
                return Err(Error::new(format!(
                    "tls: handshake: unexpected handshake message type {} before ChangeCipherSpec",
                    msg.typ
                )));
            }
            let (typ, payload) = self.read_record()?;
            match typ {
                20 => return Ok(()),
                22 => self.hs.push(&payload)?,
                21 => return Err(alert_error("handshake", &payload)),
                other => {
                    return Err(Error::new(format!(
                        "tls: handshake: unexpected record content type {other} before ChangeCipherSpec"
                    )))
                }
            }
        }
    }
}

/// ServerHello contents we care about.
#[derive(Debug)]
pub(crate) struct ServerHello {
    pub(crate) random: [u8; 32],
    pub(crate) session_id: Vec<u8>,
    pub(crate) cipher_suite: u16,
    pub(crate) compression: u8,
    pub(crate) version: TlsVersion,
    pub(crate) key_share: Option<(u16, Vec<u8>)>,
    pub(crate) alpn: Option<String>,
    pub(crate) ems: bool,
    pub(crate) renegotiation_info: Option<Vec<u8>>,
}

#[derive(Debug, Default)]
pub(crate) struct Extensions {
    entries: Vec<(u16, Vec<u8>)>,
}

impl Extensions {
    pub(crate) fn get(&self, id: u16) -> Option<&[u8]> {
        self.entries
            .iter()
            .find(|(ext, _)| *ext == id)
            .map(|(_, data)| data.as_slice())
    }

    #[allow(dead_code)]
    pub(crate) fn has(&self, id: u16) -> bool {
        self.entries.iter().any(|(ext, _)| *ext == id)
    }
}

/// Parse an extension vector that begins with its own two-byte length.
pub(crate) fn parse_extensions(data: &[u8], label: &'static str) -> Result<Extensions, Error> {
    let mut outer = Reader::new(data, label);
    let list = outer.vec_u16()?;
    outer.finish()?;
    parse_extension_list(list, label)
}

/// Parse the bare contents of an extension block (no outer length).
pub(crate) fn parse_extension_list(list: &[u8], label: &'static str) -> Result<Extensions, Error> {
    let mut r = Reader::new(list, label);
    let mut entries: Vec<(u16, Vec<u8>)> = Vec::new();
    while !r.is_empty() {
        let id = r.u16()?;
        let body = r.vec_u16()?;
        if entries.iter().any(|(existing, _)| *existing == id) {
            return Err(Error::new(format!(
                "tls: handshake: malformed {label}: duplicate extension 0x{id:04x}"
            )));
        }
        entries.push((id, body.to_vec()));
    }
    Ok(Extensions { entries })
}

pub(crate) fn parse_server_hello(body: &[u8]) -> Result<ServerHello, Error> {
    let mut r = Reader::new(body, "ServerHello");
    let legacy_version = r.u16()?;
    let random_bytes = r.bytes(32)?;
    let mut random = [0u8; 32];
    random.copy_from_slice(random_bytes);
    let session_id = r.vec_u8()?.to_vec();
    if session_id.len() > 32 {
        return Err(Error::new(
            "tls: handshake: malformed ServerHello: session id longer than 32 bytes",
        ));
    }
    let cipher_suite = r.u16()?;
    let compression = r.u8()?;
    let extensions = if r.is_empty() {
        Extensions::default()
    } else {
        let list = r.vec_u16()?;
        r.finish()?;
        parse_extension_list(list, "ServerHello")?
    };

    let mut selected_version = legacy_version;
    if let Some(data) = extensions.get(EXT_SUPPORTED_VERSIONS) {
        let mut vr = Reader::new(data, "ServerHello.supported_versions");
        selected_version = vr.u16()?;
        vr.finish()?;
    }
    let version = if selected_version == 0x0304 {
        if legacy_version != 0x0303 {
            return Err(Error::new(format!(
                "tls: handshake: malformed ServerHello: TLS 1.3 selected with legacy version 0x{legacy_version:04x}"
            )));
        }
        TlsVersion::Tls13
    } else if selected_version >= 0x0303 {
        TlsVersion::Tls12
    } else {
        return Err(Error::new(format!(
            "tls: handshake: server selected unsupported protocol version 0x{selected_version:04x}"
        )));
    };

    let mut key_share = None;
    if let Some(data) = extensions.get(EXT_KEY_SHARE) {
        let mut kr = Reader::new(data, "ServerHello.key_share");
        let group = kr.u16()?;
        let key = kr.vec_u16()?.to_vec();
        kr.finish()?;
        key_share = Some((group, key));
    }

    let alpn = match extensions.get(EXT_ALPN) {
        Some(data) => parse_alpn(data)?,
        None => None,
    };

    let ems = match extensions.get(EXT_EXTENDED_MASTER_SECRET) {
        Some(data) => {
            if !data.is_empty() {
                return Err(Error::new(
                    "tls: handshake: malformed extended_master_secret extension",
                ));
            }
            true
        }
        None => false,
    };

    let renegotiation_info = match extensions.get(EXT_RENEGOTIATION_INFO) {
        Some(data) => {
            let mut rr = Reader::new(data, "ServerHello.renegotiation_info");
            let v = rr.vec_u8()?.to_vec();
            rr.finish()?;
            Some(v)
        }
        None => None,
    };

    Ok(ServerHello {
        random,
        session_id,
        cipher_suite,
        compression,
        version,
        key_share,
        alpn,
        ems,
        renegotiation_info,
    })
}

pub(crate) fn parse_alpn(data: &[u8]) -> Result<Option<String>, Error> {
    let mut r = Reader::new(data, "ALPN extension");
    let list = r.vec_u16()?;
    r.finish()?;
    let mut lr = Reader::new(list, "ALPN extension");
    let proto = lr.vec_u8()?;
    if proto.is_empty() {
        return Err(Error::new(
            "tls: handshake: malformed ALPN extension: empty protocol name",
        ));
    }
    if !lr.is_empty() {
        return Err(Error::new(
            "tls: handshake: malformed ALPN extension: server selected more than one protocol",
        ));
    }
    match std::str::from_utf8(proto) {
        Ok(s) => Ok(Some(s.to_string())),
        Err(_) => Ok(None),
    }
}

/// TLS 1.3 downgrade sentinel: a TLS 1.2 ServerHello from a TLS 1.3 capable
/// server ends with "DOWNGRD\x01".
pub(crate) fn is_downgrade_sentinel(random: &[u8; 32]) -> bool {
    &random[24..] == b"DOWNGRD\x01"
}

pub(crate) fn alert_name(code: u8) -> &'static str {
    match code {
        0 => "close_notify",
        10 => "unexpected_message",
        20 => "bad_record_mac",
        21 => "decryption_failed",
        22 => "record_overflow",
        30 => "decompression_failure",
        40 => "handshake_failure",
        41 => "no_certificate",
        42 => "bad_certificate",
        43 => "unsupported_certificate",
        44 => "certificate_revoked",
        45 => "certificate_expired",
        46 => "certificate_unknown",
        47 => "illegal_parameter",
        48 => "unknown_ca",
        49 => "access_denied",
        50 => "decode_error",
        51 => "decrypt_error",
        60 => "export_restriction",
        70 => "protocol_version",
        71 => "insufficient_security",
        80 => "internal_error",
        86 => "inappropriate_fallback",
        90 => "user_canceled",
        100 => "no_renegotiation",
        109 => "missing_extension",
        110 => "unsupported_extension",
        112 => "unrecognized_name",
        113 => "bad_certificate_status_response",
        115 => "unknown_psk_identity",
        116 => "certificate_required",
        120 => "no_application_protocol",
        _ => "unknown_alert",
    }
}

pub(crate) fn alert_error(stage: &str, payload: &[u8]) -> Error {
    if payload.len() != 2 {
        return Error::new(format!(
            "tls: {stage}: malformed alert record ({} bytes)",
            payload.len()
        ));
    }
    let code = payload[1];
    Error::new(format!(
        "tls: {stage}: server alert {} ({})",
        alert_name(code),
        code
    ))
}

pub(crate) struct ClientHello {
    pub(crate) raw: Vec<u8>,
    pub(crate) random: [u8; 32],
    pub(crate) session_id: [u8; 32],
    pub(crate) suites: Vec<u16>,
    pub(crate) x25519: X25519Private,
    pub(crate) p256: P256Private,
}

impl ClientHello {
    pub(crate) fn offered(&self, id: u16) -> bool {
        self.suites.iter().any(|s| *s == id)
    }
}

fn push_ext(w: &mut Writer, id: u16, data: &[u8]) {
    w.u16(id);
    w.u16(data.len() as u16);
    w.bytes(data);
}

pub(crate) fn build_client_hello(cfg: &TlsConfig) -> Result<ClientHello, Error> {
    let mut random = [0u8; 32];
    emerag_util::rand::fill_bytes(&mut random)
        .map_err(|e| Error::new(format!("tls: config: no OS randomness: {e}")))?;
    let mut session_id = [0u8; 32];
    emerag_util::rand::fill_bytes(&mut session_id)
        .map_err(|e| Error::new(format!("tls: config: no OS randomness: {e}")))?;
    let x25519 = X25519Private::generate()
        .map_err(|e| Error::new(format!("tls: config: cannot generate X25519 key: {e}")))?;
    let p256 = P256Private::generate()
        .map_err(|e| Error::new(format!("tls: config: cannot generate P-256 key: {e}")))?;

    let mut suites: Vec<u16> = vec![
        crate::suite::TLS13_AES_128_GCM_SHA256,
        crate::suite::TLS13_AES_256_GCM_SHA384,
        crate::suite::TLS13_CHACHA20_POLY1305_SHA256,
    ];
    if cfg.min_version != TlsVersion::Tls13 {
        suites.extend_from_slice(&[
            crate::suite::TLS12_ECDHE_RSA_AES128_GCM_SHA256,
            crate::suite::TLS12_ECDHE_RSA_AES256_GCM_SHA384,
            crate::suite::TLS12_ECDHE_RSA_CHACHA20_POLY1305,
            crate::suite::TLS12_ECDHE_ECDSA_AES128_GCM_SHA256,
            crate::suite::TLS12_ECDHE_ECDSA_AES256_GCM_SHA384,
            crate::suite::TLS12_ECDHE_ECDSA_CHACHA20_POLY1305,
        ]);
    }

    let mut body = Writer::with_capacity(512);
    body.u16(0x0303); // legacy_version
    body.bytes(&random);
    body.vec_u8(&session_id);
    body.u16((suites.len() * 2) as u16);
    for id in &suites {
        body.u16(*id);
    }
    body.u8(1);
    body.u8(0); // null compression

    let ext_at = body.reserve_u16();

    // server_name (SNI) is omitted for IP literals per RFC 6066.
    let is_ip = cfg.server_name.parse::<IpAddr>().is_ok();
    let name = cfg.server_name.as_bytes();
    if !is_ip
        && !name.is_empty()
        && name.len() <= 255
        && cfg.server_name.is_ascii()
        && !cfg.server_name.ends_with('.')
    {
        let mut sn = Writer::new();
        let list_at = sn.reserve_u16();
        sn.u8(0); // host_name
        sn.vec_u16(name);
        sn.patch_u16(list_at);
        push_ext(&mut body, EXT_SERVER_NAME, &sn.buf);
    }

    let mut groups = Writer::new();
    groups.u16(4);
    groups.u16(GROUP_X25519);
    groups.u16(GROUP_P256);
    push_ext(&mut body, EXT_SUPPORTED_GROUPS, &groups.buf);

    let mut sigs = Writer::new();
    let sig_algs: [u16; 8] = [
        0x0804, 0x0805, 0x0806, 0x0403, 0x0503, 0x0401, 0x0501, 0x0601,
    ];
    sigs.u16((sig_algs.len() * 2) as u16);
    for s in sig_algs {
        sigs.u16(s);
    }
    push_ext(&mut body, EXT_SIGNATURE_ALGORITHMS, &sigs.buf);

    let mut versions = Writer::new();
    if cfg.min_version == TlsVersion::Tls13 {
        versions.u8(2);
        versions.u16(0x0304);
    } else {
        versions.u8(4);
        versions.u16(0x0304);
        versions.u16(0x0303);
    }
    push_ext(&mut body, EXT_SUPPORTED_VERSIONS, &versions.buf);

    let mut shares = Writer::new();
    let share_at = shares.reserve_u16();
    shares.u16(GROUP_X25519);
    shares.vec_u16(&x25519.public_key());
    shares.u16(GROUP_P256);
    shares.vec_u16(&p256.public_key().to_sec1());
    shares.patch_u16(share_at);
    push_ext(&mut body, EXT_KEY_SHARE, &shares.buf);

    let alpn: Vec<&str> = if cfg.alpn.is_empty() {
        vec!["http/1.1"]
    } else {
        cfg.alpn.iter().map(|s| s.as_str()).collect()
    };
    let mut alpns = Writer::new();
    let alpn_at = alpns.reserve_u16();
    for proto in &alpn {
        if proto.is_empty() || proto.len() > 255 {
            return Err(Error::new(format!(
                "tls: config: ALPN protocol {:?} must be 1..255 bytes",
                proto
            )));
        }
        alpns.vec_u8(proto.as_bytes());
    }
    alpns.patch_u16(alpn_at);
    push_ext(&mut body, EXT_ALPN, &alpns.buf);

    push_ext(&mut body, EXT_EXTENDED_MASTER_SECRET, &[]);

    let mut reneg = Writer::new();
    reneg.u8(0);
    push_ext(&mut body, EXT_RENEGOTIATION_INFO, &reneg.buf);

    let mut ec_points = Writer::new();
    ec_points.u8(1);
    ec_points.u8(0); // uncompressed
    push_ext(&mut body, EXT_EC_POINT_FORMATS, &ec_points.buf);

    push_ext(&mut body, EXT_SESSION_TICKET, &[]);

    body.patch_u16(ext_at);
    let raw = encode_handshake(HS_CLIENT_HELLO, &body.buf)?;
    Ok(ClientHello {
        raw,
        random,
        session_id,
        suites,
        x25519,
        p256,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handshake_messages_reassemble_across_records() {
        let a = encode_handshake(HS_SERVER_HELLO, b"hello").unwrap();
        let b = encode_handshake(HS_CERTIFICATE, b"certificate").unwrap();
        let mut buf = HandshakeBuffer::new();
        let mut all = a.clone();
        all.extend_from_slice(&b);
        // Feed one byte at a time to prove records may split anywhere.
        for byte in &all {
            buf.push(&[*byte]).unwrap();
        }
        let first = buf.next().unwrap().unwrap();
        assert_eq!(first.typ, HS_SERVER_HELLO);
        assert_eq!(first.body, b"hello");
        assert_eq!(first.raw, a);
        let second = buf.next().unwrap().unwrap();
        assert_eq!(second.typ, HS_CERTIFICATE);
        assert_eq!(second.body, b"certificate");
        assert!(buf.next().unwrap().is_none());
    }

    #[test]
    fn oversized_handshake_message_is_rejected() {
        let mut raw = vec![HS_CERTIFICATE, 0x10, 0x00, 0x01];
        raw.extend_from_slice(&[0u8; 32]);
        let mut buf = HandshakeBuffer::new();
        buf.push(&raw).unwrap();
        assert!(buf.next().is_err());
    }

    #[test]
    fn client_hello_has_expected_wire_shape() {
        let cfg = TlsConfig::new("example.com");
        let ch = build_client_hello(&cfg).unwrap();
        assert_eq!(ch.raw[0], HS_CLIENT_HELLO);
        let mut r = Reader::new(&ch.raw[4..], "ClientHello test");
        assert_eq!(r.u16().unwrap(), 0x0303);
        r.bytes(32).unwrap();
        assert_eq!(r.vec_u8().unwrap().len(), 32);
        let n = r.u16().unwrap() as usize / 2;
        let mut ids = Vec::new();
        for _ in 0..n {
            ids.push(r.u16().unwrap());
        }
        assert_eq!(ids[0], 0x1301);
        assert!(ids.contains(&0xc02f));
        assert!(ids.contains(&0xcca9));
        assert_eq!(r.u8().unwrap(), 1);
        assert_eq!(r.u8().unwrap(), 0);
        let ext = r.vec_u16().unwrap();
        r.finish().unwrap();
        let exts = parse_extensions(
            &{
                let mut framed = Vec::new();
                framed.extend_from_slice(&(ext.len() as u16).to_be_bytes());
                framed.extend_from_slice(ext);
                framed
            },
            "ClientHello test",
        )
        .unwrap();
        assert!(exts.has(EXT_SERVER_NAME));
        assert!(exts.has(EXT_KEY_SHARE));
        assert!(exts.has(EXT_SUPPORTED_VERSIONS));
        assert!(exts.has(EXT_ALPN));
        assert!(exts.has(EXT_EXTENDED_MASTER_SECRET));
        assert!(exts.has(EXT_SESSION_TICKET));
    }

    #[test]
    fn sni_is_omitted_for_ip_literals() {
        let cfg = TlsConfig::new("127.0.0.1");
        let ch = build_client_hello(&cfg).unwrap();
        let text = String::from_utf8_lossy(&ch.raw);
        assert!(!text.contains("127.0.0.1"));
    }

    #[test]
    fn downgrade_sentinel_detection() {
        let mut r = [0u8; 32];
        r[24..].copy_from_slice(b"DOWNGRD\x01");
        assert!(is_downgrade_sentinel(&r));
        r[31] = 0;
        assert!(!is_downgrade_sentinel(&r));
    }

    #[test]
    fn alert_names_are_reported() {
        let e = alert_error("handshake", &[2, 40]);
        assert_eq!(
            e.to_string(),
            "tls: handshake: server alert handshake_failure (40)"
        );
    }
}
