//! emerag-tls - a small TLS 1.2/1.3 client built on emerag-crypto.
//!
//! Only what an HTTP client needs: one handshake, ALPN http/1.1, no resumption,
//! no renegotiation, no client certificates in v1.
//!
//! The implementation is deliberately conservative: RSA key exchange, CBC
//! cipher suites, PSK/resumption, renegotiation, compression and client
//! certificates are not offered, and any server that insists on them is
//! rejected with an error naming the failing stage.

use std::io::{self, Read, Write};
use std::net::TcpStream;

mod bytes;
mod handshake;
mod key;
mod record;
mod suite;
mod tls12;
mod tls13;
mod verify;

use handshake::{HandshakeBuffer, HsConn, HS_KEY_UPDATE, HS_SERVER_HELLO};
use key::HashId;
use record::{RecordLayer, MAX_PLAINTEXT};
use suite::AeadKind;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsVersion {
    Tls12,
    Tls13,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyMode {
    /// Verify against the CA bundle supplied (or the embedded roots).
    Full,
    /// No certificate verification. Loudly discouraged.
    Insecure,
}

#[derive(Debug, Clone)]
pub struct TlsConfig {
    pub server_name: String,
    pub verify: VerifyMode,
    pub ca_pem: Option<Vec<u8>>,
    pub alpn: Vec<String>,
    pub min_version: TlsVersion,
    pub client_cert_pem: Option<Vec<u8>>,
    pub client_key_pem: Option<Vec<u8>>,
    pub pinned_spki: Option<[u8; 32]>,
}

impl TlsConfig {
    pub fn new(server_name: impl Into<String>) -> Self {
        TlsConfig {
            server_name: server_name.into(),
            verify: VerifyMode::Full,
            ca_pem: None,
            alpn: vec!["http/1.1".to_string()],
            min_version: TlsVersion::Tls12,
            client_cert_pem: None,
            client_key_pem: None,
            pinned_spki: None,
        }
    }
}

/// Application traffic secrets kept for TLS 1.3 KeyUpdate.
pub(crate) struct Tls13Keys {
    pub(crate) hash: HashId,
    pub(crate) aead: AeadKind,
    pub(crate) key_len: usize,
    pub(crate) read_secret: Vec<u8>,
    pub(crate) write_secret: Vec<u8>,
}

pub struct TlsStream {
    io: RecordLayer,
    version: TlsVersion,
    alpn: Option<String>,
    peer_spki: Option<[u8; 32]>,
    /// Decrypted application bytes not yet returned by read().
    pending: Vec<u8>,
    pending_pos: usize,
    eof: bool,
    tls13: Option<Tls13Keys>,
    /// Reassembly buffer for post-handshake messages (NewSessionTicket,
    /// KeyUpdate) which may be split across records.
    post_hs: HandshakeBuffer,
}

impl TlsStream {
    pub fn connect(tcp: TcpStream, cfg: &TlsConfig) -> Result<TlsStream, Error> {
        if cfg.client_cert_pem.is_some() || cfg.client_key_pem.is_some() {
            return Err(Error::new(
                "tls: config: client certificates are not supported by this client",
            ));
        }
        if cfg.server_name.trim().is_empty() {
            return Err(Error::new("tls: config: server_name is empty"));
        }

        let ch = handshake::build_client_hello(cfg)?;
        let mut conn = HsConn::new(tcp);
        // The first ClientHello record uses TLS 1.0's legacy record version;
        // RFC 8446 recommends 0x0301 for middlebox compatibility.
        conn.send_message(&ch.raw)?;
        conn.io.version = 0x0303;

        let sh_msg = conn.read_msg()?;
        if sh_msg.typ != HS_SERVER_HELLO {
            return Err(Error::new(format!(
                "tls: handshake: expected ServerHello, got handshake message type {} ({})",
                sh_msg.typ,
                tls13::handshake_type_name(sh_msg.typ)
            )));
        }
        conn.transcript.add(&sh_msg.raw)?;
        let sh = handshake::parse_server_hello(&sh_msg.body)?;

        match sh.version {
            TlsVersion::Tls13 => {
                if handshake::is_downgrade_sentinel(&sh.random) {
                    return Err(Error::new(
                        "tls: handshake: TLS 1.3 ServerHello carries a downgrade sentinel",
                    ));
                }
                let suite = suite::lookup(sh.cipher_suite).ok_or_else(|| {
                    Error::new(format!(
                        "tls: handshake: server selected unsupported cipher suite 0x{:04x}",
                        sh.cipher_suite
                    ))
                })?;
                if suite.version != TlsVersion::Tls13 {
                    return Err(Error::new(
                        "tls: handshake: TLS 1.3 ServerHello selected a TLS 1.2 cipher suite",
                    ));
                }
                let (group, peer) = sh.key_share.as_ref().ok_or_else(|| {
                    Error::new("tls: handshake: TLS 1.3 ServerHello has no key_share extension")
                })?;
                let shared = tls13::shared_secret(&ch, *group, peer)?;

                // Middlebox compatibility: a dummy CCS is allowed between the
                // ClientHello and the client Finished and is ignored by peers.
                conn.io.write_record(20, &[1]).map_err(|e| {
                    Error::new(format!(
                        "tls: handshake: cannot send compatibility ChangeCipherSpec: {e}"
                    ))
                })?;
                conn.compat_ccs = true;

                let out = tls13::handshake(conn, cfg, &ch, &sh, suite, shared)?;
                Ok(TlsStream {
                    io: out.conn.io,
                    version: TlsVersion::Tls13,
                    alpn: out.alpn,
                    peer_spki: Some(out.peer_spki),
                    pending: Vec::new(),
                    pending_pos: 0,
                    eof: false,
                    tls13: Some(out.keys),
                    post_hs: HandshakeBuffer::new(),
                })
            }
            TlsVersion::Tls12 => {
                if cfg.min_version == TlsVersion::Tls13 {
                    return Err(Error::new(
                        "tls: handshake: server negotiated TLS 1.2 but min_version is TLS 1.3",
                    ));
                }
                let suite = suite::lookup(sh.cipher_suite).ok_or_else(|| {
                    Error::new(format!(
                        "tls: handshake: server selected unsupported cipher suite 0x{:04x}",
                        sh.cipher_suite
                    ))
                })?;
                if suite.version != TlsVersion::Tls12 {
                    return Err(Error::new(
                        "tls: handshake: TLS 1.2 ServerHello selected a TLS 1.3 cipher suite",
                    ));
                }
                let out = tls12::handshake(conn, cfg, &ch, &sh, suite)?;
                Ok(TlsStream {
                    io: out.conn.io,
                    version: TlsVersion::Tls12,
                    alpn: out.alpn,
                    peer_spki: Some(out.peer_spki),
                    pending: Vec::new(),
                    pending_pos: 0,
                    eof: false,
                    tls13: None,
                    post_hs: HandshakeBuffer::new(),
                })
            }
        }
    }

    pub fn version(&self) -> TlsVersion {
        self.version
    }

    pub fn alpn(&self) -> Option<&str> {
        self.alpn.as_deref()
    }

    pub fn peer_spki_sha256(&self) -> Option<[u8; 32]> {
        self.peer_spki
    }

    fn handle_alert(&mut self, payload: &[u8]) -> io::Result<usize> {
        if payload.len() != 2 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "tls: read: malformed alert record ({} bytes)",
                    payload.len()
                ),
            ));
        }
        let code = payload[1];
        if code == 0 {
            self.eof = true;
            return Ok(0);
        }
        Err(io::Error::new(
            io::ErrorKind::ConnectionAborted,
            format!(
                "tls: read: server alert {} ({})",
                handshake::alert_name(code),
                code
            ),
        ))
    }

    fn handle_post_handshake(&mut self, data: &[u8]) -> io::Result<()> {
        self.post_hs
            .push(data)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        loop {
            let msg = match self.post_hs.next() {
                Ok(Some(m)) => m,
                Ok(None) => return Ok(()),
                Err(e) => return Err(io::Error::new(io::ErrorKind::InvalidData, e.to_string())),
            };
            match msg.typ {
                4 => continue, // NewSessionTicket: no resumption support
                24 if self.version == TlsVersion::Tls13 => {
                    self.handle_key_update(&msg.body)?;
                }
                0 => return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "tls: read: server requested renegotiation, which this client does not support",
                )),
                other => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "tls: read: unexpected post-handshake message type {other} ({})",
                            tls13::handshake_type_name(other)
                        ),
                    ))
                }
            }
        }
    }

    fn handle_key_update(&mut self, body: &[u8]) -> io::Result<()> {
        if body.len() != 1 || body[0] > 1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "tls: read: malformed KeyUpdate message",
            ));
        }
        let request = body[0] == 1;
        let keys = self.tls13.as_mut().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "tls: read: KeyUpdate before a TLS 1.3 handshake",
            )
        })?;
        let new_read = tls13::next_traffic_secret(keys.hash, &keys.read_secret)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        let cipher = tls13::suite_cipher(keys.aead, keys.key_len, keys.hash, &new_read)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        keys.read_secret = new_read;
        self.io.set_read_cipher(Some(cipher));

        if request {
            let msg = handshake::encode_handshake(HS_KEY_UPDATE, &[0])
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
            self.io
                .write_record(22, &msg)
                .map_err(|e| io::Error::new(e.kind(), format!("tls: write: {e}")))?;
            let new_write = tls13::next_traffic_secret(keys.hash, &keys.write_secret)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
            let cipher = tls13::suite_cipher(keys.aead, keys.key_len, keys.hash, &new_write)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
            keys.write_secret = new_write;
            self.io.set_write_cipher(Some(cipher));
            self.io
                .flush()
                .map_err(|e| io::Error::new(e.kind(), format!("tls: write: {e}")))?;
        }
        Ok(())
    }
}

impl Read for TlsStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if self.pending_pos < self.pending.len() {
            let n = core::cmp::min(buf.len(), self.pending.len() - self.pending_pos);
            buf[..n].copy_from_slice(&self.pending[self.pending_pos..self.pending_pos + n]);
            self.pending_pos += n;
            if self.pending_pos == self.pending.len() {
                self.pending.clear();
                self.pending_pos = 0;
            }
            return Ok(n);
        }
        if self.eof {
            return Ok(0);
        }

        let mut skipped = 0usize;
        loop {
            let (typ, data) = self
                .io
                .read_record()
                .map_err(|e| io::Error::new(e.kind(), format!("tls: read: {e}")))?;
            match typ {
                23 => {
                    if data.is_empty() {
                        skipped += 1;
                        if skipped > 1024 {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "tls: read: peer sent too many empty application records",
                            ));
                        }
                        continue;
                    }
                    self.pending = data;
                    self.pending_pos = 0;
                    let n = core::cmp::min(buf.len(), self.pending.len());
                    buf[..n].copy_from_slice(&self.pending[..n]);
                    self.pending_pos = n;
                    return Ok(n);
                }
                21 => return self.handle_alert(&data),
                20 => {
                    if self.version == TlsVersion::Tls13 {
                        continue;
                    }
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "tls: read: unexpected ChangeCipherSpec after the handshake",
                    ));
                }
                22 => {
                    self.handle_post_handshake(&data)?;
                    skipped += 1;
                    if skipped > 1024 {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "tls: read: peer sent too many non-application records",
                        ));
                    }
                    continue;
                }
                other => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("tls: read: unexpected record content type {other}"),
                    ))
                }
            }
        }
    }
}

impl Write for TlsStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        for chunk in buf.chunks(MAX_PLAINTEXT) {
            self.io
                .write_record(23, chunk)
                .map_err(|e| io::Error::new(e.kind(), format!("tls: write: {e}")))?;
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.io
            .flush()
            .map_err(|e| io::Error::new(e.kind(), format!("tls: write: {e}")))
    }
}

#[derive(Debug, Clone)]
pub struct Error {
    message: String,
}

impl Error {
    pub fn new(message: impl Into<String>) -> Self {
        Error {
            message: message.into(),
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::new(format!("io: {e}"))
    }
}

impl From<emerag_crypto::Error> for Error {
    fn from(e: emerag_crypto::Error) -> Self {
        Error::new(e.to_string())
    }
}
