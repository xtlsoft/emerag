//! TLS record layer: framing, buffering and AEAD protection.
//!
//! The layer owns the TCP socket. Reads are incremental: bytes that arrive
//! without completing a record stay in `inbuf`, so a WouldBlock/TimedOut from
//! the socket surfaces to the caller without losing state and can be retried.

use std::io::{self, ErrorKind, Read, Write};
use std::net::TcpStream;

use emerag_crypto::aead::{Aes128Gcm, Aes256Gcm, ChaCha20Poly1305};

use crate::suite::AeadKind;

pub(crate) const MAX_PLAINTEXT: usize = 16384;
/// Ciphertext may exceed plaintext by the tag and, for TLS 1.2, an explicit
/// nonce. RFC 5246 allows up to 2048 bytes of expansion.
const MAX_CIPHERTEXT: usize = 16384 + 2048;
const TAG_LEN: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ContentType {
    ChangeCipherSpec = 20,
    Alert = 21,
    Handshake = 22,
    ApplicationData = 23,
}

impl ContentType {
    pub(crate) fn from_u8(v: u8) -> Option<Self> {
        match v {
            20 => Some(ContentType::ChangeCipherSpec),
            21 => Some(ContentType::Alert),
            22 => Some(ContentType::Handshake),
            23 => Some(ContentType::ApplicationData),
            _ => None,
        }
    }
}

pub(crate) struct AeadCipher {
    inner: AeadInner,
}

enum AeadInner {
    Aes128(Aes128Gcm),
    Aes256(Aes256Gcm),
    ChaCha(ChaCha20Poly1305),
}

impl AeadCipher {
    pub(crate) fn new(kind: AeadKind, key: &[u8]) -> io::Result<Self> {
        let inner = match kind {
            AeadKind::Aes128Gcm => {
                if key.len() != 16 {
                    return Err(invalid(format!(
                        "AES-128-GCM key is {} bytes, expected 16",
                        key.len()
                    )));
                }
                let mut k = [0u8; 16];
                k.copy_from_slice(key);
                AeadInner::Aes128(Aes128Gcm::new(&k))
            }
            AeadKind::Aes256Gcm => {
                if key.len() != 32 {
                    return Err(invalid(format!(
                        "AES-256-GCM key is {} bytes, expected 32",
                        key.len()
                    )));
                }
                let mut k = [0u8; 32];
                k.copy_from_slice(key);
                AeadInner::Aes256(Aes256Gcm::new(&k))
            }
            AeadKind::ChaCha20Poly1305 => {
                if key.len() != 32 {
                    return Err(invalid(format!(
                        "ChaCha20-Poly1305 key is {} bytes, expected 32",
                        key.len()
                    )));
                }
                let mut k = [0u8; 32];
                k.copy_from_slice(key);
                AeadInner::ChaCha(ChaCha20Poly1305::new(&k))
            }
        };
        Ok(AeadCipher { inner })
    }

    fn seal(&self, nonce: &[u8; 12], aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
        match &self.inner {
            AeadInner::Aes128(c) => c.seal(nonce, aad, plaintext),
            AeadInner::Aes256(c) => c.seal(nonce, aad, plaintext),
            AeadInner::ChaCha(c) => c.seal(nonce, aad, plaintext),
        }
    }

    fn open(&self, nonce: &[u8; 12], aad: &[u8], sealed: &[u8]) -> Result<Vec<u8>, String> {
        match &self.inner {
            AeadInner::Aes128(c) => c.open(nonce, aad, sealed).map_err(|e| e.to_string()),
            AeadInner::Aes256(c) => c.open(nonce, aad, sealed).map_err(|e| e.to_string()),
            AeadInner::ChaCha(c) => c.open(nonce, aad, sealed).map_err(|e| e.to_string()),
        }
    }
}

/// Record protection for one direction in one key epoch.
pub(crate) enum RecordCipher {
    Tls13 { aead: AeadCipher, iv: [u8; 12] },
    Tls12Gcm { aead: AeadCipher, salt: [u8; 4] },
    Tls12ChaCha { aead: AeadCipher, iv: [u8; 12] },
}

impl RecordCipher {
    pub(crate) fn tls13(kind: AeadKind, key: &[u8], iv: [u8; 12]) -> io::Result<Self> {
        Ok(RecordCipher::Tls13 {
            aead: AeadCipher::new(kind, key)?,
            iv,
        })
    }

    pub(crate) fn tls12_gcm(kind: AeadKind, key: &[u8], salt: [u8; 4]) -> io::Result<Self> {
        if matches!(kind, AeadKind::ChaCha20Poly1305) {
            return Err(invalid(
                "ChaCha20-Poly1305 cannot use the TLS 1.2 GCM record format",
            ));
        }
        Ok(RecordCipher::Tls12Gcm {
            aead: AeadCipher::new(kind, key)?,
            salt,
        })
    }

    pub(crate) fn tls12_chacha(key: &[u8], iv: [u8; 12]) -> io::Result<Self> {
        Ok(RecordCipher::Tls12ChaCha {
            aead: AeadCipher::new(AeadKind::ChaCha20Poly1305, key)?,
            iv,
        })
    }

    /// Protect a record. Returns the outer content type and the payload.
    fn encrypt(
        &self,
        seq: u64,
        content_type: u8,
        version: u16,
        data: &[u8],
    ) -> io::Result<(u8, Vec<u8>)> {
        if data.len() > MAX_PLAINTEXT {
            return Err(invalid(format!(
                "record plaintext is {} bytes, limit {MAX_PLAINTEXT}",
                data.len()
            )));
        }
        match self {
            RecordCipher::Tls13 { aead, iv } => {
                let mut nonce = *iv;
                xor_seq(&mut nonce, seq);
                let mut inner = Vec::with_capacity(data.len() + 1);
                inner.extend_from_slice(data);
                inner.push(content_type);
                let ct_len = inner.len() + TAG_LEN;
                if ct_len > u16::MAX as usize {
                    return Err(invalid("TLS 1.3 record is too large"));
                }
                let mut aad = [0u8; 5];
                aad[0] = ContentType::ApplicationData as u8;
                aad[1] = (version >> 8) as u8;
                aad[2] = version as u8;
                aad[3] = (ct_len >> 8) as u8;
                aad[4] = ct_len as u8;
                let ct = aead.seal(&nonce, &aad, &inner);
                Ok((ContentType::ApplicationData as u8, ct))
            }
            RecordCipher::Tls12Gcm { aead, salt } => {
                let explicit = seq.to_be_bytes();
                let mut nonce = [0u8; 12];
                nonce[..4].copy_from_slice(salt);
                nonce[4..].copy_from_slice(&explicit);
                let aad = tls12_aad(seq, content_type, version, data.len());
                let mut out = Vec::with_capacity(8 + data.len() + TAG_LEN);
                out.extend_from_slice(&explicit);
                out.extend_from_slice(&aead.seal(&nonce, &aad, data));
                Ok((content_type, out))
            }
            RecordCipher::Tls12ChaCha { aead, iv } => {
                let mut nonce = *iv;
                xor_seq(&mut nonce, seq);
                let aad = tls12_aad(seq, content_type, version, data.len());
                let out = aead.seal(&nonce, &aad, data);
                Ok((content_type, out))
            }
        }
    }

    /// Unprotect a record. Returns the inner content type and plaintext.
    fn decrypt(
        &self,
        seq: u64,
        content_type: u8,
        version: u16,
        payload: &[u8],
    ) -> io::Result<(u8, Vec<u8>)> {
        match self {
            RecordCipher::Tls13 { aead, iv } => {
                if payload.len() < TAG_LEN {
                    return Err(invalid(
                        "TLS 1.3 record shorter than the authentication tag",
                    ));
                }
                if content_type != ContentType::ApplicationData as u8 {
                    return Err(invalid(format!(
                        "TLS 1.3 record has outer content type {content_type}, expected 23"
                    )));
                }
                let mut nonce = *iv;
                xor_seq(&mut nonce, seq);
                let mut aad = [0u8; 5];
                aad[0] = content_type;
                aad[1] = (version >> 8) as u8;
                aad[2] = version as u8;
                aad[3] = (payload.len() >> 8) as u8;
                aad[4] = payload.len() as u8;
                let plain = aead
                    .open(&nonce, &aad, payload)
                    .map_err(|_| invalid("bad record MAC (TLS 1.3 decryption failed)"))?;
                // Strip the zero padding added for traffic analysis resistance.
                let mut end = plain.len();
                while end > 0 && plain[end - 1] == 0 {
                    end -= 1;
                }
                if end == 0 {
                    return Err(invalid("TLS 1.3 inner plaintext has no content type"));
                }
                let inner_type = plain[end - 1];
                if ContentType::from_u8(inner_type).is_none() {
                    return Err(invalid(format!(
                        "TLS 1.3 inner content type {inner_type} is invalid"
                    )));
                }
                let data = plain[..end - 1].to_vec();
                if data.len() > MAX_PLAINTEXT {
                    return Err(invalid(format!(
                        "record plaintext is {} bytes, limit {MAX_PLAINTEXT}",
                        data.len()
                    )));
                }
                Ok((inner_type, data))
            }
            RecordCipher::Tls12Gcm { aead, salt } => {
                if payload.len() < 8 + TAG_LEN {
                    return Err(invalid(
                        "TLS 1.2 GCM record shorter than explicit nonce plus tag",
                    ));
                }
                let plain_len = payload.len() - 8 - TAG_LEN;
                if plain_len > MAX_PLAINTEXT {
                    return Err(invalid(format!(
                        "record plaintext is {plain_len} bytes, limit {MAX_PLAINTEXT}"
                    )));
                }
                let mut nonce = [0u8; 12];
                nonce[..4].copy_from_slice(salt);
                nonce[4..].copy_from_slice(&payload[..8]);
                let aad = tls12_aad(seq, content_type, version, plain_len);
                let plain = aead
                    .open(&nonce, &aad, &payload[8..])
                    .map_err(|_| invalid("bad record MAC (TLS 1.2 decryption failed)"))?;
                Ok((content_type, plain))
            }
            RecordCipher::Tls12ChaCha { aead, iv } => {
                if payload.len() < TAG_LEN {
                    return Err(invalid(
                        "TLS 1.2 record shorter than the authentication tag",
                    ));
                }
                let plain_len = payload.len() - TAG_LEN;
                if plain_len > MAX_PLAINTEXT {
                    return Err(invalid(format!(
                        "record plaintext is {plain_len} bytes, limit {MAX_PLAINTEXT}"
                    )));
                }
                let mut nonce = *iv;
                xor_seq(&mut nonce, seq);
                let aad = tls12_aad(seq, content_type, version, plain_len);
                let plain = aead
                    .open(&nonce, &aad, payload)
                    .map_err(|_| invalid("bad record MAC (TLS 1.2 ChaCha20 decryption failed)"))?;
                Ok((content_type, plain))
            }
        }
    }
}

fn tls12_aad(seq: u64, content_type: u8, version: u16, len: usize) -> Vec<u8> {
    let mut aad = Vec::with_capacity(13);
    aad.extend_from_slice(&seq.to_be_bytes());
    aad.push(content_type);
    aad.push((version >> 8) as u8);
    aad.push(version as u8);
    aad.push((len >> 8) as u8);
    aad.push(len as u8);
    aad
}

fn xor_seq(nonce: &mut [u8; 12], seq: u64) {
    let bytes = seq.to_be_bytes();
    for (i, b) in bytes.iter().enumerate() {
        nonce[4 + i] ^= b;
    }
}

fn invalid(msg: impl Into<String>) -> io::Error {
    io::Error::new(ErrorKind::InvalidData, msg.into())
}

/// The record layer state for one connection.
pub(crate) struct RecordLayer {
    tcp: TcpStream,
    inbuf: Vec<u8>,
    read_cipher: Option<RecordCipher>,
    write_cipher: Option<RecordCipher>,
    pub(crate) read_seq: u64,
    pub(crate) write_seq: u64,
    /// Legacy record version placed in outgoing headers (0x0301 for the first
    /// ClientHello, then 0x0303).
    pub(crate) version: u16,
}

impl RecordLayer {
    pub(crate) fn new(tcp: TcpStream) -> Self {
        RecordLayer {
            tcp,
            inbuf: Vec::new(),
            read_cipher: None,
            write_cipher: None,
            read_seq: 0,
            write_seq: 0,
            version: 0x0301,
        }
    }

    pub(crate) fn set_read_cipher(&mut self, cipher: Option<RecordCipher>) {
        self.read_cipher = cipher;
        self.read_seq = 0;
    }

    pub(crate) fn set_write_cipher(&mut self, cipher: Option<RecordCipher>) {
        self.write_cipher = cipher;
        self.write_seq = 0;
    }

    pub(crate) fn flush(&mut self) -> io::Result<()> {
        self.tcp.flush()
    }

    /// Read one complete record, decrypting it when a read cipher is active.
    ///
    /// A socket timeout is returned as-is with any partial record bytes kept in
    /// the internal buffer; the next call resumes exactly where this one left
    /// off.
    pub(crate) fn read_record(&mut self) -> io::Result<(u8, Vec<u8>)> {
        loop {
            let (typ, version, payload) = self.read_raw()?;

            // ChangeCipherSpec is always sent in the clear, even in TLS 1.3
            // compatibility mode.
            if typ == ContentType::ChangeCipherSpec as u8 {
                if payload.len() != 1 || payload[0] != 1 {
                    return Err(invalid(
                        "change_cipher_spec payload is not the single byte 0x01",
                    ));
                }
                return Ok((typ, payload));
            }

            match &self.read_cipher {
                None => {
                    if payload.len() > MAX_PLAINTEXT {
                        return Err(invalid(format!(
                            "plaintext record is {} bytes, limit {MAX_PLAINTEXT}",
                            payload.len()
                        )));
                    }
                    return Ok((typ, payload));
                }
                Some(cipher) => {
                    // Some peers emit a plaintext two-byte alert on a fatal
                    // error even after keys are installed. It cannot be an
                    // encrypted alert (those carry a 16-byte tag).
                    if typ == ContentType::Alert as u8 && payload.len() == 2 {
                        return Ok((typ, payload));
                    }
                    if typ == ContentType::Handshake as u8
                        || typ == ContentType::ApplicationData as u8
                        || typ == ContentType::Alert as u8
                    {
                        let seq = self.read_seq;
                        let (inner_type, plain) = cipher.decrypt(seq, typ, version, &payload)?;
                        self.read_seq = seq.checked_add(1).ok_or_else(|| {
                            invalid("read sequence number exhausted; a new key epoch is required")
                        })?;
                        return Ok((inner_type, plain));
                    }
                    return Err(invalid(format!(
                        "record has content type {typ} while record protection is active"
                    )));
                }
            }
        }
    }

    fn read_raw(&mut self) -> io::Result<(u8, u16, Vec<u8>)> {
        loop {
            if self.inbuf.len() >= 5 {
                let typ = self.inbuf[0];
                let version = u16::from_be_bytes([self.inbuf[1], self.inbuf[2]]);
                let len = u16::from_be_bytes([self.inbuf[3], self.inbuf[4]]) as usize;
                if (version >> 8) != 3 || (version & 0xff) > 4 {
                    return Err(invalid(format!(
                        "unsupported record version 0x{version:04x}"
                    )));
                }
                if len > MAX_CIPHERTEXT {
                    return Err(invalid(format!(
                        "record length {len} exceeds the {MAX_CIPHERTEXT}-byte limit"
                    )));
                }
                if self.inbuf.len() >= 5 + len {
                    let payload = self.inbuf[5..5 + len].to_vec();
                    self.inbuf.drain(..5 + len);
                    return Ok((typ, version, payload));
                }
            }

            let mut tmp = [0u8; 8192];
            match self.tcp.read(&mut tmp) {
                Ok(0) => {
                    if self.inbuf.is_empty() {
                        return Err(io::Error::new(
                            ErrorKind::UnexpectedEof,
                            "connection closed by peer",
                        ));
                    }
                    return Err(io::Error::new(
                        ErrorKind::UnexpectedEof,
                        "connection closed in the middle of a record",
                    ));
                }
                Ok(n) => self.inbuf.extend_from_slice(&tmp[..n]),
                Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }
    }

    /// Write one record (at most MAX_PLAINTEXT bytes), protecting it when a
    /// write cipher is active.
    pub(crate) fn write_record(&mut self, content_type: u8, data: &[u8]) -> io::Result<()> {
        if data.len() > MAX_PLAINTEXT {
            return Err(invalid(format!(
                "record plaintext is {} bytes, limit {MAX_PLAINTEXT}",
                data.len()
            )));
        }
        let version = self.version;
        let (outer_type, payload) = match &self.write_cipher {
            None => (content_type, data.to_vec()),
            Some(cipher) => {
                let seq = self.write_seq;
                let out = cipher.encrypt(seq, content_type, version, data)?;
                // Advance before touching the socket: if the write fails
                // halfway through, a retry must never reuse this nonce.
                self.write_seq = seq.checked_add(1).ok_or_else(|| {
                    invalid("write sequence number exhausted; a new key epoch is required")
                })?;
                out
            }
        };
        if payload.len() > u16::MAX as usize {
            return Err(invalid("record payload does not fit in u16"));
        }
        let mut header = [0u8; 5];
        header[0] = outer_type;
        header[1] = (version >> 8) as u8;
        header[2] = version as u8;
        header[3] = (payload.len() >> 8) as u8;
        header[4] = payload.len() as u8;
        self.tcp.write_all(&header)?;
        self.tcp.write_all(&payload)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::thread;
    use std::time::Duration;

    fn cipher_pair() -> (RecordCipher, RecordCipher) {
        let key = [7u8; 16];
        let iv = [3u8; 12];
        (
            RecordCipher::tls13(AeadKind::Aes128Gcm, &key, iv).unwrap(),
            RecordCipher::tls13(AeadKind::Aes128Gcm, &key, iv).unwrap(),
        )
    }

    #[test]
    fn tls13_record_roundtrip_and_padding() {
        let (enc, dec) = cipher_pair();
        let (typ, payload) = enc.encrypt(0, 23, 0x0303, b"hello").unwrap();
        assert_eq!(typ, 23);
        let (inner, plain) = dec.decrypt(0, typ, 0x0303, &payload).unwrap();
        assert_eq!(inner, 23);
        assert_eq!(plain, b"hello");
    }

    #[test]
    fn tls13_inner_padding_is_stripped() {
        let (enc, dec) = cipher_pair();
        let (typ, _) = enc.encrypt(5, 22, 0x0303, b"handshake").unwrap();
        // Re-encrypt the same content with explicit trailing zero padding by
        // calling the AEAD directly.
        let iv = [3u8; 12];
        let aead = AeadCipher::new(AeadKind::Aes128Gcm, &[7u8; 16]).unwrap();
        let mut nonce = iv;
        xor_seq(&mut nonce, 5);
        let mut inner = b"handshake".to_vec();
        inner.push(22);
        inner.extend_from_slice(&[0, 0, 0, 0]);
        let ct_len = inner.len() + TAG_LEN;
        let aad = [23u8, 3, 3, (ct_len >> 8) as u8, ct_len as u8];
        let payload = aead.seal(&nonce, &aad, &inner);
        let (inner_type, plain) = dec.decrypt(5, typ, 0x0303, &payload).unwrap();
        assert_eq!(inner_type, 22);
        assert_eq!(plain, b"handshake");
    }

    #[test]
    fn tls13_tampering_is_rejected() {
        let (enc, dec) = cipher_pair();
        let (typ, mut payload) = enc.encrypt(9, 23, 0x0303, b"secret").unwrap();
        let last = payload.len() - 1;
        payload[last] ^= 0x01;
        assert!(dec.decrypt(9, typ, 0x0303, &payload).is_err());
    }

    #[test]
    fn tls12_gcm_roundtrip() {
        let key = [1u8; 16];
        let salt = [2u8; 4];
        let enc = RecordCipher::tls12_gcm(AeadKind::Aes128Gcm, &key, salt).unwrap();
        let dec = RecordCipher::tls12_gcm(AeadKind::Aes128Gcm, &key, salt).unwrap();
        let (typ, payload) = enc.encrypt(42, 23, 0x0303, b"data").unwrap();
        assert_eq!(typ, 23);
        assert_eq!(payload.len(), 8 + 4 + 16);
        let (inner, plain) = dec.decrypt(42, typ, 0x0303, &payload).unwrap();
        assert_eq!(inner, 23);
        assert_eq!(plain, b"data");
        assert!(dec.decrypt(43, typ, 0x0303, &payload).is_err());
    }

    #[test]
    fn tls12_chacha_roundtrip() {
        let key = [9u8; 32];
        let iv = [4u8; 12];
        let enc = RecordCipher::tls12_chacha(&key, iv).unwrap();
        let dec = RecordCipher::tls12_chacha(&key, iv).unwrap();
        let (typ, payload) = enc.encrypt(7, 22, 0x0303, b"finished").unwrap();
        assert_eq!(payload.len(), 8 + 16);
        let (inner, plain) = dec.decrypt(7, typ, 0x0303, &payload).unwrap();
        assert_eq!(inner, 22);
        assert_eq!(plain, b"finished");
    }

    #[test]
    fn nonce_construction_matches_rfc7905() {
        let iv = [0xffu8; 12];
        let mut nonce = iv;
        xor_seq(&mut nonce, 1);
        let mut want = [0xffu8; 12];
        want[11] = 0xfe;
        assert_eq!(nonce, want);
        let mut nonce = iv;
        xor_seq(&mut nonce, 0x0102_0304_0506_0708);
        let want = [
            0xff, 0xff, 0xff, 0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8, 0xf7,
        ];
        assert_eq!(nonce, want);
    }

    #[test]
    fn read_timeout_keeps_partial_record_buffered() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let server = thread::spawn(move || {
            let (mut sock, _) = listener.accept().expect("accept");
            // Send only the first three header bytes, then stall for longer
            // than the client's read timeout.
            sock.write_all(&[22, 3, 3]).expect("partial header");
            sock.flush().expect("flush");
            thread::sleep(Duration::from_millis(900));
            sock.write_all(&[0, 5]).expect("length");
            sock.write_all(b"hello").expect("body");
            sock.flush().expect("flush");
            thread::sleep(Duration::from_millis(200));
        });

        let tcp = TcpStream::connect(("127.0.0.1", port)).expect("connect");
        tcp.set_read_timeout(Some(Duration::from_millis(150)))
            .expect("timeout");
        let control = tcp.try_clone().expect("clone");
        let mut layer = RecordLayer::new(tcp);

        let err = layer.read_record().expect_err("timeout expected");
        assert!(
            err.kind() == ErrorKind::WouldBlock || err.kind() == ErrorKind::TimedOut,
            "unexpected error kind {:?}: {err}",
            err.kind()
        );

        // The bytes already consumed must still be in the buffer, and the next
        // call (after the caller extends the timeout) must complete the record.
        control
            .set_read_timeout(Some(Duration::from_secs(3)))
            .expect("timeout");
        let (typ, payload) = layer.read_record().expect("resumed record");
        assert_eq!(typ, 22);
        assert_eq!(payload, b"hello");
        let _ = server.join();
    }

    #[test]
    fn record_header_roundtrip() {
        // Exercise the pure framing split used by read_raw without a socket.
        let mut framed = vec![22u8, 3, 3, 0, 5];
        framed.extend_from_slice(b"hello");
        assert_eq!(framed.len(), 10);
        assert_eq!(u16::from_be_bytes([framed[3], framed[4]]) as usize, 5);
        assert_eq!(&framed[5..], b"hello");
    }
}
