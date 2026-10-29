//! TLS 1.3 server authentication and key exchange (RFC 8446).

use emerag_crypto::ct;
use emerag_crypto::curve::P256Public;
use emerag_crypto::x509::Certificate;

use crate::bytes::Reader;
use crate::handshake::{
    self, parse_alpn, parse_extensions, ClientHello, Extensions, HandshakeMessage, ServerHello,
    EXT_ALPN, HS_CERTIFICATE, HS_CERTIFICATE_REQUEST, HS_CERTIFICATE_VERIFY,
    HS_ENCRYPTED_EXTENSIONS, HS_FINISHED,
};
use crate::key::{
    tls13_early_secret, tls13_finished_key, tls13_handshake_secret, tls13_master_secret,
    tls13_traffic_key_iv, HashId,
};
use crate::record::RecordCipher;
use crate::suite::Suite;
use crate::verify;
use crate::{Error, Tls13Keys, TlsConfig, TlsVersion};

const MAX_CERTIFICATES: usize = 16;
const CERT_VERIFY_CONTEXT: &[u8] = b"TLS 1.3, server CertificateVerify";

pub(crate) struct Output {
    pub(crate) conn: crate::handshake::HsConn,
    pub(crate) alpn: Option<String>,
    pub(crate) peer_spki: [u8; 32],
    pub(crate) keys: Tls13Keys,
}

pub(crate) fn handshake(
    mut conn: crate::handshake::HsConn,
    cfg: &TlsConfig,
    ch: &ClientHello,
    sh: &ServerHello,
    suite: Suite,
    shared: Vec<u8>,
) -> Result<Output, Error> {
    let hash = suite.hash;

    if sh.compression != 0 {
        return Err(Error::new(format!(
            "tls: handshake: server selected compression method {}",
            sh.compression
        )));
    }
    if sh.session_id != ch.session_id {
        return Err(Error::new(
            "tls: handshake: ServerHello legacy_session_id does not echo the ClientHello value",
        ));
    }
    if !ch.offered(sh.cipher_suite) {
        return Err(Error::new(format!(
            "tls: handshake: server selected cipher suite {} that was not offered",
            crate::suite::name(sh.cipher_suite)
        )));
    }
    if sh.version != TlsVersion::Tls13 {
        return Err(Error::new(
            "tls: handshake: internal error: TLS 1.3 path with a non-1.3 ServerHello",
        ));
    }
    if sh.random == handshake::HRR_RANDOM {
        return Err(Error::new(
            "tls: handshake: HelloRetryRequest is not supported by this client",
        ));
    }

    let th_sh = conn.transcript.hash(hash);
    let early = tls13_early_secret(hash);
    let hs_secret = tls13_handshake_secret(hash, &early, &shared)?;
    let c_hs = hash.derive_secret(&hs_secret, "c hs traffic", &th_sh)?;
    let s_hs = hash.derive_secret(&hs_secret, "s hs traffic", &th_sh)?;
    let master = tls13_master_secret(hash, &hs_secret)?;

    let (skey, siv) = tls13_traffic_key_iv(hash, &s_hs, suite.key_len)?;
    conn.io
        .set_read_cipher(Some(RecordCipher::tls13(suite.aead, &skey, siv).map_err(
            |e| {
                Error::new(format!(
                    "tls: handshake: cannot install server handshake keys: {e}"
                ))
            },
        )?));

    // EncryptedExtensions must be the first encrypted message.
    let ee = conn.read_msg()?;
    if ee.typ != HS_ENCRYPTED_EXTENSIONS {
        return Err(unexpected("EncryptedExtensions", &ee));
    }
    let ee_exts = parse_encrypted_extensions(&ee.body)?;
    let ee_alpn = match ee_exts.get(EXT_ALPN) {
        Some(data) => parse_alpn(data)?,
        None => None,
    };
    conn.transcript.add(&ee.raw)?;

    // Certificate
    let cert_msg = conn.read_msg()?;
    if cert_msg.typ == HS_CERTIFICATE_REQUEST {
        return Err(Error::new(
            "tls: handshake: server requested a client certificate, which this client does not support",
        ));
    }
    if cert_msg.typ != HS_CERTIFICATE {
        return Err(unexpected("Certificate", &cert_msg));
    }
    let chain = parse_certificate(&cert_msg.body)?;
    let peer_spki = verify::verify_peer(cfg, &chain)?;
    conn.transcript.add(&cert_msg.raw)?;

    // CertificateVerify
    let cv = conn.read_msg()?;
    if cv.typ != HS_CERTIFICATE_VERIFY {
        return Err(unexpected("CertificateVerify", &cv));
    }
    let (scheme, signature) = parse_certificate_verify(&cv.body)?;
    let th_cert = conn.transcript.hash(hash);
    let signed = certificate_verify_input(&th_cert);
    verify::verify_signature(&chain[0], scheme, &signed, &signature)?;
    conn.transcript.add(&cv.raw)?;

    // Finished
    let fin = conn.read_msg()?;
    if fin.typ != HS_FINISHED {
        return Err(unexpected("Finished", &fin));
    }
    let th_cv = conn.transcript.hash(hash);
    let server_finished_key = tls13_finished_key(hash, &s_hs)?;
    let expected = hash.hmac(&server_finished_key, &th_cv);
    if fin.body.len() != expected.len() || !ct::ct_eq(&fin.body, &expected) {
        return Err(Error::new(
            "tls: handshake: server Finished verify_data does not match the transcript",
        ));
    }
    conn.transcript.add(&fin.raw)?;

    let th_server_fin = conn.transcript.hash(hash);
    let c_ap = hash.derive_secret(&master, "c ap traffic", &th_server_fin)?;
    let s_ap = hash.derive_secret(&master, "s ap traffic", &th_server_fin)?;

    // Client Finished is protected with the client handshake traffic key.
    let (ckey, civ) = tls13_traffic_key_iv(hash, &c_hs, suite.key_len)?;
    conn.io
        .set_write_cipher(Some(RecordCipher::tls13(suite.aead, &ckey, civ).map_err(
            |e| {
                Error::new(format!(
                    "tls: handshake: cannot install client handshake keys: {e}"
                ))
            },
        )?));
    let client_finished_key = tls13_finished_key(hash, &c_hs)?;
    let verify_data = hash.hmac(&client_finished_key, &th_server_fin);
    let finished_msg = handshake::encode_handshake(HS_FINISHED, &verify_data)?;
    conn.send_message(&finished_msg)?;

    // Application traffic keys (sequence numbers restart at zero).
    let (ckey, civ) = tls13_traffic_key_iv(hash, &c_ap, suite.key_len)?;
    conn.io
        .set_write_cipher(Some(RecordCipher::tls13(suite.aead, &ckey, civ).map_err(
            |e| {
                Error::new(format!(
                    "tls: handshake: cannot install client application keys: {e}"
                ))
            },
        )?));
    let (skey, siv) = tls13_traffic_key_iv(hash, &s_ap, suite.key_len)?;
    conn.io
        .set_read_cipher(Some(RecordCipher::tls13(suite.aead, &skey, siv).map_err(
            |e| {
                Error::new(format!(
                    "tls: handshake: cannot install server application keys: {e}"
                ))
            },
        )?));

    let alpn = ee_alpn.or(sh.alpn.clone());
    let keys = Tls13Keys {
        hash,
        aead: suite.aead,
        key_len: suite.key_len,
        read_secret: s_ap,
        write_secret: c_ap,
    };
    Ok(Output {
        conn,
        alpn,
        peer_spki,
        keys,
    })
}

fn unexpected(expected: &str, msg: &HandshakeMessage) -> Error {
    Error::new(format!(
        "tls: handshake: expected {expected}, got handshake message type {} ({})",
        msg.typ,
        handshake_type_name(msg.typ)
    ))
}

pub(crate) fn handshake_type_name(typ: u8) -> &'static str {
    match typ {
        0 => "hello_request",
        1 => "ClientHello",
        2 => "ServerHello",
        4 => "NewSessionTicket",
        8 => "EncryptedExtensions",
        11 => "Certificate",
        12 => "ServerKeyExchange",
        13 => "CertificateRequest",
        14 => "ServerHelloDone",
        15 => "CertificateVerify",
        20 => "Finished",
        24 => "KeyUpdate",
        _ => "unknown",
    }
}

fn parse_encrypted_extensions(body: &[u8]) -> Result<Extensions, Error> {
    parse_extensions(body, "EncryptedExtensions")
}

fn parse_certificate(body: &[u8]) -> Result<Vec<Certificate>, Error> {
    let mut r = Reader::new(body, "Certificate");
    let context = r.vec_u8()?;
    if !context.is_empty() {
        return Err(Error::new(
            "tls: handshake: malformed Certificate: non-empty request context from a server",
        ));
    }
    let list = r.vec_u24()?;
    r.finish()?;
    let mut lr = Reader::new(list, "Certificate");
    let mut chain = Vec::new();
    while !lr.is_empty() {
        if chain.len() >= MAX_CERTIFICATES {
            return Err(Error::new(format!(
                "tls: handshake: server sent more than {MAX_CERTIFICATES} certificates"
            )));
        }
        let der = lr.vec_u24()?;
        // Per-certificate extensions are not needed by this client.
        let _extensions = lr.vec_u16()?;
        let cert = Certificate::parse_der(der).map_err(|e| {
            Error::new(format!(
                "tls: verify: server certificate #{}: {e}",
                chain.len()
            ))
        })?;
        chain.push(cert);
    }
    if chain.is_empty() {
        return Err(Error::new(
            "tls: handshake: server sent an empty certificate list",
        ));
    }
    Ok(chain)
}

fn parse_certificate_verify(body: &[u8]) -> Result<(u16, Vec<u8>), Error> {
    let mut r = Reader::new(body, "CertificateVerify");
    let scheme = r.u16()?;
    let sig = r.vec_u16()?.to_vec();
    r.finish()?;
    if sig.is_empty() {
        return Err(Error::new(
            "tls: handshake: malformed CertificateVerify: empty signature",
        ));
    }
    Ok((scheme, sig))
}

/// Compute the TLS 1.3 ECDHE shared secret for the server's key share.
pub(crate) fn shared_secret(ch: &ClientHello, group: u16, peer: &[u8]) -> Result<Vec<u8>, Error> {
    match group {
        handshake::GROUP_X25519 => {
            if peer.len() != 32 {
                return Err(Error::new(format!(
                    "tls: handshake: x25519 key share is {} bytes, expected 32",
                    peer.len()
                )));
            }
            let mut p = [0u8; 32];
            p.copy_from_slice(peer);
            ch.x25519
                .diffie_hellman(&p)
                .map(|s| s.to_vec())
                .map_err(|e| Error::new(format!("tls: handshake: x25519 key exchange failed: {e}")))
        }
        handshake::GROUP_P256 => {
            let point = P256Public::from_sec1(peer)
                .map_err(|e| Error::new(format!("tls: handshake: invalid P-256 key share: {e}")))?;
            ch.p256
                .diffie_hellman(&point)
                .map(|s| s.to_vec())
                .map_err(|e| Error::new(format!("tls: handshake: P-256 key exchange failed: {e}")))
        }
        other => Err(Error::new(format!(
            "tls: handshake: server chose unsupported key share group 0x{other:04x}"
        ))),
    }
}

pub(crate) fn certificate_verify_input(transcript_hash: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(64 + CERT_VERIFY_CONTEXT.len() + 1 + transcript_hash.len());
    out.extend_from_slice(&[0x20u8; 64]);
    out.extend_from_slice(CERT_VERIFY_CONTEXT);
    out.push(0);
    out.extend_from_slice(transcript_hash);
    out
}

/// Derive the next application traffic secret for a KeyUpdate.
pub(crate) fn next_traffic_secret(hash: HashId, secret: &[u8]) -> Result<Vec<u8>, Error> {
    hash.expand_label(secret, "traffic upd", &[], hash.len())
}

pub(crate) fn suite_cipher(
    aead: crate::suite::AeadKind,
    key_len: usize,
    hash: HashId,
    secret: &[u8],
) -> Result<RecordCipher, Error> {
    let (key, iv) = tls13_traffic_key_iv(hash, secret, key_len)?;
    RecordCipher::tls13(aead, &key, iv)
        .map_err(|e| Error::new(format!("tls: handshake: cannot derive traffic keys: {e}")))
}
