//! TLS 1.2 ECDHE handshake (RFC 5246 + RFC 7627 + RFC 5288/7905).

use emerag_crypto::ct;
use emerag_crypto::curve::P256Public;
use emerag_crypto::x509::Certificate;

use crate::bytes::{Reader, Writer};
use crate::handshake::{
    self, ClientHello, HsConn, ServerHello, GROUP_P256, GROUP_X25519, HS_CERTIFICATE,
    HS_CERTIFICATE_REQUEST, HS_FINISHED, HS_SERVER_HELLO_DONE, HS_SERVER_KEY_EXCHANGE,
};
use crate::key::tls12_prf;
use crate::record::RecordCipher;
use crate::suite::{AeadKind, Suite};
use crate::{Error, TlsConfig, TlsVersion};

const MAX_CERTIFICATES: usize = 16;

pub(crate) struct Output {
    pub(crate) conn: HsConn,
    pub(crate) alpn: Option<String>,
    pub(crate) peer_spki: [u8; 32],
}

struct ServerKeyExchange {
    named_curve: u16,
    params: Vec<u8>,
    public_key: Vec<u8>,
    scheme: u16,
    signature: Vec<u8>,
}

pub(crate) fn handshake(
    mut conn: HsConn,
    cfg: &TlsConfig,
    ch: &ClientHello,
    sh: &ServerHello,
    suite: Suite,
) -> Result<Output, Error> {
    if sh.compression != 0 {
        return Err(Error::new(format!(
            "tls: handshake: server selected compression method {}",
            sh.compression
        )));
    }
    if !ch.offered(sh.cipher_suite) {
        return Err(Error::new(format!(
            "tls: handshake: server selected cipher suite {} that was not offered",
            crate::suite::name(sh.cipher_suite)
        )));
    }
    if suite.version != TlsVersion::Tls12 {
        return Err(Error::new(
            "tls: handshake: internal error: TLS 1.2 path with a TLS 1.3 suite",
        ));
    }
    if cfg.min_version == TlsVersion::Tls13 {
        return Err(Error::new(
            "tls: handshake: server negotiated TLS 1.2 but min_version is TLS 1.3",
        ));
    }
    if handshake::is_downgrade_sentinel(&sh.random) {
        return Err(Error::new(
            "tls: handshake: TLS 1.2 ServerHello carries the TLS 1.3 downgrade sentinel (possible downgrade attack)",
        ));
    }
    if !sh.ems {
        return Err(Error::new(
            "tls: handshake: server does not support extended master secret (RFC 7627 is required)",
        ));
    }
    if let Some(info) = &sh.renegotiation_info {
        if !info.is_empty() {
            return Err(Error::new(
                "tls: handshake: server supplied non-empty renegotiation_info",
            ));
        }
    }
    if suite.kx.is_none() {
        return Err(Error::new(
            "tls: handshake: selected TLS 1.2 cipher suite has no key exchange",
        ));
    }

    let mut chain: Option<Vec<Certificate>> = None;
    let mut ske: Option<ServerKeyExchange> = None;
    loop {
        let msg = conn.read_msg()?;
        match msg.typ {
            HS_CERTIFICATE => {
                if chain.is_some() {
                    return Err(Error::new(
                        "tls: handshake: server sent more than one Certificate message",
                    ));
                }
                chain = Some(parse_certificate(&msg.body)?);
                conn.transcript.add(&msg.raw)?;
            }
            HS_SERVER_KEY_EXCHANGE => {
                if ske.is_some() {
                    return Err(Error::new(
                        "tls: handshake: server sent more than one ServerKeyExchange message",
                    ));
                }
                ske = Some(parse_server_key_exchange(&msg.body)?);
                conn.transcript.add(&msg.raw)?;
            }
            HS_CERTIFICATE_REQUEST => {
                return Err(Error::new(
                    "tls: handshake: server requested a client certificate, which this client does not support",
                ))
            }
            HS_SERVER_HELLO_DONE => {
                if !msg.body.is_empty() {
                    return Err(Error::new(
                        "tls: handshake: malformed ServerHelloDone: expected an empty body",
                    ));
                }
                conn.transcript.add(&msg.raw)?;
                break;
            }
            0 => {
                return Err(Error::new(
                    "tls: handshake: server sent HelloRequest (renegotiation is not supported)",
                ))
            }
            other => {
                return Err(Error::new(format!(
                    "tls: handshake: unexpected handshake message type {other} ({}) during server flight",
                    crate::tls13::handshake_type_name(other)
                )))
            }
        }
    }

    let chain = chain
        .ok_or_else(|| Error::new("tls: handshake: server did not send a Certificate message"))?;
    let ske =
        ske.ok_or_else(|| Error::new("tls: handshake: server did not send ServerKeyExchange"))?;

    let peer_spki = crate::verify::verify_peer(cfg, &chain)?;

    let mut signed = Vec::with_capacity(64 + ske.params.len());
    signed.extend_from_slice(&ch.random);
    signed.extend_from_slice(&sh.random);
    signed.extend_from_slice(&ske.params);
    crate::verify::verify_signature(&chain[0], ske.scheme, &signed, &ske.signature)?;

    let (pre_master, client_public) = ecdhe_shared_secret(ch, &ske.named_curve, &ske.public_key)?;

    let mut cke = Writer::new();
    cke.vec_u8(&client_public);
    let cke_msg = handshake::encode_handshake(16, &cke.buf)?;
    conn.send_message(&cke_msg)?;

    // RFC 7627: session_hash covers everything through ClientKeyExchange.
    let session_hash = conn.transcript.hash(suite.hash);
    let master = tls12_prf(
        suite.hash,
        &pre_master,
        "extended master secret",
        &session_hash,
        48,
    );

    let iv_len = match suite.aead {
        AeadKind::ChaCha20Poly1305 => 12,
        _ => 4,
    };
    let needed = suite.key_len * 2 + iv_len * 2;
    let mut seed = Vec::with_capacity(64);
    seed.extend_from_slice(&sh.random);
    seed.extend_from_slice(&ch.random);
    let key_block = tls12_prf(suite.hash, &master, "key expansion", &seed, needed);
    let (client_key, server_key, client_iv, server_iv) =
        split_key_block(&key_block, suite.key_len, iv_len)?;

    let client_cipher = make_cipher(suite.aead, &client_key, &client_iv)?;
    let server_cipher = make_cipher(suite.aead, &server_key, &server_iv)?;

    let transcript_hash = conn.transcript.hash(suite.hash);
    let client_verify = tls12_prf(suite.hash, &master, "client finished", &transcript_hash, 12);

    // ChangeCipherSpec is a plaintext record; the Finished that follows uses
    // the new write state (sequence number zero).
    conn.io
        .write_record(20, &[1])
        .map_err(|e| Error::new(format!("tls: handshake: cannot send ChangeCipherSpec: {e}")))?;
    conn.io.set_write_cipher(Some(client_cipher));
    let fin_msg = handshake::encode_handshake(HS_FINISHED, &client_verify)?;
    conn.send_message(&fin_msg)?;

    conn.read_ccs()?;
    conn.io.set_read_cipher(Some(server_cipher));

    let server_fin = conn.read_msg()?;
    if server_fin.typ != HS_FINISHED {
        return Err(Error::new(format!(
            "tls: handshake: expected server Finished, got handshake message type {} ({})",
            server_fin.typ,
            crate::tls13::handshake_type_name(server_fin.typ)
        )));
    }
    let transcript_hash = conn.transcript.hash(suite.hash);
    let expected = tls12_prf(suite.hash, &master, "server finished", &transcript_hash, 12);
    if server_fin.body.len() != expected.len() || !ct::ct_eq(&server_fin.body, &expected) {
        return Err(Error::new(
            "tls: handshake: server Finished verify_data does not match the transcript",
        ));
    }
    conn.transcript.add(&server_fin.raw)?;

    let alpn = sh.alpn.clone();
    Ok(Output {
        conn,
        alpn,
        peer_spki,
    })
}

fn split_key_block(
    block: &[u8],
    key_len: usize,
    iv_len: usize,
) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>), Error> {
    let need = key_len * 2 + iv_len * 2;
    if block.len() != need {
        return Err(Error::new(
            "tls: handshake: key block has an unexpected length",
        ));
    }
    let (client_key, rest) = block.split_at(key_len);
    let (server_key, rest) = rest.split_at(key_len);
    let (client_iv, server_iv) = rest.split_at(iv_len);
    Ok((
        client_key.to_vec(),
        server_key.to_vec(),
        client_iv.to_vec(),
        server_iv.to_vec(),
    ))
}

fn make_cipher(kind: AeadKind, key: &[u8], iv: &[u8]) -> Result<RecordCipher, Error> {
    match kind {
        AeadKind::ChaCha20Poly1305 => {
            if iv.len() != 12 {
                return Err(Error::new(
                    "tls: handshake: ChaCha20-Poly1305 key block gave a bad IV length",
                ));
            }
            let mut v = [0u8; 12];
            v.copy_from_slice(iv);
            RecordCipher::tls12_chacha(key, v)
                .map_err(|e| Error::new(format!("tls: handshake: {e}")))
        }
        _ => {
            if iv.len() != 4 {
                return Err(Error::new(
                    "tls: handshake: AES-GCM key block gave a bad implicit IV length",
                ));
            }
            let mut v = [0u8; 4];
            v.copy_from_slice(iv);
            RecordCipher::tls12_gcm(kind, key, v)
                .map_err(|e| Error::new(format!("tls: handshake: {e}")))
        }
    }
}

fn ecdhe_shared_secret(
    ch: &ClientHello,
    named_curve: &u16,
    peer: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), Error> {
    match *named_curve {
        GROUP_X25519 => {
            if peer.len() != 32 {
                return Err(Error::new(format!(
                    "tls: handshake: x25519 server key is {} bytes, expected 32",
                    peer.len()
                )));
            }
            let mut p = [0u8; 32];
            p.copy_from_slice(peer);
            let shared = ch.x25519.diffie_hellman(&p).map_err(|e| {
                Error::new(format!("tls: handshake: x25519 key exchange failed: {e}"))
            })?;
            Ok((shared.to_vec(), ch.x25519.public_key().to_vec()))
        }
        GROUP_P256 => {
            let point = P256Public::from_sec1(peer).map_err(|e| {
                Error::new(format!("tls: handshake: invalid P-256 server key: {e}"))
            })?;
            let shared = ch.p256.diffie_hellman(&point).map_err(|e| {
                Error::new(format!("tls: handshake: P-256 key exchange failed: {e}"))
            })?;
            Ok((shared.to_vec(), ch.p256.public_key().to_sec1().to_vec()))
        }
        other => Err(Error::new(format!(
            "tls: handshake: server chose unsupported ECDHE group 0x{other:04x}"
        ))),
    }
}

fn parse_certificate(body: &[u8]) -> Result<Vec<Certificate>, Error> {
    let mut r = Reader::new(body, "Certificate");
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

fn parse_server_key_exchange(body: &[u8]) -> Result<ServerKeyExchange, Error> {
    let mut r = Reader::new(body, "ServerKeyExchange");
    let curve_type = r.u8()?;
    if curve_type != 3 {
        return Err(Error::new(format!(
            "tls: handshake: ServerKeyExchange uses curve type {curve_type}, only named_curve (3) is supported"
        )));
    }
    let named_curve = r.u16()?;
    let public_key = r.vec_u8()?.to_vec();
    if public_key.is_empty() {
        return Err(Error::new(
            "tls: handshake: ServerKeyExchange has an empty ECDHE public key",
        ));
    }
    let params = body[..r.position()].to_vec();
    let scheme = r.u16()?;
    let signature = r.vec_u16()?.to_vec();
    r.finish()?;
    if signature.is_empty() {
        return Err(Error::new(
            "tls: handshake: ServerKeyExchange has an empty signature",
        ));
    }
    Ok(ServerKeyExchange {
        named_curve,
        params,
        public_key,
        scheme,
        signature,
    })
}
