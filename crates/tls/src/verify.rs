//! Certificate chain validation and handshake signature verification.

use std::time::{SystemTime, UNIX_EPOCH};

use emerag_crypto::curve::{P256Public, P384Public};
use emerag_crypto::rsa::{HashAlg as RsaHash, RsaPublicKey};
use emerag_crypto::x509::{CertStore, Certificate};

use crate::{Error, TlsConfig, VerifyMode};

const OID_RSA_ENCRYPTION: &str = "1.2.840.113549.1.1.1";
const OID_EC_PUBLIC_KEY: &str = "1.2.840.10045.2.1";
const OID_P256: &str = "1.2.840.10045.3.1.7";
const OID_P384: &str = "1.3.132.0.34";

pub(crate) fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Verify the peer chain according to cfg and return the leaf SPKI SHA-256.
///
/// In VerifyMode::Insecure the chain is only parsed (the caller already did
/// that), never validated, but the SPKI is still reported.
pub(crate) fn verify_peer(cfg: &TlsConfig, chain: &[Certificate]) -> Result<[u8; 32], Error> {
    let leaf = chain
        .first()
        .ok_or_else(|| Error::new("tls: verify: server sent an empty certificate chain"))?;
    let spki = leaf.spki_sha256();

    if cfg.verify == VerifyMode::Insecure {
        return Ok(spki);
    }

    let owned_store;
    let store: &CertStore = match &cfg.ca_pem {
        Some(pem) => {
            owned_store = CertStore::from_pem(pem).map_err(|e| {
                Error::new(format!(
                    "tls: verify: cannot parse the supplied CA bundle: {e}"
                ))
            })?;
            &owned_store
        }
        None => CertStore::embedded()
            .map_err(|e| Error::new(format!("tls: verify: embedded roots unavailable: {e}")))?,
    };

    let now = now_unix();
    let result = match &cfg.pinned_spki {
        Some(pin) => store.verify_chain_pinned(chain, &cfg.server_name, now, pin),
        None => store.verify_chain(chain, &cfg.server_name, now),
    };
    result.map_err(|e| Error::new(format!("tls: verify: {e}")))?;
    Ok(spki)
}

/// Verify one handshake signature (TLS 1.2 ServerKeyExchange or TLS 1.3
/// CertificateVerify) with the leaf certificate's public key.
pub(crate) fn verify_signature(
    cert: &Certificate,
    scheme: u16,
    message: &[u8],
    signature: &[u8],
) -> Result<(), Error> {
    match cert.spki_algorithm.as_str() {
        OID_RSA_ENCRYPTION => verify_rsa(cert, scheme, message, signature),
        OID_EC_PUBLIC_KEY => verify_ecdsa(cert, scheme, message, signature),
        other => Err(Error::new(format!(
            "tls: verify: unsupported certificate public key algorithm {other}"
        ))),
    }
}

fn verify_rsa(
    cert: &Certificate,
    scheme: u16,
    message: &[u8],
    signature: &[u8],
) -> Result<(), Error> {
    let key = RsaPublicKey::from_der_spki(&cert.spki)
        .map_err(|e| Error::new(format!("tls: verify: cannot parse the server RSA key: {e}")))?;
    let (alg, pss) = match scheme {
        0x0401 => (RsaHash::Sha256, false),
        0x0501 => (RsaHash::Sha384, false),
        0x0601 => (RsaHash::Sha512, false),
        0x0804 => (RsaHash::Sha256, true),
        0x0805 => (RsaHash::Sha384, true),
        0x0806 => (RsaHash::Sha512, true),
        _ => {
            return Err(Error::new(format!(
                "tls: verify: signature algorithm {} (0x{scheme:04x}) is not valid with an RSA certificate",
                signature_alg_name(scheme)
            )))
        }
    };
    let ok = if pss {
        key.verify_pss(alg, message, signature, alg.digest_len())
    } else {
        key.verify_pkcs1v15(alg, message, signature)
    }
    .map_err(|e| Error::new(format!("tls: verify: RSA signature check failed: {e}")))?;
    if !ok {
        return Err(Error::new(format!(
            "tls: verify: server signature ({}) does not verify with its RSA public key",
            signature_alg_name(scheme)
        )));
    }
    Ok(())
}

fn verify_ecdsa(
    cert: &Certificate,
    scheme: u16,
    message: &[u8],
    signature: &[u8],
) -> Result<(), Error> {
    let (alg, scheme_curve) = match scheme {
        0x0403 => (RsaHash::Sha256, "P-256"),
        0x0503 => (RsaHash::Sha384, "P-384"),
        _ => {
            return Err(Error::new(format!(
                "tls: verify: signature algorithm {} (0x{scheme:04x}) is not valid with an ECDSA certificate",
                signature_alg_name(scheme)
            )))
        }
    };
    let curve = cert
        .spki_curve
        .as_deref()
        .ok_or_else(|| Error::new("tls: verify: ECDSA certificate has no named curve"))?;
    let ok = match curve {
        OID_P256 => {
            let key = P256Public::from_sec1(&cert.public_key_bits).map_err(|e| {
                Error::new(format!(
                    "tls: verify: cannot parse the server P-256 key: {e}"
                ))
            })?;
            key.verify_digest(alg, message, signature).map_err(|e| {
                Error::new(format!("tls: verify: ECDSA signature check failed: {e}"))
            })?
        }
        OID_P384 => {
            let key = P384Public::from_sec1(&cert.public_key_bits).map_err(|e| {
                Error::new(format!(
                    "tls: verify: cannot parse the server P-384 key: {e}"
                ))
            })?;
            key.verify_digest(alg, message, signature).map_err(|e| {
                Error::new(format!("tls: verify: ECDSA signature check failed: {e}"))
            })?
        }
        other => {
            return Err(Error::new(format!(
                "tls: verify: unsupported ECDSA certificate curve {other}"
            )))
        }
    };
    if !ok {
        return Err(Error::new(format!(
            "tls: verify: server signature ({}, {scheme_curve} key) does not verify",
            signature_alg_name(scheme)
        )));
    }
    Ok(())
}

pub(crate) fn signature_alg_name(scheme: u16) -> &'static str {
    match scheme {
        0x0401 => "rsa_pkcs1_sha256",
        0x0501 => "rsa_pkcs1_sha384",
        0x0601 => "rsa_pkcs1_sha512",
        0x0804 => "rsa_pss_rsae_sha256",
        0x0805 => "rsa_pss_rsae_sha384",
        0x0806 => "rsa_pss_rsae_sha512",
        0x0403 => "ecdsa_secp256r1_sha256",
        0x0503 => "ecdsa_secp384r1_sha384",
        0x0603 => "ecdsa_secp521r1_sha512",
        _ => "unknown",
    }
}
