//! The concrete cipher suites this client offers.

use crate::key::HashId;
use crate::TlsVersion;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AeadKind {
    Aes128Gcm,
    Aes256Gcm,
    ChaCha20Poly1305,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KeyExchange {
    EcdheRsa,
    EcdheEcdsa,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Suite {
    pub(crate) id: u16,
    pub(crate) version: TlsVersion,
    pub(crate) hash: HashId,
    pub(crate) key_len: usize,
    pub(crate) aead: AeadKind,
    /// TLS 1.2 only; TLS 1.3 authentication is decided by CertificateVerify.
    pub(crate) kx: Option<KeyExchange>,
}

pub(crate) const TLS13_AES_128_GCM_SHA256: u16 = 0x1301;
pub(crate) const TLS13_AES_256_GCM_SHA384: u16 = 0x1302;
pub(crate) const TLS13_CHACHA20_POLY1305_SHA256: u16 = 0x1303;
pub(crate) const TLS12_ECDHE_RSA_AES128_GCM_SHA256: u16 = 0xc02f;
pub(crate) const TLS12_ECDHE_RSA_AES256_GCM_SHA384: u16 = 0xc030;
pub(crate) const TLS12_ECDHE_RSA_CHACHA20_POLY1305: u16 = 0xcca8;
pub(crate) const TLS12_ECDHE_ECDSA_AES128_GCM_SHA256: u16 = 0xc02b;
pub(crate) const TLS12_ECDHE_ECDSA_AES256_GCM_SHA384: u16 = 0xc02c;
pub(crate) const TLS12_ECDHE_ECDSA_CHACHA20_POLY1305: u16 = 0xcca9;

pub(crate) fn lookup(id: u16) -> Option<Suite> {
    let s = |version, hash, key_len, aead, kx| Suite {
        id,
        version,
        hash,
        key_len,
        aead,
        kx,
    };
    match id {
        TLS13_AES_128_GCM_SHA256 => Some(s(
            TlsVersion::Tls13,
            HashId::Sha256,
            16,
            AeadKind::Aes128Gcm,
            None,
        )),
        TLS13_AES_256_GCM_SHA384 => Some(s(
            TlsVersion::Tls13,
            HashId::Sha384,
            32,
            AeadKind::Aes256Gcm,
            None,
        )),
        TLS13_CHACHA20_POLY1305_SHA256 => Some(s(
            TlsVersion::Tls13,
            HashId::Sha256,
            32,
            AeadKind::ChaCha20Poly1305,
            None,
        )),
        TLS12_ECDHE_RSA_AES128_GCM_SHA256 => Some(s(
            TlsVersion::Tls12,
            HashId::Sha256,
            16,
            AeadKind::Aes128Gcm,
            Some(KeyExchange::EcdheRsa),
        )),
        TLS12_ECDHE_RSA_AES256_GCM_SHA384 => Some(s(
            TlsVersion::Tls12,
            HashId::Sha384,
            32,
            AeadKind::Aes256Gcm,
            Some(KeyExchange::EcdheRsa),
        )),
        TLS12_ECDHE_RSA_CHACHA20_POLY1305 => Some(s(
            TlsVersion::Tls12,
            HashId::Sha256,
            32,
            AeadKind::ChaCha20Poly1305,
            Some(KeyExchange::EcdheRsa),
        )),
        TLS12_ECDHE_ECDSA_AES128_GCM_SHA256 => Some(s(
            TlsVersion::Tls12,
            HashId::Sha256,
            16,
            AeadKind::Aes128Gcm,
            Some(KeyExchange::EcdheEcdsa),
        )),
        TLS12_ECDHE_ECDSA_AES256_GCM_SHA384 => Some(s(
            TlsVersion::Tls12,
            HashId::Sha384,
            32,
            AeadKind::Aes256Gcm,
            Some(KeyExchange::EcdheEcdsa),
        )),
        TLS12_ECDHE_ECDSA_CHACHA20_POLY1305 => Some(s(
            TlsVersion::Tls12,
            HashId::Sha256,
            32,
            AeadKind::ChaCha20Poly1305,
            Some(KeyExchange::EcdheEcdsa),
        )),
        _ => None,
    }
}

pub(crate) fn name(id: u16) -> &'static str {
    match id {
        TLS13_AES_128_GCM_SHA256 => "TLS_AES_128_GCM_SHA256",
        TLS13_AES_256_GCM_SHA384 => "TLS_AES_256_GCM_SHA384",
        TLS13_CHACHA20_POLY1305_SHA256 => "TLS_CHACHA20_POLY1305_SHA256",
        TLS12_ECDHE_RSA_AES128_GCM_SHA256 => "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        TLS12_ECDHE_RSA_AES256_GCM_SHA384 => "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        TLS12_ECDHE_RSA_CHACHA20_POLY1305 => "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
        TLS12_ECDHE_ECDSA_AES128_GCM_SHA256 => "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        TLS12_ECDHE_ECDSA_AES256_GCM_SHA384 => "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
        TLS12_ECDHE_ECDSA_CHACHA20_POLY1305 => "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
        _ => "UNKNOWN",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_offered_suite_resolves() {
        for id in [
            TLS13_AES_128_GCM_SHA256,
            TLS13_AES_256_GCM_SHA384,
            TLS13_CHACHA20_POLY1305_SHA256,
            TLS12_ECDHE_RSA_AES128_GCM_SHA256,
            TLS12_ECDHE_RSA_AES256_GCM_SHA384,
            TLS12_ECDHE_RSA_CHACHA20_POLY1305,
            TLS12_ECDHE_ECDSA_AES128_GCM_SHA256,
            TLS12_ECDHE_ECDSA_AES256_GCM_SHA384,
            TLS12_ECDHE_ECDSA_CHACHA20_POLY1305,
        ] {
            let s = lookup(id).expect("suite");
            assert_eq!(s.id, id);
            assert_eq!(
                s.key_len,
                match s.aead {
                    AeadKind::Aes128Gcm => 16,
                    _ => 32,
                }
            );
            assert_ne!(name(id), "UNKNOWN");
        }
        assert!(lookup(0x0000).is_none());
    }
}
