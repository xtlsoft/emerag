//! TLS options used by the HTTP client and translated into emerag-tls config.

use emerag_tls::{TlsConfig, TlsVersion, VerifyMode};

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum TlsVerify {
    /// Verify against the CA roots embedded in the binary (default).
    #[default]
    EmbeddedCa,
    /// Verify against the operating system trust store.
    SystemCa,
    /// Verify against a PEM bundle supplied by the user (--cacert).
    CaFile(Vec<u8>),
    /// Verify normally and additionally pin the server SPKI SHA-256.
    PinnedSpki([u8; 32]),
    /// No verification at all. Loudly discouraged; the CLI warns every session.
    Insecure,
}

impl TlsVerify {
    pub fn is_insecure(&self) -> bool {
        matches!(self, TlsVerify::Insecure)
    }

    /// Short label for status lines and the doctor screen.
    pub fn label(&self) -> &'static str {
        match self {
            TlsVerify::EmbeddedCa => "embedded-ca",
            TlsVerify::SystemCa => "system-ca",
            TlsVerify::CaFile(_) => "ca-file",
            TlsVerify::PinnedSpki(_) => "pinned-spki",
            TlsVerify::Insecure => "insecure",
        }
    }
}

#[derive(Debug, Clone)]
pub struct TlsOptions {
    pub verify: TlsVerify,
    /// SNI name; defaults to the URL host.
    pub sni: Option<String>,
    /// ALPN protocols; http/1.1 only for this client.
    pub alpn: Vec<String>,
    pub client_cert_pem: Option<Vec<u8>>,
    pub client_key_pem: Option<Vec<u8>>,
}

impl TlsOptions {
    pub fn new() -> Self {
        TlsOptions {
            verify: TlsVerify::EmbeddedCa,
            sni: None,
            alpn: vec!["http/1.1".to_string()],
            client_cert_pem: None,
            client_key_pem: None,
        }
    }

    /// Build the emerag-tls configuration for a connection to host.
    ///
    /// Note: emerag-tls currently exposes a single "Full" verification mode and
    /// does not distinguish embedded roots from the system store, so
    /// EmbeddedCa and SystemCa both map to VerifyMode::Full for now. When the
    /// TLS crate grows that switch this mapping is the only place to change.
    pub fn to_tls_config(&self, host: &str) -> TlsConfig {
        let mut cfg = TlsConfig::new(self.sni.clone().unwrap_or_else(|| host.to_string()));
        match &self.verify {
            TlsVerify::EmbeddedCa => {
                cfg.verify = VerifyMode::Full;
            }
            TlsVerify::SystemCa => {
                cfg.verify = VerifyMode::Full;
            }
            TlsVerify::CaFile(pem) => {
                cfg.verify = VerifyMode::Full;
                cfg.ca_pem = Some(pem.clone());
            }
            TlsVerify::PinnedSpki(pin) => {
                cfg.verify = VerifyMode::Full;
                cfg.pinned_spki = Some(*pin);
            }
            TlsVerify::Insecure => {
                cfg.verify = VerifyMode::Insecure;
            }
        }
        if !self.alpn.is_empty() {
            cfg.alpn = self.alpn.clone();
        }
        cfg.client_cert_pem = self.client_cert_pem.clone();
        cfg.client_key_pem = self.client_key_pem.clone();
        cfg.min_version = TlsVersion::Tls12;
        cfg
    }
}

impl Default for TlsOptions {
    fn default() -> Self {
        TlsOptions::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_options_map_to_full_verification() {
        let opts = TlsOptions::new();
        let cfg = opts.to_tls_config("api.example.com");
        assert_eq!(cfg.server_name, "api.example.com");
        assert_eq!(cfg.verify, VerifyMode::Full);
        assert_eq!(cfg.alpn, vec!["http/1.1".to_string()]);
        assert_eq!(cfg.min_version, TlsVersion::Tls12);
        assert!(cfg.ca_pem.is_none());
        assert!(cfg.pinned_spki.is_none());
    }

    #[test]
    fn sni_override_and_ca_file() {
        let mut opts = TlsOptions::new();
        opts.sni = Some("front.example.com".to_string());
        opts.verify = TlsVerify::CaFile(b"-----BEGIN CERTIFICATE-----".to_vec());
        let cfg = opts.to_tls_config("10.0.0.1");
        assert_eq!(cfg.server_name, "front.example.com");
        assert_eq!(cfg.verify, VerifyMode::Full);
        assert_eq!(
            cfg.ca_pem.as_deref(),
            Some(&b"-----BEGIN CERTIFICATE-----"[..])
        );
    }

    #[test]
    fn pinned_and_insecure_modes() {
        let mut opts = TlsOptions::new();
        opts.verify = TlsVerify::PinnedSpki([7u8; 32]);
        let cfg = opts.to_tls_config("example.com");
        assert_eq!(cfg.verify, VerifyMode::Full);
        assert_eq!(cfg.pinned_spki, Some([7u8; 32]));

        opts.verify = TlsVerify::Insecure;
        let cfg = opts.to_tls_config("example.com");
        assert_eq!(cfg.verify, VerifyMode::Insecure);
        assert!(opts.verify.is_insecure());
        assert_eq!(TlsVerify::CaFile(Vec::new()).label(), "ca-file");
    }
}
