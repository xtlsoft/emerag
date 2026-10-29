//! X.509 certificate parsing (RFC 5280) and TLS-server path validation.
//!
//! This module is deliberately small but strict: a DER reader that accepts only
//! definite, minimal lengths and bounds its recursion depth, a parser that
//! extracts exactly the fields a TLS client needs, and a path builder that
//! checks every signature, validity window, CA bit and path length constraint.
//!
//! Only standard-library types plus the crypto primitives in hash, rsa and
//! curve are used. All input is treated as hostile: every slice is bounds
//! checked, integer conversions are fallible, and failures are Results.
//! Unknown or weak algorithms are rejected, never accepted.

use std::net::IpAddr;

use crate::{ct, curve, hash, pem, rsa, Error, Result};

/// Refuse to even look at a "certificate" larger than this (1 MiB).
const MAX_CERT_DER: usize = 1 << 20;
/// Maximum nesting accepted by the DER reader.
const MAX_DER_DEPTH: u32 = 16;
/// Maximum number of certificates on a path, including the leaf.
const MAX_CHAIN_DEPTH: usize = 8;
/// Tolerance applied to notBefore/notAfter (RFC 5280 permits a little skew).
const CLOCK_SKEW: i64 = 60;

const TAG_BOOLEAN: u8 = 0x01;
const TAG_INTEGER: u8 = 0x02;
const TAG_BIT_STRING: u8 = 0x03;
const TAG_OCTET_STRING: u8 = 0x04;
const TAG_OID: u8 = 0x06;
const TAG_SEQUENCE: u8 = 0x30;
const TAG_SET: u8 = 0x31;
const TAG_UTC_TIME: u8 = 0x17;
const TAG_GENERALIZED_TIME: u8 = 0x18;
const TAG_BMP_STRING: u8 = 0x1e;
const TAG_UNIVERSAL_STRING: u8 = 0x1c;

const OID_RSA: &str = "1.2.840.113549.1.1.1";
const OID_RSA_PSS_KEY: &str = "1.2.840.113549.1.1.10";
const OID_EC: &str = "1.2.840.10045.2.1";
const OID_P256: &str = "1.2.840.10045.3.1.7";
const OID_P384: &str = "1.3.132.0.34";

const OID_SHA256_RSA: &str = "1.2.840.113549.1.1.11";
const OID_SHA384_RSA: &str = "1.2.840.113549.1.1.12";
const OID_SHA512_RSA: &str = "1.2.840.113549.1.1.13";
const OID_RSA_PSS: &str = "1.2.840.113549.1.1.10";
const OID_ECDSA_SHA256: &str = "1.2.840.10045.4.3.2";
const OID_ECDSA_SHA384: &str = "1.2.840.10045.4.3.3";
const OID_ECDSA_SHA512: &str = "1.2.840.10045.4.3.4";

const OID_BASIC_CONSTRAINTS: &str = "2.5.29.19";
const OID_KEY_USAGE: &str = "2.5.29.15";
const OID_EXT_KEY_USAGE: &str = "2.5.29.37";
const OID_SUBJECT_ALT_NAME: &str = "2.5.29.17";
const OID_SUBJECT_KEY_ID: &str = "2.5.29.14";
const OID_AUTHORITY_KEY_ID: &str = "2.5.29.35";
const OID_NAME_CONSTRAINTS: &str = "2.5.29.30";

const OID_CN: &str = "2.5.4.3";

const EKU_SERVER_AUTH: &str = "1.3.6.1.5.5.7.3.1";
const EKU_ANY: &str = "2.5.29.37.0";

pub const KU_DIGITAL_SIGNATURE: u16 = 1 << 0;
pub const KU_NON_REPUDIATION: u16 = 1 << 1;
pub const KU_KEY_ENCIPHERMENT: u16 = 1 << 2;
pub const KU_DATA_ENCIPHERMENT: u16 = 1 << 3;
pub const KU_KEY_AGREEMENT: u16 = 1 << 4;
pub const KU_KEY_CERT_SIGN: u16 = 1 << 5;
pub const KU_CRL_SIGN: u16 = 1 << 6;
pub const KU_ENCIPHER_ONLY: u16 = 1 << 7;
pub const KU_DECIPHER_ONLY: u16 = 1 << 8;

/// A parsed X.509 v3 certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Certificate {
    /// The complete, verbatim certificate (used for trust anchor comparison).
    pub der: Vec<u8>,
    /// The DER of the TBSCertificate, i.e. the signed bytes.
    pub tbs_der: Vec<u8>,
    /// serialNumber value, as encoded (may include one sign-padding zero).
    pub serial: Vec<u8>,
    /// Subject rendered RFC 4514 style (most specific RDN first).
    pub subject_rdn: String,
    /// Issuer rendered RFC 4514 style.
    pub issuer_rdn: String,
    /// subject CN when present, used only as a hostname fallback.
    pub subject_cn: Option<String>,
    pub not_before_unix: i64,
    pub not_after_unix: i64,
    /// Full SubjectPublicKeyInfo DER (what SPKI pinning hashes).
    pub spki: Vec<u8>,
    /// SubjectPublicKeyInfo algorithm OID.
    pub spki_algorithm: String,
    /// SubjectPublicKeyInfo algorithm parameters, raw DER (empty when absent).
    pub spki_params: Vec<u8>,
    /// For id-ecPublicKey: the named curve OID.
    pub spki_curve: Option<String>,
    /// Public key BIT STRING contents (RSA: PKCS#1 RSAPublicKey, EC: SEC1 point).
    pub public_key_bits: Vec<u8>,
    pub san_dns: Vec<String>,
    pub san_ip: Vec<Vec<u8>>,
    /// True when a subjectAltName extension is present (even without DNS names).
    pub san_present: bool,
    pub ca: bool,
    pub path_len: Option<u32>,
    pub key_usage: Option<u16>,
    pub extended_key_usage: Vec<String>,
    pub eku_present: bool,
    pub signature_algorithm: String,
    pub signature_params: Vec<u8>,
    pub signature: Vec<u8>,
    pub authority_key_id: Option<Vec<u8>>,
    pub subject_key_id: Option<Vec<u8>>,
    /// Critical extensions we do not implement; validation refuses them.
    pub unsupported_critical: Vec<String>,
}

impl Certificate {
    /// Parse one DER encoded certificate. Trailing bytes are rejected.
    pub fn parse_der(der: &[u8]) -> Result<Self> {
        if der.len() > MAX_CERT_DER {
            return Err(Error::new(format!(
                "x509: certificate too large ({} bytes, limit {MAX_CERT_DER})",
                der.len()
            )));
        }
        let mut r = Reader::new(der);
        let cert = r.expect(TAG_SEQUENCE, "Certificate")?;
        r.finish("Certificate")?;
        let mut c = r.nested(cert)?;

        let tbs_tlv = c.expect(TAG_SEQUENCE, "TBSCertificate")?;
        let (outer_alg, outer_params) = parse_algorithm(&mut c, "signatureAlgorithm")?;
        let sig_bits = c.expect(TAG_BIT_STRING, "signatureValue")?;
        c.finish("Certificate")?;
        let signature = bit_string(sig_bits.content, "signatureValue", true)?.to_vec();
        if signature.is_empty() {
            return Err(Error::new("x509: empty signature"));
        }

        let mut t = c.nested(tbs_tlv)?;

        // version [0] EXPLICIT Version DEFAULT v1
        let version = if t.peek() == Some(0xa0) {
            let v = t.expect(0xa0, "version")?;
            let mut vr = t.nested(v)?;
            let i = vr.expect(TAG_INTEGER, "Version")?;
            vr.finish("version")?;
            let v = parse_uint(i.content, "Version")?;
            if v > 2 {
                return Err(Error::new(format!("x509: invalid certificate version {v}")));
            }
            v as u8
        } else {
            0
        };

        let serial = t.expect(TAG_INTEGER, "serialNumber")?;
        if serial.content.is_empty() {
            return Err(Error::new("x509: empty serialNumber"));
        }
        if serial.content[0] & 0x80 != 0 {
            return Err(Error::new("x509: negative serialNumber"));
        }

        let (tbs_alg, tbs_params) = parse_algorithm(&mut t, "signature")?;
        if tbs_alg != outer_alg || tbs_params != outer_params {
            return Err(Error::new(
                "x509: TBSCertificate signature algorithm differs from outer signatureAlgorithm",
            ));
        }

        let issuer_rdns = parse_name(&mut t)?;
        let issuer_rdn = render_name(&issuer_rdns);

        let validity = t.expect(TAG_SEQUENCE, "Validity")?;
        let (not_before_unix, not_after_unix) = {
            let mut vr = t.nested(validity)?;
            let nb = vr.read()?;
            if nb.tag != TAG_UTC_TIME && nb.tag != TAG_GENERALIZED_TIME {
                return Err(Error::new(format!(
                    "x509: bad notBefore tag {:#04x}",
                    nb.tag
                )));
            }
            let nb = parse_time(&nb, "notBefore")?;
            let na = vr.read()?;
            if na.tag != TAG_UTC_TIME && na.tag != TAG_GENERALIZED_TIME {
                return Err(Error::new(format!(
                    "x509: bad notAfter tag {:#04x}",
                    na.tag
                )));
            }
            let na = parse_time(&na, "notAfter")?;
            vr.finish("Validity")?;
            (nb, na)
        };
        if not_before_unix > not_after_unix {
            return Err(Error::new("x509: notBefore is after notAfter"));
        }

        let subject_rdns = parse_name(&mut t)?;
        let subject_rdn = render_name(&subject_rdns);
        let subject_cn = subject_rdns
            .iter()
            .flat_map(|rdn| rdn.iter())
            .find(|a| a.oid == OID_CN)
            .map(|a| raw_value_string(a.tag, &a.value))
            .filter(|s| !s.is_empty());

        let spki_tlv = t.expect(TAG_SEQUENCE, "subjectPublicKeyInfo")?;
        let (spki_algorithm, spki_params, spki_curve, public_key_bits) = {
            let mut sr = t.nested(spki_tlv)?;
            let (alg, params) = parse_algorithm(&mut sr, "SubjectPublicKeyInfo algorithm")?;
            let key_bits = sr.expect(TAG_BIT_STRING, "subjectPublicKey")?;
            sr.finish("SubjectPublicKeyInfo")?;
            let bits = bit_string(key_bits.content, "subjectPublicKey", true)?.to_vec();
            let curve_oid = if alg == OID_EC {
                named_curve(&params)?
            } else {
                None
            };
            (alg, params, curve_oid, bits)
        };

        // issuerUniqueID [1] / subjectUniqueID [2] are legal in v2/v3; skip them.
        if t.peek() == Some(0x81) {
            skip_element(&mut t, 0)?;
        }
        if t.peek() == Some(0x82) {
            skip_element(&mut t, 0)?;
        }

        let exts = if t.peek() == Some(0xa3) {
            if version != 2 {
                return Err(Error::new(
                    "x509: extensions are only legal in v3 certificates",
                ));
            }
            parse_extensions(&mut t)?
        } else {
            Extensions::default()
        };
        t.finish("TBSCertificate")?;

        Ok(Certificate {
            der: der.to_vec(),
            tbs_der: tbs_tlv.full.to_vec(),
            serial: serial.content.to_vec(),
            subject_rdn,
            issuer_rdn,
            subject_cn,
            not_before_unix,
            not_after_unix,
            spki: spki_tlv.full.to_vec(),
            spki_algorithm,
            spki_params,
            spki_curve,
            public_key_bits,
            san_dns: exts.san_dns,
            san_ip: exts.san_ip,
            san_present: exts.san_present,
            ca: exts.ca,
            path_len: exts.path_len,
            key_usage: exts.key_usage,
            extended_key_usage: exts.eku,
            eku_present: exts.eku_present,
            signature_algorithm: outer_alg,
            signature_params: outer_params,
            signature,
            authority_key_id: exts.aki,
            subject_key_id: exts.ski,
            unsupported_critical: exts.unknown_critical,
        })
    }

    /// Subject distinguished name, RFC 4514 style (e.g. "CN=a.example, O=ACME").
    pub fn subject(&self) -> String {
        self.subject_rdn.clone()
    }

    /// Issuer distinguished name, same format as subject().
    pub fn issuer(&self) -> String {
        self.issuer_rdn.clone()
    }

    pub fn not_before(&self) -> i64 {
        self.not_before_unix
    }

    pub fn not_after(&self) -> i64 {
        self.not_after_unix
    }

    /// dNSName entries of the subjectAltName extension, in encoding order.
    pub fn dns_names(&self) -> &[String] {
        &self.san_dns
    }

    pub fn is_ca(&self) -> bool {
        self.ca
    }

    /// Hex of the serial number with DER sign padding removed.
    pub fn serial_hex(&self) -> String {
        let mut s = &self.serial[..];
        while s.len() > 1 && s[0] == 0 {
            s = &s[1..];
        }
        emerag_util::hex::encode(s)
    }

    /// SHA-256 over the DER of the SubjectPublicKeyInfo (the pin value).
    pub fn spki_sha256(&self) -> [u8; 32] {
        hash::sha256(&self.spki)
    }

    /// Constant-time comparison against an SPKI pin.
    pub fn matches_spki_pin(&self, pin: &[u8; 32]) -> bool {
        ct::ct_eq(&self.spki_sha256(), pin)
    }

    pub fn is_self_issued(&self) -> bool {
        self.subject_rdn == self.issuer_rdn
    }

    pub fn key_usage_has(&self, bit: u16) -> bool {
        self.key_usage.map(|ku| ku & bit != 0).unwrap_or(false)
    }

    /// Verify this certificate's signature with an issuer's public key.
    ///
    /// Ok(false) means the signature is invalid or the issuer key type does not
    /// match the signature algorithm. Err means the algorithm is unknown, weak
    /// or unsupported: the caller must not accept the certificate.
    pub fn verify_signed_by(&self, issuer: &Certificate) -> Result<bool> {
        match self.signature_algorithm.as_str() {
            OID_SHA256_RSA => self.verify_rsa(issuer, rsa::HashAlg::Sha256, false),
            OID_SHA384_RSA => self.verify_rsa(issuer, rsa::HashAlg::Sha384, false),
            OID_SHA512_RSA => self.verify_rsa(issuer, rsa::HashAlg::Sha512, false),
            OID_RSA_PSS => {
                let (alg, salt_len) = parse_pss_params(&self.signature_params)?;
                self.verify_rsa_params(issuer, alg, true, salt_len)
            }
            OID_ECDSA_SHA256 => self.verify_ecdsa(issuer, rsa::HashAlg::Sha256),
            OID_ECDSA_SHA384 => self.verify_ecdsa(issuer, rsa::HashAlg::Sha384),
            OID_ECDSA_SHA512 => self.verify_ecdsa(issuer, rsa::HashAlg::Sha512),
            other => Err(Error::new(format!(
                "x509: unsupported signature algorithm {other} ({}); refusing to accept",
                sig_alg_name(other)
            ))),
        }
    }

    fn verify_rsa(&self, issuer: &Certificate, alg: rsa::HashAlg, pss: bool) -> Result<bool> {
        self.verify_rsa_params(issuer, alg, pss, alg.digest_len())
    }

    fn verify_rsa_params(
        &self,
        issuer: &Certificate,
        alg: rsa::HashAlg,
        pss: bool,
        salt_len: usize,
    ) -> Result<bool> {
        if issuer.spki_algorithm != OID_RSA && issuer.spki_algorithm != OID_RSA_PSS_KEY {
            return Ok(false);
        }
        let key = rsa::RsaPublicKey::from_der_spki(&issuer.spki)?;
        if pss {
            key.verify_pss(alg, &self.tbs_der, &self.signature, salt_len)
        } else {
            key.verify_pkcs1v15(alg, &self.tbs_der, &self.signature)
        }
    }

    fn verify_ecdsa(&self, issuer: &Certificate, alg: rsa::HashAlg) -> Result<bool> {
        if issuer.spki_algorithm != OID_EC {
            return Ok(false);
        }
        match issuer.spki_curve.as_deref() {
            Some(OID_P256) => {
                let key = curve::P256Public::from_sec1(&issuer.public_key_bits)?;
                key.verify_digest(alg, &self.tbs_der, &self.signature)
            }
            Some(OID_P384) => {
                let key = curve::P384Public::from_sec1(&issuer.public_key_bits)?;
                key.verify_digest(alg, &self.tbs_der, &self.signature)
            }
            other => Err(Error::new(format!(
                "x509: unsupported EC named curve {}",
                other.unwrap_or("<none>")
            ))),
        }
    }

    /// RFC 6125 hostname matching against SAN dNSName, falling back to subject
    /// CN only when the certificate has no subjectAltName extension at all.
    pub fn matches_hostname(&self, host: &str) -> bool {
        let host = normalize_host(host);
        if host.is_empty() || !host.is_ascii() {
            return false;
        }
        if let Ok(ip) = host.parse::<IpAddr>() {
            let raw = match ip {
                IpAddr::V4(v4) => v4.octets().to_vec(),
                IpAddr::V6(v6) => v6.octets().to_vec(),
            };
            return self.san_ip.iter().any(|candidate| candidate == &raw);
        }
        if self.san_dns.iter().any(|name| dns_matches(name, &host)) {
            return true;
        }
        if !self.san_present {
            if let Some(cn) = &self.subject_cn {
                return dns_matches(cn, &host);
            }
        }
        false
    }

    /// Validity check with clock skew; idx only decorates the error message.
    fn check_validity(&self, idx: usize, now_unix: u64) -> Result<()> {
        let now = if now_unix > i64::MAX as u64 {
            i64::MAX
        } else {
            now_unix as i64
        };
        if now.saturating_add(CLOCK_SKEW) < self.not_before_unix {
            return Err(Error::new(format!(
                "cert[{idx}]: certificate not valid before {} (now {})",
                timestamp(self.not_before_unix),
                timestamp(now)
            )));
        }
        if now.saturating_sub(CLOCK_SKEW) > self.not_after_unix {
            return Err(Error::new(format!(
                "cert[{idx}]: certificate expired at {} (now {})",
                timestamp(self.not_after_unix),
                timestamp(now)
            )));
        }
        Ok(())
    }

    /// A TLS server leaf must be allowed to do key exchange and server auth.
    fn check_server_role(&self, idx: usize) -> Result<()> {
        if let Some(ku) = self.key_usage {
            if ku & (KU_DIGITAL_SIGNATURE | KU_KEY_ENCIPHERMENT | KU_KEY_AGREEMENT) == 0 {
                return Err(Error::new(format!(
                    "cert[{idx}]: keyUsage does not permit TLS server use (digitalSignature, keyEncipherment and keyAgreement are all clear)"
                )));
            }
        }
        if self.eku_present
            && !self
                .extended_key_usage
                .iter()
                .any(|oid| oid == EKU_SERVER_AUTH || oid == EKU_ANY)
        {
            return Err(Error::new(format!(
                "cert[{idx}]: extendedKeyUsage does not permit serverAuth"
            )));
        }
        Ok(())
    }
}

/// A set of trusted root certificates.
pub struct CertStore {
    pub roots: Vec<Certificate>,
}

impl CertStore {
    /// The Mozilla-derived roots embedded in the binary.
    pub fn embedded() -> Result<&'static CertStore> {
        static EMBEDDED: std::sync::OnceLock<Result<CertStore>> = std::sync::OnceLock::new();
        match EMBEDDED.get_or_init(|| CertStore::from_pem(include_bytes!("../assets/roots.pem"))) {
            Ok(store) => Ok(store),
            Err(e) => Err(e.clone()),
        }
    }

    /// Build a trust store from a PEM bundle (--cacert, SSL_CERT_FILE).
    pub fn from_pem(pem_bytes: &[u8]) -> Result<Self> {
        let roots = parse_pem_certs(pem_bytes)?;
        Ok(CertStore { roots })
    }

    /// Build a trust store from already parsed certificates.
    pub fn from_certs(roots: Vec<Certificate>) -> Self {
        CertStore { roots }
    }

    /// Verify a server chain: chain[0] is the leaf, the rest are intermediates.
    ///
    /// Paths are built depth-first against this store's roots, in any order, so
    /// servers may send extra or cross-signed certificates. Every signature,
    /// validity window, CA bit and path length constraint is checked, and the
    /// leaf hostname must match host. Errors name the offending certificate.
    pub fn verify_chain(&self, chain: &[Certificate], host: &str, now_unix: u64) -> Result<()> {
        let leaf = chain
            .first()
            .ok_or_else(|| Error::new("x509: empty certificate chain"))?;
        if let Some(oid) = leaf.unsupported_critical.first() {
            return Err(Error::new(format!(
                "cert[0] (leaf): unsupported critical extension {oid}"
            )));
        }
        leaf.check_validity(0, now_unix)?;
        leaf.check_server_role(0)?;
        if !leaf.matches_hostname(host) {
            let cn = leaf.subject_cn.as_deref().unwrap_or("<none>");
            return Err(Error::new(format!(
                "cert[0] (leaf): hostname mismatch: '{host}' is not covered by SAN DNS names [{}] (CN {cn})",
                leaf.san_dns.join(", ")
            )));
        }
        let mut path = vec![0usize];
        self.build_path(chain, 0, &mut path, 0, now_unix)
    }

    /// Verify a chain and additionally pin the leaf public key.
    pub fn verify_chain_pinned(
        &self,
        chain: &[Certificate],
        host: &str,
        now_unix: u64,
        spki_sha256: &[u8; 32],
    ) -> Result<()> {
        self.verify_chain(chain, host, now_unix)?;
        let leaf = &chain[0];
        if !leaf.matches_spki_pin(spki_sha256) {
            return Err(Error::new(
                "cert[0] (leaf): SPKI pin mismatch (public key does not match the configured pin)",
            ));
        }
        Ok(())
    }

    fn build_path(
        &self,
        chain: &[Certificate],
        cur: usize,
        path: &mut Vec<usize>,
        ca_below: usize,
        now_unix: u64,
    ) -> Result<()> {
        if path.len() >= MAX_CHAIN_DEPTH {
            return Err(Error::new(format!(
                "cert[{cur}]: certificate chain deeper than {MAX_CHAIN_DEPTH}"
            )));
        }
        let c = &chain[cur];

        // A server may include its own self-signed root; accept it only when it
        // is byte-identical to a trust anchor.
        if self.roots.iter().any(|root| root.der == c.der) {
            return Ok(());
        }

        let mut last_err: Option<String> = None;
        // Number of non-self-issued intermediate CAs below the next cert up.
        let below = ca_below + usize::from(c.ca && !c.is_self_issued());

        for root in &self.roots {
            if root.subject_rdn != c.issuer_rdn {
                continue;
            }
            if let Some(pl) = root.path_len {
                if below > pl as usize {
                    last_err = Some(format!(
                        "cert[{cur}]: path length constraint {pl} of root '{}' exceeded",
                        root.subject_rdn
                    ));
                    continue;
                }
            }
            match c.verify_signed_by(root) {
                Ok(true) => return Ok(()),
                Ok(false) => {
                    if last_err.is_none() {
                        last_err = Some(format!(
                            "cert[{cur}]: signature does not verify against trusted root '{}'",
                            root.subject_rdn
                        ));
                    }
                }
                Err(e) => last_err = Some(format!("cert[{cur}]: {e}")),
            }
        }

        for (i, cand) in chain.iter().enumerate().skip(1) {
            if cand.subject_rdn != c.issuer_rdn || path.contains(&i) {
                continue;
            }
            if !cand.ca {
                last_err = Some(format!(
                    "cert[{i}]: not a CA certificate (basicConstraints CA:FALSE)"
                ));
                continue;
            }
            if let Some(ku) = cand.key_usage {
                if ku & KU_KEY_CERT_SIGN == 0 {
                    last_err = Some(format!(
                        "cert[{i}]: keyUsage does not permit certificate signing"
                    ));
                    continue;
                }
            }
            if let Some(oid) = cand.unsupported_critical.first() {
                last_err = Some(format!("cert[{i}]: unsupported critical extension {oid}"));
                continue;
            }
            if let Err(e) = cand.check_validity(i, now_unix) {
                last_err = Some(e.message().to_string());
                continue;
            }
            if let Some(pl) = cand.path_len {
                if below > pl as usize {
                    last_err = Some(format!(
                        "cert[{i}]: path length constraint {pl} exceeded ({} intermediate CA(s) below)",
                        below
                    ));
                    continue;
                }
            }
            match c.verify_signed_by(cand) {
                Ok(true) => {}
                Ok(false) => {
                    last_err = Some(format!(
                        "cert[{cur}]: signature does not verify against cert[{i}] ({})",
                        sig_alg_name(&c.signature_algorithm)
                    ));
                    continue;
                }
                Err(e) => {
                    last_err = Some(format!("cert[{cur}]: {e}"));
                    continue;
                }
            }
            path.push(i);
            match self.build_path(chain, i, path, below, now_unix) {
                Ok(()) => return Ok(()),
                Err(e) => {
                    path.pop();
                    last_err = Some(e.message().to_string());
                }
            }
        }

        Err(Error::new(last_err.unwrap_or_else(|| {
            format!("cert[{cur}]: no trusted root for issuer '{}'", c.issuer_rdn)
        })))
    }
}

/// Parse every CERTIFICATE block in a PEM document, preserving order.
pub fn parse_pem_certs(pem_bytes: &[u8]) -> Result<Vec<Certificate>> {
    let blocks = pem::parse(pem_bytes)?;
    let mut out = Vec::new();
    for block in blocks {
        if block.label != "CERTIFICATE" && block.label != "X509 CERTIFICATE" {
            continue;
        }
        let cert = Certificate::parse_der(&block.der)
            .map_err(|e| Error::new(format!("pem certificate {}: {e}", out.len())))?;
        out.push(cert);
    }
    if out.is_empty() {
        return Err(Error::new("x509: no CERTIFICATE blocks in PEM input"));
    }
    Ok(out)
}

// ---------------------------------------------------------------- DER reader

#[derive(Clone, Copy)]
struct Tlv<'a> {
    tag: u8,
    content: &'a [u8],
    full: &'a [u8],
}

struct Reader<'a> {
    b: &'a [u8],
    p: usize,
    depth: u32,
}

impl<'a> Reader<'a> {
    fn new(b: &'a [u8]) -> Self {
        Reader { b, p: 0, depth: 0 }
    }

    fn end(&self) -> bool {
        self.p >= self.b.len()
    }

    fn peek(&self) -> Option<u8> {
        self.b.get(self.p).copied()
    }

    fn read(&mut self) -> Result<Tlv<'a>> {
        let start = self.p;
        let tag = match self.b.get(self.p) {
            Some(&t) => t,
            None => return Err(Error::new("der: unexpected end of data while reading tag")),
        };
        self.p += 1;
        if tag & 0x1f == 0x1f {
            return Err(Error::new("der: high-tag-number form is not supported"));
        }
        let first = match self.b.get(self.p) {
            Some(&v) => v,
            None => return Err(Error::new("der: truncated length")),
        };
        self.p += 1;
        let len: usize = if first < 0x80 {
            first as usize
        } else if first == 0x80 {
            return Err(Error::new("der: indefinite length is not allowed"));
        } else {
            let n = (first & 0x7f) as usize;
            if n > 4 {
                return Err(Error::new("der: length of length larger than 4"));
            }
            if self.b.len().saturating_sub(self.p) < n {
                return Err(Error::new("der: truncated long-form length"));
            }
            if self.b[self.p] == 0 {
                return Err(Error::new("der: non-minimal long-form length"));
            }
            let mut v: u64 = 0;
            for i in 0..n {
                v = (v << 8) | self.b[self.p + i] as u64;
            }
            self.p += n;
            if v < 0x80 {
                return Err(Error::new("der: long-form length used for a short value"));
            }
            if v > self.b.len().saturating_sub(start) as u64 {
                return Err(Error::new("der: value length exceeds available input"));
            }
            v as usize
        };
        let content_start = self.p;
        let content_end = match content_start.checked_add(len) {
            Some(end) if end <= self.b.len() => end,
            _ => return Err(Error::new("der: value overruns input")),
        };
        self.p = content_end;
        Ok(Tlv {
            tag,
            content: &self.b[content_start..content_end],
            full: &self.b[start..content_end],
        })
    }

    fn expect(&mut self, tag: u8, what: &str) -> Result<Tlv<'a>> {
        let t = self.read()?;
        if t.tag != tag {
            return Err(Error::new(format!(
                "der: expected {what} (tag {tag:#04x}), found {:#04x}",
                t.tag
            )));
        }
        Ok(t)
    }

    fn finish(&self, what: &str) -> Result<()> {
        if self.end() {
            Ok(())
        } else {
            Err(Error::new(format!(
                "der: {} trailing byte(s) after {what}",
                self.b.len() - self.p
            )))
        }
    }

    fn nested(&self, t: Tlv<'a>) -> Result<Reader<'a>> {
        self.child(t.content)
    }

    fn child(&self, content: &'a [u8]) -> Result<Reader<'a>> {
        let depth = self.depth + 1;
        if depth > MAX_DER_DEPTH {
            return Err(Error::new(format!(
                "der: nesting deeper than {MAX_DER_DEPTH} levels"
            )));
        }
        Ok(Reader {
            b: content,
            p: 0,
            depth,
        })
    }
}

/// Skip one DER element, validating its structure and bounding recursion.
fn skip_element(r: &mut Reader<'_>, depth: u32) -> Result<()> {
    if depth > MAX_DER_DEPTH {
        return Err(Error::new(format!(
            "der: nesting deeper than {MAX_DER_DEPTH} levels"
        )));
    }
    let t = r.read()?;
    if t.tag & 0x20 != 0 {
        let mut inner = Reader::new(t.content);
        while !inner.end() {
            skip_element(&mut inner, depth + 1)?;
        }
    }
    Ok(())
}

// ------------------------------------------------------------------ primitives

fn parse_uint(content: &[u8], what: &str) -> Result<u64> {
    if content.is_empty() {
        return Err(Error::new(format!("der: empty INTEGER for {what}")));
    }
    if content[0] & 0x80 != 0 {
        return Err(Error::new(format!("der: negative INTEGER for {what}")));
    }
    let body = if content.len() > 1 && content[0] == 0 {
        if content[1] & 0x80 == 0 {
            return Err(Error::new(format!(
                "der: non-minimal INTEGER encoding for {what}"
            )));
        }
        &content[1..]
    } else {
        content
    };
    let mut v: u64 = 0;
    for &b in body {
        v = v
            .checked_mul(256)
            .and_then(|v| v.checked_add(b as u64))
            .ok_or_else(|| Error::new(format!("der: INTEGER overflow for {what}")))?;
    }
    Ok(v)
}

fn parse_bool(content: &[u8], what: &str) -> Result<bool> {
    match content {
        [0x00] => Ok(false),
        [0xff] => Ok(true),
        _ => Err(Error::new(format!(
            "der: invalid BOOLEAN encoding for {what}"
        ))),
    }
}

/// Validate a BIT STRING and return its octets (unused bits stripped).
fn bit_string<'a>(content: &'a [u8], what: &str, require_whole: bool) -> Result<&'a [u8]> {
    if content.is_empty() {
        return Err(Error::new(format!("der: empty BIT STRING for {what}")));
    }
    let unused = content[0] as usize;
    if unused > 7 {
        return Err(Error::new(format!(
            "der: invalid unused-bit count {unused} for {what}"
        )));
    }
    if content.len() == 1 {
        if unused != 0 {
            return Err(Error::new(format!(
                "der: non-zero unused bits in empty BIT STRING for {what}"
            )));
        }
        return Ok(&[]);
    }
    if unused != 0 {
        if require_whole {
            return Err(Error::new(format!(
                "der: {what} BIT STRING must be a whole number of octets"
            )));
        }
        let mask = (1u8 << unused) - 1;
        if content[content.len() - 1] & mask != 0 {
            return Err(Error::new(format!(
                "der: non-zero unused bits in BIT STRING for {what}"
            )));
        }
    }
    Ok(&content[1..])
}

fn bit_flags(content: &[u8], what: &str) -> Result<u16> {
    if content.is_empty() {
        return Err(Error::new(format!("der: empty BIT STRING for {what}")));
    }
    let unused = content[0] as usize;
    if unused > 7 {
        return Err(Error::new(format!(
            "der: invalid unused-bit count {unused} for {what}"
        )));
    }
    let bits = &content[1..];
    if bits.is_empty() {
        if unused != 0 {
            return Err(Error::new(format!(
                "der: non-zero unused bits in empty BIT STRING for {what}"
            )));
        }
        return Ok(0);
    }
    let total = bits.len() * 8 - unused;
    let mut flags = 0u16;
    for i in 0..total.min(16) {
        if bits[i / 8] & (0x80 >> (i % 8)) != 0 {
            flags |= 1 << i;
        }
    }
    Ok(flags)
}

fn oid_string(content: &[u8]) -> Result<String> {
    if content.is_empty() {
        return Err(Error::new("der: empty OBJECT IDENTIFIER"));
    }
    let mut arcs: Vec<u64> = Vec::new();
    let mut val: u64 = 0;
    let mut fresh = true;
    for &b in content {
        if fresh && b == 0x80 {
            return Err(Error::new("der: non-minimal OBJECT IDENTIFIER arc"));
        }
        fresh = false;
        val = val
            .checked_mul(128)
            .and_then(|v| v.checked_add((b & 0x7f) as u64))
            .ok_or_else(|| Error::new("der: OBJECT IDENTIFIER arc overflow"))?;
        if b & 0x80 == 0 {
            arcs.push(val);
            val = 0;
            fresh = true;
        }
    }
    if !fresh {
        return Err(Error::new("der: truncated OBJECT IDENTIFIER"));
    }
    let first = arcs[0];
    let (a, b) = if first < 40 {
        (0, first)
    } else if first < 80 {
        (1, first - 40)
    } else {
        (2, first - 80)
    };
    let mut out = format!("{a}.{b}");
    for arc in &arcs[1..] {
        out.push('.');
        out.push_str(&arc.to_string());
    }
    Ok(out)
}

fn parse_oid(r: &mut Reader<'_>) -> Result<String> {
    let t = r.expect(TAG_OID, "OBJECT IDENTIFIER")?;
    oid_string(t.content)
}

/// Parse AlgorithmIdentifier, returning (OID, raw DER parameters or empty).
fn parse_algorithm(r: &mut Reader<'_>, what: &str) -> Result<(String, Vec<u8>)> {
    let seq = r.expect(TAG_SEQUENCE, what)?;
    let mut ar = r.nested(seq)?;
    let oid = parse_oid(&mut ar)?;
    let params = if ar.end() {
        Vec::new()
    } else {
        ar.read()?.full.to_vec()
    };
    ar.finish(what)?;
    Ok((oid, params))
}

fn named_curve(params: &[u8]) -> Result<Option<String>> {
    if params.is_empty() {
        return Ok(None);
    }
    let mut r = Reader::new(params);
    let t = r.read()?;
    r.finish("ECParameters")?;
    if t.tag != TAG_OID {
        return Err(Error::new(
            "x509: explicit EC parameters are not supported (only named curves)",
        ));
    }
    Ok(Some(oid_string(t.content)?))
}

// ---------------------------------------------------------------- names, time

struct Attr {
    oid: String,
    tag: u8,
    value: Vec<u8>,
}

fn parse_name(r: &mut Reader<'_>) -> Result<Vec<Vec<Attr>>> {
    let seq = r.expect(TAG_SEQUENCE, "Name")?;
    let mut nr = r.nested(seq)?;
    let mut rdns = Vec::new();
    while !nr.end() {
        let set = nr.expect(TAG_SET, "RelativeDistinguishedName")?;
        let mut sr = nr.nested(set)?;
        let mut rdn = Vec::new();
        while !sr.end() {
            let atv = sr.expect(TAG_SEQUENCE, "AttributeTypeAndValue")?;
            let mut ar = sr.nested(atv)?;
            let oid = parse_oid(&mut ar)?;
            let value = ar.read()?;
            rdn.push(Attr {
                oid,
                tag: value.tag,
                value: value.content.to_vec(),
            });
            ar.finish("AttributeTypeAndValue")?;
        }
        if rdn.is_empty() {
            return Err(Error::new("x509: empty RelativeDistinguishedName"));
        }
        rdns.push(rdn);
    }
    Ok(rdns)
}

fn attr_name(oid: &str) -> String {
    let short = match oid {
        "2.5.4.3" => "CN",
        "2.5.4.6" => "C",
        "2.5.4.7" => "L",
        "2.5.4.8" => "ST",
        "2.5.4.10" => "O",
        "2.5.4.11" => "OU",
        "2.5.4.5" => "serialNumber",
        "2.5.4.9" => "street",
        "2.5.4.17" => "postalCode",
        "2.5.4.4" => "SN",
        "2.5.4.42" => "GN",
        "0.9.2342.19200300.100.1.25" => "DC",
        "0.9.2342.19200300.100.1.1" => "UID",
        "1.2.840.113549.1.9.1" => "emailAddress",
        _ => return oid.to_string(),
    };
    short.to_string()
}

fn render_name(rdns: &[Vec<Attr>]) -> String {
    let mut parts: Vec<String> = Vec::with_capacity(rdns.len());
    for rdn in rdns.iter().rev() {
        let mut sub: Vec<String> = Vec::with_capacity(rdn.len());
        for attr in rdn {
            sub.push(format!(
                "{}={}",
                attr_name(&attr.oid),
                quote_value(&raw_value_string(attr.tag, &attr.value))
            ));
        }
        parts.push(sub.join("+"));
    }
    parts.join(", ")
}

/// Decode an attribute value; never fails (X.509 attrs are display data).
fn raw_value_string(tag: u8, bytes: &[u8]) -> String {
    match tag {
        TAG_BMP_STRING => decode_utf16be(bytes),
        TAG_UNIVERSAL_STRING => {
            let mut out = String::new();
            for chunk in bytes.chunks_exact(4) {
                let cp = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
                out.push(char::from_u32(cp).unwrap_or('\u{fffd}'));
            }
            out
        }
        _ => match core::str::from_utf8(bytes) {
            Ok(s) => s.to_string(),
            Err(_) => bytes.iter().map(|&b| b as char).collect(),
        },
    }
}

fn decode_utf16be(bytes: &[u8]) -> String {
    let mut out = String::new();
    let mut high: Option<u16> = None;
    for chunk in bytes.chunks_exact(2) {
        let unit = u16::from_be_bytes([chunk[0], chunk[1]]);
        match unit {
            0xd800..=0xdbff => high = Some(unit),
            0xdc00..=0xdfff => {
                if let Some(h) = high.take() {
                    let cp = 0x1_0000 + (((h as u32) - 0xd800) << 10 | ((unit as u32) - 0xdc00));
                    out.push(char::from_u32(cp).unwrap_or('\u{fffd}'));
                } else {
                    out.push('\u{fffd}');
                }
            }
            _ => {
                high = None;
                out.push(char::from_u32(unit as u32).unwrap_or('\u{fffd}'));
            }
        }
    }
    out
}

/// RFC 4514 escaping for a rendered value.
fn quote_value(s: &str) -> String {
    let chars: Vec<char> = s.chars().collect();
    let mut out = String::with_capacity(s.len());
    for (i, &ch) in chars.iter().enumerate() {
        match ch {
            ',' | '+' | '"' | '\\' | '<' | '>' | ';' | '=' => {
                out.push('\\');
                out.push(ch);
            }
            '#' if i == 0 => {
                out.push('\\');
                out.push('#');
            }
            ' ' if i == 0 || i + 1 == chars.len() => {
                out.push('\\');
                out.push(' ');
            }
            c if (c as u32) < 0x20 || (c as u32) == 0x7f => {
                out.push_str(&format!("\\{:02x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out
}

fn parse_time(t: &Tlv<'_>, what: &str) -> Result<i64> {
    let s = core::str::from_utf8(t.content)
        .map_err(|_| Error::new(format!("x509: {what} is not ASCII")))?;
    let (year, rest) = match t.tag {
        TAG_UTC_TIME => {
            if s.len() != 13 || !s.is_ascii() {
                return Err(Error::new(format!("x509: {what} is not a 13-byte UTCTime")));
            }
            if !s.as_bytes()[..12].iter().all(|b| b.is_ascii_digit()) || !s.ends_with('Z') {
                return Err(Error::new(format!("x509: malformed UTCTime in {what}")));
            }
            let yy: i64 = s[..2]
                .parse()
                .map_err(|_| Error::new(format!("x509: malformed year in {what}")))?;
            (if yy >= 50 { 1900 + yy } else { 2000 + yy }, &s[2..])
        }
        TAG_GENERALIZED_TIME => {
            if s.len() != 15 || !s.is_ascii() {
                return Err(Error::new(format!(
                    "x509: {what} is not a 15-byte GeneralizedTime"
                )));
            }
            if !s.as_bytes()[..14].iter().all(|b| b.is_ascii_digit()) || !s.ends_with('Z') {
                return Err(Error::new(format!(
                    "x509: malformed GeneralizedTime in {what}"
                )));
            }
            let year: i64 = s[..4]
                .parse()
                .map_err(|_| Error::new(format!("x509: malformed year in {what}")))?;
            (year, &s[4..])
        }
        _ => {
            return Err(Error::new(format!(
                "x509: unexpected time tag {:#04x} for {what}",
                t.tag
            )))
        }
    };
    let num = |from: usize, to: usize| -> Result<i64> {
        rest.get(from..to)
            .and_then(|part| part.parse::<i64>().ok())
            .ok_or_else(|| Error::new(format!("x509: malformed time digits in {what}")))
    };
    let month = num(0, 2)?;
    let day = num(2, 4)?;
    let hour = num(4, 6)?;
    let minute = num(6, 8)?;
    let second = num(8, 10)?;
    if !(1..=9999).contains(&year) {
        return Err(Error::new(format!(
            "x509: year {year} out of range in {what}"
        )));
    }
    if !(1..=12).contains(&month)
        || day < 1
        || day > days_in_month(year, month)
        || hour > 23
        || minute > 59
        || second > 59
    {
        return Err(Error::new(format!("x509: invalid calendar time in {what}")));
    }
    let days = days_from_civil(year, month, day);
    days.checked_mul(86400)
        .and_then(|v| v.checked_add(hour * 3600 + minute * 60 + second))
        .ok_or_else(|| Error::new(format!("x509: time out of range in {what}")))
}

fn is_leap(year: i64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

fn days_in_month(year: i64, month: i64) -> i64 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if is_leap(year) {
                29
            } else {
                28
            }
        }
        _ => 0,
    }
}

/// Days since 1970-01-01 for a proleptic Gregorian date (Hinnant's algorithm).
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = if month > 2 { month - 3 } else { month + 9 };
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

fn timestamp(t: i64) -> String {
    if t >= 0 {
        emerag_util::time::format_rfc3339((t as u64).saturating_mul(1000))
    } else {
        format!("{t} (unix seconds)")
    }
}

// ------------------------------------------------------------------ extensions

#[derive(Default)]
struct Extensions {
    ca: bool,
    path_len: Option<u32>,
    key_usage: Option<u16>,
    eku: Vec<String>,
    eku_present: bool,
    san_dns: Vec<String>,
    san_ip: Vec<Vec<u8>>,
    san_present: bool,
    ski: Option<Vec<u8>>,
    aki: Option<Vec<u8>>,
    unknown_critical: Vec<String>,
}

fn parse_extensions(r: &mut Reader<'_>) -> Result<Extensions> {
    let wrapper = r.expect(0xa3, "extensions")?;
    let mut wr = r.nested(wrapper)?;
    let seq = wr.expect(TAG_SEQUENCE, "Extensions")?;
    wr.finish("extensions wrapper")?;
    let mut sr = wr.nested(seq)?;

    let mut ex = Extensions::default();
    let mut seen: Vec<String> = Vec::new();
    while !sr.end() {
        let ext = sr.expect(TAG_SEQUENCE, "Extension")?;
        let mut er = sr.nested(ext)?;
        let oid = parse_oid(&mut er)?;
        if seen.iter().any(|s| s == &oid) {
            return Err(Error::new(format!("x509: duplicate extension {oid}")));
        }
        seen.push(oid.clone());
        let mut critical = false;
        if er.peek() == Some(TAG_BOOLEAN) {
            let b = er.expect(TAG_BOOLEAN, "critical")?;
            critical = parse_bool(b.content, "critical")?;
        }
        let value = er.expect(TAG_OCTET_STRING, "extnValue")?;
        er.finish("Extension")?;

        match oid.as_str() {
            OID_BASIC_CONSTRAINTS => {
                let mut vr = er.nested(value)?;
                let bc = vr.expect(TAG_SEQUENCE, "BasicConstraints")?;
                vr.finish("BasicConstraints")?;
                let mut br = vr.nested(bc)?;
                let mut ca = false;
                if br.peek() == Some(TAG_BOOLEAN) {
                    let b = br.expect(TAG_BOOLEAN, "cA")?;
                    ca = parse_bool(b.content, "cA")?;
                }
                let mut path_len = None;
                if br.peek() == Some(TAG_INTEGER) {
                    let i = br.expect(TAG_INTEGER, "pathLenConstraint")?;
                    let v = parse_uint(i.content, "pathLenConstraint")?;
                    if v > u32::MAX as u64 {
                        return Err(Error::new("x509: pathLenConstraint too large"));
                    }
                    path_len = Some(v as u32);
                }
                br.finish("BasicConstraints")?;
                if !ca && path_len.is_some() {
                    return Err(Error::new("x509: pathLenConstraint present with cA=FALSE"));
                }
                ex.ca = ca;
                ex.path_len = path_len;
            }
            OID_KEY_USAGE => {
                let mut vr = er.nested(value)?;
                let bs = vr.expect(TAG_BIT_STRING, "KeyUsage")?;
                vr.finish("KeyUsage")?;
                ex.key_usage = Some(bit_flags(bs.content, "KeyUsage")?);
            }
            OID_EXT_KEY_USAGE => {
                let mut vr = er.nested(value)?;
                let seq = vr.expect(TAG_SEQUENCE, "ExtKeyUsageSyntax")?;
                vr.finish("ExtKeyUsageSyntax")?;
                let mut qr = vr.nested(seq)?;
                if qr.end() {
                    return Err(Error::new("x509: empty ExtKeyUsageSyntax"));
                }
                while !qr.end() {
                    ex.eku.push(parse_oid(&mut qr)?);
                }
                ex.eku_present = true;
            }
            OID_SUBJECT_ALT_NAME => {
                let mut vr = er.nested(value)?;
                let seq = vr.expect(TAG_SEQUENCE, "SubjectAltName")?;
                vr.finish("SubjectAltName")?;
                let mut qr = vr.nested(seq)?;
                if qr.end() {
                    return Err(Error::new("x509: empty SubjectAltName"));
                }
                while !qr.end() {
                    let name = qr.read()?;
                    match name.tag {
                        0x82 => {
                            // dNSName ::= IA5String
                            if !name.content.iter().all(|b| b.is_ascii()) {
                                return Err(Error::new(
                                    "x509: subjectAltName dNSName is not IA5/ASCII",
                                ));
                            }
                            let text = core::str::from_utf8(name.content).map_err(|_| {
                                Error::new("x509: subjectAltName dNSName is not valid ASCII")
                            })?;
                            ex.san_dns.push(text.to_string());
                        }
                        0x87 => {
                            // iPAddress ::= OCTET STRING (4 or 16 octets)
                            let raw = name.content.to_vec();
                            if raw.len() == 4 || raw.len() == 16 {
                                ex.san_ip.push(raw);
                            }
                        }
                        _ => {}
                    }
                }
                ex.san_present = true;
            }
            OID_SUBJECT_KEY_ID => {
                let mut vr = er.nested(value)?;
                let o = vr.expect(TAG_OCTET_STRING, "SubjectKeyIdentifier")?;
                vr.finish("SubjectKeyIdentifier")?;
                ex.ski = Some(o.content.to_vec());
            }
            OID_AUTHORITY_KEY_ID => {
                let mut vr = er.nested(value)?;
                let seq = vr.expect(TAG_SEQUENCE, "AuthorityKeyIdentifier")?;
                vr.finish("AuthorityKeyIdentifier")?;
                let mut qr = vr.nested(seq)?;
                while !qr.end() {
                    let field = qr.read()?;
                    if field.tag == 0x80 {
                        ex.aki = Some(field.content.to_vec());
                    }
                }
            }
            OID_NAME_CONSTRAINTS => {
                // We do not implement name constraints; a critical constraint
                // must never be ignored. (Non-critical instances are harmless.)
                if critical {
                    ex.unknown_critical.push(OID_NAME_CONSTRAINTS.to_string());
                }
            }
            other => {
                if critical {
                    ex.unknown_critical.push(other.to_string());
                }
            }
        }
    }
    Ok(ex)
}

// ---------------------------------------------------------------- hostnames

fn normalize_host(host: &str) -> String {
    let host = host.trim();
    let host = host.strip_prefix('[').unwrap_or(host);
    let host = host.strip_suffix(']').unwrap_or(host);
    let host = host.trim_end_matches('.');
    host.to_ascii_lowercase()
}

/// Wildcard matching for a single dNSName pattern per RFC 6125.
fn dns_matches(pattern: &str, host: &str) -> bool {
    let pattern = normalize_host(pattern);
    let host = normalize_host(host);
    // emerag speaks A-labels only: U-labels would need an IDNA library.
    if pattern.is_empty() || host.is_empty() || !pattern.is_ascii() || !host.is_ascii() {
        return false;
    }
    match pattern.strip_prefix("*.") {
        None => pattern == host,
        Some(suffix) => {
            if suffix.is_empty() || suffix.contains('*') {
                return false;
            }
            // A wildcard label must never be an IDN A-label: that would let one
            // pattern cover every internationalised label under it.
            if suffix
                .split('.')
                .next()
                .map(|label| label.starts_with("xn--"))
                .unwrap_or(false)
            {
                return false;
            }
            if is_public_suffix(suffix) {
                return false;
            }
            if !host.ends_with(suffix) {
                return false;
            }
            let cut = host.len() - suffix.len();
            if cut < 2 || host.as_bytes()[cut - 1] != b'.' {
                return false;
            }
            let label = &host[..cut - 1];
            !label.is_empty() && !label.contains('.')
        }
    }
}

/// Naive public-suffix rejection for wildcards ("*.com" must never match).
fn is_public_suffix(suffix: &str) -> bool {
    if !suffix.contains('.') {
        return true;
    }
    const KNOWN: &[&str] = &[
        "co.uk",
        "org.uk",
        "ac.uk",
        "gov.uk",
        "com.au",
        "net.au",
        "org.au",
        "co.nz",
        "co.jp",
        "ne.jp",
        "or.jp",
        "com.cn",
        "net.cn",
        "org.cn",
        "gov.cn",
        "com.br",
        "com.mx",
        "com.tr",
        "com.tw",
        "com.hk",
        "com.sg",
        "co.in",
        "co.kr",
        "co.za",
        "com.ar",
        "com.pl",
        "github.io",
        "appspot.com",
        "cloudfront.net",
        "herokuapp.com",
        "azurewebsites.net",
    ];
    KNOWN.contains(&suffix)
}

// ------------------------------------------------------------- signature algs

fn sig_alg_name(oid: &str) -> &'static str {
    match oid {
        OID_SHA256_RSA => "sha256WithRSAEncryption",
        OID_SHA384_RSA => "sha384WithRSAEncryption",
        OID_SHA512_RSA => "sha512WithRSAEncryption",
        OID_RSA_PSS => "RSASSA-PSS",
        OID_ECDSA_SHA256 => "ecdsa-with-SHA256",
        OID_ECDSA_SHA384 => "ecdsa-with-SHA384",
        OID_ECDSA_SHA512 => "ecdsa-with-SHA512",
        "1.2.840.113549.1.1.5" => "sha1WithRSAEncryption (rejected)",
        "1.2.840.10045.4.1" => "ecdsa-with-SHA1 (rejected)",
        "1.3.101.112" => "Ed25519 (unsupported)",
        _ => "unknown",
    }
}

fn hash_alg_from_oid(oid: &str) -> Option<rsa::HashAlg> {
    match oid {
        "2.16.840.1.101.3.4.2.1" => Some(rsa::HashAlg::Sha256),
        "2.16.840.1.101.3.4.2.2" => Some(rsa::HashAlg::Sha384),
        "2.16.840.1.101.3.4.2.3" => Some(rsa::HashAlg::Sha512),
        _ => None,
    }
}

fn parse_hash_algorithm(r: &mut Reader<'_>, what: &str) -> Result<rsa::HashAlg> {
    let oid = {
        let seq = r.expect(TAG_SEQUENCE, what)?;
        r.finish(what)?;
        let mut ar = r.nested(seq)?;
        let oid = parse_oid(&mut ar)?;
        // Parameters are normally NULL; ignore whatever it is.
        if !ar.end() {
            let _ = ar.read()?;
        }
        ar.finish(what)?;
        oid
    };
    hash_alg_from_oid(&oid).ok_or_else(|| {
        Error::new(format!(
            "x509: unsupported digest algorithm {oid} in {what} (SHA-1 is rejected)"
        ))
    })
}

fn parse_mgf1(r: &mut Reader<'_>, what: &str) -> Result<rsa::HashAlg> {
    let seq = r.expect(TAG_SEQUENCE, what)?;
    r.finish(what)?;
    let mut ar = r.nested(seq)?;
    let oid = parse_oid(&mut ar)?;
    if oid != "1.2.840.113549.1.1.8" {
        return Err(Error::new(format!(
            "x509: unsupported mask generation function {oid}"
        )));
    }
    let hash = parse_hash_algorithm(&mut ar, "MGF1 hashAlgorithm")?;
    ar.finish(what)?;
    Ok(hash)
}

/// Parse RSASSA-PSS parameters, returning (hash, salt length).
fn parse_pss_params(params: &[u8]) -> Result<(rsa::HashAlg, usize)> {
    if params.is_empty() {
        return Err(Error::new(
            "x509: RSASSA-PSS signature has no parameters (SHA-1 default is rejected)",
        ));
    }
    let mut r = Reader::new(params);
    let seq = r.expect(TAG_SEQUENCE, "RSASSA-PSS-params")?;
    r.finish("RSASSA-PSS-params")?;
    let mut sr = r.nested(seq)?;
    let mut hash: Option<rsa::HashAlg> = None;
    let mut mgf: Option<rsa::HashAlg> = None;
    let mut salt: Option<usize> = None;
    let mut trailer: Option<u64> = None;
    while !sr.end() {
        let field = sr.read()?;
        match field.tag {
            0xa0 => {
                let mut fr = sr.nested(field)?;
                hash = Some(parse_hash_algorithm(&mut fr, "hashAlgorithm")?);
                fr.finish("hashAlgorithm")?;
            }
            0xa1 => {
                let mut fr = sr.nested(field)?;
                mgf = Some(parse_mgf1(&mut fr, "maskGenAlgorithm")?);
                fr.finish("maskGenAlgorithm")?;
            }
            0xa2 => {
                let mut fr = sr.nested(field)?;
                let i = fr.expect(TAG_INTEGER, "saltLength")?;
                fr.finish("saltLength")?;
                let v = parse_uint(i.content, "saltLength")?;
                if v > 64 {
                    return Err(Error::new("x509: RSASSA-PSS saltLength is too large"));
                }
                salt = Some(v as usize);
            }
            0xa3 => {
                let mut fr = sr.nested(field)?;
                let i = fr.expect(TAG_INTEGER, "trailerField")?;
                fr.finish("trailerField")?;
                trailer = Some(parse_uint(i.content, "trailerField")?);
            }
            other => {
                return Err(Error::new(format!(
                    "x509: unexpected field {other:#04x} in RSASSA-PSS parameters"
                )))
            }
        }
    }
    let hash = hash.ok_or_else(|| {
        Error::new("x509: RSASSA-PSS parameters omit hashAlgorithm (SHA-1 default is rejected)")
    })?;
    match mgf {
        Some(m) if m == hash => {}
        Some(_) => {
            return Err(Error::new(
                "x509: RSASSA-PSS mask generation hash differs from the message hash",
            ))
        }
        None => {
            return Err(Error::new(
                "x509: RSASSA-PSS parameters omit maskGenAlgorithm (SHA-1 default is rejected)",
            ))
        }
    }
    if let Some(t) = trailer {
        if t != 1 {
            return Err(Error::new(format!(
                "x509: unsupported RSASSA-PSS trailerField {t}"
            )));
        }
    }
    Ok((hash, salt.unwrap_or(20)))
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_906_502_400; // 2030-06-01T00:00:00Z
    const VALID_FROM: i64 = 1_735_689_600; // 2025-01-01T00:00:00Z
    const VALID_TO: i64 = 2_051_222_400; // 2035-01-01T00:00:00Z

    macro_rules! certs {
        ($name:literal) => {
            parse_pem_certs(include_bytes!(concat!("../tests/data/", $name)))
                .expect("test fixture must parse")
        };
    }

    macro_rules! cert {
        ($name:literal) => {
            certs!($name).remove(0)
        };
    }

    fn real_chain(bytes: &[u8]) -> Vec<Certificate> {
        parse_pem_certs(bytes).expect("chain fixture must parse")
    }

    fn root_store() -> CertStore {
        CertStore::from_certs(vec![cert!("root.pem")])
    }

    fn tlv(tag: u8, content: &'static [u8]) -> Tlv<'static> {
        Tlv {
            tag,
            content,
            full: content,
        }
    }

    fn synthetic_cert(signature_algorithm: &str) -> Certificate {
        Certificate {
            der: Vec::new(),
            tbs_der: Vec::new(),
            serial: vec![1],
            subject_rdn: "CN=synthetic".to_string(),
            issuer_rdn: "CN=issuer".to_string(),
            subject_cn: Some("synthetic".to_string()),
            not_before_unix: 0,
            not_after_unix: i64::MAX,
            spki: Vec::new(),
            spki_algorithm: OID_RSA.to_string(),
            spki_params: Vec::new(),
            spki_curve: None,
            public_key_bits: Vec::new(),
            san_dns: Vec::new(),
            san_ip: Vec::new(),
            san_present: false,
            ca: false,
            path_len: None,
            key_usage: None,
            extended_key_usage: Vec::new(),
            eku_present: false,
            signature_algorithm: signature_algorithm.to_string(),
            signature_params: Vec::new(),
            signature: Vec::new(),
            authority_key_id: None,
            subject_key_id: None,
            unsupported_critical: Vec::new(),
        }
    }

    // ------------------------------------------------------------- DER reader

    #[test]
    fn der_reader_rejects_non_strict_encodings() {
        // Indefinite length (BER only).
        assert!(Reader::new(&[0x30, 0x80, 0x00, 0x00]).read().is_err());
        // Long form for a value that fits in short form.
        assert!(Reader::new(&[0x30, 0x81, 0x05, 0, 0, 0, 0, 0])
            .read()
            .is_err());
        // 4-byte length that overruns any real buffer.
        assert!(Reader::new(&[0x30, 0x84, 0xff, 0xff, 0xff, 0xff])
            .read()
            .is_err());
        // Truncated content.
        assert!(Reader::new(&[0x30, 0x05, 0x02]).read().is_err());
        // High-tag-number form.
        assert!(Reader::new(&[0x1f, 0x81, 0x00]).read().is_err());
        // Truncated tag / length.
        assert!(Reader::new(&[0x30]).read().is_err());
        assert!(Reader::new(&[]).read().is_err());
        // Leading zero in a long-form length.
        assert!(Reader::new(&[0x30, 0x82, 0x00, 0x80, 0, 0, 0])
            .read()
            .is_err());

        let empty = Reader::new(&[0x30, 0x00]).read().unwrap();
        assert_eq!(empty.tag, TAG_SEQUENCE);
        assert!(empty.content.is_empty());
    }

    #[test]
    fn der_reader_enforces_depth_limit() {
        // 22 nested constructed elements, all with valid single-byte lengths.
        let mut buf = vec![0x30u8, 0x00];
        for _ in 0..22 {
            let mut outer = vec![0x30u8, buf.len() as u8];
            outer.extend_from_slice(&buf);
            buf = outer;
        }
        let mut r = Reader::new(&buf);
        let err = skip_element(&mut r, 0).unwrap_err();
        assert!(err.message().contains("nesting"), "{}", err);

        let flat = [0x30u8, 0x00];
        let mut r = Reader::new(&flat);
        skip_element(&mut r, 0).unwrap();
    }

    #[test]
    fn parse_der_rejects_trailing_and_oversized_input() {
        let mut der = cert!("leaf.pem").der;
        der.push(0x00);
        assert!(Certificate::parse_der(&der).is_err());
        assert!(Certificate::parse_der(&[]).is_err());
        assert!(Certificate::parse_der(&vec![0u8; MAX_CERT_DER + 1])
            .unwrap_err()
            .message()
            .contains("too large"));
    }

    // ------------------------------------------------------------------- PEM

    #[test]
    fn pem_certificate_parsing() {
        let mut doc = String::new();
        doc.push_str(core::str::from_utf8(include_bytes!("../tests/data/leaf.pem")).unwrap());
        doc.push_str(
            core::str::from_utf8(include_bytes!("../tests/data/intermediate.pem")).unwrap(),
        );
        let parsed = parse_pem_certs(doc.as_bytes()).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(
            parsed[0].subject_rdn,
            "CN=www.emerag.test, O=emerag test, C=US"
        );
        assert_eq!(
            parsed[1].subject_rdn,
            "CN=emerag Test Intermediate CA, O=emerag test, C=US"
        );

        let not_a_cert = pem::encode("PRIVATE KEY", b"not a certificate");
        assert!(parse_pem_certs(not_a_cert.as_bytes()).is_err());

        let mut der = cert!("leaf.pem").der;
        der.truncate(der.len() / 2);
        let bad = pem::encode("CERTIFICATE", &der);
        let err = parse_pem_certs(bad.as_bytes()).unwrap_err();
        assert!(err.message().contains("pem certificate"), "{}", err);
    }

    // ---------------------------------------------------------- real chains

    #[test]
    fn parse_example_com_chain_fields() {
        let chain = real_chain(include_bytes!("../tests/data/example.com.pem"));
        assert_eq!(chain.len(), 4);
        let leaf = &chain[0];
        assert_eq!(leaf.subject_rdn, "CN=example.com");
        assert_eq!(
            leaf.issuer_rdn,
            "CN=Cloudflare TLS Issuing ECC CA 3, O=SSL Corporation, C=US"
        );
        assert_eq!(leaf.serial_hex(), "01eee6aabb521d5e14fc315fd9985690");
        assert_eq!(leaf.not_before_unix, 1_790_462_951);
        assert!(leaf.not_after_unix > leaf.not_before_unix);
        assert!(!leaf.is_ca());
        assert!(leaf.path_len.is_none());
        assert_eq!(leaf.spki_algorithm, OID_EC);
        assert_eq!(leaf.spki_curve.as_deref(), Some(OID_P256));
        assert_eq!(leaf.signature_algorithm, OID_ECDSA_SHA256);
        assert_eq!(
            leaf.dns_names().to_vec(),
            vec!["example.com".to_string(), "*.example.com".to_string()]
        );
        assert!(leaf.san_present);
        assert!(leaf.eku_present);
        assert_eq!(leaf.extended_key_usage, vec![EKU_SERVER_AUTH.to_string()]);
        assert!(leaf.key_usage.is_some());
        assert!(leaf.authority_key_id.is_some());

        let ca = &chain[1];
        assert!(ca.is_ca());
        assert_eq!(ca.path_len, Some(0));
        assert_eq!(ca.subject_rdn, leaf.issuer_rdn);
        assert!(ca.key_usage_has(KU_KEY_CERT_SIGN));
        assert_eq!(ca.signature_algorithm, OID_ECDSA_SHA384);
        assert_eq!(ca.spki_curve.as_deref(), Some(OID_P256));

        assert!(chain[3].is_ca());
        assert_eq!(
            chain[3].subject_rdn,
            "CN=SSL.com TLS ECC Root CA 2022, O=SSL Corporation, C=US"
        );
    }

    #[test]
    fn parse_all_real_chains() {
        let cases: Vec<(Vec<Certificate>, &str)> = vec![
            (
                real_chain(include_bytes!("../tests/data/example.com.pem")),
                "example.com",
            ),
            (
                real_chain(include_bytes!("../tests/data/api.deepseek.com.pem")),
                "api.deepseek.com",
            ),
            (
                real_chain(include_bytes!("../tests/data/api.anthropic.com.pem")),
                "api.anthropic.com",
            ),
            (
                real_chain(include_bytes!("../tests/data/github.com.pem")),
                "github.com",
            ),
        ];
        for (chain, host) in cases {
            assert!(chain.len() >= 3, "{host}: expected at least 3 certificates");
            let leaf = &chain[0];
            assert!(!leaf.is_ca(), "{host}: leaf must not be a CA");
            assert!(
                leaf.matches_hostname(host),
                "{host}: leaf must match its host"
            );
            assert_eq!(leaf.issuer_rdn, chain[1].subject_rdn, "{host}");
            assert!(chain[1].is_ca(), "{host}: intermediate must be a CA");
            assert!(!leaf.dns_names().is_empty(), "{host}");
            assert!(leaf.not_after_unix > leaf.not_before_unix, "{host}");
            assert!(leaf.der.len() > 100, "{host}");
            assert!(!leaf.tbs_der.is_empty(), "{host}");
            assert!(!leaf.signature.is_empty(), "{host}");
        }
    }

    // ---------------------------------------------------------- local certs

    #[test]
    fn parse_local_leaf_fields() {
        let leaf = cert!("leaf.pem");
        assert_eq!(leaf.subject_rdn, "CN=www.emerag.test, O=emerag test, C=US");
        assert_eq!(leaf.subject_cn.as_deref(), Some("www.emerag.test"));
        assert_eq!(
            leaf.issuer_rdn,
            "CN=emerag Test Intermediate CA, O=emerag test, C=US"
        );
        assert_eq!(leaf.not_before_unix, VALID_FROM);
        assert_eq!(leaf.not_after_unix, VALID_TO);
        assert_eq!(
            leaf.dns_names().to_vec(),
            vec![
                "www.emerag.test".to_string(),
                "emerag.test".to_string(),
                "*.wild.emerag.test".to_string()
            ]
        );
        assert_eq!(leaf.san_ip, vec![vec![127, 0, 0, 1]]);
        assert_eq!(
            leaf.key_usage,
            Some(KU_DIGITAL_SIGNATURE | KU_KEY_ENCIPHERMENT)
        );
        assert_eq!(leaf.extended_key_usage, vec![EKU_SERVER_AUTH.to_string()]);
        assert!(!leaf.is_ca());
        assert_eq!(leaf.signature_algorithm, OID_SHA256_RSA);
        assert_eq!(leaf.spki_algorithm, OID_RSA);
        assert!(leaf.subject_key_id.is_some());
        assert!(leaf.authority_key_id.is_some());
        assert!(leaf.unsupported_critical.is_empty());
        assert!(!leaf.der.is_empty());
        assert!(leaf.tbs_der.len() < leaf.der.len());
        assert!(!leaf.signature.is_empty());
    }

    #[test]
    fn parse_local_ca_fields() {
        let root = cert!("root.pem");
        assert!(root.is_ca());
        assert_eq!(root.path_len, Some(1));
        assert!(root.is_self_issued());
        assert!(root.key_usage_has(KU_KEY_CERT_SIGN));
        assert!(root.key_usage_has(KU_CRL_SIGN));
        assert!(root.subject_key_id.is_some());

        let inter = cert!("intermediate.pem");
        assert!(inter.is_ca());
        assert_eq!(inter.path_len, Some(0));
        assert!(inter.key_usage_has(KU_KEY_CERT_SIGN));
        assert!(inter.authority_key_id.is_some());
        assert_eq!(inter.authority_key_id, root.subject_key_id);
        assert!(!inter.is_self_issued());

        let ec = cert!("ec_intermediate.pem");
        assert!(ec.is_ca());
        assert_eq!(ec.spki_algorithm, OID_EC);
        assert_eq!(ec.spki_curve.as_deref(), Some(OID_P256));

        assert!(cert!("pss.pem").signature_algorithm == OID_RSA_PSS);
        assert!(!cert!("pss.pem").signature_params.is_empty());
        assert_eq!(cert!("sha384.pem").signature_algorithm, OID_SHA384_RSA);
        assert_eq!(cert!("leaf_ec.pem").signature_algorithm, OID_ECDSA_SHA256);
        assert_eq!(cert!("leaf_ec.pem").spki_curve.as_deref(), Some(OID_P256));
    }

    #[test]
    fn parse_time_handles_utc_and_generalized() {
        let utc = tlv(TAG_UTC_TIME, b"240229120000Z");
        assert_eq!(parse_time(&utc, "t").unwrap(), 1_709_208_000);
        let gen = tlv(TAG_GENERALIZED_TIME, b"20500101000000Z");
        assert_eq!(parse_time(&gen, "t").unwrap(), 2_524_608_000);
        // RFC 5280: UTCTime years 50..99 mean 1950..1999.
        let old = tlv(TAG_UTC_TIME, b"500101000000Z");
        assert_eq!(parse_time(&old, "t").unwrap(), -631_152_000);
        // Invalid calendar dates, missing digits, non-Z offsets, wrong widths.
        assert!(parse_time(&tlv(TAG_UTC_TIME, b"240230120000Z"), "t").is_err());
        assert!(parse_time(&tlv(TAG_UTC_TIME, b"24022912000Z"), "t").is_err());
        assert!(parse_time(&tlv(TAG_GENERALIZED_TIME, b"205001010000Z"), "t").is_err());
        assert!(parse_time(&tlv(TAG_UTC_TIME, b"240229120000+"), "t").is_err());
        assert!(parse_time(&tlv(TAG_UTC_TIME, b"24022912000aZ"), "t").is_err());
        // Local certificates use the same conversions.
        assert_eq!(cert!("expired.pem").not_before_unix, 1_577_836_800);
        assert_eq!(cert!("expired.pem").not_after_unix, 1_609_459_200);
    }

    // -------------------------------------------------------------- hostname

    #[test]
    fn hostname_matching_example_com() {
        let chain = real_chain(include_bytes!("../tests/data/example.com.pem"));
        let leaf = &chain[0];
        assert!(leaf.matches_hostname("example.com"));
        assert!(leaf.matches_hostname("EXAMPLE.com."));
        assert!(leaf.matches_hostname("www.example.com"));
        assert!(!leaf.matches_hostname("a.b.example.com"));
        assert!(!leaf.matches_hostname("example.com.evil.test"));
        assert!(!leaf.matches_hostname("notexample.com"));
        assert!(!leaf.matches_hostname(""));
        assert!(!leaf.matches_hostname("example.com:443"));
        assert!(!leaf.matches_hostname("127.0.0.1"));
    }

    #[test]
    fn dns_wildcard_rules() {
        assert!(dns_matches("*.example.com", "www.example.com"));
        assert!(dns_matches("*.example.com", "WWW.EXAMPLE.COM"));
        assert!(!dns_matches("*.example.com", "example.com"));
        assert!(!dns_matches("*.example.com", "a.b.example.com"));
        assert!(!dns_matches("*.example.com", "wwwexample.com"));
        assert!(!dns_matches("www.*.com", "www.a.com"));
        assert!(!dns_matches("*", "a.com"));
        assert!(!dns_matches("*.com", "a.com"));
        assert!(!dns_matches("*.co.uk", "a.co.uk"));
        assert!(!dns_matches("*.github.io", "a.github.io"));
        assert!(dns_matches("*.foo.co.uk", "a.foo.co.uk"));
        assert!(dns_matches("*.a.example.com", "b.a.example.com"));
        assert!(!dns_matches("*.xn--e1afmkfd.test", "a.xn--e1afmkfd.test"));
        assert!(dns_matches("a.example.com", "a.example.com"));
        assert!(dns_matches("a.example.com", "A.EXAMPLE.COM."));
        assert!(!dns_matches("a.example.com", "b.example.com"));
        assert!(!dns_matches("", "a.com"));
        assert!(!dns_matches("a.example.com", ""));
        // U-labels are not matched (no IDNA table in the binary).
        assert!(!dns_matches("\u{e9}.example.com", "x.example.com"));
        assert!(!dns_matches("*.example.com", "\u{e9}.example.com"));
    }

    #[test]
    fn cn_used_only_without_san() {
        let nosan = cert!("nosan.pem");
        assert!(!nosan.san_present);
        assert_eq!(nosan.subject_cn.as_deref(), Some("nosan.emerag.test"));
        assert!(nosan.matches_hostname("nosan.emerag.test"));
        assert!(!nosan.matches_hostname("other.emerag.test"));

        let leaf = cert!("leaf.pem");
        assert!(leaf.san_present);
        assert!(!leaf.matches_hostname("leaf.emerag.test"));
    }

    #[test]
    fn ip_san_matching() {
        let leaf = cert!("leaf.pem");
        assert!(leaf.matches_hostname("127.0.0.1"));
        assert!(!leaf.matches_hostname("127.0.0.2"));
        assert!(!leaf.matches_hostname("::1"));
        assert!(!leaf.matches_hostname("[::1]"));
    }

    #[test]
    fn hostname_negative_real_chain() {
        let chain = real_chain(include_bytes!("../tests/data/github.com.pem"));
        let leaf = &chain[0];
        assert!(leaf.matches_hostname("github.com"));
        assert!(leaf.matches_hostname("www.github.com"));
        assert!(!leaf.matches_hostname("github.com.evil.example"));
        assert!(!leaf.matches_hostname("gist.github.com"));
        assert!(!leaf.matches_hostname("github.io"));
        assert!(leaf.matches_hostname("www.github.com."));
    }

    #[test]
    fn wildcard_over_idn_alabel_is_rejected() {
        let leaf = cert!("wildidn.pem");
        assert_eq!(
            leaf.dns_names().to_vec(),
            vec!["*.xn--e1afmkfd.test".to_string()]
        );
        assert!(!leaf.matches_hostname("www.xn--e1afmkfd.test"));
        assert!(!leaf.matches_hostname("xn--e1afmkfd.test"));
    }

    // -------------------------------------------------------- leaf validity

    #[test]
    fn validity_allows_sixty_seconds_of_skew() {
        let leaf = cert!("leaf.pem");
        leaf.check_validity(0, VALID_FROM as u64 + 30).unwrap();
        assert!(leaf.check_validity(0, (VALID_FROM - 90) as u64).is_err());
        leaf.check_validity(0, VALID_TO as u64 + 30).unwrap();
        let err = leaf.check_validity(0, VALID_TO as u64 + 90).unwrap_err();
        assert!(err.message().contains("expired"), "{}", err);
        assert!(err.message().contains("cert[0]"), "{}", err);
    }

    #[test]
    fn leaf_role_checks() {
        cert!("leaf.pem").check_server_role(0).unwrap();
        cert!("nosan.pem").check_server_role(0).unwrap();

        let err = cert!("badku.pem").check_server_role(0).unwrap_err();
        assert!(err.message().contains("keyUsage"), "{}", err);
        let err = cert!("clienteku.pem").check_server_role(0).unwrap_err();
        assert!(err.message().contains("serverAuth"), "{}", err);
    }

    // ------------------------------------------------- chain failures (no sigs)

    #[test]
    fn chain_rejects_expired_leaf() {
        let chain = vec![cert!("expired.pem"), cert!("intermediate.pem")];
        let err = root_store()
            .verify_chain(&chain, "expired.emerag.test", NOW)
            .unwrap_err();
        assert!(err.message().contains("cert[0]"), "{}", err);
        assert!(err.message().contains("expired"), "{}", err);
    }

    #[test]
    fn chain_rejects_wrong_hostname() {
        let chain = vec![cert!("leaf.pem"), cert!("intermediate.pem")];
        let err = root_store()
            .verify_chain(&chain, "evil.example", NOW)
            .unwrap_err();
        assert!(err.message().contains("cert[0]"), "{}", err);
        assert!(err.message().contains("hostname mismatch"), "{}", err);
    }

    #[test]
    fn chain_rejects_bad_leaf_key_usage_and_eku() {
        let chain = vec![cert!("badku.pem"), cert!("intermediate.pem")];
        let err = root_store()
            .verify_chain(&chain, "badku.emerag.test", NOW)
            .unwrap_err();
        assert!(err.message().contains("keyUsage"), "{}", err);

        let chain = vec![cert!("clienteku.pem"), cert!("intermediate.pem")];
        let err = root_store()
            .verify_chain(&chain, "clienteku.emerag.test", NOW)
            .unwrap_err();
        assert!(err.message().contains("serverAuth"), "{}", err);
    }

    #[test]
    fn chain_rejects_unknown_critical_extension() {
        let chain = vec![cert!("critical.pem"), cert!("intermediate.pem")];
        assert_eq!(chain[0].unsupported_critical, vec!["1.2.3.4".to_string()]);
        let err = root_store()
            .verify_chain(&chain, "critical.emerag.test", NOW)
            .unwrap_err();
        assert!(
            err.message().contains("critical extension 1.2.3.4"),
            "{}",
            err
        );
    }

    #[test]
    fn chain_rejects_non_ca_issuer() {
        let chain = vec![cert!("notca_leaf.pem"), cert!("notca.pem")];
        let err = root_store()
            .verify_chain(&chain, "notca.emerag.test", NOW)
            .unwrap_err();
        assert!(err.message().contains("cert[1]"), "{}", err);
        assert!(err.message().contains("not a CA"), "{}", err);
    }

    #[test]
    fn chain_rejects_untrusted_root() {
        let chain = vec![cert!("orphan.pem")];
        let err = root_store()
            .verify_chain(&chain, "orphan.emerag.test", NOW)
            .unwrap_err();
        assert!(err.message().contains("no trusted root"), "{}", err);
    }

    #[test]
    fn empty_chain_is_an_error() {
        let empty: Vec<Certificate> = Vec::new();
        assert!(root_store().verify_chain(&empty, "x", NOW).is_err());
    }

    #[test]
    fn embedded_roots_parse() {
        let store = CertStore::embedded().expect("embedded roots must parse");
        assert_eq!(store.roots.len(), 118);
        assert!(store.roots.iter().all(|root| !root.subject_rdn.is_empty()));
        assert!(store
            .roots
            .iter()
            .any(|root| root.subject_rdn.contains("DigiCert Global Root G2")));
        assert!(store
            .roots
            .iter()
            .any(|root| root.subject_rdn.contains("ISRG Root X1")));
        assert!(include_bytes!("../assets/roots.pem").len() > 190_000);
    }

    #[test]
    fn unknown_or_weak_signature_algorithms_are_errors() {
        let issuer = synthetic_cert(OID_SHA256_RSA);
        for oid in [
            "1.2.840.113549.1.1.5", // sha1WithRSAEncryption
            "1.2.840.10045.4.1",    // ecdsa-with-SHA1
            "1.3.101.112",          // Ed25519
            "1.2.840.113549.1.1.4", // md5WithRSAEncryption
            "1.2.3.4.5",            // invented
        ] {
            let cert = synthetic_cert(oid);
            let err = cert.verify_signed_by(&issuer).unwrap_err();
            assert!(
                err.message().contains("unsupported signature algorithm"),
                "{oid}: {err}"
            );
        }
    }

    // ------------------------------------------------------------------ fuzz

    #[test]
    fn fuzz_truncation_and_byte_flips_never_panic() {
        let seeds = vec![
            cert!("leaf.pem").der,
            cert!("intermediate.pem").der,
            cert!("pss.pem").der,
            cert!("leaf_ec.pem").der,
            real_chain(include_bytes!("../tests/data/example.com.pem"))[0]
                .der
                .clone(),
        ];
        let mut cases = 0usize;

        // Truncate every seed at every 7th byte.
        for seed in &seeds {
            for cut in (0..seed.len()).step_by(7) {
                let _ = Certificate::parse_der(&seed[..cut]);
                cases += 1;
            }
        }

        // Flip one bit at every 11th byte.
        for seed in &seeds {
            for at in (0..seed.len()).step_by(11) {
                let mut case = seed.clone();
                case[at] ^= 0xa5;
                let _ = Certificate::parse_der(&case);
                cases += 1;
            }
        }

        // 500 pseudo-random mutations (xorshift, no external crates).
        let mut state: u64 = 0x1234_5678_9abc_def0;
        for i in 0..500usize {
            let seed = &seeds[i % seeds.len()];
            let mut case = seed.clone();
            match i % 4 {
                0 => {
                    let cut = (i * 7) % case.len();
                    case.truncate(cut);
                }
                1 => {
                    let at = (i * 13) % case.len();
                    case[at] ^= 0x01 << (i % 8);
                }
                2 => {
                    for _ in 0..8 {
                        state ^= state << 13;
                        state ^= state >> 7;
                        state ^= state << 17;
                        let at = (state >> 33) as usize % case.len();
                        case[at] = (state >> 17) as u8;
                    }
                }
                _ => {
                    let cut = (i * 7) % case.len();
                    case.truncate(cut);
                    case.extend_from_slice(&[0x30, 0x80, 0xff, 0x00]);
                }
            }
            let _ = Certificate::parse_der(&case);
            cases += 1;
        }
        assert!(cases >= 500, "only {cases} fuzz cases ran");
    }

    #[test]
    fn chain_local_rsa_verifies() {
        let chain = vec![cert!("leaf.pem"), cert!("intermediate.pem")];
        root_store()
            .verify_chain(&chain, "www.emerag.test", VALID_FROM as u64 + 3600)
            .unwrap();
    }

    #[test]
    fn chain_local_ecdsa_p256_verifies() {
        let chain = vec![cert!("leaf_ec.pem"), cert!("ec_intermediate.pem")];
        root_store()
            .verify_chain(&chain, "ec.emerag.test", NOW)
            .unwrap();
    }

    #[test]
    fn chain_local_rsa_pss_and_sha384_verify() {
        let chain = vec![cert!("pss.pem"), cert!("intermediate.pem")];
        root_store()
            .verify_chain(&chain, "pss.emerag.test", NOW)
            .unwrap();
        let chain = vec![cert!("sha384.pem"), cert!("intermediate.pem")];
        root_store()
            .verify_chain(&chain, "sha384.emerag.test", NOW)
            .unwrap();
    }

    #[test]
    fn chain_local_skew_boundaries() {
        let chain = vec![cert!("leaf.pem"), cert!("intermediate.pem")];
        root_store()
            .verify_chain(&chain, "www.emerag.test", VALID_TO as u64 + 30)
            .unwrap();
        assert!(root_store()
            .verify_chain(&chain, "www.emerag.test", VALID_TO as u64 + 90)
            .is_err());
    }

    #[test]
    fn chain_accepts_shuffled_intermediates_and_trusted_root_in_chain() {
        let chain = vec![
            cert!("leaf.pem"),
            cert!("root.pem"),
            cert!("intermediate.pem"),
        ];
        root_store()
            .verify_chain(&chain, "www.emerag.test", NOW)
            .unwrap();
    }

    #[test]
    fn chain_pathlen_violation_is_reported() {
        let chain = vec![cert!("plviol.pem"), cert!("subca.pem"), cert!("pl0.pem")];
        let err = root_store()
            .verify_chain(&chain, "plviol.emerag.test", NOW)
            .unwrap_err();
        assert!(err.message().contains("path length"), "{}", err);
        assert!(err.message().contains("cert[2]"), "{}", err);
    }

    #[test]
    fn full_chain_with_caller_supplied_roots() {
        let chain = vec![cert!("leaf.pem"), cert!("intermediate.pem")];
        let store = CertStore::from_pem(include_bytes!("../tests/data/root.pem")).unwrap();
        store.verify_chain(&chain, "www.emerag.test", NOW).unwrap();
    }

    #[test]
    fn real_leaf_signature_verifies_against_intermediate() {
        let cases: Vec<(Vec<Certificate>, &str)> = vec![
            (
                real_chain(include_bytes!("../tests/data/example.com.pem")),
                "example.com",
            ),
            (
                real_chain(include_bytes!("../tests/data/api.deepseek.com.pem")),
                "api.deepseek.com",
            ),
            (
                real_chain(include_bytes!("../tests/data/api.anthropic.com.pem")),
                "api.anthropic.com",
            ),
            (
                real_chain(include_bytes!("../tests/data/github.com.pem")),
                "github.com",
            ),
        ];
        for (chain, host) in cases {
            assert!(
                chain[0].verify_signed_by(&chain[1]).unwrap(),
                "{host}: leaf signature must verify with chain[1]"
            );
        }
    }

    #[test]
    fn full_chain_api_deepseek_verifies_against_embedded_roots() {
        let chain = real_chain(include_bytes!("../tests/data/api.deepseek.com.pem"));
        let now = (chain[0].not_before_unix + 3600) as u64;
        CertStore::embedded()
            .unwrap()
            .verify_chain(&chain, "api.deepseek.com", now)
            .unwrap();
    }

    #[test]
    fn full_chain_example_com_verifies_against_embedded_roots() {
        let chain = real_chain(include_bytes!("../tests/data/example.com.pem"));
        let now = (chain[0].not_before_unix + 3600) as u64;
        CertStore::embedded()
            .unwrap()
            .verify_chain(&chain, "example.com", now)
            .unwrap();
    }

    #[test]
    fn full_chain_github_verifies_against_embedded_roots() {
        let chain = real_chain(include_bytes!("../tests/data/github.com.pem"));
        let now = (chain[0].not_before_unix + 3600) as u64;
        CertStore::embedded()
            .unwrap()
            .verify_chain(&chain, "github.com", now)
            .unwrap();
    }

    #[test]
    fn full_chain_anthropic_verifies_against_embedded_roots() {
        let chain = real_chain(include_bytes!("../tests/data/api.anthropic.com.pem"));
        let now = (chain[0].not_before_unix + 3600) as u64;
        CertStore::embedded()
            .unwrap()
            .verify_chain(&chain, "api.anthropic.com", now)
            .unwrap();
    }

    #[test]
    fn tampered_signature_is_rejected() {
        let inter = cert!("intermediate.pem");

        let mut leaf = cert!("leaf.pem");
        assert!(leaf.verify_signed_by(&inter).unwrap());
        let at = leaf.tbs_der.len() - 40;
        leaf.tbs_der[at] ^= 0x01;
        assert!(!leaf.verify_signed_by(&inter).unwrap());

        let mut leaf2 = cert!("leaf.pem");
        let last = leaf2.signature.len() - 1;
        leaf2.signature[last] ^= 0xff;
        assert!(!leaf2.verify_signed_by(&inter).unwrap());
    }

    #[test]
    fn spki_pin_helpers() {
        let chain = real_chain(include_bytes!("../tests/data/example.com.pem"));
        let leaf = &chain[0];
        let pin = leaf.spki_sha256();
        assert!(leaf.matches_spki_pin(&pin));
        assert!(!leaf.matches_spki_pin(&[0u8; 32]));

        let now = (leaf.not_before_unix + 3600) as u64;
        let store = CertStore::embedded().unwrap();
        store
            .verify_chain_pinned(&chain, "example.com", now, &pin)
            .unwrap();
        assert!(store
            .verify_chain_pinned(&chain, "example.com", now, &[0u8; 32])
            .is_err());
    }
}
