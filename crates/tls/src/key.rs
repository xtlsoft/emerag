//! Hash selection, HKDF/HKDF-Expand-Label and the TLS 1.2 PRF.
//!
//! The TLS 1.3 key schedule and the TLS 1.2 PRF are implemented here so they
//! can be checked against published vectors without touching the network.

use emerag_crypto::hash;

use crate::Error;

/// The two transcript hashes TLS needs (SHA-512 is not used by any suite we
/// offer, and SHA-1 is deliberately unsupported).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HashId {
    Sha256,
    Sha384,
}

impl HashId {
    pub(crate) fn len(self) -> usize {
        match self {
            HashId::Sha256 => 32,
            HashId::Sha384 => 48,
        }
    }

    pub(crate) fn digest(self, data: &[u8]) -> Vec<u8> {
        match self {
            HashId::Sha256 => hash::sha256(data).to_vec(),
            HashId::Sha384 => hash::sha384(data).to_vec(),
        }
    }

    pub(crate) fn hmac(self, key: &[u8], data: &[u8]) -> Vec<u8> {
        match self {
            HashId::Sha256 => hash::hmac_sha256(key, data).to_vec(),
            HashId::Sha384 => hash::hmac_sha384(key, data).to_vec(),
        }
    }

    pub(crate) fn hkdf_extract(self, salt: &[u8], ikm: &[u8]) -> Vec<u8> {
        self.hmac(salt, ikm)
    }

    pub(crate) fn hkdf_expand(
        self,
        prk: &[u8],
        info: &[u8],
        out_len: usize,
    ) -> Result<Vec<u8>, Error> {
        if prk.len() != self.len() {
            return Err(Error::new(format!(
                "tls: handshake: key schedule: PRK length {} does not match hash length {}",
                prk.len(),
                self.len()
            )));
        }
        let mut out = vec![0u8; out_len];
        let r = match self {
            HashId::Sha256 => {
                let mut k = [0u8; 32];
                k.copy_from_slice(prk);
                hash::hkdf_expand_sha256(&k, info, &mut out)
            }
            HashId::Sha384 => hash::hkdf_expand_sha384(prk, info, &mut out),
        };
        r.map_err(|e| Error::new(format!("tls: handshake: key schedule: {e}")))?;
        Ok(out)
    }

    /// HKDF-Expand-Label from RFC 8446 section 7.1.
    pub(crate) fn expand_label(
        self,
        secret: &[u8],
        label: &str,
        context: &[u8],
        out_len: usize,
    ) -> Result<Vec<u8>, Error> {
        if out_len > u16::MAX as usize {
            return Err(Error::new(
                "tls: handshake: key schedule: output length does not fit in u16",
            ));
        }
        if context.len() > 255 {
            return Err(Error::new(
                "tls: handshake: key schedule: HKDF context longer than 255 bytes",
            ));
        }
        let full = format!("tls13 {label}");
        if full.len() > 255 {
            return Err(Error::new(
                "tls: handshake: key schedule: HKDF label longer than 255 bytes",
            ));
        }
        let mut info = Vec::with_capacity(4 + full.len() + context.len());
        info.extend_from_slice(&(out_len as u16).to_be_bytes());
        info.push(full.len() as u8);
        info.extend_from_slice(full.as_bytes());
        info.push(context.len() as u8);
        info.extend_from_slice(context);
        self.hkdf_expand(secret, &info, out_len)
    }

    /// Derive-Secret(secret, label, transcript_hash).
    pub(crate) fn derive_secret(
        self,
        secret: &[u8],
        label: &str,
        transcript_hash: &[u8],
    ) -> Result<Vec<u8>, Error> {
        self.expand_label(secret, label, transcript_hash, self.len())
    }
}

/// TLS 1.2 P_hash (RFC 5246 section 5).
pub(crate) fn p_hash(hash_id: HashId, secret: &[u8], seed: &[u8], out_len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(out_len);
    let mut a = hash_id.hmac(secret, seed);
    while out.len() < out_len {
        let mut input = Vec::with_capacity(a.len() + seed.len());
        input.extend_from_slice(&a);
        input.extend_from_slice(seed);
        let block = hash_id.hmac(secret, &input);
        out.extend_from_slice(&block);
        a = hash_id.hmac(secret, &a);
    }
    out.truncate(out_len);
    out
}

/// TLS 1.2 PRF(secret, label, seed).
pub(crate) fn tls12_prf(
    hash_id: HashId,
    secret: &[u8],
    label: &str,
    seed: &[u8],
    out_len: usize,
) -> Vec<u8> {
    let mut label_seed = Vec::with_capacity(label.len() + seed.len());
    label_seed.extend_from_slice(label.as_bytes());
    label_seed.extend_from_slice(seed);
    p_hash(hash_id, secret, &label_seed, out_len)
}

/// The early secret for a handshake without a PSK: HKDF-Extract(0, 0), where
/// both inputs are Hash.length zero bytes (RFC 8446 section 7.1).
pub(crate) fn tls13_early_secret(hash_id: HashId) -> Vec<u8> {
    let zeros = vec![0u8; hash_id.len()];
    hash_id.hkdf_extract(&zeros, &zeros)
}

/// The handshake secret: HKDF-Extract(Derive-Secret(early, "derived", ""),
/// ECDHE).
pub(crate) fn tls13_handshake_secret(
    hash_id: HashId,
    early_secret: &[u8],
    shared_secret: &[u8],
) -> Result<Vec<u8>, Error> {
    let empty_hash = hash_id.digest(&[]);
    let derived = hash_id.derive_secret(early_secret, "derived", &empty_hash)?;
    Ok(hash_id.hkdf_extract(&derived, shared_secret))
}

/// The master secret: HKDF-Extract(Derive-Secret(handshake, "derived", ""), 0).
pub(crate) fn tls13_master_secret(
    hash_id: HashId,
    handshake_secret: &[u8],
) -> Result<Vec<u8>, Error> {
    let empty_hash = hash_id.digest(&[]);
    let derived = hash_id.derive_secret(handshake_secret, "derived", &empty_hash)?;
    let zeros = vec![0u8; hash_id.len()];
    Ok(hash_id.hkdf_extract(&derived, &zeros))
}

/// Derive a TLS 1.3 traffic key and IV pair.
pub(crate) fn tls13_traffic_key_iv(
    hash_id: HashId,
    secret: &[u8],
    key_len: usize,
) -> Result<(Vec<u8>, [u8; 12]), Error> {
    let key = hash_id.expand_label(secret, "key", &[], key_len)?;
    let iv_vec = hash_id.expand_label(secret, "iv", &[], 12)?;
    let mut iv = [0u8; 12];
    iv.copy_from_slice(&iv_vec);
    Ok((key, iv))
}

/// Derive the TLS 1.3 Finished key from a traffic secret.
pub(crate) fn tls13_finished_key(hash_id: HashId, secret: &[u8]) -> Result<Vec<u8>, Error> {
    hash_id.expand_label(secret, "finished", &[], hash_id.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use emerag_util::hex;

    fn h(s: &str) -> Vec<u8> {
        hex::decode(s).expect("test vector hex")
    }

    // RFC 8448 section 3: ClientHello and ServerHello handshake messages.
    const RFC8448_CLIENT_HELLO: &str = "010000c00303cb34ecb1e78163ba1c38c6dacb196a6dffa21a8d9912ec18a2ef6283024dece7000006130113031302010000910000000b0009000006736572766572ff01000100000a00140012001d0017001800190100010101020103010400230000003300260024001d002099381de560e4bd43d23d8e435a7dbafeb3c06e51c13cae4d5413691e529aaf2c002b0003020304000d0020001e040305030603020308040805080604010501060102010402050206020202002d00020101001c00024001";
    const RFC8448_SERVER_HELLO: &str = "020000560303a6af06a4121860dc5e6e60249cd34c95930c8ac5cb1434dac155772ed3e2692800130100002e00330024001d0020c9828876112095fe66762bdbf7c672e156d6cc253b833df1dd69b1b04e751f0f002b00020304";
    const RFC8448_ENCRYPTED_EXTENSIONS: &str =
        "080000240022000a00140012001d00170018001901000101010201030104001c0002400100000000";
    const RFC8448_CERTIFICATE: &str = "0b0001b9000001b50001b0308201ac30820115a003020102020102300d06092a864886f70d01010b0500300e310c300a06035504031303727361301e170d3136303733303031323335395a170d3236303733303031323335395a300e310c300a0603550403130372736130819f300d06092a864886f70d010101050003818d0030818902818100b4bb498f8279303d980836399b36c6988c0c68de55e1bdb826d3901a2461eafd2de49a91d015abbc9a95137ace6c1af19eaa6af98c7ced43120998e187a80ee0ccb0524b1b018c3e0b63264d449a6d38e22a5fda430846748030530ef0461c8ca9d9efbfae8ea6d1d03e2bd193eff0ab9a8002c47428a6d35a8d88d79f7f1e3f0203010001a31a301830090603551d1304023000300b0603551d0f0404030205a0300d06092a864886f70d01010b05000381810085aad2a0e5b9276b908c65f73a7267170618a54c5f8a7b337d2df7a594365417f2eae8f8a58c8f8172f9319cf36b7fd6c55b80f21a03015156726096fd335e5e67f2dbf102702e608ccae6bec1fc63a42a99be5c3eb7107c3c54e9b9eb2bd5203b1c3b84e0a8b2f759409ba3eac9d91d402dcc0cc8f8961229ac9187b42b4de10000";
    const RFC8448_CERTIFICATE_VERIFY: &str = "0f000084080400805a747c5d88fa9bd2e55ab085a61015b7211f824cd484145ab3ff52f1fda8477b0b7abc90db78e2d33a5c141a078653fa6bef780c5ea248eeaaa785c4f394cab6d30bbe8d4859ee511f602957b15411ac027671459e46445c9ea58c181e818e95b8c3fb0bf3278409d3be152a3da5043e063dda65cdf5aea20d53dfacd42f74f3";

    fn transcript_through_sh() -> Vec<u8> {
        let mut t = h(RFC8448_CLIENT_HELLO);
        t.extend_from_slice(&h(RFC8448_SERVER_HELLO));
        t
    }

    #[test]
    fn rfc8448_transcript_and_handshake_secrets() {
        let t = transcript_through_sh();
        assert_eq!(
            hex::encode(&HashId::Sha256.digest(&t)),
            "860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8"
        );

        let early = tls13_early_secret(HashId::Sha256);
        assert_eq!(
            hex::encode(&early),
            "33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a"
        );

        let shared = h("8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d");
        let hs = tls13_handshake_secret(HashId::Sha256, &early, &shared).unwrap();
        assert_eq!(
            hex::encode(&hs),
            "1dc826e93606aa6fdc0aadc12f741b01046aa6b99f691ed221a9f0ca043fbeac"
        );

        let th = HashId::Sha256.digest(&t);
        let c_hs = HashId::Sha256
            .derive_secret(&hs, "c hs traffic", &th)
            .unwrap();
        let s_hs = HashId::Sha256
            .derive_secret(&hs, "s hs traffic", &th)
            .unwrap();
        assert_eq!(
            hex::encode(&c_hs),
            "b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21"
        );
        assert_eq!(
            hex::encode(&s_hs),
            "b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38"
        );

        let master = tls13_master_secret(HashId::Sha256, &hs).unwrap();
        assert_eq!(
            hex::encode(&master),
            "18df06843d13a08bf2a449844c5f8a478001bc4d4c627984d5a41da8d0402919"
        );

        let (skey, siv) = tls13_traffic_key_iv(HashId::Sha256, &s_hs, 16).unwrap();
        assert_eq!(hex::encode(&skey), "3fce516009c21727d0f2e4e86ee403bc");
        assert_eq!(hex::encode(&siv), "5d313eb2671276ee13000b30");

        let (ckey, civ) = tls13_traffic_key_iv(HashId::Sha256, &c_hs, 16).unwrap();
        assert_eq!(hex::encode(&ckey), "dbfaa693d1762c5b666af5d950258d01");
        assert_eq!(hex::encode(&civ), "5bd3c71b836e0b76bb73265f");
    }

    #[test]
    fn rfc8448_application_secrets_and_finished() {
        let mut t = transcript_through_sh();
        t.extend_from_slice(&h(RFC8448_ENCRYPTED_EXTENSIONS));
        t.extend_from_slice(&h(RFC8448_CERTIFICATE));
        t.extend_from_slice(&h(RFC8448_CERTIFICATE_VERIFY));
        // Transcript through CertificateVerify, used by the server Finished.
        let th_cv = HashId::Sha256.digest(&t);
        let mut t_fin = t.clone();
        t_fin.extend_from_slice(&h(
            "140000209b9b141d906337fbd2cbdce71df4deda4ab42c309572cb7fffee5454b78f0718",
        ));
        let th_server_fin = HashId::Sha256.digest(&t_fin);
        assert_eq!(
            hex::encode(&th_server_fin),
            "9608102a0f1ccc6db6250b7b7e417b1a000eaada3daae4777a7686c9ff83df13"
        );

        let early = tls13_early_secret(HashId::Sha256);
        let shared = h("8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d");
        let hs = tls13_handshake_secret(HashId::Sha256, &early, &shared).unwrap();
        let th = HashId::Sha256.digest(&transcript_through_sh());
        let c_hs = HashId::Sha256
            .derive_secret(&hs, "c hs traffic", &th)
            .unwrap();
        let s_hs = HashId::Sha256
            .derive_secret(&hs, "s hs traffic", &th)
            .unwrap();
        let master = tls13_master_secret(HashId::Sha256, &hs).unwrap();

        let s_fin_key = tls13_finished_key(HashId::Sha256, &s_hs).unwrap();
        assert_eq!(
            hex::encode(&s_fin_key),
            "008d3b66f816ea559f96b537e885c31fc068bf492c652f01f288a1d8cdc19fc8"
        );
        let expected_server = HashId::Sha256.hmac(&s_fin_key, &th_cv);
        assert_eq!(
            hex::encode(&expected_server),
            "9b9b141d906337fbd2cbdce71df4deda4ab42c309572cb7fffee5454b78f0718"
        );

        let c_hs_secret = c_hs;
        let c_fin_key = tls13_finished_key(HashId::Sha256, &c_hs_secret).unwrap();
        assert_eq!(
            hex::encode(&c_fin_key),
            "b80ad01015fb2f0bd65ff7d4da5d6bf83f84821d1f87fdc7d3c75b5a7b42d9c4"
        );
        let expected_client = HashId::Sha256.hmac(&c_fin_key, &th_server_fin);
        assert_eq!(
            hex::encode(&expected_client),
            "a8ec436d677634ae525ac1fcebe11a039ec17694fac6e98527b642f2edd5ce61"
        );

        let c_ap = HashId::Sha256
            .derive_secret(&master, "c ap traffic", &th_server_fin)
            .unwrap();
        let s_ap = HashId::Sha256
            .derive_secret(&master, "s ap traffic", &th_server_fin)
            .unwrap();
        assert_eq!(
            hex::encode(&c_ap),
            "9e40646ce79a7f9dc05af8889bce6552875afa0b06df0087f792ebb7c17504a5"
        );
        assert_eq!(
            hex::encode(&s_ap),
            "a11af9f05531f856ad47116b45a950328204b4f44bfb6b3a4b4f1f3fcb631643"
        );

        let (ck, civ) = tls13_traffic_key_iv(HashId::Sha256, &c_ap, 16).unwrap();
        assert_eq!(hex::encode(&ck), "17422dda596ed5d9acd890e3c63f5051");
        assert_eq!(hex::encode(&civ), "5b78923dee08579033e523d9");
        let (sk, siv) = tls13_traffic_key_iv(HashId::Sha256, &s_ap, 16).unwrap();
        assert_eq!(hex::encode(&sk), "9f02283b6c9c07efc26bb9f2ac92e356");
        assert_eq!(hex::encode(&siv), "cf782b88dd83549aadf1e984");
    }

    #[test]
    fn tls12_prf_known_answer() {
        // Published TLS 1.2 PRF test vector (SHA-256), also reproduced with an
        // independent Python HMAC implementation.
        let secret = h("9bbe436ba940f017b17652849a71db35");
        let seed = h("a0ba9f936cda311827a6f796ffd5198c");
        let out = tls12_prf(HashId::Sha256, &secret, "test label", &seed, 100);
        assert_eq!(
            hex::encode(&out),
            "e3f229ba727be17b8d122620557cd453c2aab21d07c3d495329b52d4e61edb5a6b301791e90d35c9c9a46b4e14baf9af0fa022f7077def17abfd3797c0564bab4fbc91666e9def9b97fce34f796789baa48082d122ee42c5a72e5a5110fff70187347b66"
        );
    }

    #[test]
    fn tls12_prf_sha384_known_answer() {
        // Same secret/seed as the SHA-256 vector above; expected value was
        // produced with Python's independent hmac/hashlib implementation.
        let secret = h("9bbe436ba940f017b17652849a71db35");
        let seed = h("a0ba9f936cda311827a6f796ffd5198c");
        let out = tls12_prf(HashId::Sha384, &secret, "test label", &seed, 100);
        assert_eq!(
            hex::encode(&out),
            "dd88775cd827187b67a3f7652b5c13f715791cc46e0274a6d3fb16651103defc544cd8afb68369a219bb918b8b21ddb1764af0a70339e6dec085e574f655851ba692513203536bdfc3675e53768210f0a2389dd324311a440c7c30ef44b391d914c3b0c7"
        );
    }

    #[test]
    fn hkdf_expand_label_layout() {
        // RFC 8448 "tls13 c hs traffic" info field, byte for byte.
        let secret = h("1dc826e93606aa6fdc0aadc12f741b01046aa6b99f691ed221a9f0ca043fbeac");
        let hash = h("860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8");
        let got = HashId::Sha256
            .expand_label(&secret, "c hs traffic", &hash, 32)
            .unwrap();
        assert_eq!(
            hex::encode(&got),
            "b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21"
        );
    }
}
