//! RSA PKCS#1 v1.5 and PSS verification (RFC 8017).
//!
//! Only verification is implemented; emerag never holds RSA private keys.
//! Public keys are parsed from SubjectPublicKeyInfo or PKCS#1 RSAPublicKey
//! DER. Modular exponentiation uses Montgomery multiplication over
//! little-endian 64-bit limbs, which is compact and portable (u128 multiplies
//! compile to software routines on 32-bit targets, no assembly is used).
//!
//! Digests come from the crate hash module; there is no third-party hash
//! dependency anywhere. HashAlg is defined here because both the RSA and the
//! curve verifiers select a digest algorithm.

use crate::ct::ct_eq;
use crate::hash::{sha256, sha384, sha512};
use crate::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlg {
    Sha256,
    Sha384,
    Sha512,
}

impl HashAlg {
    pub fn digest_len(self) -> usize {
        match self {
            HashAlg::Sha256 => 32,
            HashAlg::Sha384 => 48,
            HashAlg::Sha512 => 64,
        }
    }

    /// ASN.1 DigestInfo prefix for PKCS#1 v1.5.
    pub fn digest_info_prefix(self) -> &'static [u8] {
        match self {
            HashAlg::Sha256 => &[
                0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x01, 0x05, 0x00, 0x04, 0x20,
            ],
            HashAlg::Sha384 => &[
                0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x02, 0x05, 0x00, 0x04, 0x30,
            ],
            HashAlg::Sha512 => &[
                0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x03, 0x05, 0x00, 0x04, 0x40,
            ],
        }
    }

    pub(crate) fn digest(self, data: &[u8]) -> Vec<u8> {
        match self {
            HashAlg::Sha256 => sha256(data).to_vec(),
            HashAlg::Sha384 => sha384(data).to_vec(),
            HashAlg::Sha512 => sha512(data).to_vec(),
        }
    }
}

// ---------------------------------------------------------------------------
// Minimal DER reader
// ---------------------------------------------------------------------------

struct Der<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Der<'a> {
    fn new(data: &'a [u8]) -> Self {
        Der { data, pos: 0 }
    }

    fn done(&self) -> bool {
        self.pos == self.data.len()
    }

    fn read_tlv(&mut self) -> Result<(u8, &'a [u8])> {
        if self.pos >= self.data.len() {
            return Err(Error::new("der: truncated tag"));
        }
        let tag = self.data[self.pos];
        self.pos += 1;
        if tag & 0x1f == 0x1f {
            return Err(Error::new("der: high tag numbers unsupported"));
        }
        if self.pos >= self.data.len() {
            return Err(Error::new("der: truncated length"));
        }
        let first = self.data[self.pos];
        self.pos += 1;
        let len = if first < 0x80 {
            first as usize
        } else if first == 0x80 {
            return Err(Error::new("der: indefinite length"));
        } else {
            let n = (first & 0x7f) as usize;
            if n == 0 || n > 4 {
                return Err(Error::new("der: length too large"));
            }
            if n > self.data.len() - self.pos {
                return Err(Error::new("der: truncated length"));
            }
            let mut v = 0usize;
            for i in 0..n {
                v = (v << 8) | self.data[self.pos + i] as usize;
            }
            self.pos += n;
            v
        };
        if len > self.data.len() - self.pos {
            return Err(Error::new("der: truncated body"));
        }
        let body = &self.data[self.pos..self.pos + len];
        self.pos += len;
        Ok((tag, body))
    }
}

/// Strip the sign padding of a DER INTEGER and return its magnitude.
/// Negative and zero values are rejected.
fn der_uint(body: &[u8]) -> Result<&[u8]> {
    if body.is_empty() {
        return Err(Error::new("der: empty integer"));
    }
    if body[0] & 0x80 != 0 {
        return Err(Error::new("der: negative integer"));
    }
    let mut i = 0;
    while i < body.len() && body[i] == 0 {
        i += 1;
    }
    let mag = &body[i..];
    if mag.is_empty() {
        return Err(Error::new("der: zero integer"));
    }
    Ok(mag)
}

// ---------------------------------------------------------------------------
// Big integers (little-endian u64 limbs)
// ---------------------------------------------------------------------------

use core::cmp::Ordering;

fn trim(v: &mut Vec<u64>) {
    while let Some(&0) = v.last() {
        v.pop();
    }
}

fn cmp_limbs(a: &[u64], b: &[u64]) -> Ordering {
    if a.len() != b.len() {
        return a.len().cmp(&b.len());
    }
    for i in (0..a.len()).rev() {
        if a[i] != b[i] {
            return a[i].cmp(&b[i]);
        }
    }
    Ordering::Equal
}

fn bit_len(v: &[u64]) -> usize {
    for i in (0..v.len()).rev() {
        if v[i] != 0 {
            return i * 64 + (64 - v[i].leading_zeros() as usize);
        }
    }
    0
}

fn from_be_bytes(bytes: &[u8]) -> Vec<u64> {
    let mut v = vec![0u64; (bytes.len() + 7) / 8];
    for (i, &b) in bytes.iter().rev().enumerate() {
        v[i / 8] |= (b as u64) << ((i % 8) * 8);
    }
    trim(&mut v);
    v
}

fn to_be_fixed(limbs: &[u64], len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len];
    let mut idx = len;
    for &limb in limbs {
        let bytes = limb.to_be_bytes();
        for j in (0..8).rev() {
            if idx == 0 {
                return out;
            }
            idx -= 1;
            out[idx] = bytes[j];
        }
    }
    out
}

/// a -= b, assuming a is at least b. The left side may be longer.
fn sub_in_place(a: &mut [u64], b: &[u64]) {
    let mut borrow = 0u64;
    for i in 0..a.len() {
        let bi = if i < b.len() { b[i] } else { 0 };
        let (x, b1) = a[i].overflowing_sub(bi);
        let (y, b2) = x.overflowing_sub(borrow);
        a[i] = y;
        borrow = (b1 | b2) as u64;
    }
}

/// r = r * 2 mod m, in place. Requires r < m.
fn mod_double_in_place(r: &mut [u64], m: &[u64]) {
    let mut carry = 0u64;
    for x in r.iter_mut() {
        let v = *x;
        *x = (v << 1) | carry;
        carry = v >> 63;
    }
    if carry != 0 || cmp_limbs(r, m) != Ordering::Less {
        sub_in_place(r, m);
    }
}

fn mont_n0(n0: u64) -> u64 {
    // Newton iteration: doubles the number of correct bits per round.
    let mut inv = 1u64;
    for _ in 0..6 {
        inv = inv.wrapping_mul(2u64.wrapping_sub(n0.wrapping_mul(inv)));
    }
    inv.wrapping_neg()
}

#[derive(Clone)]
struct Modulus {
    n: Vec<u64>,
    n0: u64,
    r2: Vec<u64>,
    k: usize,
}

impl Modulus {
    fn new(n: Vec<u64>) -> Self {
        let k = n.len();
        let n0 = mont_n0(n[0]);
        // R = 2^(64k) mod n by repeated doubling, then R^2 mod n likewise.
        let mut r = vec![0u64; k];
        r[0] = 1;
        let doublings = 128 * k;
        for _ in 0..doublings {
            mod_double_in_place(&mut r, &n);
        }
        Modulus { n, n0, r2: r, k }
    }

    fn mont_mul(&self, a: &[u64], b: &[u64]) -> Vec<u64> {
        let k = self.k;
        let mut t = vec![0u64; 2 * k + 2];
        for i in 0..k {
            let ai = if i < a.len() { a[i] } else { 0 };
            let mut carry: u128 = 0;
            for j in 0..k {
                let bj = if j < b.len() { b[j] } else { 0 };
                let uv = t[i + j] as u128 + (ai as u128) * (bj as u128) + carry;
                t[i + j] = uv as u64;
                carry = uv >> 64;
            }
            let mut idx = i + k;
            while carry != 0 {
                let uv = t[idx] as u128 + carry;
                t[idx] = uv as u64;
                carry = uv >> 64;
                idx += 1;
            }
        }
        for i in 0..k {
            let u = t[i].wrapping_mul(self.n0);
            let mut carry: u128 = 0;
            for j in 0..k {
                let uv = t[i + j] as u128 + (u as u128) * (self.n[j] as u128) + carry;
                t[i + j] = uv as u64;
                carry = uv >> 64;
            }
            let mut idx = i + k;
            while carry != 0 {
                let uv = t[idx] as u128 + carry;
                t[idx] = uv as u64;
                carry = uv >> 64;
                idx += 1;
            }
        }
        let mut r = t[k..2 * k].to_vec();
        if t[2 * k] != 0 || t[2 * k + 1] != 0 || cmp_limbs(&r, &self.n) != Ordering::Less {
            sub_in_place(&mut r, &self.n);
        }
        r
    }

    fn to_mont(&self, x: &[u64]) -> Vec<u64> {
        let mut v = x.to_vec();
        v.resize(self.k, 0);
        self.mont_mul(&v, &self.r2)
    }

    fn from_mont(&self, x: &[u64]) -> Vec<u64> {
        let mut one = vec![0u64; self.k];
        one[0] = 1;
        self.mont_mul(x, &one)
    }

    /// base^exp mod n. The exponent is public (RSA e), so no blinding.
    fn mod_exp(&self, base: &[u64], exp: &[u64]) -> Vec<u64> {
        let mut acc = self.to_mont(&[1u64]);
        let base_m = self.to_mont(base);
        let bits = bit_len(exp);
        for i in (0..bits).rev() {
            acc = self.mont_mul(&acc, &acc);
            if (exp[i / 64] >> (i % 64)) & 1 == 1 {
                acc = self.mont_mul(&acc, &base_m);
            }
        }
        self.from_mont(&acc)
    }
}

// ---------------------------------------------------------------------------
// RSA public key
// ---------------------------------------------------------------------------

const RSA_OID: [u8; 9] = [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];

#[derive(Clone)]
pub struct RsaPublicKey {
    modulus: Modulus,
    e: Vec<u64>,
    bits: usize,
}

impl RsaPublicKey {
    /// Parse a SubjectPublicKeyInfo (RFC 5280) RSA key.
    pub fn from_der_spki(der: &[u8]) -> Result<Self> {
        let mut outer = Der::new(der);
        let (tag, body) = outer.read_tlv()?;
        if tag != 0x30 || !outer.done() {
            return Err(Error::new("rsa: SPKI is not a single SEQUENCE"));
        }
        let mut seq = Der::new(body);
        let (tag, alg_body) = seq.read_tlv()?;
        if tag != 0x30 {
            return Err(Error::new("rsa: SPKI missing AlgorithmIdentifier"));
        }
        let (tag, bits) = seq.read_tlv()?;
        if tag != 0x03 || !seq.done() {
            return Err(Error::new("rsa: SPKI missing subjectPublicKey"));
        }
        let mut alg = Der::new(alg_body);
        let (tag, oid) = alg.read_tlv()?;
        if tag != 0x06 || oid != RSA_OID {
            return Err(Error::new("rsa: not an rsaEncryption key"));
        }
        if !alg.done() {
            let (tag, params) = alg.read_tlv()?;
            if tag != 0x05 || !params.is_empty() || !alg.done() {
                return Err(Error::new("rsa: unexpected algorithm parameters"));
            }
        }
        if bits.is_empty() || bits[0] != 0 {
            return Err(Error::new("rsa: invalid subjectPublicKey BIT STRING"));
        }
        Self::from_pkcs1_der(&bits[1..])
    }

    /// Parse a PKCS#1 RSAPublicKey.
    pub fn from_pkcs1_der(der: &[u8]) -> Result<Self> {
        let mut outer = Der::new(der);
        let (tag, body) = outer.read_tlv()?;
        if tag != 0x30 || !outer.done() {
            return Err(Error::new("rsa: RSAPublicKey is not a single SEQUENCE"));
        }
        let mut seq = Der::new(body);
        let (tag, n_body) = seq.read_tlv()?;
        if tag != 0x02 {
            return Err(Error::new("rsa: RSAPublicKey missing modulus"));
        }
        let (tag, e_body) = seq.read_tlv()?;
        if tag != 0x02 || !seq.done() {
            return Err(Error::new("rsa: RSAPublicKey missing exponent"));
        }
        let n = from_be_bytes(der_uint(n_body)?);
        let e = from_be_bytes(der_uint(e_body)?);
        Self::from_parts(n, e)
    }

    fn from_parts(n: Vec<u64>, e: Vec<u64>) -> Result<Self> {
        let bits = bit_len(&n);
        if bits < 1024 {
            return Err(Error::new("rsa: modulus shorter than 1024 bits"));
        }
        if n.is_empty() || n[0] & 1 == 0 {
            return Err(Error::new("rsa: modulus must be odd"));
        }
        if e.is_empty() || e[0] & 1 == 0 {
            return Err(Error::new("rsa: public exponent must be odd"));
        }
        if (e.len() == 1 && e[0] < 3) || cmp_limbs(&e, &n) != Ordering::Less {
            return Err(Error::new("rsa: public exponent out of range"));
        }
        let modulus = Modulus::new(n);
        Ok(RsaPublicKey { modulus, e, bits })
    }

    pub fn bits(&self) -> usize {
        self.bits
    }

    fn modulus_bytes(&self) -> usize {
        (self.bits + 7) / 8
    }

    /// s^e mod n as a fixed-width EM string, or None when s is out of range.
    fn public_op(&self, signature: &[u8]) -> Option<Vec<u8>> {
        let k = self.modulus_bytes();
        if signature.len() != k {
            return None;
        }
        let s = from_be_bytes(signature);
        if cmp_limbs(&s, &self.modulus.n) != Ordering::Less {
            return None;
        }
        let m = self.modulus.mod_exp(&s, &self.e);
        Some(to_be_fixed(&m, k))
    }

    pub fn verify_pkcs1v15(&self, alg: HashAlg, message: &[u8], signature: &[u8]) -> Result<bool> {
        let k = self.modulus_bytes();
        if signature.len() != k {
            return Ok(false);
        }
        let prefix = alg.digest_info_prefix();
        let t_len = prefix.len() + alg.digest_len();
        if k < t_len + 11 {
            return Ok(false);
        }
        let em = match self.public_op(signature) {
            Some(v) => v,
            None => return Ok(false),
        };
        let mut expected = vec![0u8; k];
        expected[1] = 0x01;
        let ps_len = k - t_len - 3;
        for b in expected[2..2 + ps_len].iter_mut() {
            *b = 0xff;
        }
        expected[2 + ps_len] = 0x00;
        let t = &mut expected[3 + ps_len..];
        t[..prefix.len()].copy_from_slice(prefix);
        t[prefix.len()..].copy_from_slice(&alg.digest(message));
        Ok(ct_eq(&em, &expected))
    }

    pub fn verify_pss(
        &self,
        alg: HashAlg,
        message: &[u8],
        signature: &[u8],
        salt_len: usize,
    ) -> Result<bool> {
        let h_len = alg.digest_len();
        let mod_bits = self.bits;
        let k = self.modulus_bytes();
        if signature.len() != k {
            return Ok(false);
        }
        let em_bits = mod_bits - 1;
        let em_len = (em_bits + 7) / 8;
        if em_len > k {
            return Ok(false);
        }
        if em_len < h_len + salt_len + 2 {
            return Ok(false);
        }
        let full = match self.public_op(signature) {
            Some(v) => v,
            None => return Ok(false),
        };
        if full[..k - em_len].iter().any(|&b| b != 0) {
            return Ok(false);
        }
        let em = &full[k - em_len..];
        if em[em_len - 1] != 0xbc {
            return Ok(false);
        }
        let split = em_len - h_len - 1;
        let masked_db = &em[..split];
        let h = &em[split..split + h_len];
        let unused = 8 * em_len - em_bits;
        if unused > 0 && em[0] & (0xffu8 << (8 - unused)) != 0 {
            return Ok(false);
        }
        let db_len = split;
        let mut db = vec![0u8; db_len];
        mgf1(alg, h, &mut db);
        for (i, b) in db.iter_mut().enumerate() {
            *b ^= masked_db[i];
        }
        if unused > 0 {
            db[0] &= 0xffu8 >> unused;
        }
        let ps_len = db_len - salt_len - 1;
        let mut bad = 0u8;
        for &b in &db[..ps_len] {
            bad |= b;
        }
        bad |= db[ps_len] ^ 0x01;
        if bad != 0 {
            return Ok(false);
        }
        let salt = &db[ps_len + 1..];
        let m_hash = alg.digest(message);
        let mut m_prime = Vec::with_capacity(8 + h_len + salt_len);
        m_prime.extend_from_slice(&[0u8; 8]);
        m_prime.extend_from_slice(&m_hash);
        m_prime.extend_from_slice(salt);
        Ok(ct_eq(h, &alg.digest(&m_prime)))
    }
}

fn mgf1(alg: HashAlg, seed: &[u8], out: &mut [u8]) {
    let h_len = alg.digest_len();
    let mut counter: u32 = 0;
    let mut pos = 0;
    let mut buf = Vec::with_capacity(seed.len() + 4);
    while pos < out.len() {
        buf.clear();
        buf.extend_from_slice(seed);
        buf.extend_from_slice(&counter.to_be_bytes());
        let digest = alg.digest(&buf);
        let n = core::cmp::min(h_len, out.len() - pos);
        out[pos..pos + n].copy_from_slice(&digest[..n]);
        pos += n;
        counter = counter.wrapping_add(1);
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn hex_eq(bytes: &[u8], expected: &str) -> bool {
        emerag_util::hex::encode(bytes) == expected
    }

    #[test]
    fn sha2_published_vectors() {
        // FIPS 180-4 / RFC 6234 vectors.
        assert!(hex_eq(
            &sha256(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        ));
        assert!(hex_eq(
            &sha256(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        ));
        assert!(hex_eq(
            &sha256(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        ));
        assert!(hex_eq(
            &sha256(&vec![b'a'; 1_000_000]),
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
        ));
        assert!(hex_eq(
            &sha384(b"abc"),
            "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"
        ));
        assert!(hex_eq(
            &sha384(b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"),
            "09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712fcc7c71a557e2db966c3e9fa91746039"
        ));
        assert!(hex_eq(
            &sha512(b"abc"),
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
        ));
        assert!(hex_eq(
            &sha512(b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"),
            "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909"
        ));
    }

    #[test]
    fn hash_algorithm_plumbing() {
        assert_eq!(HashAlg::Sha256.digest_len(), 32);
        assert_eq!(HashAlg::Sha384.digest_len(), 48);
        assert_eq!(HashAlg::Sha512.digest_len(), 64);
        assert_eq!(HashAlg::Sha256.digest(b"abc"), sha256(b"abc").to_vec());
        assert_eq!(HashAlg::Sha384.digest(b"abc"), sha384(b"abc").to_vec());
        assert_eq!(HashAlg::Sha512.digest(b"abc"), sha512(b"abc").to_vec());
        // DigestInfo prefixes must end with an OCTET STRING of the right size.
        for alg in [HashAlg::Sha256, HashAlg::Sha384, HashAlg::Sha512] {
            let p = alg.digest_info_prefix();
            assert_eq!(p[p.len() - 2], 0x04);
            assert_eq!(p[p.len() - 1] as usize, alg.digest_len());
        }
    }
}

#[cfg(test)]
mod vectors {
    use super::*;
    use emerag_util::hex::decode;

    pub(super) fn alg(a: u8) -> HashAlg {
        match a {
            0 => HashAlg::Sha256,
            1 => HashAlg::Sha384,
            _ => HashAlg::Sha512,
        }
    }

    // (name, spki_der_hex, hash_alg, mode (0=pkcs1, 1=pss), salt_len, message_hex, signature_hex)
    pub(super) const RSA_CASES: &[(&str, &str, u8, u8, usize, &str, &str)] = &[
        ("pkcs1-sha256-2048", "30820122300d06092a864886f70d01010105000382010f003082010a0282010100c8328fc013fdbe27db6a81406bf5174e07c0c451f190fec003b169290432aedff70f78ba7c64eebc6b0fd0611f88e140042a282428d3d0a44b4f8714c8c6517c64886bcb42bf88853f638e89624c6519a402b9bd16f2945ed3b79d5907b438e688d245b04ae030188057a6d21c6d9e151beeb88f6a499b4d147b7823d203c36d0df27a4cd7479b63b03f7d0bb1f8b1c47023b73e48722ee5c2f37c24aace8072aa3e6f47b57ec54e352acef74b8f1b6f2b608ad50c1baa58d809177e4fcae09f6e075a8157357e6129869c4808f22389961c72633c98d60d0ccadd9a3024abfbabff088dfd727f9e39fe1cd2ea5ad3ee16ebac4e182389beb23a9ed3eec09ef30203010001", 0, 0, 0, "656d657261672072736120706b63733120736861323536207465737420766563746f72207631", "ac73b414c1a898d75fd9b97b0731697a63a336a95ee9c2ec65d8e7db7e5e32482985e55d01ff577c52b474d046a79c9f9fb41f19701886294a6a6ab9311822092148a14e8c1bc4ffca7353f73601bd944209010e5f4f32db2accd8be7e3fa90f84b55a69a4d6b69ecda146c7d01c399f03a3cdc8d57a74b9be9e01a25b8a7e8ee33c8b2fc4a0e43df31938bff566bb1986149da19bfc1feac139cdb559232dfe96b8cfe2a34e66a71a53b3167443b7506eea41faa739445d93b2fe2cc5bd47db29c28e7ab6920014666de3c54ffda0f38fc751fa4d0e032974988f0ac310befddf98334f9a5ff134da409ac88e027383f36bb74141f4bf883f07eb68c36b3ded"),
        ("pss-sha256-32-2048", "30820122300d06092a864886f70d01010105000382010f003082010a0282010100c8328fc013fdbe27db6a81406bf5174e07c0c451f190fec003b169290432aedff70f78ba7c64eebc6b0fd0611f88e140042a282428d3d0a44b4f8714c8c6517c64886bcb42bf88853f638e89624c6519a402b9bd16f2945ed3b79d5907b438e688d245b04ae030188057a6d21c6d9e151beeb88f6a499b4d147b7823d203c36d0df27a4cd7479b63b03f7d0bb1f8b1c47023b73e48722ee5c2f37c24aace8072aa3e6f47b57ec54e352acef74b8f1b6f2b608ad50c1baa58d809177e4fcae09f6e075a8157357e6129869c4808f22389961c72633c98d60d0ccadd9a3024abfbabff088dfd727f9e39fe1cd2ea5ad3ee16ebac4e182389beb23a9ed3eec09ef30203010001", 0, 1, 32, "656d6572616720707373207368613235362073616c743332207465737420766563746f72207631", "17aba7aa4254b09107fa50acefedf70aeedff0e61c6fce2b3e2dffcec694d97775ed9c4e52a9bbd17009633c29656fcfc336405e8de647e9bad7198023fcb0f4565ef7f04ad7757c7e77b65453b1046fd0ca556b0ec91eb5685bacc0ba7a29aeccf12c5f5b3fbf55929a9f3c73129480398ade5c814e6f1d31d23694d6d51de92b03c3ae540f0268c4f03a7f884efc6279e6a1e053861e4b3ddca8c504ec8f655ea8ca3c1fe3c5afefddead3aa8ad1b69a2e36bce9071045a777fbe0a74e5fbc3a2d1cf2d7f461190f78a20d08851ed05e118ac8ae64abb5cba769e4df4b86307788bbdfe5a0ad3c8fbb8605362eb4952b83c7837652dae2830717d0b37e5b42"),
        ("pkcs1-sha384-2048", "30820122300d06092a864886f70d01010105000382010f003082010a0282010100c8328fc013fdbe27db6a81406bf5174e07c0c451f190fec003b169290432aedff70f78ba7c64eebc6b0fd0611f88e140042a282428d3d0a44b4f8714c8c6517c64886bcb42bf88853f638e89624c6519a402b9bd16f2945ed3b79d5907b438e688d245b04ae030188057a6d21c6d9e151beeb88f6a499b4d147b7823d203c36d0df27a4cd7479b63b03f7d0bb1f8b1c47023b73e48722ee5c2f37c24aace8072aa3e6f47b57ec54e352acef74b8f1b6f2b608ad50c1baa58d809177e4fcae09f6e075a8157357e6129869c4808f22389961c72633c98d60d0ccadd9a3024abfbabff088dfd727f9e39fe1cd2ea5ad3ee16ebac4e182389beb23a9ed3eec09ef30203010001", 1, 0, 0, "656d6572616720706b63733120736861333834", "4023ee7a54a87bbb7c4db4ab12d7c334366d4700577cc436f090937c67a6cbc2fed6e54bb16960672eb9e7d10367ad0da4f82e6432b4cb2b93067f2113887d74013a462464bc149cc9fcfbddaeab6f6f356ac6bed9d4f5023426d190c1f156a695c4d7a2fcd0b948813757c6fceca53dd520b87212e3797de09befc4360e24417c8cb6e0d9dbdfc5b570f47226d45a7ac2a72ac3f1d104679c159d09f71221a8a484253c6cfa34bd4c7b1aa600366a2785d3f84ba8423e06c08c748c0321bbdfea467d24d099883df935ce36cf6d6f639f29f7a5a149fbf3dc297ab1c339c1bde9016a0a3109f829f59623ec4acccf9fb6685f44638585e60d4cdbf87f024530"),
        ("pss-sha384-48-2048", "30820122300d06092a864886f70d01010105000382010f003082010a0282010100c8328fc013fdbe27db6a81406bf5174e07c0c451f190fec003b169290432aedff70f78ba7c64eebc6b0fd0611f88e140042a282428d3d0a44b4f8714c8c6517c64886bcb42bf88853f638e89624c6519a402b9bd16f2945ed3b79d5907b438e688d245b04ae030188057a6d21c6d9e151beeb88f6a499b4d147b7823d203c36d0df27a4cd7479b63b03f7d0bb1f8b1c47023b73e48722ee5c2f37c24aace8072aa3e6f47b57ec54e352acef74b8f1b6f2b608ad50c1baa58d809177e4fcae09f6e075a8157357e6129869c4808f22389961c72633c98d60d0ccadd9a3024abfbabff088dfd727f9e39fe1cd2ea5ad3ee16ebac4e182389beb23a9ed3eec09ef30203010001", 1, 1, 48, "656d6572616720707373207368613338342073616c743438", "b68ea8ad1180fc501d46bcf67394e5dab6c54c2f16d121d21e2457f90509b9aa2e4ccf815ed51979121c810a60697418130fc13e6c1400a488b1d1a1791f2ac6d6137a67fb6f34234ed4694612358e5fbb222db959026ffb1d5e76b2125636afb7e1f2d11db7210e574eea432c8a85dec51babf4d4009dee28644faea2c0f54ffab2f856b7357b23fa8124619124d4feff42a9155264d818759c03881614a40d575e353fb50f422c7fa9a9cb311bc011364a0255964dd35db5213f2795ce3aa38049b807d9e36b7d0b0ab4968de4674a6cb086785383e3dc2a1b8eb4ab5e029d4cc3a4069637a1f282f26ec5c7eab97bfbb3baaa50ac7c0f82dc3a5e13bbcb8a"),
        ("pss-sha384-32-2048", "30820122300d06092a864886f70d01010105000382010f003082010a0282010100c8328fc013fdbe27db6a81406bf5174e07c0c451f190fec003b169290432aedff70f78ba7c64eebc6b0fd0611f88e140042a282428d3d0a44b4f8714c8c6517c64886bcb42bf88853f638e89624c6519a402b9bd16f2945ed3b79d5907b438e688d245b04ae030188057a6d21c6d9e151beeb88f6a499b4d147b7823d203c36d0df27a4cd7479b63b03f7d0bb1f8b1c47023b73e48722ee5c2f37c24aace8072aa3e6f47b57ec54e352acef74b8f1b6f2b608ad50c1baa58d809177e4fcae09f6e075a8157357e6129869c4808f22389961c72633c98d60d0ccadd9a3024abfbabff088dfd727f9e39fe1cd2ea5ad3ee16ebac4e182389beb23a9ed3eec09ef30203010001", 1, 1, 32, "656d6572616720707373207368613338342073616c743332", "af759a6f6a86a774a3d03e1c7b5d6b4b95073c21c914fafa34b986538001fbe68780bc28cbc9dbde707a5130cb2097d26fb0cb70198486f6fa450e6d1d807696fc0ea1d197f528f0d948a22727af743f1f65fdf16e696ea09b23aeb1a2cb60d4891339ff1d63c9fd9fcc64412ee150de20d4bf6e28cc63c9cab578199aba495535ae11d79b3b746dcdc53d20a48ab963900821824413d4edafa55949efe3e77ffcb71d53323f44ffbc9ce4d0fc194642be1fb2ce9cc7f73390e4508a09ad1dd070573a588030a416431e05ae2cbf4c953fb6e6b4503a18c91eb61d1db1338a56f90275c62b3dd8b754ff30c01b02c67f32b102e3115e8236aea2cd6ef5925803"),
        ("pkcs1-sha512-2048", "30820122300d06092a864886f70d01010105000382010f003082010a0282010100c8328fc013fdbe27db6a81406bf5174e07c0c451f190fec003b169290432aedff70f78ba7c64eebc6b0fd0611f88e140042a282428d3d0a44b4f8714c8c6517c64886bcb42bf88853f638e89624c6519a402b9bd16f2945ed3b79d5907b438e688d245b04ae030188057a6d21c6d9e151beeb88f6a499b4d147b7823d203c36d0df27a4cd7479b63b03f7d0bb1f8b1c47023b73e48722ee5c2f37c24aace8072aa3e6f47b57ec54e352acef74b8f1b6f2b608ad50c1baa58d809177e4fcae09f6e075a8157357e6129869c4808f22389961c72633c98d60d0ccadd9a3024abfbabff088dfd727f9e39fe1cd2ea5ad3ee16ebac4e182389beb23a9ed3eec09ef30203010001", 2, 0, 0, "656d6572616720706b63733120736861353132", "508153bbd3498a805721e1facb41232e6c56dd0e76030797cee41e60c48a9a4e6e2d136ede0dfaefc0ef486a738c6715e07ac9fa2854e4855af0a1a3ec2f847f4df1c0f2e858f527e42a9699d9ab464daefd621d4923d4b4047051d3cebd396809428472b5418e791e41aeab0b85d53dfe730815ef5418ea8bd6359cf7d4f05d08fca1081d19fc3efd588b2290bbd1ac2d9984df41a40de2475e1c2d9c752d8e434d53280777563bdbc64c12c447335eaaa51bb5c2bfa691df4359ac1cfdabc0e81f3d79b22faceb13b3f53c6182297f35957ef8ed97879100f3d47c2da430e6ad4db0559e2be9c5ac0e0aac6601117f9a436905a38f13f316cdd160985bb8c4"),
        ("pss-sha512-64-2048", "30820122300d06092a864886f70d01010105000382010f003082010a0282010100c8328fc013fdbe27db6a81406bf5174e07c0c451f190fec003b169290432aedff70f78ba7c64eebc6b0fd0611f88e140042a282428d3d0a44b4f8714c8c6517c64886bcb42bf88853f638e89624c6519a402b9bd16f2945ed3b79d5907b438e688d245b04ae030188057a6d21c6d9e151beeb88f6a499b4d147b7823d203c36d0df27a4cd7479b63b03f7d0bb1f8b1c47023b73e48722ee5c2f37c24aace8072aa3e6f47b57ec54e352acef74b8f1b6f2b608ad50c1baa58d809177e4fcae09f6e075a8157357e6129869c4808f22389961c72633c98d60d0ccadd9a3024abfbabff088dfd727f9e39fe1cd2ea5ad3ee16ebac4e182389beb23a9ed3eec09ef30203010001", 2, 1, 64, "656d6572616720707373207368613531322073616c743634", "7c89d4123eef57321dade34d2821bf2cb10cc62fe6ff8c7ad1807293658e8643a8c0bc5bb5a4b4fe41ab3b2ffd4720dd2e7a272942f3454c414e7517979ef91be43ee99f99c59bebffdfaca9531e338c5035ae44256913180271a0cf0b236189ac76f90dc4a6e389f368f5123aca226aa8cf7c3b031990c1faa13c0abcfaa05affe7049a7c7a5b8073ff21c9fb1574a5b0e53ea13be30720dbdafe33499189daf0b3d0eb373dbbcab95da5f52e44a3bb4813dcd808231d7bd921dac584e8fe3b53617b54fcf179cb9e2e8c81acf936fded6a8ca4e8d19e4966915d6cd353ecf2f6487c0f61503c12cbda1ba84293e34dd20dc8b0479604a308c52592d9f0450a"),
        ("pss-sha512-32-2048", "30820122300d06092a864886f70d01010105000382010f003082010a0282010100c8328fc013fdbe27db6a81406bf5174e07c0c451f190fec003b169290432aedff70f78ba7c64eebc6b0fd0611f88e140042a282428d3d0a44b4f8714c8c6517c64886bcb42bf88853f638e89624c6519a402b9bd16f2945ed3b79d5907b438e688d245b04ae030188057a6d21c6d9e151beeb88f6a499b4d147b7823d203c36d0df27a4cd7479b63b03f7d0bb1f8b1c47023b73e48722ee5c2f37c24aace8072aa3e6f47b57ec54e352acef74b8f1b6f2b608ad50c1baa58d809177e4fcae09f6e075a8157357e6129869c4808f22389961c72633c98d60d0ccadd9a3024abfbabff088dfd727f9e39fe1cd2ea5ad3ee16ebac4e182389beb23a9ed3eec09ef30203010001", 2, 1, 32, "656d6572616720707373207368613531322073616c743332", "62f3e504883f4ed0c149232900637cceb4d08f7592869e239f07252aaa544f6730aea1f25fdf0b286b76b9403b6e10c56e848dd8c0990292d1339a8c376ec59362d3fe569619b5acaa0c02d87f613529644faec6de264a9c85ff75aca6cb64dbcbbb82678d02e3fa2a456f5baba342c91c6da413572d89bf44cbc122584fe2cb4e1485604fc394dc0a719dce224e2ede6f86de2f2309532f7dc9ba43c932aa2c262e1f1e8d870b3f8ce7c4f2bfce40f4b2d1168c9fd9259f255cd6ffb4d2943acd8203ad9948362b252be6273b0e3f1876893bcd3e0482dc472eb3967eebad151065a885c715abfe87ac145020ca5b7a2abe10c37f65a2d80f65412dc58adff7"),
        ("pkcs1-sha256-3072", "308201a2300d06092a864886f70d01010105000382018f003082018a0282018100c655d1faf7f60146ca384aa411969121b6f9e4b49aa0e730839b3a9778fdfc29d9fcc7805468059e67ad17c33919644f8bf40253dfd69ed7eb34b70a6092305f84591545f2fa0b0548df89e5a024752683249e07517107492859013612ac6227b304a0416630210c19cc7f64bba108b15a775cc2cbafdc2fcbc8f29d4740d068963d4c7be599a21ae1c36eedcec039cf4519623a0eb00d5004eca8e3aa816125c987bedf702d940132768599527c764f91d4b54f9f4af4e07e425aa7ed7ef1ab3d0e80655ee9f1fd825a713b77c858478e1c7d9190dfc0a2aae4075506065c528dd16b0cc9ccd01b9618b45fb5b774af6d61bf4d9697ab397eb1d3756cfef7e62f34e3eeada3d42dd343bebe1dbb58d0fd49c0a2d5a3a3ee7de610cd7f536fe61ea6361345adfe79d9867a8e4fe17ff82278eddf286dc05a0eb5fd81737331bbd7bb3e87fde953328b0cc869f2f1bcd5614c5bad5a86cc72d30c847267e555c3d583755939e5b38504a8d2ee58860945d2793d6ab47289ed0322123940998fef0203010001", 0, 0, 0, "656d6572616720727361203330373220706b6373312073686132353620766563746f72", "b60681edb6f4f59ce92c55b4c9f55258e95580fabc2b2f653737da854c86e6c8a561f143bf760cdc8ef4c705a711b6fe3d3675f7fb9bce553b2ef83628bbf6382a3ed274e653c10951fc39e70a556aba8e37194406213b194c70f0dca97163b5f95e4f9df4211fe9146db4ca5990bc3ecb98a0e4b53db0504e920a1b270a337f2772639475bc69426a479144d16fa56407bcb93df78b5384f22ccb90035757f17a6a4709379c84d9ffc8c2fa12a58f372e9f8ab36386a6472b98b5c17da3e739076f5cee952a57a14e09d3b1f32d34c4c41a63fa4346bf7ca0fc6fd64733459a5676a91e354632d883923a89f23823cbd62bfdbcde6eda4b9bc46b3434f38d13408380e5f58ede6dd30254dc5e909577c2708cbe23d2f048cd78fdec3dc629e4e963289af034c156b59e53fb398b0b1149adda777ef01ddca39931a30cc04c1524bc297164c4ee688106915fb6194d937738266e171fe721f39271c2a011fda63371e7d970bf8ea93b42b744670b1630d77465c64af7cb90ca7f53a9426f9d07"),
        ("pss-sha256-32-3072", "308201a2300d06092a864886f70d01010105000382018f003082018a0282018100c655d1faf7f60146ca384aa411969121b6f9e4b49aa0e730839b3a9778fdfc29d9fcc7805468059e67ad17c33919644f8bf40253dfd69ed7eb34b70a6092305f84591545f2fa0b0548df89e5a024752683249e07517107492859013612ac6227b304a0416630210c19cc7f64bba108b15a775cc2cbafdc2fcbc8f29d4740d068963d4c7be599a21ae1c36eedcec039cf4519623a0eb00d5004eca8e3aa816125c987bedf702d940132768599527c764f91d4b54f9f4af4e07e425aa7ed7ef1ab3d0e80655ee9f1fd825a713b77c858478e1c7d9190dfc0a2aae4075506065c528dd16b0cc9ccd01b9618b45fb5b774af6d61bf4d9697ab397eb1d3756cfef7e62f34e3eeada3d42dd343bebe1dbb58d0fd49c0a2d5a3a3ee7de610cd7f536fe61ea6361345adfe79d9867a8e4fe17ff82278eddf286dc05a0eb5fd81737331bbd7bb3e87fde953328b0cc869f2f1bcd5614c5bad5a86cc72d30c847267e555c3d583755939e5b38504a8d2ee58860945d2793d6ab47289ed0322123940998fef0203010001", 0, 1, 32, "656d65726167207073732033303732", "49051a951d2a0cb762c928c6d996a53b44e2ad4be364e1e1e52fca88c87849166fcc0f99742c992a88999a6fd299230a05bdc02d68606c86d5687065afc1cf3df435bf8ea5a3aa522f3c023c7c14ac7288bfc0f48665a222fb80a9dde0b152aade21a300c05f2082678685a4320e4d7406005df8817bfbcbb9e8fd61520d83d1cb3558c1fda2196751e08241ecc58a79a21c9a78f466eefda26328b4406caa84b6744edfd7cec7f112bae973147476df28fad550157324dcaaf7ecad8f0b468ab27f463c65c9c57fef1001e72dce0435d6144a1cccad465f9896d4a127e3ca8ca535f4df01beb23871a07bbd59005622957a403e848619b804dbbd963955139c952c3d12f9e774808f2437473b1dbae17d40c63e8a2d5ce3f144af41f2b4567485dc91b12e5c78a8895bc622f258bd35efbcf48a4965cbd819a2d4aa0ff958502e988c733f525065102510f3d15080d984e261cf57336caf0ab10757b13ed1c8d7fc5f62fac448bdeddc91f7a3b3457d9ccfddb90dd8b95834c0e10679f8c789"),
        ("pkcs1-sha512-3072", "308201a2300d06092a864886f70d01010105000382018f003082018a0282018100c655d1faf7f60146ca384aa411969121b6f9e4b49aa0e730839b3a9778fdfc29d9fcc7805468059e67ad17c33919644f8bf40253dfd69ed7eb34b70a6092305f84591545f2fa0b0548df89e5a024752683249e07517107492859013612ac6227b304a0416630210c19cc7f64bba108b15a775cc2cbafdc2fcbc8f29d4740d068963d4c7be599a21ae1c36eedcec039cf4519623a0eb00d5004eca8e3aa816125c987bedf702d940132768599527c764f91d4b54f9f4af4e07e425aa7ed7ef1ab3d0e80655ee9f1fd825a713b77c858478e1c7d9190dfc0a2aae4075506065c528dd16b0cc9ccd01b9618b45fb5b774af6d61bf4d9697ab397eb1d3756cfef7e62f34e3eeada3d42dd343bebe1dbb58d0fd49c0a2d5a3a3ee7de610cd7f536fe61ea6361345adfe79d9867a8e4fe17ff82278eddf286dc05a0eb5fd81737331bbd7bb3e87fde953328b0cc869f2f1bcd5614c5bad5a86cc72d30c847267e555c3d583755939e5b38504a8d2ee58860945d2793d6ab47289ed0322123940998fef0203010001", 2, 0, 0, "656d6572616720706b637331203330373220736861353132", "5d45c5a9b7ad336eaf44ab301022e440a6062eb3cc790862fab5f312ad63afcf27b82ccfa6d996610963a597cbd8c97cf73ba3b1e228f1e81e0b680992eb133c00f12097102be48d8a1466e4fdb884dec4e4720f15a5904ff6e0c8e9a20249e0bd6f7cd8042d816b6592e91d5335bfc9481906126b3d51d80391597f2a9f6bb88ce23c3627f061268785aaa594c4a3e1a043f11a69caa61c89bfc2f0ef52a9af9c1e65da5a8becbef36afa14afb44e81602bc86c869bb223999fc7c3f0a8f1817857050a55e6fec4d9706e36b38af124869f93ab26bb018384a33f42b6d7eee1e7250a4afa4a24d7ae8b56bc62ae8d96266803378a54209cee27240bf00a2f07a8013fec1c9e7d79a6366f67141a3fe1fa591e58d585b63f6bdc674794aaf2e016ebc07345202dcb2c403d528087ac3f79370e6762dd6322c39de099a6b4bee73532bca1426df74c1b2d7b3f7c59f99c736ac5b934871499834b3fcf1966f8d1d58d8f3274adb5d0f38c1320ba05bd98b8eb03f6387c8932b9d406fe502b6438"),
        ("pkcs1-sha256-1024", "30819f300d06092a864886f70d010101050003818d0030818902818100f70e4d6f568b4e5f194fcac8358fe914e31c83276d866f70fd26bea3bcdf56ab8050f52d3fd36fe4e710711800708f7ef1968ab644f8c407b79abf0a8dfb0a3530185bd977c54c74f672456145f04fd579efb94a8399f87ead364c8fb6775ac3c576a48bd14d9ed44faa33cb551e3218cb49177f203ee89d925775f1998772fb0203010001", 0, 0, 0, "656d6572616720706b6373312031303234", "f5cb1d48e4cf4ae759aa32941e3b9f7ef9a263bc0411e92bb810ee1d3a1ad37ddc313c9cfb87c5d863216b36913a5ba2aff5a55346edc4ed6a357d9eaf444a61f06e16685b1a8235e6950927ff1cbc798c20f06b170de846e9f422add6c2308bcfe0000b568bc949091991501b467c88606a331d713336831b806271d6f81ca4"),
        ("pss-sha256-32-1024", "30819f300d06092a864886f70d010101050003818d0030818902818100f70e4d6f568b4e5f194fcac8358fe914e31c83276d866f70fd26bea3bcdf56ab8050f52d3fd36fe4e710711800708f7ef1968ab644f8c407b79abf0a8dfb0a3530185bd977c54c74f672456145f04fd579efb94a8399f87ead364c8fb6775ac3c576a48bd14d9ed44faa33cb551e3218cb49177f203ee89d925775f1998772fb0203010001", 0, 1, 32, "656d65726167207073732031303234", "a887a27261bdf2c1e7e19fe33e2b32aa870bb2828b7efa5c9ee82831508f9fbe5b23a0478cb3d23f3ec9d0fcfa47600d007f25e9210bb08a9d6f3fa8771c2df3976e6fb1239f303897d71f57a4eaf7f03be4a269974bbda26c674061ce25cf682dd6ead16fb10e4b830d50d31611a4e3b99f2e08d303b8b540a2a5b5759b2f61"),
        ("differential-0", "30819f300d06092a864886f70d010101050003818d0030818902818100f70e4d6f568b4e5f194fcac8358fe914e31c83276d866f70fd26bea3bcdf56ab8050f52d3fd36fe4e710711800708f7ef1968ab644f8c407b79abf0a8dfb0a3530185bd977c54c74f672456145f04fd579efb94a8399f87ead364c8fb6775ac3c576a48bd14d9ed44faa33cb551e3218cb49177f203ee89d925775f1998772fb0203010001", 1, 0, 0, "f85975482eb8af75fab16ce216c845b242256ce9dfa83be08022415cebf095eae6f41ac53e1550a347327065333285811fd8192f4e1a36a7ec7c4a6af421228adf6cdbf39a72e19f79676cc1c6037dd3e4", "d0fce102624abd12f56d44accfd78e1a3764aead6494280875b04565457995f70e5499e364ad98099bcc94f50e267d9862c21c9d47587aa9a049b43cdc0dda53f62974e504045fcc332283131bec9ce5736f5ba5116715f3997ae6eeaa3074a8f69ceecbef3342a6988932c813d83882a67f3fb7bf330a2065af3250fbae9fa2"),
        ("differential-1", "30819f300d06092a864886f70d010101050003818d0030818902818100f70e4d6f568b4e5f194fcac8358fe914e31c83276d866f70fd26bea3bcdf56ab8050f52d3fd36fe4e710711800708f7ef1968ab644f8c407b79abf0a8dfb0a3530185bd977c54c74f672456145f04fd579efb94a8399f87ead364c8fb6775ac3c576a48bd14d9ed44faa33cb551e3218cb49177f203ee89d925775f1998772fb0203010001", 0, 1, 32, "54207070a44ebcee2bcda2ed5eb389c5175ffe514272786fc6966f43a3b3f471824b2b02aef96e38d99b7c4357562645ff81f77b3c86cdc9bf688f", "3f0181b203b170f6d2d994f467d9feb2ad607d690a3d9c27f28fd6f84c15fb5fdfb9723e3abf9c467e9c1936b1edd39e095fc7d2a14e621a2b3b055aefb2ef08bc6742812c7e9f2a75f24e398d113bd6d9565729321af632355505cf29c8c34b917873b35f4df27ac07324dad9681f66d0cf52229f6fbec4d73f1ce153660347"),
        ("differential-2", "30819f300d06092a864886f70d010101050003818d0030818902818100f70e4d6f568b4e5f194fcac8358fe914e31c83276d866f70fd26bea3bcdf56ab8050f52d3fd36fe4e710711800708f7ef1968ab644f8c407b79abf0a8dfb0a3530185bd977c54c74f672456145f04fd579efb94a8399f87ead364c8fb6775ac3c576a48bd14d9ed44faa33cb551e3218cb49177f203ee89d925775f1998772fb0203010001", 0, 0, 0, "53f3c5dc099160e359fbaaba11c1e8f3a0d42e1a03cb3232de999f1116ec54e3896fa574b010e2b64a302466488cd6491e9b5800ab017f38e88ba13ea5a095", "e7b7bd0d862c94dca65b439a1c84e9b2137c85a4cf98269e870407a1793e44358ee3af189de00b96cab769f7e25e23003fe68b211841b98028bdbaeb54149bf0117d9516c2f7b7f6f65d8abc8eb6f4dc0d87fb1bb6771b1ffa0b34fd77eba3004ce10a8d9c4642954bf50c745bb9f56f796f7f525a5311b45f3c6c4bce9593d8"),
        ("differential-3", "30819f300d06092a864886f70d010101050003818d0030818902818100f70e4d6f568b4e5f194fcac8358fe914e31c83276d866f70fd26bea3bcdf56ab8050f52d3fd36fe4e710711800708f7ef1968ab644f8c407b79abf0a8dfb0a3530185bd977c54c74f672456145f04fd579efb94a8399f87ead364c8fb6775ac3c576a48bd14d9ed44faa33cb551e3218cb49177f203ee89d925775f1998772fb0203010001", 0, 0, 0, "c6f4d6b74f3fe315dbb29d4576c113340195713cdf90aa93ac2873c18fcf1dddbdce5d9f8c8d35fe", "40b6239f330d141aff9dc5253e8c845fce21ff1c88f329793b254865c756eacd2157bdc6be4bd400040732caa7d9c933fafdcefa8e983dd7bf036e2b61267263062049b46fe7f17ffbcdc955fc5a8dbf7ff210717eefb38c60be1f128215e29ae266cacf39c67cea32dd60eff36b4d0ba64ae01ed1b39fcf00fd229e27776909"),
        ("differential-4", "30820122300d06092a864886f70d01010105000382010f003082010a0282010100c8328fc013fdbe27db6a81406bf5174e07c0c451f190fec003b169290432aedff70f78ba7c64eebc6b0fd0611f88e140042a282428d3d0a44b4f8714c8c6517c64886bcb42bf88853f638e89624c6519a402b9bd16f2945ed3b79d5907b438e688d245b04ae030188057a6d21c6d9e151beeb88f6a499b4d147b7823d203c36d0df27a4cd7479b63b03f7d0bb1f8b1c47023b73e48722ee5c2f37c24aace8072aa3e6f47b57ec54e352acef74b8f1b6f2b608ad50c1baa58d809177e4fcae09f6e075a8157357e6129869c4808f22389961c72633c98d60d0ccadd9a3024abfbabff088dfd727f9e39fe1cd2ea5ad3ee16ebac4e182389beb23a9ed3eec09ef30203010001", 2, 0, 0, "e16c75274c96", "89f8fe0cb98037db986aadf0fbfdc71ae7e8e1d45135ff4fd96e8a413906ac0b043c39ffe88a1233c747353b2029a645f18a40df256eaf38a21ab4bb992bc822b5b4f0ba3d1584b86fb2514ee4c71779e897421dc43b9b7c8557c3d05ac439724d252ca98e01ae345baf8db4a9a641fcc01ce97b56beb69a6919a68f4b0358d8425dadad007c0a205115283578252423aea37bef4e6272859f82f2ca4c339565c0314a24b177183a6dac951b969a7f119cf473ae1017373e2c645b0b38090b129edf2f42bfd1807fc6ea32461ca0ef8d1351f744614061e3a1be95488de6d0b2ab1daceee986bf41ff4604e5642d0d0d0a874bd18ab8ad9f047464c2becc5393"),
        ("differential-5", "308201a2300d06092a864886f70d01010105000382018f003082018a0282018100c655d1faf7f60146ca384aa411969121b6f9e4b49aa0e730839b3a9778fdfc29d9fcc7805468059e67ad17c33919644f8bf40253dfd69ed7eb34b70a6092305f84591545f2fa0b0548df89e5a024752683249e07517107492859013612ac6227b304a0416630210c19cc7f64bba108b15a775cc2cbafdc2fcbc8f29d4740d068963d4c7be599a21ae1c36eedcec039cf4519623a0eb00d5004eca8e3aa816125c987bedf702d940132768599527c764f91d4b54f9f4af4e07e425aa7ed7ef1ab3d0e80655ee9f1fd825a713b77c858478e1c7d9190dfc0a2aae4075506065c528dd16b0cc9ccd01b9618b45fb5b774af6d61bf4d9697ab397eb1d3756cfef7e62f34e3eeada3d42dd343bebe1dbb58d0fd49c0a2d5a3a3ee7de610cd7f536fe61ea6361345adfe79d9867a8e4fe17ff82278eddf286dc05a0eb5fd81737331bbd7bb3e87fde953328b0cc869f2f1bcd5614c5bad5a86cc72d30c847267e555c3d583755939e5b38504a8d2ee58860945d2793d6ab47289ed0322123940998fef0203010001", 0, 0, 0, "8630b3eebc48d846a3a12db56aa1302b2a1fb149ca8578a00db351450ef8ffa0fde08c002d8fd90e14bc0f02a345b4d6af2f624d0a583683eaf313941c9ce934d8d8dd01d06b0e", "3908af93576131363be270549bdcf7d077428c914e1d710322adc45090e467f017e112a079e71f11dee0e98c9f2e5565798c6e1b463e90f7bc808085081dcddc99ca5da412902de0cbf926f4d78a9169203e56d23317809eba3bcabee5d492559ac3f0079ba0f245c3112bfb775175395720975f20c7fa7f3b22a690e9dcaef2651e4cd6a58bbef572747226b795685edc3258807e2908f17b8388593e0ab95ce12459b90de6a301a5021ae6c9ab935dc7686a6eb98b0c017b70fb47f7db73f4fd51797a3359e3a76bddc15bdfceeaf0a99ccb68bf399e54620dface677cbfa99e4b347bb696dba8746ffc344f87aeda0319e4aef60a717305a7a968f5db0d1c3499a3c6f0a7108f94d626e05d51d62583487b9db82763379e6aac30c159595b2508866fb01485d026b654e713e14f4ed17a5afdcea29f7c5d96cbf38fe209dd8c78618e798230af4d1b6cfb879b9e5b370a688b2b66377e83f946953c1610e295105fecdc47316632058ab8fc33cf484101312f4790fae6df8a9c0362705363"),
        ("differential-6", "30820122300d06092a864886f70d01010105000382010f003082010a0282010100c8328fc013fdbe27db6a81406bf5174e07c0c451f190fec003b169290432aedff70f78ba7c64eebc6b0fd0611f88e140042a282428d3d0a44b4f8714c8c6517c64886bcb42bf88853f638e89624c6519a402b9bd16f2945ed3b79d5907b438e688d245b04ae030188057a6d21c6d9e151beeb88f6a499b4d147b7823d203c36d0df27a4cd7479b63b03f7d0bb1f8b1c47023b73e48722ee5c2f37c24aace8072aa3e6f47b57ec54e352acef74b8f1b6f2b608ad50c1baa58d809177e4fcae09f6e075a8157357e6129869c4808f22389961c72633c98d60d0ccadd9a3024abfbabff088dfd727f9e39fe1cd2ea5ad3ee16ebac4e182389beb23a9ed3eec09ef30203010001", 1, 0, 0, "e5b4bc9ebf06b31023e9a10d7054649164e8978dc2aa84eb8fdebce52519aadb", "b92bc309fcd5dd19d7bcb404c676801745f8565d806c6b9e8395696e74f13cc8b91040625e173b5ea5f831fe58e7d694fcea3df32549eebc67028fc38b78b759a60e3888a69ab47bd72a66bb223af3618b759a80f0c7e6ed78768de7f2c987195e4a466e9f512aa0a05f3ab1a31d3150aeca80eb4e48acf87afa825b80c1aa1c5c042b25226f71562a15e1c3a404ace66b406d975ce82a71a678a14d310b63f49eef1b27a1d14bfdd337b3df8b807b2ac3b2684ebb613c1c0d2993768e713cd6b40392197c40b926ad59662f76aa8752112a2006c127f8b007288884188c13a0629b7f7431ab723fe00973a471d43df20e6b55af369698fc700de1c30ab4ca02"),
        ("differential-7", "30819f300d06092a864886f70d010101050003818d0030818902818100f70e4d6f568b4e5f194fcac8358fe914e31c83276d866f70fd26bea3bcdf56ab8050f52d3fd36fe4e710711800708f7ef1968ab644f8c407b79abf0a8dfb0a3530185bd977c54c74f672456145f04fd579efb94a8399f87ead364c8fb6775ac3c576a48bd14d9ed44faa33cb551e3218cb49177f203ee89d925775f1998772fb0203010001", 0, 1, 32, "1a8c91f1a7bd2b6139e2ceb570e38fbde005aa69c785723b7e418be42746105497b71b4a617bd876dc596f9c6481353151fade1a8efef46e90df093d90a298a8446dc0ce2a2f0fc7a5", "5cb55fccfbc9a354d8c02be6c8195e988d72e5edde58d018ee69924873de24114e8f1de6c983c40f9156ecc7011a04633ec607eb35fbe34518c63fc27b111a915ee9928ffd1e260c81ae42ff3dd141f082f4cc06795b86df4ab36c0439f38e45cbb02b283337dc036d89168fa10eb489b743cefffdc734fd66c137fe2b8d1502"),
        ("differential-8", "30819f300d06092a864886f70d010101050003818d0030818902818100f70e4d6f568b4e5f194fcac8358fe914e31c83276d866f70fd26bea3bcdf56ab8050f52d3fd36fe4e710711800708f7ef1968ab644f8c407b79abf0a8dfb0a3530185bd977c54c74f672456145f04fd579efb94a8399f87ead364c8fb6775ac3c576a48bd14d9ed44faa33cb551e3218cb49177f203ee89d925775f1998772fb0203010001", 0, 1, 32, "9ad15dfd6beb5fc0fe8b7e12c8b43b3ec9e87b9ba35a6233ee888a8cc5be54da8729c8252ef2e6a1e2a4f06ea129138de3cfcd8a85ad13ad2dfcb27638b166a020aa50b03b89d41dfe3be5509311faf63fb267dba29de3a1afd071792e384b89eb71", "a1493d206a486c9f13ee469a32b4617c6cb3045c4146190f6afc80f7c3dbe87c37140cfaafbc5ac04ea06aa450b6396547ff7080d9ca0ad6108cee4bfc2b2165805592f3a121844ece6cdc08d6bb21715a3b0e30b7e93b0ed7c0779ace56f2fbb8b38ae5c84a54c660257fba05cc5fba8ca8f14efa19ea9801168e9e943ed434"),
        ("differential-9", "308201a2300d06092a864886f70d01010105000382018f003082018a0282018100c655d1faf7f60146ca384aa411969121b6f9e4b49aa0e730839b3a9778fdfc29d9fcc7805468059e67ad17c33919644f8bf40253dfd69ed7eb34b70a6092305f84591545f2fa0b0548df89e5a024752683249e07517107492859013612ac6227b304a0416630210c19cc7f64bba108b15a775cc2cbafdc2fcbc8f29d4740d068963d4c7be599a21ae1c36eedcec039cf4519623a0eb00d5004eca8e3aa816125c987bedf702d940132768599527c764f91d4b54f9f4af4e07e425aa7ed7ef1ab3d0e80655ee9f1fd825a713b77c858478e1c7d9190dfc0a2aae4075506065c528dd16b0cc9ccd01b9618b45fb5b774af6d61bf4d9697ab397eb1d3756cfef7e62f34e3eeada3d42dd343bebe1dbb58d0fd49c0a2d5a3a3ee7de610cd7f536fe61ea6361345adfe79d9867a8e4fe17ff82278eddf286dc05a0eb5fd81737331bbd7bb3e87fde953328b0cc869f2f1bcd5614c5bad5a86cc72d30c847267e555c3d583755939e5b38504a8d2ee58860945d2793d6ab47289ed0322123940998fef0203010001", 2, 1, 64, "73a6507f356dc1da473d130048ab7de105f5fbb29b1ad1ce26d27c311921c9b1ac63c5ec7d563853ef01efdefb313bee95d64fdd1265401baf", "2513cc2bc65cc931097153ed0d096a76ccfe53c9f2e7656d6d5126a8543c318a4685654e0806bf779b0b046871c0e19e202d135df8fbaa4d573c8ee06f579ddd6eb1920a85129d3d3f04e0bebc43d90b1897d57b7c973c1e94a570a6d0511a86efa37fccee68ec7e4c3d29bb176e90a05b5ddbb94e89f268f4a22509a841f2db17d1b3dd5b3e153938cd95a28e688cd6f1aefb85639a1d18e03ac40dd2a190059cfb60346909881797be36e30c05ba7d778928b69fbdb32bd50ef4dbf4e4c8848b4188f30929d7db941ca1b0e0b7355dececf5b83e420a7ffa69bf77db581742f61dd4f45b4f61edb656adcadbdb5e9cb709acf606fca7d48bd214be103d0e2f30ae464a34a1bb9bc921c7255b9e6b9c15d30c200f94e6be1a42a37274764eb399647005e9aefd6a23a1a945dc590d632ab69d6dfd9c08246a58daa10677242472d015a8c86608e222f0a03c6e5c963d588a1f87af4516bfee00edbee8fc7bdbd3a34da3c94e3b77886268b674178d4b204aff555fdc24edd0be0e6a0bed6d62"),
        ("differential-10", "308201a2300d06092a864886f70d01010105000382018f003082018a0282018100c655d1faf7f60146ca384aa411969121b6f9e4b49aa0e730839b3a9778fdfc29d9fcc7805468059e67ad17c33919644f8bf40253dfd69ed7eb34b70a6092305f84591545f2fa0b0548df89e5a024752683249e07517107492859013612ac6227b304a0416630210c19cc7f64bba108b15a775cc2cbafdc2fcbc8f29d4740d068963d4c7be599a21ae1c36eedcec039cf4519623a0eb00d5004eca8e3aa816125c987bedf702d940132768599527c764f91d4b54f9f4af4e07e425aa7ed7ef1ab3d0e80655ee9f1fd825a713b77c858478e1c7d9190dfc0a2aae4075506065c528dd16b0cc9ccd01b9618b45fb5b774af6d61bf4d9697ab397eb1d3756cfef7e62f34e3eeada3d42dd343bebe1dbb58d0fd49c0a2d5a3a3ee7de610cd7f536fe61ea6361345adfe79d9867a8e4fe17ff82278eddf286dc05a0eb5fd81737331bbd7bb3e87fde953328b0cc869f2f1bcd5614c5bad5a86cc72d30c847267e555c3d583755939e5b38504a8d2ee58860945d2793d6ab47289ed0322123940998fef0203010001", 0, 1, 32, "cd5e30c87b9fae8fcd010f0a3ee157b129568bd1ef8dd40edfab9bb9264d00ee7c8ca1541ae33d6caa0053cebdd73975d7192ddbdece7071387f0273323b018f9b5835fb33c1cc889fab9e55f6", "1e6e91a02bc1389c03f93d1b686dffe3f72204453650425f1fa642a27c72d5762e77e10fc9f662b8e1399641a3e6bacda7cfe7f2c9e0c838618ec181ae75e74889e0d657ce0b4a41cecae1326bdd889136053a35eae770e6bb3adebc9d4f3fb8040904d9d4e11117b93f63dc9dfc174f35f2532d1eb29358296c80dfcee4cbeae6f8e58ae07eda6480dea728e536d53d4714826da7d350f30334ff09612852ab0c9372c1aa6a625317f9edbf45741c31dc49f77f76db0a064016c10539dc88056224345063ef4dfdfae2bcc241ab37e36e96eb7e8c2c432ea3b92b33956a5508acce83ca98ce18b0ed6f95ce1795f6009a4545f31ddca2580a59772c037bdb101f6cab2d6016d4e5e4c0f261f06d9de66c81be5ba6abcf0f9817882413139ad658d7ab09b5798622e2a51a89e0ebe6ac0394004a9c383976a0debf348e33d686bc97b8a9f6c920802cd02f8e2acea29760e933265de24afadbca3c1d2e8c195117cf24b2bf9c9063cd45815a54371abf3c1ea9c6af62fb24af0f0ee197f68c68"),
        ("differential-11", "30819f300d06092a864886f70d010101050003818d0030818902818100f70e4d6f568b4e5f194fcac8358fe914e31c83276d866f70fd26bea3bcdf56ab8050f52d3fd36fe4e710711800708f7ef1968ab644f8c407b79abf0a8dfb0a3530185bd977c54c74f672456145f04fd579efb94a8399f87ead364c8fb6775ac3c576a48bd14d9ed44faa33cb551e3218cb49177f203ee89d925775f1998772fb0203010001", 1, 1, 32, "144b4d4675690c146d8a83d47c65952fd7b8bcc3f8da72ba8418c18f6e88c58abb8c498290d7332c3245413ab9", "a234f221dd5fefc9d6d7487647c474dd29ebf5556aa7010983d829901ac2251c9bfcf4780409e7f8d383ec6d4120086f8cebb44f5584010d037960c8d24622d54b0b6c9fb26e611a01e9f8fbf4e3a1cf82e8388000ec96947dee94853547583eabd8c966a87bad38089cba66aff79a9f3b98bcfa0558a9d36f9d197f263180bf"),
        ("differential-12", "30819f300d06092a864886f70d010101050003818d0030818902818100f70e4d6f568b4e5f194fcac8358fe914e31c83276d866f70fd26bea3bcdf56ab8050f52d3fd36fe4e710711800708f7ef1968ab644f8c407b79abf0a8dfb0a3530185bd977c54c74f672456145f04fd579efb94a8399f87ead364c8fb6775ac3c576a48bd14d9ed44faa33cb551e3218cb49177f203ee89d925775f1998772fb0203010001", 1, 1, 48, "f7f4ec5ed4655ced1d4bb95d734e5c10a059eff70a0588a472bef603968a4fc0156652465c8cbb8f7c", "c9cc1dc1c781fe2aaea073231b31ca75456f69243ee881aa1504678136123bb411ec3160b731d96b38967b743b8cda029ef76b9ca3055c81c2f8a87f875899e614a306d3b08fa42547daa21066c3cb0ea8dc6b45db06857e68f9034b8c3a29ac48c5083bd5b78b128259a082c7cbdeec77d08007d26693bf58703e6f93b3eef4"),
        ("differential-13", "30819f300d06092a864886f70d010101050003818d0030818902818100f70e4d6f568b4e5f194fcac8358fe914e31c83276d866f70fd26bea3bcdf56ab8050f52d3fd36fe4e710711800708f7ef1968ab644f8c407b79abf0a8dfb0a3530185bd977c54c74f672456145f04fd579efb94a8399f87ead364c8fb6775ac3c576a48bd14d9ed44faa33cb551e3218cb49177f203ee89d925775f1998772fb0203010001", 0, 1, 32, "6446f8c707", "024f3284fbf28e1bdfb7ee7eced93df222a3def039d54e85a16d17416f63dc64530c8cd120ec9faa501b4908d2cfcc1c642b28d438798a0802a8d9aef8581b9ff90d21b6a76b54b1e83144f34d28a2137f4cc900d6ff04d80555127185d56dd818b4bc0901dff2090ca26d5c243da936ed612843c24b6407131e5b18c783514a"),
        ("differential-14", "30819f300d06092a864886f70d010101050003818d0030818902818100f70e4d6f568b4e5f194fcac8358fe914e31c83276d866f70fd26bea3bcdf56ab8050f52d3fd36fe4e710711800708f7ef1968ab644f8c407b79abf0a8dfb0a3530185bd977c54c74f672456145f04fd579efb94a8399f87ead364c8fb6775ac3c576a48bd14d9ed44faa33cb551e3218cb49177f203ee89d925775f1998772fb0203010001", 0, 1, 32, "454b68059767cabdbde5d1bacf123417f61dffa3899d70e49e7b6b74b5bf54cd3dd8e44a7a45c1f4e5afcb91c7cc44c5c2ccf772214e64fe83196804a9ebc750b7f66feff9b243c776add37dc6", "28e8bba6e264128f1bc6f36c8116e22bf991ccfbc14466fa1d22270557d49f159866bc8cf91aabe8b1c7ea8292a1799754172567f6b86499136f14233ec01c69778abae595fab8ece84913d847ae197769c148df88989122641d76ef84c83a99f6e59dcc9d466aa4f646b84fd5e48265fefeb1f8911ba86472ef3654f8d6b535"),
        ("differential-15", "30820122300d06092a864886f70d01010105000382010f003082010a0282010100c8328fc013fdbe27db6a81406bf5174e07c0c451f190fec003b169290432aedff70f78ba7c64eebc6b0fd0611f88e140042a282428d3d0a44b4f8714c8c6517c64886bcb42bf88853f638e89624c6519a402b9bd16f2945ed3b79d5907b438e688d245b04ae030188057a6d21c6d9e151beeb88f6a499b4d147b7823d203c36d0df27a4cd7479b63b03f7d0bb1f8b1c47023b73e48722ee5c2f37c24aace8072aa3e6f47b57ec54e352acef74b8f1b6f2b608ad50c1baa58d809177e4fcae09f6e075a8157357e6129869c4808f22389961c72633c98d60d0ccadd9a3024abfbabff088dfd727f9e39fe1cd2ea5ad3ee16ebac4e182389beb23a9ed3eec09ef30203010001", 0, 1, 32, "0c4f65ad7c598bcbffb090067b3433990cde6eb1c16624afbe9cd30510bfe19a76807e8f7eaafaf2a04297967f2426c7f1673610033a37005477e8bc2d30f520c839287a5221", "bb3fcd30520e478a9154f81c07c8ecc8e05f307426ada8f848e5384681e848981db7b1781491e02b194f5cb74f037563ad058b320185dad1f9c6d0c15758c37bf185fda74414f51a24c07fac0db9b9f83760d91ef7235245ca41ff7b5ffeaae28fcf8945102967d3229476855f7fc6a37bb8acebdc87b58f8882c8426c2459264a232629e15233c008634206fb591c242f3c749a25f3b666f8db04d34af2987aaf35579cfdac01cfbd114743ba73a3f0e4e01093137be57316f33f315ecc963c496a1764ad2187f641b1691e412bddf5da3f0f2440febcb8143fd83c241db46100aaa2707c10a019d40d0c0b18c2dd49b8c73afbb29ab13c11cc4bf7e9e80268"),
    ];
    const RSA_PKCS1_KEY: &str = "3082010a0282010100c8328fc013fdbe27db6a81406bf5174e07c0c451f190fec003b169290432aedff70f78ba7c64eebc6b0fd0611f88e140042a282428d3d0a44b4f8714c8c6517c64886bcb42bf88853f638e89624c6519a402b9bd16f2945ed3b79d5907b438e688d245b04ae030188057a6d21c6d9e151beeb88f6a499b4d147b7823d203c36d0df27a4cd7479b63b03f7d0bb1f8b1c47023b73e48722ee5c2f37c24aace8072aa3e6f47b57ec54e352acef74b8f1b6f2b608ad50c1baa58d809177e4fcae09f6e075a8157357e6129869c4808f22389961c72633c98d60d0ccadd9a3024abfbabff088dfd727f9e39fe1cd2ea5ad3ee16ebac4e182389beb23a9ed3eec09ef30203010001";
    const RSA_SMALL_KEY: &str = "305c300d06092a864886f70d0101010500034b003048024100c683bf54d153e72dbb26ba73b9aaef84f66b38294e69b6a1ddc2a89e3620809db00adf46a45b94233fa18ee7afd668d22edc5eed7455dfbd99feb93ff7edd1ef0203010001";

    fn case_key(c: &(&str, &str, u8, u8, usize, &str, &str)) -> RsaPublicKey {
        RsaPublicKey::from_der_spki(&decode(c.1).unwrap()).unwrap()
    }

    fn verify_case(
        c: &(&str, &str, u8, u8, usize, &str, &str),
        msg: &[u8],
        sig: &[u8],
        alg_id: u8,
    ) -> bool {
        let key = case_key(c);
        if c.3 == 0 {
            key.verify_pkcs1v15(alg(alg_id), msg, sig).unwrap()
        } else {
            key.verify_pss(alg(alg_id), msg, sig, c.4).unwrap()
        }
    }

    #[test]
    fn all_positive_vectors() {
        for c in RSA_CASES {
            let msg = decode(c.5).unwrap();
            let sig = decode(c.6).unwrap();
            assert!(verify_case(c, &msg, &sig, c.2), "vector failed: {}", c.0);
        }
    }

    #[test]
    fn modified_message_and_signature_rejected() {
        for c in RSA_CASES {
            let mut msg = decode(c.5).unwrap();
            if msg.is_empty() {
                msg.push(0x00);
            } else {
                msg[0] ^= 0x01;
            }
            let sig = decode(c.6).unwrap();
            assert!(
                !verify_case(c, &msg, &sig, c.2),
                "modified message accepted: {}",
                c.0
            );
            let mut sig2 = sig.clone();
            let last = sig2.len() - 1;
            sig2[last] ^= 0x01;
            assert!(
                !verify_case(c, &sig2, &decode(c.5).unwrap(), c.2),
                "modified signature accepted: {}",
                c.0
            );
            let short = &sig[..sig.len() - 1];
            assert!(!verify_case(c, short, &decode(c.5).unwrap(), c.2));
        }
    }

    #[test]
    fn wrong_hash_rejected() {
        for c in RSA_CASES {
            let msg = decode(c.5).unwrap();
            let sig = decode(c.6).unwrap();
            let wrong = (c.2 + 1) % 3;
            assert!(
                !verify_case(c, &msg, &sig, wrong),
                "wrong hash accepted: {}",
                c.0
            );
        }
    }

    #[test]
    fn pkcs1_der_parses_and_verifies() {
        let key = RsaPublicKey::from_pkcs1_der(&decode(RSA_PKCS1_KEY).unwrap()).unwrap();
        assert_eq!(key.bits(), 2048);
        let c = &RSA_CASES[0];
        assert_eq!(c.0, "pkcs1-sha256-2048");
        assert!(key
            .verify_pkcs1v15(
                HashAlg::Sha256,
                &decode(c.5).unwrap(),
                &decode(c.6).unwrap()
            )
            .unwrap());
    }

    #[test]
    fn pss_salt_length_is_enforced() {
        let mut checked = 0;
        for c in RSA_CASES {
            if c.3 != 1 || c.4 != 32 {
                continue;
            }
            let key = case_key(c);
            let msg = decode(c.5).unwrap();
            let sig = decode(c.6).unwrap();
            assert!(!key.verify_pss(alg(c.2), &msg, &sig, 31).unwrap());
            assert!(!key.verify_pss(alg(c.2), &msg, &sig, 33).unwrap());
            checked += 1;
            if checked == 3 {
                break;
            }
        }
        assert!(checked > 0);
    }

    #[test]
    fn weak_and_malformed_keys_rejected() {
        assert!(RsaPublicKey::from_der_spki(&decode(RSA_SMALL_KEY).unwrap()).is_err());
        assert!(RsaPublicKey::from_der_spki(&[]).is_err());
        assert!(RsaPublicKey::from_der_spki(&[0x30, 0x00]).is_err());
        assert!(RsaPublicKey::from_der_spki(&[0x30u8; 300]).is_err());
        let key = decode(RSA_CASES[0].1).unwrap();
        assert!(RsaPublicKey::from_der_spki(&key[..key.len() - 1]).is_err());
        let mut trailing = key.clone();
        trailing.push(0);
        assert!(RsaPublicKey::from_der_spki(&trailing).is_err());
        let mut bad = key.clone();
        bad[0] = 0x31;
        assert!(RsaPublicKey::from_der_spki(&bad).is_err());
    }

    #[test]
    fn out_of_range_signature_rejected() {
        let key = decode(RSA_CASES[0].1).unwrap();
        let key = RsaPublicKey::from_der_spki(&key).unwrap();
        let k = (key.bits() + 7) / 8;
        let sig = vec![0xffu8; k];
        assert!(!key.verify_pkcs1v15(HashAlg::Sha256, b"x", &sig).unwrap());
        assert!(!key.verify_pss(HashAlg::Sha256, b"x", &sig, 32).unwrap());
        assert!(!key.verify_pkcs1v15(HashAlg::Sha256, b"x", &[]).unwrap());
        assert!(!key.verify_pss(HashAlg::Sha512, b"x", &sig, 64).unwrap());
    }
}

// ---------------------------------------------------------------------------
// Release-mode performance probes (run with --ignored --nocapture)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod perf {
    use super::vectors::*;
    use super::*;
    use emerag_util::hex::decode;

    #[test]
    #[ignore]
    fn perf_rsa2048_verify() {
        let iters = 200;
        for idx in 0..2 {
            let c = &RSA_CASES[idx];
            let key = RsaPublicKey::from_der_spki(&decode(c.1).unwrap()).unwrap();
            let msg = decode(c.5).unwrap();
            let sig = decode(c.6).unwrap();
            let start = std::time::Instant::now();
            for _ in 0..iters {
                let ok = if c.3 == 0 {
                    key.verify_pkcs1v15(alg(c.2), &msg, &sig).unwrap()
                } else {
                    key.verify_pss(alg(c.2), &msg, &sig, c.4).unwrap()
                };
                assert!(ok);
            }
            println!(
                "{} verify: {:.1} us/op",
                if c.3 == 0 {
                    "rsa-2048 pkcs1v15-sha256"
                } else {
                    "rsa-2048 pss-sha256"
                },
                start.elapsed().as_secs_f64() * 1e6 / iters as f64
            );
        }
        // Key parsing cost (Montgomery setup included).
        let raw = decode(RSA_CASES[0].1).unwrap();
        let iters = 200;
        let start = std::time::Instant::now();
        for _ in 0..iters {
            let _ = RsaPublicKey::from_der_spki(&raw).unwrap();
        }
        println!(
            "rsa-2048 spki parse: {:.1} us/op",
            start.elapsed().as_secs_f64() * 1e6 / iters as f64
        );
    }
}
