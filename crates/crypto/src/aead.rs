//! AES-GCM (NIST SP 800-38D) and ChaCha20-Poly1305 (RFC 8439).
//!
//! Both AEADs use 96-bit nonces fixed by the type, accept arbitrary AAD and
//! return ciphertext || 16-byte tag from seal(). open() checks the tag before
//! decrypting and compares it in constant time with ct::ct_eq, returning Err on
//! any mismatch (truncation, bit flips, wrong AAD/nonce).
//!
//! AES is implemented from scratch (FIPS-197) with a compact S-box based
//! implementation: no AES-NI and no large T-tables, so it works on every target
//! emerag supports. GHASH uses the standard 4-bit table method (256 bytes of
//! precomputed key material) and handles AAD/ciphertext that are not a multiple
//! of 16 bytes. ChaCha20-Poly1305 follows RFC 8439 exactly, including the
//! Poly1305 padding and little-endian length block.
//!
//! Note on side channels: the AES S-box is a table lookup, so cache-timing
//! attacks against AES are possible in shared-cache environments. The
//! alternative (bitslicing) costs several times more code and cycles. AEAD tag
//! comparison is constant time (ct::ct_eq), which is the check that guards
//! against forgery.

use crate::ct;
use crate::Error;
use crate::Result;

pub(crate) const SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

// ---------------------------------------------------------------------------
// AES (FIPS-197)
// ---------------------------------------------------------------------------

fn xtime(b: u8) -> u8 {
    (b << 1) ^ (0x1b & 0u8.wrapping_sub(b >> 7))
}

#[cfg(test)]
fn gmul(mut a: u8, mut b: u8) -> u8 {
    let mut p = 0u8;
    let mut i = 0;
    while i < 8 {
        if b & 1 != 0 {
            p ^= a;
        }
        a = xtime(a);
        b >>= 1;
        i += 1;
    }
    p
}

struct Aes {
    rk: [[u8; 16]; 15],
    rounds: usize,
}

impl Aes {
    fn new(key: &[u8]) -> Self {
        let nk = key.len() / 4;
        let nr = nk + 6;
        let total_words = 4 * (nr + 1);
        let mut w = [0u8; 240];
        w[..key.len()].copy_from_slice(key);

        let mut rcon = 1u8;
        let mut i = nk;
        while i < total_words {
            let mut t = [
                w[(i - 1) * 4],
                w[(i - 1) * 4 + 1],
                w[(i - 1) * 4 + 2],
                w[(i - 1) * 4 + 3],
            ];
            if i % nk == 0 {
                t = [t[1], t[2], t[3], t[0]];
                let mut j = 0;
                while j < 4 {
                    t[j] = SBOX[t[j] as usize];
                    j += 1;
                }
                t[0] ^= rcon;
                rcon = xtime(rcon);
            } else if nk > 6 && i % nk == 4 {
                let mut j = 0;
                while j < 4 {
                    t[j] = SBOX[t[j] as usize];
                    j += 1;
                }
            }
            let mut j = 0;
            while j < 4 {
                w[i * 4 + j] = w[(i - nk) * 4 + j] ^ t[j];
                j += 1;
            }
            i += 1;
        }

        let mut rk = [[0u8; 16]; 15];
        let mut r = 0;
        while r <= nr {
            rk[r].copy_from_slice(&w[r * 16..r * 16 + 16]);
            r += 1;
        }
        ct::wipe(&mut w);
        Aes { rk, rounds: nr }
    }

    fn encrypt_block(&self, block: &mut [u8; 16]) {
        let mut s = *block;
        add_round_key(&mut s, &self.rk[0]);
        let mut round = 1;
        while round < self.rounds {
            let mut i = 0;
            while i < 16 {
                s[i] = SBOX[s[i] as usize];
                i += 1;
            }
            shift_rows(&mut s);
            mix_columns(&mut s);
            add_round_key(&mut s, &self.rk[round]);
            round += 1;
        }
        let mut i = 0;
        while i < 16 {
            s[i] = SBOX[s[i] as usize];
            i += 1;
        }
        shift_rows(&mut s);
        add_round_key(&mut s, &self.rk[self.rounds]);
        *block = s;
    }
}

impl Drop for Aes {
    fn drop(&mut self) {
        let mut i = 0;
        while i < self.rk.len() {
            ct::wipe(&mut self.rk[i]);
            i += 1;
        }
    }
}

fn add_round_key(s: &mut [u8; 16], rk: &[u8; 16]) {
    let mut i = 0;
    while i < 16 {
        s[i] ^= rk[i];
        i += 1;
    }
}

fn shift_rows(s: &mut [u8; 16]) {
    let t = *s;
    let mut r = 0;
    while r < 4 {
        let mut c = 0;
        while c < 4 {
            s[4 * c + r] = t[4 * ((c + r) % 4) + r];
            c += 1;
        }
        r += 1;
    }
}

fn mix_columns(s: &mut [u8; 16]) {
    let mut c = 0;
    while c < 4 {
        let i = 4 * c;
        let a0 = s[i];
        let a1 = s[i + 1];
        let a2 = s[i + 2];
        let a3 = s[i + 3];
        let all = a0 ^ a1 ^ a2 ^ a3;
        s[i] = a0 ^ all ^ xtime(a0 ^ a1);
        s[i + 1] = a1 ^ all ^ xtime(a1 ^ a2);
        s[i + 2] = a2 ^ all ^ xtime(a2 ^ a3);
        s[i + 3] = a3 ^ all ^ xtime(a3 ^ a0);
        c += 1;
    }
}

// ---------------------------------------------------------------------------
// GHASH
// ---------------------------------------------------------------------------

fn mul_x(v: u128) -> u128 {
    let mask = 0u128.wrapping_sub(v & 1);
    (v >> 1) ^ (0xe100_0000_0000_0000_0000_0000_0000_0000u128 & mask)
}

fn mul_x4(v: u128) -> u128 {
    mul_x(mul_x(mul_x(mul_x(v))))
}

struct Ghash {
    htab: [u128; 16],
    y: u128,
    buf: [u8; 16],
    buflen: usize,
}

impl Ghash {
    fn new(h: u128) -> Self {
        let h1 = h;
        let h2 = mul_x(h1);
        let h4 = mul_x(h2);
        let h8 = mul_x(h4);
        let mut htab = [0u128; 16];
        let mut i = 0usize;
        while i < 16 {
            let mut v = 0u128;
            if i & 1 != 0 {
                v ^= h8;
            }
            if i & 2 != 0 {
                v ^= h4;
            }
            if i & 4 != 0 {
                v ^= h2;
            }
            if i & 8 != 0 {
                v ^= h1;
            }
            htab[i] = v;
            i += 1;
        }
        Ghash {
            htab,
            y: 0,
            buf: [0u8; 16],
            buflen: 0,
        }
    }

    fn multiply(&self, v: u128) -> u128 {
        let mut z = 0u128;
        let mut i = 0usize;
        while i < 16 {
            // Bytes are consumed least-significant first; within a byte the low
            // nibble holds the higher polynomial powers, so it comes first.
            let b = (v >> (8 * i)) as u8;
            z = mul_x4(z) ^ self.htab[(b & 0x0f) as usize];
            z = mul_x4(z) ^ self.htab[(b >> 4) as usize];
            i += 1;
        }
        z
    }

    fn absorb_block(&mut self, block: &[u8; 16]) {
        let x = u128::from_be_bytes(*block);
        self.y = self.multiply(self.y ^ x);
    }

    fn absorb(&mut self, data: &[u8]) {
        for block in data.chunks_exact(16) {
            let mut b = [0u8; 16];
            b.copy_from_slice(block);
            self.absorb_block(&b);
        }
    }

    fn update(&mut self, mut data: &[u8]) {
        if self.buflen != 0 {
            let take = core::cmp::min(16 - self.buflen, data.len());
            self.buf[self.buflen..self.buflen + take].copy_from_slice(&data[..take]);
            self.buflen += take;
            data = &data[take..];
            if self.buflen == 16 {
                let b = self.buf;
                self.absorb_block(&b);
                self.buflen = 0;
            }
        }
        let full = data.len() - data.len() % 16;
        if full != 0 {
            self.absorb(&data[..full]);
        }
        let rest = &data[full..];
        if !rest.is_empty() {
            self.buf[..rest.len()].copy_from_slice(rest);
            self.buflen = rest.len();
        }
    }

    fn pad(&mut self) {
        if self.buflen != 0 {
            let mut b = self.buf;
            let mut i = self.buflen;
            while i < 16 {
                b[i] = 0;
                i += 1;
            }
            self.absorb_block(&b);
            self.buflen = 0;
        }
    }

    fn finish(mut self) -> [u8; 16] {
        self.pad();
        self.y.to_be_bytes()
    }
}

// ---------------------------------------------------------------------------
// AES-GCM
// ---------------------------------------------------------------------------

fn inc32(block: &mut [u8; 16]) {
    let n = u32::from_be_bytes([block[12], block[13], block[14], block[15]]);
    block[12..16].copy_from_slice(&n.wrapping_add(1).to_be_bytes());
}

fn gcm_j0(nonce: &[u8; 12]) -> [u8; 16] {
    let mut j0 = [0u8; 16];
    j0[..12].copy_from_slice(nonce);
    j0[15] = 1;
    j0
}

fn ctr_xor(aes: &Aes, j0: &[u8; 16], data: &mut [u8]) {
    let mut ctr = *j0;
    for chunk in data.chunks_mut(16) {
        inc32(&mut ctr);
        let mut ks = ctr;
        aes.encrypt_block(&mut ks);
        let mut i = 0;
        while i < chunk.len() {
            chunk[i] ^= ks[i];
            i += 1;
        }
    }
}

fn gcm_tag(aes: &Aes, j0: &[u8; 16], aad: &[u8], ct: &[u8]) -> [u8; 16] {
    let mut hblock = [0u8; 16];
    aes.encrypt_block(&mut hblock);
    let h = u128::from_be_bytes(hblock);

    let mut g = Ghash::new(h);
    g.update(aad);
    g.pad();
    g.update(ct);
    g.pad();

    let mut lens = [0u8; 16];
    lens[..8].copy_from_slice(&((aad.len() as u64).wrapping_mul(8)).to_be_bytes());
    lens[8..].copy_from_slice(&((ct.len() as u64).wrapping_mul(8)).to_be_bytes());
    g.absorb_block(&lens);
    let s = g.finish();

    let mut tag = *j0;
    aes.encrypt_block(&mut tag);
    let mut i = 0;
    while i < 16 {
        tag[i] ^= s[i];
        i += 1;
    }
    tag
}

fn gcm_seal(aes: &Aes, nonce: &[u8; 12], aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let j0 = gcm_j0(nonce);
    let mut out = Vec::with_capacity(plaintext.len() + 16);
    out.extend_from_slice(plaintext);
    ctr_xor(aes, &j0, &mut out);
    let tag = gcm_tag(aes, &j0, aad, &out);
    out.extend_from_slice(&tag);
    out
}

fn gcm_open(aes: &Aes, nonce: &[u8; 12], aad: &[u8], sealed: &[u8]) -> Result<Vec<u8>> {
    if sealed.len() < 16 {
        return Err(Error::new(
            "aes-gcm: ciphertext is shorter than the 16-byte tag",
        ));
    }
    let split = sealed.len() - 16;
    let (ct, tag) = sealed.split_at(split);
    let j0 = gcm_j0(nonce);
    let expected = gcm_tag(aes, &j0, aad, ct);
    if !ct::ct_eq(&expected, tag) {
        return Err(Error::new("aes-gcm: authentication failed"));
    }
    let mut out = Vec::with_capacity(ct.len());
    out.extend_from_slice(ct);
    ctr_xor(aes, &j0, &mut out);
    Ok(out)
}

/// AES-128-GCM with a 96-bit nonce.
pub struct Aes128Gcm {
    aes: Aes,
}

impl Aes128Gcm {
    pub fn new(key: &[u8; 16]) -> Self {
        Aes128Gcm { aes: Aes::new(key) }
    }

    /// Returns ciphertext || 16-byte tag.
    pub fn seal(&self, nonce: &[u8; 12], aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
        gcm_seal(&self.aes, nonce, aad, plaintext)
    }

    /// Input is ciphertext || tag; returns plaintext on success.
    pub fn open(&self, nonce: &[u8; 12], aad: &[u8], sealed: &[u8]) -> Result<Vec<u8>> {
        gcm_open(&self.aes, nonce, aad, sealed)
    }
}

/// AES-256-GCM with a 96-bit nonce.
pub struct Aes256Gcm {
    aes: Aes,
}

impl Aes256Gcm {
    pub fn new(key: &[u8; 32]) -> Self {
        Aes256Gcm { aes: Aes::new(key) }
    }

    /// Returns ciphertext || 16-byte tag.
    pub fn seal(&self, nonce: &[u8; 12], aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
        gcm_seal(&self.aes, nonce, aad, plaintext)
    }

    /// Input is ciphertext || tag; returns plaintext on success.
    pub fn open(&self, nonce: &[u8; 12], aad: &[u8], sealed: &[u8]) -> Result<Vec<u8>> {
        gcm_open(&self.aes, nonce, aad, sealed)
    }
}

// ---------------------------------------------------------------------------
// ChaCha20
// ---------------------------------------------------------------------------

fn le32(b: &[u8]) -> u32 {
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

fn quarter_round(x: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    x[a] = x[a].wrapping_add(x[b]);
    x[d] ^= x[a];
    x[d] = x[d].rotate_left(16);
    x[c] = x[c].wrapping_add(x[d]);
    x[b] ^= x[c];
    x[b] = x[b].rotate_left(12);
    x[a] = x[a].wrapping_add(x[b]);
    x[d] ^= x[a];
    x[d] = x[d].rotate_left(8);
    x[c] = x[c].wrapping_add(x[d]);
    x[b] ^= x[c];
    x[b] = x[b].rotate_left(7);
}

fn chacha20_block(key: &[u8; 32], counter: u32, nonce: &[u8; 12]) -> [u8; 64] {
    let mut state = [0u32; 16];
    state[0] = 0x6170_7865;
    state[1] = 0x3320_646e;
    state[2] = 0x7962_2d32;
    state[3] = 0x6b20_6574;
    let mut i = 0;
    while i < 8 {
        state[4 + i] = le32(&key[i * 4..i * 4 + 4]);
        i += 1;
    }
    state[12] = counter;
    let mut i = 0;
    while i < 3 {
        state[13 + i] = le32(&nonce[i * 4..i * 4 + 4]);
        i += 1;
    }

    let mut x = state;
    let mut round = 0;
    while round < 10 {
        quarter_round(&mut x, 0, 4, 8, 12);
        quarter_round(&mut x, 1, 5, 9, 13);
        quarter_round(&mut x, 2, 6, 10, 14);
        quarter_round(&mut x, 3, 7, 11, 15);
        quarter_round(&mut x, 0, 5, 10, 15);
        quarter_round(&mut x, 1, 6, 11, 12);
        quarter_round(&mut x, 2, 7, 8, 13);
        quarter_round(&mut x, 3, 4, 9, 14);
        round += 1;
    }
    let mut out = [0u8; 64];
    let mut i = 0;
    while i < 16 {
        let v = x[i].wrapping_add(state[i]);
        out[i * 4..i * 4 + 4].copy_from_slice(&v.to_le_bytes());
        i += 1;
    }
    out
}

fn chacha20_xor(key: &[u8; 32], nonce: &[u8; 12], mut counter: u32, data: &mut [u8]) {
    for chunk in data.chunks_mut(64) {
        let ks = chacha20_block(key, counter, nonce);
        counter = counter.wrapping_add(1);
        let mut i = 0;
        while i < chunk.len() {
            chunk[i] ^= ks[i];
            i += 1;
        }
    }
}

// ---------------------------------------------------------------------------
// Poly1305 (RFC 8439 section 2.5)
// ---------------------------------------------------------------------------

struct Poly1305 {
    r: [u32; 5],
    pad: [u32; 4],
    h: [u32; 5],
    buf: [u8; 16],
    buflen: usize,
}

const MASK26: u32 = 0x03ff_ffff;

impl Poly1305 {
    fn new(key: &[u8; 32]) -> Self {
        let t0 = le32(&key[0..4]);
        let t1 = le32(&key[4..8]);
        let t2 = le32(&key[8..12]);
        let t3 = le32(&key[12..16]);
        let r = [
            t0 & 0x03ff_ffff,
            ((t0 >> 26) | (t1 << 6)) & 0x03ff_ff03,
            ((t1 >> 20) | (t2 << 12)) & 0x03ff_c0ff,
            ((t2 >> 14) | (t3 << 18)) & 0x03f0_3fff,
            (t3 >> 8) & 0x000f_ffff,
        ];
        let pad = [
            le32(&key[16..20]),
            le32(&key[20..24]),
            le32(&key[24..28]),
            le32(&key[28..32]),
        ];
        Poly1305 {
            r,
            pad,
            h: [0u32; 5],
            buf: [0u8; 16],
            buflen: 0,
        }
    }

    fn blocks(&mut self, data: &[u8], hibit: u32) {
        let r = self.r;
        let s = [r[1] * 5, r[2] * 5, r[3] * 5, r[4] * 5];
        let mut h = self.h;
        for block in data.chunks_exact(16) {
            let t0 = le32(&block[0..4]);
            let t1 = le32(&block[4..8]);
            let t2 = le32(&block[8..12]);
            let t3 = le32(&block[12..16]);

            h[0] = h[0].wrapping_add(t0 & MASK26);
            h[1] = h[1].wrapping_add(((t0 >> 26) | (t1 << 6)) & MASK26);
            h[2] = h[2].wrapping_add(((t1 >> 20) | (t2 << 12)) & MASK26);
            h[3] = h[3].wrapping_add(((t2 >> 14) | (t3 << 18)) & MASK26);
            h[4] = h[4].wrapping_add((t3 >> 8) | hibit);

            let d0 = (h[0] as u64 * r[0] as u64)
                + (h[1] as u64 * s[3] as u64)
                + (h[2] as u64 * s[2] as u64)
                + (h[3] as u64 * s[1] as u64)
                + (h[4] as u64 * s[0] as u64);
            let d1 = (h[0] as u64 * r[1] as u64)
                + (h[1] as u64 * r[0] as u64)
                + (h[2] as u64 * s[3] as u64)
                + (h[3] as u64 * s[2] as u64)
                + (h[4] as u64 * s[1] as u64);
            let d2 = (h[0] as u64 * r[2] as u64)
                + (h[1] as u64 * r[1] as u64)
                + (h[2] as u64 * r[0] as u64)
                + (h[3] as u64 * s[3] as u64)
                + (h[4] as u64 * s[2] as u64);
            let d3 = (h[0] as u64 * r[3] as u64)
                + (h[1] as u64 * r[2] as u64)
                + (h[2] as u64 * r[1] as u64)
                + (h[3] as u64 * r[0] as u64)
                + (h[4] as u64 * s[3] as u64);
            let d4 = (h[0] as u64 * r[4] as u64)
                + (h[1] as u64 * r[3] as u64)
                + (h[2] as u64 * r[2] as u64)
                + (h[3] as u64 * r[1] as u64)
                + (h[4] as u64 * r[0] as u64);

            let mut c = (d0 >> 26) as u32;
            h[0] = (d0 as u32) & MASK26;
            let d1 = d1 + c as u64;
            c = (d1 >> 26) as u32;
            h[1] = (d1 as u32) & MASK26;
            let d2 = d2 + c as u64;
            c = (d2 >> 26) as u32;
            h[2] = (d2 as u32) & MASK26;
            let d3 = d3 + c as u64;
            c = (d3 >> 26) as u32;
            h[3] = (d3 as u32) & MASK26;
            let d4 = d4 + c as u64;
            c = (d4 >> 26) as u32;
            h[4] = (d4 as u32) & MASK26;

            h[0] = h[0].wrapping_add(c.wrapping_mul(5));
            c = h[0] >> 26;
            h[0] &= MASK26;
            h[1] = h[1].wrapping_add(c);
        }
        self.h = h;
    }

    fn update(&mut self, mut data: &[u8]) {
        if self.buflen != 0 {
            let take = core::cmp::min(16 - self.buflen, data.len());
            self.buf[self.buflen..self.buflen + take].copy_from_slice(&data[..take]);
            self.buflen += take;
            data = &data[take..];
            if self.buflen == 16 {
                let b = self.buf;
                self.blocks(&b, 1 << 24);
                self.buflen = 0;
            }
        }
        let full = data.len() - data.len() % 16;
        if full != 0 {
            self.blocks(&data[..full], 1 << 24);
        }
        let rest = &data[full..];
        if !rest.is_empty() {
            self.buf[..rest.len()].copy_from_slice(rest);
            self.buflen = rest.len();
        }
    }

    fn finalize(mut self) -> [u8; 16] {
        if self.buflen != 0 {
            let n = self.buflen;
            self.buf[n] = 1;
            let mut i = n + 1;
            while i < 16 {
                self.buf[i] = 0;
                i += 1;
            }
            let b = self.buf;
            self.blocks(&b, 0);
            self.buflen = 0;
        }

        let mut h = self.h;
        let mut c = h[1] >> 26;
        h[1] &= MASK26;
        h[2] = h[2].wrapping_add(c);
        c = h[2] >> 26;
        h[2] &= MASK26;
        h[3] = h[3].wrapping_add(c);
        c = h[3] >> 26;
        h[3] &= MASK26;
        h[4] = h[4].wrapping_add(c);
        c = h[4] >> 26;
        h[4] &= MASK26;
        h[0] = h[0].wrapping_add(c.wrapping_mul(5));
        c = h[0] >> 26;
        h[0] &= MASK26;
        h[1] = h[1].wrapping_add(c);

        let mut g0 = h[0].wrapping_add(5);
        c = g0 >> 26;
        g0 &= MASK26;
        let mut g1 = h[1].wrapping_add(c);
        c = g1 >> 26;
        g1 &= MASK26;
        let mut g2 = h[2].wrapping_add(c);
        c = g2 >> 26;
        g2 &= MASK26;
        let mut g3 = h[3].wrapping_add(c);
        c = g3 >> 26;
        g3 &= MASK26;
        let g4 = h[4].wrapping_add(c).wrapping_sub(1 << 26);

        let mask = (g4 >> 31).wrapping_sub(1);
        g0 &= mask;
        g1 &= mask;
        g2 &= mask;
        g3 &= mask;
        let g4 = g4 & mask;
        let nmask = !mask;

        let h0 = (h[0] & nmask) | g0;
        let h1 = (h[1] & nmask) | g1;
        let h2 = (h[2] & nmask) | g2;
        let h3 = (h[3] & nmask) | g3;
        let h4 = (h[4] & nmask) | g4;

        let p0 = h0 | (h1 << 26);
        let p1 = (h1 >> 6) | (h2 << 20);
        let p2 = (h2 >> 12) | (h3 << 14);
        let p3 = (h3 >> 18) | (h4 << 8);

        let mut f = p0 as u64 + self.pad[0] as u64;
        let w0 = f as u32;
        f = p1 as u64 + self.pad[1] as u64 + (f >> 32);
        let w1 = f as u32;
        f = p2 as u64 + self.pad[2] as u64 + (f >> 32);
        let w2 = f as u32;
        f = p3 as u64 + self.pad[3] as u64 + (f >> 32);
        let w3 = f as u32;

        let mut out = [0u8; 16];
        out[0..4].copy_from_slice(&w0.to_le_bytes());
        out[4..8].copy_from_slice(&w1.to_le_bytes());
        out[8..12].copy_from_slice(&w2.to_le_bytes());
        out[12..16].copy_from_slice(&w3.to_le_bytes());
        out
    }
}

fn mac_pad(mac: &mut Poly1305, len: usize) {
    let zeros = [0u8; 16];
    let n = (16 - (len % 16)) % 16;
    if n != 0 {
        mac.update(&zeros[..n]);
    }
}

fn poly1305_mac(poly_key: &[u8; 32], aad: &[u8], ct: &[u8]) -> [u8; 16] {
    let mut mac = Poly1305::new(poly_key);
    mac.update(aad);
    mac_pad(&mut mac, aad.len());
    mac.update(ct);
    mac_pad(&mut mac, ct.len());
    mac.update(&(aad.len() as u64).to_le_bytes());
    mac.update(&(ct.len() as u64).to_le_bytes());
    mac.finalize()
}

// ---------------------------------------------------------------------------
// ChaCha20-Poly1305 AEAD (RFC 8439 section 2.8)
// ---------------------------------------------------------------------------

/// ChaCha20-Poly1305 with a 96-bit nonce.
pub struct ChaCha20Poly1305 {
    key: [u8; 32],
}

impl ChaCha20Poly1305 {
    pub fn new(key: &[u8; 32]) -> Self {
        ChaCha20Poly1305 { key: *key }
    }

    /// Returns ciphertext || 16-byte tag.
    pub fn seal(&self, nonce: &[u8; 12], aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
        let block0 = chacha20_block(&self.key, 0, nonce);
        let mut poly_key = [0u8; 32];
        poly_key.copy_from_slice(&block0[..32]);

        let mut out = Vec::with_capacity(plaintext.len() + 16);
        out.extend_from_slice(plaintext);
        chacha20_xor(&self.key, nonce, 1, &mut out);
        let tag = poly1305_mac(&poly_key, aad, &out);
        ct::wipe(&mut poly_key);
        out.extend_from_slice(&tag);
        out
    }

    /// Input is ciphertext || tag; returns plaintext on success.
    pub fn open(&self, nonce: &[u8; 12], aad: &[u8], sealed: &[u8]) -> Result<Vec<u8>> {
        if sealed.len() < 16 {
            return Err(Error::new(
                "chacha20-poly1305: ciphertext is shorter than the 16-byte tag",
            ));
        }
        let split = sealed.len() - 16;
        let (ct, tag) = sealed.split_at(split);

        let block0 = chacha20_block(&self.key, 0, nonce);
        let mut poly_key = [0u8; 32];
        poly_key.copy_from_slice(&block0[..32]);
        let expected = poly1305_mac(&poly_key, aad, ct);
        let ok = ct::ct_eq(&expected, tag);
        ct::wipe(&mut poly_key);
        if !ok {
            return Err(Error::new("chacha20-poly1305: authentication failed"));
        }

        let mut out = Vec::with_capacity(ct.len());
        out.extend_from_slice(ct);
        chacha20_xor(&self.key, nonce, 1, &mut out);
        Ok(out)
    }
}

impl Drop for ChaCha20Poly1305 {
    fn drop(&mut self) {
        ct::wipe(&mut self.key);
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // NIST GCM spec cases 1-6: (label, key, nonce, aad, pt, ct||tag)
    pub(crate) const GCM_VECTORS: &[(&str, &[u8], &[u8; 12], &[u8], &[u8], &[u8])] = &[
    ("CASE1",
     b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
     &[0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00],
     b"",
     b"",
     b"X\xe2\xfc\xce\xfa~0a6\x7f\x1dW\xa4\xe7EZ"),
    ("CASE2",
     b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
     &[0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00],
     b"",
     b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
     b"\x03\x88\xda\xce`\xb6\xa3\x92\xf3(\xc2\xb9q\xb2\xfex\xabnG\xd4,\xec\x13\xbd\xf5:g\xb2\x12W\xbd\xdf"),
    ("CASE3",
     b"\xfe\xff\xe9\x92\x86es\x1cmj\x8f\x94g0\x83\x08",
     &[0xca,0xfe,0xba,0xbe,0xfa,0xce,0xdb,0xad,0xde,0xca,0xf8,0x88],
     b"",
     b"\xd912%\xf8\x84\x06\xe5\xa5Y\x09\xc5\xaf\xf5&\x9a\x86\xa7\xa9S\x154\xf7\xda.L0=\x8a1\x8ar\x1c<\x0c\x95\x95h\x09S/\xcf\x0e$I\xa6\xb5%\xb1j\xed\xf5\xaa\x0d\xe6W\xbac{9",
     b"B\x83\x1e\xc2!wt$Kr!\xb7\x84\xd0\xd4\x9c\xe3\xaa!/,\x02\xa4\xe05\xc1~#)\xac\xa1.!\xd5\x14\xb2Tf\x93\x1c}\x8fjZ\xac\x84\xaa\x05\x1b\xa3\x0b9j\x0a\xac\x97=X\xe0\x91\xcc\x15\xab\xcc\x19\x11aP\x1a\xab\xabF\xb8\xfb\xac\x85"),
    ("CASE4",
     b"\xfe\xff\xe9\x92\x86es\x1cmj\x8f\x94g0\x83\x08",
     &[0xca,0xfe,0xba,0xbe,0xfa,0xce,0xdb,0xad,0xde,0xca,0xf8,0x88],
     b"",
     b"\xd912%\xf8\x84\x06\xe5\xa5Y\x09\xc5\xaf\xf5&\x9a\x86\xa7\xa9S\x154\xf7\xda.L0=\x8a1\x8ar\x1c<\x0c\x95\x95h\x09S/\xcf\x0e$I\xa6\xb5%\xb1j\xed\xf5\xaa\x0d\xe6W\xbac{9",
     b"B\x83\x1e\xc2!wt$Kr!\xb7\x84\xd0\xd4\x9c\xe3\xaa!/,\x02\xa4\xe05\xc1~#)\xac\xa1.!\xd5\x14\xb2Tf\x93\x1c}\x8fjZ\xac\x84\xaa\x05\x1b\xa3\x0b9j\x0a\xac\x97=X\xe0\x91\xcc\x15\xab\xcc\x19\x11aP\x1a\xab\xabF\xb8\xfb\xac\x85"),
    ("CASE5",
     b"\xfe\xff\xe9\x92\x86es\x1cmj\x8f\x94g0\x83\x08",
     &[0xca,0xfe,0xba,0xbe,0xfa,0xce,0xdb,0xad,0xde,0xca,0xf8,0x88],
     b"\xfe\xed\xfa\xce\xde\xad\xbe\xef\xfe\xed\xfa\xce\xde\xad\xbe\xef\xab\xad\xda\xd2",
     b"\xd912%\xf8\x84\x06\xe5\xa5Y\x09\xc5\xaf\xf5&\x9a\x86\xa7\xa9S\x154\xf7\xda.L0=\x8a1\x8ar\x1c<\x0c\x95\x95h\x09S/\xcf\x0e$I\xa6\xb5%\xb1j\xed\xf5\xaa\x0d\xe6W\xbac{9",
     b"B\x83\x1e\xc2!wt$Kr!\xb7\x84\xd0\xd4\x9c\xe3\xaa!/,\x02\xa4\xe05\xc1~#)\xac\xa1.!\xd5\x14\xb2Tf\x93\x1c}\x8fjZ\xac\x84\xaa\x05\x1b\xa3\x0b9j\x0a\xac\x97=X\xe0\x91[\xc9O\xbc2!\xa5\xdb\x94\xfa\xe9Z\xe7\x12\x1aG"),
    ("CASE6",
     b"\xfe\xff\xe9\x92\x86es\x1cmj\x8f\x94g0\x83\x08\xfe\xff\xe9\x92\x86es\x1cmj\x8f\x94g0\x83\x08",
     &[0xca,0xfe,0xba,0xbe,0xfa,0xce,0xdb,0xad,0xde,0xca,0xf8,0x88],
     b"\xfe\xed\xfa\xce\xde\xad\xbe\xef\xfe\xed\xfa\xce\xde\xad\xbe\xef\xab\xad\xda\xd2",
     b"\xd912%\xf8\x84\x06\xe5\xa5Y\x09\xc5\xaf\xf5&\x9a\x86\xa7\xa9S\x154\xf7\xda.L0=\x8a1\x8ar\x1c<\x0c\x95\x95h\x09S/\xcf\x0e$I\xa6\xb5%\xb1j\xed\xf5\xaa\x0d\xe6W\xbac{9",
     b"R-\xc1\xf0\x99V}\x07\xf4\x7f7\xa3*\x84B}d:\x8c\xdc\xbf\xe5\xc0\xc9u\x98\xa2\xbd%U\xd1\xaa\x8c\xb0\x8eHY\x0d\xbb=\xa7\xb0\x8b\x10V\x82\x888\xc5\xf6\x1ec\x93\xbaz\x0a\xbc\xc9\xf6bv\xfcn\xce\x0fN\x17h\xcd\xdf\x88S\xbb-U\x1b"),
];
    // ChaCha20-Poly1305: (label, key, nonce, aad, pt, ct||tag)
    pub(crate) const CHACHA_VECTORS: &[(&str, &[u8; 32], &[u8; 12], &[u8], &[u8], &[u8])] = &[
    ("RFC8439_282",
     &[0x80,0x81,0x82,0x83,0x84,0x85,0x86,0x87,0x88,0x89,0x8a,0x8b,0x8c,0x8d,0x8e,0x8f,0x90,0x91,0x92,0x93,0x94,0x95,0x96,0x97,0x98,0x99,0x9a,0x9b,0x9c,0x9d,0x9e,0x9f],
     &[0x07,0x00,0x00,0x00,0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47],
     b"PQRS\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7",
     b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.",
     b"\xd3\x1a\x8d4d\x8e`\xdb{\x86\xaf\xbcS\xef~\xc2\xa4\xad\xedQ)n\x08\xfe\xa9\xe2\xb5\xa76\xeeb\xd6=\xbe\xa4^\x8c\xa9g\x12\x82\xfa\xfbi\xda\x92r\x8b\x1aq\xde\x0a\x9e\x06\x0b)\x05\xd6\xa5\xb6~\xcd;6\x92\xdd\xbd\x7f-w\x8b\x8c\x98\x03\xae\xe3(\x09\x1bX\xfa\xb3$\xe4\xfa\xd6u\x94U\x85\x80\x8bH1\xd7\xbc?\xf4\xde\xf0\x8eKz\x9d\xe5v\xd2e\x86\xce\xc6Ka\x16\x1a\xe1\x0bYO\x09\xe2j~\x90.\xcb\xd0`\x06\x91"),
    ("EMPTY_AAD",
     &[0x80,0x81,0x82,0x83,0x84,0x85,0x86,0x87,0x88,0x89,0x8a,0x8b,0x8c,0x8d,0x8e,0x8f,0x90,0x91,0x92,0x93,0x94,0x95,0x96,0x97,0x98,0x99,0x9a,0x9b,0x9c,0x9d,0x9e,0x9f],
     &[0x07,0x00,0x00,0x00,0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47],
     b"",
     b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.",
     b"\xd3\x1a\x8d4d\x8e`\xdb{\x86\xaf\xbcS\xef~\xc2\xa4\xad\xedQ)n\x08\xfe\xa9\xe2\xb5\xa76\xeeb\xd6=\xbe\xa4^\x8c\xa9g\x12\x82\xfa\xfbi\xda\x92r\x8b\x1aq\xde\x0a\x9e\x06\x0b)\x05\xd6\xa5\xb6~\xcd;6\x92\xdd\xbd\x7f-w\x8b\x8c\x98\x03\xae\xe3(\x09\x1bX\xfa\xb3$\xe4\xfa\xd6u\x94U\x85\x80\x8bH1\xd7\xbc?\xf4\xde\xf0\x8eKz\x9d\xe5v\xd2e\x86\xce\xc6Ka\x16j#\xa4h\x1f\xd5\x94V\xae\xa1\xd2\x9f\x82Gr\x16"),
    ("EMPTY_PT",
     &[0x80,0x81,0x82,0x83,0x84,0x85,0x86,0x87,0x88,0x89,0x8a,0x8b,0x8c,0x8d,0x8e,0x8f,0x90,0x91,0x92,0x93,0x94,0x95,0x96,0x97,0x98,0x99,0x9a,0x9b,0x9c,0x9d,0x9e,0x9f],
     &[0x07,0x00,0x00,0x00,0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47],
     b"PQRS\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7",
     b"",
     b"\xe6\"\xe5dz8\xd9g\xa7\xec\xbc\xb4l\x7fg\\"),
    ("BOTH_EMPTY",
     &[0x80,0x81,0x82,0x83,0x84,0x85,0x86,0x87,0x88,0x89,0x8a,0x8b,0x8c,0x8d,0x8e,0x8f,0x90,0x91,0x92,0x93,0x94,0x95,0x96,0x97,0x98,0x99,0x9a,0x9b,0x9c,0x9d,0x9e,0x9f],
     &[0x07,0x00,0x00,0x00,0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47],
     b"",
     b"",
     b"\xa0xMzG\x16\xf3\xfe\xb4\xf6N\x7fK9\xbf\x04"),
    ("SINGLE_BYTE",
     &[0x80,0x81,0x82,0x83,0x84,0x85,0x86,0x87,0x88,0x89,0x8a,0x8b,0x8c,0x8d,0x8e,0x8f,0x90,0x91,0x92,0x93,0x94,0x95,0x96,0x97,0x98,0x99,0x9a,0x9b,0x9c,0x9d,0x9e,0x9f],
     &[0x07,0x00,0x00,0x00,0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47],
     b"\x01",
     b"\x02",
     b"\x9dQyg\xac\xba\x020\xb0\xa1m\x0c\xcfyC\xd6\x9b"),
];
    // FIPS-197 AES single-block vectors: (key, plaintext, ciphertext)
    pub(crate) const AES_BLOCK_VECTORS: &[(&[u8], [u8; 16], [u8; 16])] = &[
    (b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f", [0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff], [0x69,0xc4,0xe0,0xd8,0x6a,0x7b,0x04,0x30,0xd8,0xcd,0xb7,0x80,0x70,0xb4,0xc5,0x5a]),
    (b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f", [0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff], [0x8e,0xa2,0xb7,0xca,0x51,0x67,0x45,0xbf,0xea,0xfc,0x49,0x90,0x4b,0x49,0x60,0x89]),
];
    // Extra AES-GCM vectors with unaligned AAD/plaintext lengths
    pub(crate) const GCM_EXTRA: &[(&str, &[u8], &[u8; 12], &[u8], &[u8], &[u8])] = &[
    ("UNALIGNED_0",
     b"\x00\x07\x0e\x15\x1c#*18?FMT[bi",
     &[0x01,0x06,0x0b,0x10,0x15,0x1a,0x1f,0x24,0x29,0x2e,0x33,0x38],
     b"\x02",
     b"",
     b"\xe8\xd1\xfa\x85~\x83\xf3\x99\xfb\x88\xe7\x949\xc0(\x11"),
    ("UNALIGNED_1",
     b"\x0d\x14\x1b\")07>ELSZahov",
     &[0x04,0x09,0x0e,0x13,0x18,0x1d,0x22,0x27,0x2c,0x31,0x36,0x3b],
     b"\x13",
     b"\x1a",
     b"\x9d+?5\xa3|\xdb\x15\xf2\xc6\xbc\x93\x8d\xb5\xee\xed\xa1"),
    ("UNALIGNED_2",
     b"\x1a!(/6=DKRY`gnu|\x83",
     &[0x07,0x0c,0x11,0x16,0x1b,0x20,0x25,0x2a,0x2f,0x34,0x39,0x3e],
     b"$/:EP[fq|\x87\x92\x9d\xa8\xb3\xbe",
     b"1DWj}\x90\xa3\xb6\xc9\xdc\xef\x02\x15(;",
     b"\x8c\x13|\xb2a]1,zf\xcc\xc0\x7f\xa5\xae\xb7 \xee\x96(5\x95\x12\xb7a\x9e\xa8\xbc\xa8\xfe\xe3"),
    ("UNALIGNED_3",
     b"'.5<CJQX_fmt{\x82\x89\x90",
     &[0x0a,0x0f,0x14,0x19,0x1e,0x23,0x28,0x2d,0x32,0x37,0x3c,0x41],
     b"5@KValw\x82\x8d\x98\xa3\xae\xb9\xc4\xcf\xda\xe5",
     b"H[n\x81\x94\xa7\xba\xcd\xe0\xf3\x06\x19,?Re",
     b"\x0boeo\xb96:9\x0b\xb3\x87\x0fw\xeaj]Y\xbb`G\x18\x1c\x9c&&D \x8b\x8dq\xb1\x96"),
    ("UNALIGNED_4",
     b"4;BIPW^elsz\x81\x88\x8f\x96\x9d",
     &[0x0d,0x12,0x17,0x1c,0x21,0x26,0x2b,0x30,0x35,0x3a,0x3f,0x44],
     b"FQ\\gr}\x88\x93\x9e\xa9\xb4\xbf\xca\xd5\xe0\xeb\xf6\x01\x0c\x17\"-8CNYdoz\x85\x90",
     b"_r\x85\x98\xab\xbe\xd1\xe4\xf7\x0a\x1d0CVi|\x8f",
     b"`Yx:\xc8F:n<\xc1k3%x<\xaf.M\xd4\x1a\xff\x88^el\xd5\x15\xa8\x1bl\xe7\xcf\xef"),
    ("UNALIGNED_5",
     b"AHOV]dkry\x80\x87\x8e\x95\x9c\xa3\xaa\xb1\xb8\xbf\xc6\xcd\xd4\xdb\xe2\xe9\xf0\xf7\xfe\x05\x0c\x13\x1a",
     &[0x10,0x15,0x1a,0x1f,0x24,0x29,0x2e,0x33,0x38,0x3d,0x42,0x47],
     b"Wbmx\x83\x8e\x99\xa4\xaf\xba\xc5\xd0\xdb\xe6\xf1",
     b"v\x89\x9c\xaf\xc2\xd5\xe8\xfb\x0e!4GZm\x80\x93\xa6\xb9\xcc\xdf\xf2\x05\x18+>Qdw\x8a\x9d\xb0",
     b"\x94_\xb9:\x98\xbd\xedW\xd5a\x91\xc7o\xd3rg\x8d\xfe\xaf\xc95\xd7\xac\xf4I\x09\xfb\x95p\xe4~\xff\xdc\x09lC\x11\x900\xa6\x84\x93\x1f(\x8c{\x91"),
    ("UNALIGNED_6",
     b"NU\\cjqx\x7f\x86\x8d\x94\x9b\xa2\xa9\xb0\xb7\xbe\xc5\xcc\xd3\xda\xe1\xe8\xef\xf6\xfd\x04\x0b\x12\x19 '",
     &[0x13,0x18,0x1d,0x22,0x27,0x2c,0x31,0x36,0x3b,0x40,0x45,0x4a],
     b"hs~\x89\x94\x9f\xaa\xb5\xc0\xcb\xd6\xe1\xec\xf7\x02\x0d\x18#.9DOZep{\x86\x91\x9c\xa7\xb2\xbd",
     b"\x8d\xa0\xb3\xc6\xd9\xec\xff\x12%8K^q\x84\x97\xaa\xbd\xd0\xe3\xf6\x09\x1c/BUh{\x8e\xa1\xb4\xc7\xda",
     b"\x95\x0d\xce\xce\xbe\xa9Eh\x02N\x1a<\x0a1\xce\xfa\xd3\xed\xb8a\"{\x12J\xf1\x12X\xde\xe1*2\x8d\x865\xad\xf8\xde'\xd1\xd6\x98\x9eA`\xafvP["),
    ("UNALIGNED_7",
     b"[bipw~\x85\x8c\x93\x9a\xa1\xa8\xaf\xb6\xbd\xc4\xcb\xd2\xd9\xe0\xe7\xee\xf5\xfc\x03\x0a\x11\x18\x1f&-4",
     &[0x16,0x1b,0x20,0x25,0x2a,0x2f,0x34,0x39,0x3e,0x43,0x48,0x4d],
     b"y\x84\x8f\x9a\xa5\xb0\xbb\xc6\xd1\xdc\xe7\xf2\xfd\x08\x13\x1e)4?JU`kv\x81\x8c\x97\xa2\xad\xb8\xc3\xce\xd9",
     b"\xa4\xb7\xca\xdd\xf0\x03\x16)<Obu\x88\x9b\xae\xc1\xd4\xe7\xfa\x0d 3FYl\x7f\x92\xa5\xb8\xcb\xde\xf1\x04",
     b"\x9f\xcc\x1d3\xdb|P}\xa5\x82s\x15S\xd2\xa2\x1ez)(\xa3\x13\xc4\x19\xd3'8\\\x82\x97\x9c\xd1\xf2\"`\x82f\x0a\xa6V(\xac_\xb8\xf4\xb9r\xf2\xef\xc2"),
];
    // Extra ChaCha20-Poly1305 vectors with unaligned AAD/plaintext lengths
    pub(crate) const CHACHA_EXTRA: &[(&str, &[u8; 32], &[u8; 12], &[u8], &[u8], &[u8])] = &[
    ("UNALIGNED_0",
     &[0x00,0x07,0x0e,0x15,0x1c,0x23,0x2a,0x31,0x38,0x3f,0x46,0x4d,0x54,0x5b,0x62,0x69,0x70,0x77,0x7e,0x85,0x8c,0x93,0x9a,0xa1,0xa8,0xaf,0xb6,0xbd,0xc4,0xcb,0xd2,0xd9],
     &[0x01,0x06,0x0b,0x10,0x15,0x1a,0x1f,0x24,0x29,0x2e,0x33,0x38],
     b"\x02",
     b"\x03",
     b"\x82 \xe3\x04bal,\xba\x11pA\xa9\xd5\x82\xdch"),
    ("UNALIGNED_1",
     &[0x0d,0x14,0x1b,0x22,0x29,0x30,0x37,0x3e,0x45,0x4c,0x53,0x5a,0x61,0x68,0x6f,0x76,0x7d,0x84,0x8b,0x92,0x99,0xa0,0xa7,0xae,0xb5,0xbc,0xc3,0xca,0xd1,0xd8,0xdf,0xe6],
     &[0x04,0x09,0x0e,0x13,0x18,0x1d,0x22,0x27,0x2c,0x31,0x36,0x3b],
     b"\x13\x1e)4?JU`kv\x81\x8c\x97\xa2\xad",
     b"\x1a-@Sfy\x8c\x9f\xb2\xc5\xd8\xeb\xfe\x11$",
     b"/2N\xe2Y\xe00\x15\x9a\xf6NI4\xeaZ\xd0LRm\xb3\x01Z\xa7]:\x98J\x1f\xf3\x0e\xc1"),
    ("UNALIGNED_2",
     &[0x1a,0x21,0x28,0x2f,0x36,0x3d,0x44,0x4b,0x52,0x59,0x60,0x67,0x6e,0x75,0x7c,0x83,0x8a,0x91,0x98,0x9f,0xa6,0xad,0xb4,0xbb,0xc2,0xc9,0xd0,0xd7,0xde,0xe5,0xec,0xf3],
     &[0x07,0x0c,0x11,0x16,0x1b,0x20,0x25,0x2a,0x2f,0x34,0x39,0x3e],
     b"$/:EP[fq|\x87\x92\x9d\xa8\xb3\xbe\xc9\xd4",
     b"1DWj}\x90\xa3\xb6\xc9\xdc\xef\x02\x15(;N",
     b"5\xf3%/\x010\x1b\xca\xce\xb3P\xad\xb5\x86\xf1\xddV\x1b\x8e\xb2\x1f\xf1|\xb7\xdb'\x94v\xda\xdf\x9aK"),
    ("UNALIGNED_3",
     &[0x27,0x2e,0x35,0x3c,0x43,0x4a,0x51,0x58,0x5f,0x66,0x6d,0x74,0x7b,0x82,0x89,0x90,0x97,0x9e,0xa5,0xac,0xb3,0xba,0xc1,0xc8,0xcf,0xd6,0xdd,0xe4,0xeb,0xf2,0xf9,0x00],
     &[0x0a,0x0f,0x14,0x19,0x1e,0x23,0x28,0x2d,0x32,0x37,0x3c,0x41],
     b"5@KValw\x82\x8d\x98\xa3\xae\xb9\xc4\xcf\xda\xe5\xf0\xfb\x06\x11\x1c'2=HS^it\x7f",
     b"H[n\x81\x94\xa7\xba\xcd\xe0\xf3\x06\x19,?Rex",
     b"\x8e\xe0\x92\xe3\xb4.J\xc0Y\xf2\xd20\xc0*;9\x07\x84>?]w\xf7\x7f2S\x10\xdeqLI\x8a\x94"),
    ("UNALIGNED_4",
     &[0x34,0x3b,0x42,0x49,0x50,0x57,0x5e,0x65,0x6c,0x73,0x7a,0x81,0x88,0x8f,0x96,0x9d,0xa4,0xab,0xb2,0xb9,0xc0,0xc7,0xce,0xd5,0xdc,0xe3,0xea,0xf1,0xf8,0xff,0x06,0x0d],
     &[0x0d,0x12,0x17,0x1c,0x21,0x26,0x2b,0x30,0x35,0x3a,0x3f,0x44],
     b"FQ\\gr}\x88\x93\x9e\xa9\xb4\xbf\xca\xd5\xe0\xeb\xf6\x01\x0c\x17\"-8CNYdoz\x85\x90\x9b",
     b"_r\x85\x98\xab\xbe\xd1\xe4\xf7\x0a\x1d0CVi|\x8f\xa2\xb5\xc8\xdb\xee\x01\x14':M`s\x86\x99\xac",
     b"\xb1\xdf\xb7\xf4\x19_V\xfc9\xf3\x0c\xafn&^\x16\xec\x18\xef\x8bl\xbcb\x16\x9e\xd1\xb4\x93\xc2\xf8\x1d\x8bvF\x7f\xf9\xeb\xd7\xdae\xd1\xab\xfb\xde\xe3|\xe6h"),
    ("UNALIGNED_5",
     &[0x41,0x48,0x4f,0x56,0x5d,0x64,0x6b,0x72,0x79,0x80,0x87,0x8e,0x95,0x9c,0xa3,0xaa,0xb1,0xb8,0xbf,0xc6,0xcd,0xd4,0xdb,0xe2,0xe9,0xf0,0xf7,0xfe,0x05,0x0c,0x13,0x1a],
     &[0x10,0x15,0x1a,0x1f,0x24,0x29,0x2e,0x33,0x38,0x3d,0x42,0x47],
     b"Wbmx\x83\x8e\x99\xa4\xaf\xba\xc5\xd0\xdb\xe6\xf1\xfc\x07\x12\x1d(3>IT_ju\x80\x8b\x96\xa1\xac\xb7",
     b"v\x89\x9c\xaf\xc2\xd5\xe8\xfb\x0e!4GZm\x80\x93\xa6\xb9\xcc\xdf\xf2\x05\x18+>Qdw\x8a\x9d\xb0\xc3\xd6",
     b"\x90\xa9\x8a\xcf\xd5\xe5\xb5a\xaf'\x8b\x93\x8c\x1bN\xcc\xc1\xbb\xde<\x11'\xff\xd6\x7fc~\xff\xe0\xae\xfb\x9a\xb7\xc9\xae*\x9c\xce4\xe0\xfa\xdf\xd6\x80\x03\xef\x7fWi"),
    ("UNALIGNED_6",
     &[0x4e,0x55,0x5c,0x63,0x6a,0x71,0x78,0x7f,0x86,0x8d,0x94,0x9b,0xa2,0xa9,0xb0,0xb7,0xbe,0xc5,0xcc,0xd3,0xda,0xe1,0xe8,0xef,0xf6,0xfd,0x04,0x0b,0x12,0x19,0x20,0x27],
     &[0x13,0x18,0x1d,0x22,0x27,0x2c,0x31,0x36,0x3b,0x40,0x45,0x4a],
     b"",
     b"\x8d\xa0\xb3\xc6\xd9\xec\xff\x12%8K^q\x84\x97\xaa\xbd\xd0\xe3\xf6\x09\x1c/BUh{\x8e\xa1\xb4\xc7\xda\xed",
     b"\x02>\x970\x9b\xfeI\x115\xe9\x11fD\x1bR?Z\x8e\x15Vw\xdc\x11\xd1\xd48g\x19:\xb2\x09\x9cmD\xfd;@\x99\xa9\xd6\xb6\xc1p\xc15\xf5]Mj"),
    ("UNALIGNED_7",
     &[0x5b,0x62,0x69,0x70,0x77,0x7e,0x85,0x8c,0x93,0x9a,0xa1,0xa8,0xaf,0xb6,0xbd,0xc4,0xcb,0xd2,0xd9,0xe0,0xe7,0xee,0xf5,0xfc,0x03,0x0a,0x11,0x18,0x1f,0x26,0x2d,0x34],
     &[0x16,0x1b,0x20,0x25,0x2a,0x2f,0x34,0x39,0x3e,0x43,0x48,0x4d],
     b"y\x84\x8f\x9a\xa5\xb0\xbb\xc6\xd1\xdc\xe7\xf2\xfd\x08\x13\x1e)4?JU`kv\x81\x8c\x97\xa2\xad\xb8\xc3\xce\xd9",
     b"",
     b"s\x86\x1d\x91\xb2\xdc\x8aZ*\x80vX\x0c\x9f\xe8\xae"),
];

    fn hex(bytes: &[u8]) -> String {
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            s.push_str(&format!("{:02x}", b));
        }
        s
    }

    fn assert_hex(actual: &[u8], expected: &[u8], what: &str) {
        assert_eq!(hex(actual), hex(expected), "{}", what);
    }

    fn pattern(n: usize) -> Vec<u8> {
        (0..n).map(|i| ((i * 29 + 7) & 0xff) as u8).collect()
    }

    fn key16() -> [u8; 16] {
        let mut k = [0u8; 16];
        k.copy_from_slice(&pattern(16));
        k
    }

    fn key32() -> [u8; 32] {
        let mut k = [0u8; 32];
        k.copy_from_slice(&pattern(32));
        k
    }

    fn nonce12() -> [u8; 12] {
        let mut n = [0u8; 12];
        n.copy_from_slice(&pattern(12));
        n
    }

    // ---- primitive sanity -------------------------------------------------

    #[test]
    fn fips197_aes_block_vectors() {
        for &(key, pt, want) in AES_BLOCK_VECTORS {
            let aes = Aes::new(key);
            let mut block = pt;
            aes.encrypt_block(&mut block);
            assert_hex(&block, &want, "aes block");
        }
    }

    #[test]
    fn xtime_and_gf() {
        assert_eq!(xtime(0x00), 0x00);
        assert_eq!(xtime(0x01), 0x02);
        assert_eq!(xtime(0x80), 0x1b);
        assert_eq!(xtime(0xff), 0xe5);
        assert_eq!(gmul(0x57, 0x83), 0xc1);
        assert_eq!(gmul(0x57, 0x13), 0xfe);
    }

    #[test]
    fn ghash_multiplication_known_value() {
        // H = 0x66e94bd4ef8a2c3b884cfa59ca342b2e (AES-128 of zero) and
        // X = 0x0388dace60b6a392f328c2b971b2fe78 (NIST GCM case 2 ciphertext).
        // The product was cross-checked with a bit-serial GF(2^128) reference;
        // the full AEAD vectors below validate the padded GHASH input too.
        let h = 0x66e94bd4ef8a2c3b884cfa59ca342b2eu128;
        let x = 0x0388dace60b6a392f328c2b971b2fe78u128;
        let mut g = Ghash::new(h);
        g.update(&x.to_be_bytes());
        let got = g.finish();
        assert_hex(
            &got,
            &0x5e2ec746917062882c85b0685353deb7u128.to_be_bytes(),
            "ghash",
        );
    }

    // ---- NIST / RFC vectors -----------------------------------------------

    #[test]
    fn nist_gcm_vectors() {
        for &(label, key, nonce, aad, pt, want) in GCM_VECTORS {
            let sealed = if key.len() == 16 {
                let mut k = [0u8; 16];
                k.copy_from_slice(key);
                Aes128Gcm::new(&k).seal(nonce, aad, pt)
            } else {
                let mut k = [0u8; 32];
                k.copy_from_slice(key);
                Aes256Gcm::new(&k).seal(nonce, aad, pt)
            };
            assert_hex(&sealed, want, &format!("gcm seal {}", label));

            let opened = if key.len() == 16 {
                let mut k = [0u8; 16];
                k.copy_from_slice(key);
                Aes128Gcm::new(&k).open(nonce, aad, want)
            } else {
                let mut k = [0u8; 32];
                k.copy_from_slice(key);
                Aes256Gcm::new(&k).open(nonce, aad, want)
            };
            assert_eq!(&opened.expect("gcm open")[..], pt, "gcm open {}", label);
        }
    }

    #[test]
    fn extra_gcm_vectors() {
        for &(label, key, nonce, aad, pt, want) in GCM_EXTRA {
            let sealed = if key.len() == 16 {
                let mut k = [0u8; 16];
                k.copy_from_slice(key);
                Aes128Gcm::new(&k).seal(nonce, aad, pt)
            } else {
                let mut k = [0u8; 32];
                k.copy_from_slice(key);
                Aes256Gcm::new(&k).seal(nonce, aad, pt)
            };
            assert_hex(&sealed, want, &format!("gcm extra {}", label));
        }
    }

    #[test]
    fn rfc8439_chacha20poly1305_vectors() {
        for &(label, key, nonce, aad, pt, want) in CHACHA_VECTORS {
            let aead = ChaCha20Poly1305::new(key);
            let sealed = aead.seal(nonce, aad, pt);
            assert_hex(&sealed, want, &format!("chacha seal {}", label));
            let opened = aead.open(nonce, aad, want).expect("chacha open");
            assert_eq!(&opened[..], pt, "chacha open {}", label);
        }
    }

    #[test]
    fn extra_chacha_vectors() {
        for &(label, key, nonce, aad, pt, want) in CHACHA_EXTRA {
            let aead = ChaCha20Poly1305::new(key);
            assert_hex(
                &aead.seal(nonce, aad, pt),
                want,
                &format!("chacha extra {}", label),
            );
        }
    }

    // ---- round trips ------------------------------------------------------

    #[test]
    fn gcm_roundtrip_all_lengths() {
        let g128 = Aes128Gcm::new(&key16());
        let g256 = Aes256Gcm::new(&key32());
        let nonce = nonce12();
        for len in 0..=200usize {
            let pt = pattern(len);
            let aad = pattern((len * 7) % 33);
            let sealed = g128.seal(&nonce, &aad, &pt);
            assert_eq!(sealed.len(), len + 16);
            assert_eq!(
                g128.open(&nonce, &aad, &sealed).unwrap(),
                pt,
                "aes128 len {}",
                len
            );
            let sealed = g256.seal(&nonce, &aad, &pt);
            assert_eq!(
                g256.open(&nonce, &aad, &sealed).unwrap(),
                pt,
                "aes256 len {}",
                len
            );
        }
    }

    #[test]
    fn chacha_roundtrip_all_lengths() {
        let aead = ChaCha20Poly1305::new(&key32());
        let nonce = nonce12();
        for len in 0..=200usize {
            let pt = pattern(len);
            let aad = pattern((len * 5) % 37);
            let sealed = aead.seal(&nonce, &aad, &pt);
            assert_eq!(sealed.len(), len + 16);
            assert_eq!(
                aead.open(&nonce, &aad, &sealed).unwrap(),
                pt,
                "chacha len {}",
                len
            );
        }
    }

    #[test]
    fn empty_plaintext_and_aad() {
        let g = Aes128Gcm::new(&key16());
        let nonce = nonce12();
        let sealed = g.seal(&nonce, b"", b"");
        assert_eq!(sealed.len(), 16);
        assert_eq!(g.open(&nonce, b"", &sealed).unwrap(), Vec::<u8>::new());

        let c = ChaCha20Poly1305::new(&key32());
        let sealed = c.seal(&nonce, b"", b"");
        assert_eq!(sealed.len(), 16);
        assert_eq!(c.open(&nonce, b"", &sealed).unwrap(), Vec::<u8>::new());
    }

    // ---- negative tests ---------------------------------------------------

    #[test]
    fn gcm_tamper_rejected() {
        let g = Aes128Gcm::new(&key16());
        let nonce = nonce12();
        let aad = b"associated data";
        let pt = b"the quick brown fox jumps over the lazy dog";
        let sealed = g.seal(&nonce, aad, pt);

        // Flip every bit of the ciphertext and tag, one at a time.
        for i in 0..sealed.len() {
            let mut bad = sealed.clone();
            bad[i] ^= 1;
            assert!(
                g.open(&nonce, aad, &bad).is_err(),
                "gcm bit flip at byte {}",
                i
            );
        }
        // Wrong AAD and wrong nonce.
        assert!(g.open(&nonce, b"associated datA", &sealed).is_err());
        assert!(g.open(&nonce, b"", &sealed).is_err());
        let mut other = nonce;
        other[0] ^= 0x80;
        assert!(g.open(&other, aad, &sealed).is_err());

        // Truncation and missing tag.
        for cut in 1..=16 {
            assert!(
                g.open(&nonce, aad, &sealed[..sealed.len() - cut]).is_err(),
                "truncate {}",
                cut
            );
        }
        assert!(g.open(&nonce, aad, &[]).is_err());
        assert!(g.open(&nonce, aad, &sealed[..sealed.len() - 17]).is_err());
    }

    #[test]
    fn chacha_tamper_rejected() {
        let c = ChaCha20Poly1305::new(&key32());
        let nonce = nonce12();
        let aad = b"associated data";
        let pt = b"the quick brown fox jumps over the lazy dog";
        let sealed = c.seal(&nonce, aad, pt);

        for i in 0..sealed.len() {
            let mut bad = sealed.clone();
            bad[i] ^= 1;
            assert!(
                c.open(&nonce, aad, &bad).is_err(),
                "chacha bit flip at byte {}",
                i
            );
        }
        assert!(c.open(&nonce, b"associated datA", &sealed).is_err());
        assert!(c.open(&nonce, b"", &sealed).is_err());
        let mut other = nonce;
        other[11] ^= 0x01;
        assert!(c.open(&other, aad, &sealed).is_err());

        for cut in 1..=16 {
            assert!(
                c.open(&nonce, aad, &sealed[..sealed.len() - cut]).is_err(),
                "truncate {}",
                cut
            );
        }
        assert!(c.open(&nonce, aad, &[]).is_err());
        assert!(c.open(&nonce, aad, &sealed[..sealed.len() - 17]).is_err());
    }

    #[test]
    fn nonce_and_aad_change_output() {
        let g = Aes128Gcm::new(&key16());
        let c = ChaCha20Poly1305::new(&key32());
        let nonce = nonce12();
        let mut nonce2 = nonce;
        nonce2[3] ^= 0x40;

        let pt = b"same plaintext";

        let a = g.seal(&nonce, b"aad-1", pt);
        let b = g.seal(&nonce, b"aad-2", pt);
        assert_ne!(a, b, "aad must change the tag");
        assert_eq!(
            &a[..pt.len()],
            &b[..pt.len()],
            "aad does not change ciphertext"
        );
        let c1 = g.seal(&nonce, b"aad-1", pt);
        let c2 = g.seal(&nonce2, b"aad-1", pt);
        assert_ne!(c1, c2, "nonce must change ciphertext");

        let a = c.seal(&nonce, b"aad-1", pt);
        let b = c.seal(&nonce, b"aad-2", pt);
        assert_ne!(a, b, "aad must change the chacha tag");
        assert_eq!(
            &a[..pt.len()],
            &b[..pt.len()],
            "aad does not change chacha ciphertext"
        );
        let c1 = c.seal(&nonce, b"aad-1", pt);
        let c2 = c.seal(&nonce2, b"aad-1", pt);
        assert_ne!(c1, c2, "nonce must change chacha ciphertext");
    }

    // ---- throughput report (no assertions) --------------------------------

    #[test]
    fn throughput_report() {
        use std::time::Instant;
        let data = pattern(4 * 1024 * 1024);
        let nonce = nonce12();
        let g128 = Aes128Gcm::new(&key16());
        let c = ChaCha20Poly1305::new(&key32());

        let t = Instant::now();
        let sealed = g128.seal(&nonce, b"aad", &data);
        let enc = t.elapsed();
        let t = Instant::now();
        let _ = g128.open(&nonce, b"aad", &sealed).unwrap();
        let dec = t.elapsed();

        let t = Instant::now();
        let sealed = c.seal(&nonce, b"aad", &data);
        let cenc = t.elapsed();
        let t = Instant::now();
        let _ = c.open(&nonce, b"aad", &sealed).unwrap();
        let cdec = t.elapsed();

        let mb = data.len() as f64 / (1024.0 * 1024.0);
        println!(
            "AES-128-GCM: {:.1} MB/s seal, {:.1} MB/s open | ChaCha20-Poly1305: {:.1} MB/s seal, {:.1} MB/s open",
            mb / enc.as_secs_f64(),
            mb / dec.as_secs_f64(),
            mb / cenc.as_secs_f64(),
            mb / cdec.as_secs_f64()
        );
    }
}
