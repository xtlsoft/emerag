//! X25519 (RFC 7748) and NIST P-256/P-384.
//!
//! X25519 uses the Montgomery ladder over GF(2^255-19) with 5x51-bit limbs.
//! P-256 and P-384 share one generic implementation: Montgomery field
//! arithmetic, Jacobian coordinates with the a = -3 formulas, and a fixed
//! 4-bit window scalar multiplication whose table lookups and point-addition
//! special cases are resolved without secret-dependent branches.
//!
//! P-384 is provided for X.509 certificate chain verification (ECDSA P-384 is
//! common in public roots); ECDH is implemented for symmetry but is not used by
//! the TLS client.

use crate::ct::ct_eq_u8;
use crate::rsa::HashAlg;
use crate::{Error, Result};

// ===========================================================================
// X25519 (RFC 7748)
// ===========================================================================

type Fe = [u64; 5];
const FE_MASK: u64 = (1u64 << 51) - 1;
const X25519_A24: u64 = 121665;
const X25519_BASE: [u8; 32] = {
    let mut b = [0u8; 32];
    b[0] = 9;
    b
};

fn load8(b: &[u8], off: usize) -> u64 {
    let mut v = 0u64;
    for i in 0..8 {
        v |= (b[off + i] as u64) << (8 * i);
    }
    v
}

fn fe_from_bytes(b: &[u8; 32]) -> Fe {
    let mut h = [0u64; 5];
    h[0] = load8(b, 0) & FE_MASK;
    h[1] = (load8(b, 6) >> 3) & FE_MASK;
    h[2] = (load8(b, 12) >> 6) & FE_MASK;
    h[3] = (load8(b, 19) >> 1) & FE_MASK;
    h[4] = (load8(b, 24) >> 12) & FE_MASK;
    h
}

/// Carry-propagate base 2^51 limbs, folding bit 255 back as 2^255 = 19.
fn fe_carry(mut h: Fe) -> Fe {
    for _ in 0..2 {
        let c0 = h[0] >> 51;
        h[0] &= FE_MASK;
        h[1] += c0;
        let c1 = h[1] >> 51;
        h[1] &= FE_MASK;
        h[2] += c1;
        let c2 = h[2] >> 51;
        h[2] &= FE_MASK;
        h[3] += c2;
        let c3 = h[3] >> 51;
        h[3] &= FE_MASK;
        h[4] += c3;
        let c4 = h[4] >> 51;
        h[4] &= FE_MASK;
        h[0] += c4 * 19;
    }
    h
}

fn fe_add(a: &Fe, b: &Fe) -> Fe {
    let mut h = [0u64; 5];
    let mut carry = 0u64;
    for i in 0..5 {
        let v = a[i] + b[i] + carry;
        h[i] = v & FE_MASK;
        carry = v >> 51;
    }
    h[0] += carry * 19;
    fe_carry(h)
}

fn fe_sub(a: &Fe, b: &Fe) -> Fe {
    let mut h = [0u64; 5];
    h[0] = a[0] + 0xFFFFFFFFFFFDA - b[0];
    h[1] = a[1] + 0xFFFFFFFFFFFFE - b[1];
    h[2] = a[2] + 0xFFFFFFFFFFFFE - b[2];
    h[3] = a[3] + 0xFFFFFFFFFFFFE - b[3];
    h[4] = a[4] + 0xFFFFFFFFFFFFE - b[4];
    fe_carry(h)
}

fn fe_mul(a: &Fe, b: &Fe) -> Fe {
    let mut c = [0u128; 9];
    for i in 0..5 {
        for j in 0..5 {
            c[i + j] += (a[i] as u128) * (b[j] as u128);
        }
    }
    let mut d = [0u64; 10];
    let mut carry: u128 = 0;
    for i in 0..9 {
        let v = c[i] + carry;
        d[i] = (v as u64) & FE_MASK;
        carry = v >> 51;
    }
    d[9] = carry as u64;
    let mut h = [0u64; 5];
    for i in 0..5 {
        h[i] = d[i] + 19 * d[i + 5];
    }
    fe_carry(h)
}

fn fe_sqr(a: &Fe) -> Fe {
    fe_mul(a, a)
}

fn fe_mul_small(a: &Fe, s: u64) -> Fe {
    let mut h = [0u64; 5];
    let mut carry: u128 = 0;
    for i in 0..5 {
        let v = (a[i] as u128) * (s as u128) + carry;
        h[i] = (v as u64) & FE_MASK;
        carry = v >> 51;
    }
    h[0] += (carry as u64) * 19;
    fe_carry(h)
}

fn fe_cswap(a: &mut Fe, b: &mut Fe, swap: u64) {
    let mask = 0u64.wrapping_sub(swap & 1);
    for i in 0..5 {
        let t = mask & (a[i] ^ b[i]);
        a[i] ^= t;
        b[i] ^= t;
    }
}

fn fe_pow(a: &Fe, exp: &[u64; 5]) -> Fe {
    let mut acc: Fe = [1, 0, 0, 0, 0];
    for i in (0..255).rev() {
        acc = fe_sqr(&acc);
        if (exp[i / 51] >> (i % 51)) & 1 == 1 {
            acc = fe_mul(&acc, a);
        }
    }
    acc
}

fn fe_invert(a: &Fe) -> Fe {
    // a^(p-2), p-2 = 2^255 - 21.
    const EXP: [u64; 5] = [FE_MASK - 20, FE_MASK, FE_MASK, FE_MASK, FE_MASK];
    fe_pow(a, &EXP)
}

fn fe_to_bytes(a: &Fe) -> [u8; 32] {
    let mut h = fe_carry(*a);
    // q = 1 exactly when h >= p (i.e. h + 19 >= 2^255).
    let mut q = (h[0] + 19) >> 51;
    q = (h[1] + q) >> 51;
    q = (h[2] + q) >> 51;
    q = (h[3] + q) >> 51;
    q = (h[4] + q) >> 51;
    h[0] += 19 * q;
    h[1] += h[0] >> 51;
    h[0] &= FE_MASK;
    h[2] += h[1] >> 51;
    h[1] &= FE_MASK;
    h[3] += h[2] >> 51;
    h[2] &= FE_MASK;
    h[4] += h[3] >> 51;
    h[3] &= FE_MASK;
    h[4] &= FE_MASK;

    let mut out = [0u8; 32];
    let w0 = h[0] | (h[1] << 51);
    let w1 = (h[1] >> 13) | (h[2] << 38);
    let w2 = (h[2] >> 26) | (h[3] << 25);
    let w3 = (h[3] >> 39) | (h[4] << 12);
    for i in 0..8 {
        out[i] = (w0 >> (8 * i)) as u8;
        out[8 + i] = (w1 >> (8 * i)) as u8;
        out[16 + i] = (w2 >> (8 * i)) as u8;
        out[24 + i] = (w3 >> (8 * i)) as u8;
    }
    out
}

/// Raw X25519 scalar multiplication (clamping applied here).
fn x25519(scalar: &[u8; 32], u: &[u8; 32]) -> [u8; 32] {
    let mut k = *scalar;
    k[0] &= 248;
    k[31] &= 127;
    k[31] |= 64;

    let x1 = fe_from_bytes(u);
    let mut x2: Fe = [1, 0, 0, 0, 0];
    let mut z2: Fe = [0; 5];
    let mut x3 = x1;
    let mut z3: Fe = [1, 0, 0, 0, 0];
    let mut swap = 0u64;

    for t in (0..=254u32).rev() {
        let kt = ((k[(t >> 3) as usize] >> (t & 7)) & 1) as u64;
        swap ^= kt;
        fe_cswap(&mut x2, &mut x3, swap);
        fe_cswap(&mut z2, &mut z3, swap);
        swap = kt;

        let a = fe_add(&x2, &z2);
        let aa = fe_sqr(&a);
        let b = fe_sub(&x2, &z2);
        let bb = fe_sqr(&b);
        let e = fe_sub(&aa, &bb);
        let c = fe_add(&x3, &z3);
        let d = fe_sub(&x3, &z3);
        let da = fe_mul(&d, &a);
        let cb = fe_mul(&c, &b);
        let t1 = fe_add(&da, &cb);
        x3 = fe_sqr(&t1);
        let t2 = fe_sub(&da, &cb);
        z3 = fe_mul(&x1, &fe_sqr(&t2));
        x2 = fe_mul(&aa, &bb);
        let t3 = fe_add(&aa, &fe_mul_small(&e, X25519_A24));
        z2 = fe_mul(&e, &t3);
    }
    fe_cswap(&mut x2, &mut x3, swap);
    fe_cswap(&mut z2, &mut z3, swap);
    let out = fe_mul(&x2, &fe_invert(&z2));
    fe_to_bytes(&out)
}

fn x25519_all_zero(bytes: &[u8; 32]) -> bool {
    let mut acc = 0u8;
    for &b in bytes {
        acc |= b;
    }
    acc == 0
}

#[derive(Clone)]
pub struct X25519Private {
    bytes: [u8; 32],
}

impl X25519Private {
    pub fn generate() -> Result<Self> {
        let mut bytes = [0u8; 32];
        emerag_util::rand::fill_bytes(&mut bytes)?;
        Ok(X25519Private { bytes })
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        X25519Private { bytes }
    }

    pub fn public_key(&self) -> [u8; 32] {
        x25519(&self.bytes, &X25519_BASE)
    }

    pub fn diffie_hellman(&self, peer: &[u8; 32]) -> Result<[u8; 32]> {
        let mut u = *peer;
        // RFC 7748: the most significant bit of the u-coordinate is ignored.
        u[31] &= 127;
        let out = x25519(&self.bytes, &u);
        if x25519_all_zero(&out) {
            return Err(Error::new(
                "x25519: all-zero shared secret (low-order peer point)",
            ));
        }
        Ok(out)
    }
}

// ===========================================================================
// Generic prime-field arithmetic (Montgomery form, 64-bit limbs)
// ===========================================================================

trait ModArith: Copy + PartialEq {
    fn zero() -> Self;
    fn one() -> Self;
    fn byte_len() -> usize;
    /// Interpret bytes as a big-endian integer, requiring the value < modulus.
    fn from_be_exact(bytes: &[u8]) -> Result<Self>;
    /// Interpret bytes as a big-endian integer and reduce once (value < 2*modulus).
    fn from_be_reduced(bytes: &[u8]) -> Result<Self>;
    fn to_be_vec(&self) -> Vec<u8>;
    fn fadd(&self, other: &Self) -> Self;
    fn fsub(&self, other: &Self) -> Self;
    fn fmul(&self, other: &Self) -> Self;
    fn fsqr(&self) -> Self {
        self.fmul(self)
    }
    fn fneg(&self) -> Self {
        Self::zero().fsub(self)
    }
    fn fpow(&self, exp: &[u64]) -> Self;
    fn finv(&self) -> Self;
    fn is_zero(&self) -> bool;
    fn is_odd(&self) -> bool;
    /// Constant-time selection: choice 0 yields a, choice 1 yields b.
    fn select(a: &Self, b: &Self, choice: u8) -> Self;
}

macro_rules! mod_type {
    ($name:ident, $k:expr, $modulus:ident, $n0:expr, $r2:ident, $one:ident, $inv_exp:ident) => {
        #[derive(Clone, Copy, PartialEq, Eq, Debug)]
        struct $name([u64; $k]);

        impl $name {
            const MODULUS: [u64; $k] = $modulus;
            const N0: u64 = $n0;
            const MONT_ONE: [u64; $k] = $one;

            fn mmul(a: &[u64; $k], b: &[u64; $k]) -> [u64; $k] {
                let mut t = [0u64; 2 * $k + 2];
                for i in 0..$k {
                    let mut carry: u128 = 0;
                    for j in 0..$k {
                        let uv = t[i + j] as u128 + (a[i] as u128) * (b[j] as u128) + carry;
                        t[i + j] = uv as u64;
                        carry = uv >> 64;
                    }
                    let mut idx = i + $k;
                    while carry != 0 {
                        let uv = t[idx] as u128 + carry;
                        t[idx] = uv as u64;
                        carry = uv >> 64;
                        idx += 1;
                    }
                }
                for i in 0..$k {
                    let u = t[i].wrapping_mul(Self::N0);
                    let mut carry: u128 = 0;
                    for j in 0..$k {
                        let uv =
                            t[i + j] as u128 + (u as u128) * (Self::MODULUS[j] as u128) + carry;
                        t[i + j] = uv as u64;
                        carry = uv >> 64;
                    }
                    let mut idx = i + $k;
                    while carry != 0 {
                        let uv = t[idx] as u128 + carry;
                        t[idx] = uv as u64;
                        carry = uv >> 64;
                        idx += 1;
                    }
                }
                let mut r = [0u64; $k];
                r.copy_from_slice(&t[$k..2 * $k]);
                let mut lt = false;
                for i in (0..$k).rev() {
                    if r[i] != Self::MODULUS[i] {
                        lt = r[i] < Self::MODULUS[i];
                        break;
                    }
                }
                if t[2 * $k] != 0 || t[2 * $k + 1] != 0 || !lt {
                    let mut borrow = 0u64;
                    for i in 0..$k {
                        let (x, b1) = r[i].overflowing_sub(Self::MODULUS[i]);
                        let (y, b2) = x.overflowing_sub(borrow);
                        r[i] = y;
                        borrow = (b1 | b2) as u64;
                    }
                }
                r
            }

            fn ge(a: &[u64; $k], b: &[u64; $k]) -> bool {
                for i in (0..$k).rev() {
                    if a[i] != b[i] {
                        return a[i] > b[i];
                    }
                }
                true
            }

            fn from_mont(a: &[u64; $k]) -> [u64; $k] {
                let mut one = [0u64; $k];
                one[0] = 1;
                Self::mmul(a, &one)
            }

            fn from_be_limbs(bytes: &[u8]) -> Result<[u64; $k]> {
                if bytes.len() != $k * 8 {
                    return Err(Error::new("ec: wrong field element length"));
                }
                let mut w = [0u64; $k];
                for i in 0..$k {
                    let mut x = 0u64;
                    for j in 0..8 {
                        x = (x << 8) | bytes[i * 8 + j] as u64;
                    }
                    w[$k - 1 - i] = x;
                }
                Ok(w)
            }

            #[allow(dead_code)]
            fn from_canonical_limbs(v: [u64; $k]) -> Self {
                $name(Self::mmul(&v, &$r2))
            }
        }

        impl ModArith for $name {
            fn zero() -> Self {
                $name([0u64; $k])
            }
            fn one() -> Self {
                $name(Self::MONT_ONE)
            }
            fn byte_len() -> usize {
                $k * 8
            }
            fn from_be_exact(bytes: &[u8]) -> Result<Self> {
                let w = Self::from_be_limbs(bytes)?;
                if Self::ge(&w, &Self::MODULUS) {
                    return Err(Error::new("ec: field element out of range"));
                }
                Ok($name(Self::mmul(&w, &$r2)))
            }
            fn from_be_reduced(bytes: &[u8]) -> Result<Self> {
                let mut w = Self::from_be_limbs(bytes)?;
                if Self::ge(&w, &Self::MODULUS) {
                    let mut borrow = 0u64;
                    for i in 0..$k {
                        let (x, b1) = w[i].overflowing_sub(Self::MODULUS[i]);
                        let (y, b2) = x.overflowing_sub(borrow);
                        w[i] = y;
                        borrow = (b1 | b2) as u64;
                    }
                }
                Ok($name(Self::mmul(&w, &$r2)))
            }
            fn to_be_vec(&self) -> Vec<u8> {
                let v = Self::from_mont(&self.0);
                let mut out = Vec::with_capacity($k * 8);
                for i in (0..$k).rev() {
                    out.extend_from_slice(&v[i].to_be_bytes());
                }
                out
            }
            fn fadd(&self, other: &Self) -> Self {
                let mut r = [0u64; $k];
                let mut carry = 0u64;
                for i in 0..$k {
                    let v = self.0[i] as u128 + other.0[i] as u128 + carry as u128;
                    r[i] = v as u64;
                    carry = (v >> 64) as u64;
                }
                let mut d = [0u64; $k];
                let mut borrow = 0u64;
                for i in 0..$k {
                    let v = (r[i] as u128)
                        .wrapping_sub(Self::MODULUS[i] as u128)
                        .wrapping_sub(borrow as u128);
                    d[i] = v as u64;
                    borrow = ((v >> 64) & 1) as u64;
                }
                let take = ((carry != 0) | (borrow == 0)) as u64;
                let mask = 0u64.wrapping_sub(take);
                let mut out = [0u64; $k];
                for i in 0..$k {
                    out[i] = (d[i] & mask) | (r[i] & !mask);
                }
                $name(out)
            }
            fn fsub(&self, other: &Self) -> Self {
                let mut r = [0u64; $k];
                let mut borrow = 0u64;
                for i in 0..$k {
                    let (x, b1) = self.0[i].overflowing_sub(other.0[i]);
                    let (y, b2) = x.overflowing_sub(borrow);
                    r[i] = y;
                    borrow = (b1 | b2) as u64;
                }
                let mut d = [0u64; $k];
                let mut carry = 0u64;
                for i in 0..$k {
                    let v = r[i] as u128 + Self::MODULUS[i] as u128 + carry as u128;
                    d[i] = v as u64;
                    carry = (v >> 64) as u64;
                }
                let mask = 0u64.wrapping_sub(borrow);
                let mut out = [0u64; $k];
                for i in 0..$k {
                    out[i] = (d[i] & mask) | (r[i] & !mask);
                }
                $name(out)
            }
            fn fmul(&self, other: &Self) -> Self {
                $name(Self::mmul(&self.0, &other.0))
            }
            fn fpow(&self, exp: &[u64]) -> Self {
                let mut acc = Self::one();
                for i in (0..exp.len() * 64).rev() {
                    acc = acc.fsqr();
                    if (exp[i / 64] >> (i % 64)) & 1 == 1 {
                        acc = acc.fmul(self);
                    }
                }
                acc
            }
            fn finv(&self) -> Self {
                self.fpow(&$inv_exp)
            }
            fn is_zero(&self) -> bool {
                let mut acc = 0u64;
                for &limb in self.0.iter() {
                    acc |= limb;
                }
                acc == 0
            }
            fn is_odd(&self) -> bool {
                Self::from_mont(&self.0)[0] & 1 == 1
            }
            fn select(a: &Self, b: &Self, choice: u8) -> Self {
                let mask = 0u64.wrapping_sub((choice & 1) as u64);
                let mut out = [0u64; $k];
                for i in 0..$k {
                    out[i] = (a.0[i] & !mask) | (b.0[i] & mask);
                }
                $name(out)
            }
        }
    };
}

const P256_P: [u64; 4] = [
    0xFFFFFFFFFFFFFFFF,
    0x00000000FFFFFFFF,
    0x0000000000000000,
    0xFFFFFFFF00000001,
];
const P256_N: [u64; 4] = [
    0xF3B9CAC2FC632551,
    0xBCE6FAADA7179E84,
    0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFF00000000,
];
const P256_B: [u64; 4] = [
    0x3BCE3C3E27D2604B,
    0x651D06B0CC53B0F6,
    0xB3EBBD55769886BC,
    0x5AC635D8AA3A93E7,
];
const P256_R2: [u64; 4] = [
    0x0000000000000003,
    0xFFFFFFFBFFFFFFFF,
    0xFFFFFFFFFFFFFFFE,
    0x00000004FFFFFFFD,
];
const P256_R1: [u64; 4] = [
    0x0000000000000001,
    0xFFFFFFFF00000000,
    0xFFFFFFFFFFFFFFFF,
    0x00000000FFFFFFFE,
];
const P256_N_R2: [u64; 4] = [
    0x83244C95BE79EEA2,
    0x4699799C49BD6FA6,
    0x2845B2392B6BEC59,
    0x66E12D94F3D95620,
];
const P256_N_R1: [u64; 4] = [
    0x0C46353D039CDAAF,
    0x4319055258E8617B,
    0x0000000000000000,
    0x00000000FFFFFFFF,
];
const P256_N0: u64 = 0x0000000000000001;
const P256_N_N0: u64 = 0xCCD1C8AAEE00BC4F;
const P256_INV_EXP: [u64; 4] = [
    0xFFFFFFFFFFFFFFFD,
    0x00000000FFFFFFFF,
    0x0000000000000000,
    0xFFFFFFFF00000001,
];
const P256_N_INV_EXP: [u64; 4] = [
    0xF3B9CAC2FC63254F,
    0xBCE6FAADA7179E84,
    0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFF00000000,
];
const P256_SQRT_EXP: [u64; 4] = [
    0x0000000000000000,
    0x0000000040000000,
    0x4000000000000000,
    0x3FFFFFFFC0000000,
];
const P256_GX: [u8; 32] = *b"\x6b\x17\xd1\xf2\xe1\x2c\x42\x47\xf8\xbc\xe6\xe5\x63\xa4\x40\xf2\x77\x03\x7d\x81\x2d\xeb\x33\xa0\xf4\xa1\x39\x45\xd8\x98\xc2\x96";
const P256_GY: [u8; 32] = *b"\x4f\xe3\x42\xe2\xfe\x1a\x7f\x9b\x8e\xe7\xeb\x4a\x7c\x0f\x9e\x16\x2b\xce\x33\x57\x6b\x31\x5e\xce\xcb\xb6\x40\x68\x37\xbf\x51\xf5";

mod_type!(Fp256, 4, P256_P, P256_N0, P256_R2, P256_R1, P256_INV_EXP);
mod_type!(
    Scalar256,
    4,
    P256_N,
    P256_N_N0,
    P256_N_R2,
    P256_N_R1,
    P256_N_INV_EXP
);

const P384_P: [u64; 6] = [
    0x00000000FFFFFFFF,
    0xFFFFFFFF00000000,
    0xFFFFFFFFFFFFFFFE,
    0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF,
];
const P384_N: [u64; 6] = [
    0xECEC196ACCC52973,
    0x581A0DB248B0A77A,
    0xC7634D81F4372DDF,
    0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF,
];
const P384_B: [u64; 6] = [
    0x2A85C8EDD3EC2AEF,
    0xC656398D8A2ED19D,
    0x0314088F5013875A,
    0x181D9C6EFE814112,
    0x988E056BE3F82D19,
    0xB3312FA7E23EE7E4,
];
const P384_R2: [u64; 6] = [
    0xFFFFFFFE00000001,
    0x0000000200000000,
    0xFFFFFFFE00000000,
    0x0000000200000000,
    0x0000000000000001,
    0x0000000000000000,
];
const P384_R1: [u64; 6] = [
    0xFFFFFFFF00000001,
    0x00000000FFFFFFFF,
    0x0000000000000001,
    0x0000000000000000,
    0x0000000000000000,
    0x0000000000000000,
];
const P384_N_R2: [u64; 6] = [
    0x2D319B2419B409A9,
    0xFF3D81E5DF1AA419,
    0xBC3E483AFCB82947,
    0xD40D49174AAB1CC5,
    0x3FB05B7A28266895,
    0x0C84EE012B39BF21,
];
const P384_N_R1: [u64; 6] = [
    0x1313E695333AD68D,
    0xA7E5F24DB74F5885,
    0x389CB27E0BC8D220,
    0x0000000000000000,
    0x0000000000000000,
    0x0000000000000000,
];
const P384_N0: u64 = 0x0000000100000001;
const P384_N_N0: u64 = 0x6ED46089E88FDC45;
const P384_INV_EXP: [u64; 6] = [
    0x00000000FFFFFFFD,
    0xFFFFFFFF00000000,
    0xFFFFFFFFFFFFFFFE,
    0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF,
];
const P384_N_INV_EXP: [u64; 6] = [
    0xECEC196ACCC52971,
    0x581A0DB248B0A77A,
    0xC7634D81F4372DDF,
    0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF,
];
const P384_SQRT_EXP: [u64; 6] = [
    0x0000000040000000,
    0xBFFFFFFFC0000000,
    0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF,
    0x3FFFFFFFFFFFFFFF,
];
const P384_GX: [u8; 48] = *b"\xaa\x87\xca\x22\xbe\x8b\x05\x37\x8e\xb1\xc7\x1e\xf3\x20\xad\x74\x6e\x1d\x3b\x62\x8b\xa7\x9b\x98\x59\xf7\x41\xe0\x82\x54\x2a\x38\x55\x02\xf2\x5d\xbf\x55\x29\x6c\x3a\x54\x5e\x38\x72\x76\x0a\xb7";
const P384_GY: [u8; 48] = *b"\x36\x17\xde\x4a\x96\x26\x2c\x6f\x5d\x9e\x98\xbf\x92\x92\xdc\x29\xf8\xf4\x1d\xbd\x28\x9a\x14\x7c\xe9\xda\x31\x13\xb5\xf0\xb8\xc0\x0a\x60\xb1\xce\x1d\x7e\x81\x9d\x7a\x43\x1d\x7c\x90\xea\x0e\x5f";

mod_type!(Fp384, 6, P384_P, P384_N0, P384_R2, P384_R1, P384_INV_EXP);
mod_type!(
    Scalar384,
    6,
    P384_N,
    P384_N_N0,
    P384_N_R2,
    P384_N_R1,
    P384_N_INV_EXP
);

// ===========================================================================
// Generic short-Weierstrass curve arithmetic (a = -3, Jacobian coordinates)
// ===========================================================================

fn f2<F: ModArith>(a: &F) -> F {
    a.fadd(a)
}

fn f4<F: ModArith>(a: &F) -> F {
    let t = f2(a);
    t.fadd(&t)
}

fn f8<F: ModArith>(a: &F) -> F {
    let t = f4(a);
    t.fadd(&t)
}

#[derive(Clone, Copy, Debug)]
struct Affine<F: ModArith> {
    x: F,
    y: F,
}

#[derive(Clone, Copy, Debug)]
struct Jacobian<F: ModArith> {
    x: F,
    y: F,
    z: F,
}

impl<F: ModArith> Jacobian<F> {
    fn infinity() -> Self {
        Jacobian {
            x: F::one(),
            y: F::one(),
            z: F::zero(),
        }
    }

    fn is_infinity(&self) -> bool {
        self.z.is_zero()
    }

    fn from_affine(p: &Affine<F>) -> Self {
        Jacobian {
            x: p.x,
            y: p.y,
            z: F::one(),
        }
    }

    /// Point doubling, a = -3 (dbl-2001-b).
    fn double(&self) -> Self {
        let delta = self.z.fsqr();
        let gamma = self.y.fsqr();
        let beta = self.x.fmul(&gamma);
        let t = self.x.fsub(&delta).fmul(&self.x.fadd(&delta));
        let alpha = f2(&t).fadd(&t);
        let x3 = alpha.fsqr().fsub(&f8(&beta));
        let z3 = self.y.fadd(&self.z).fsqr().fsub(&gamma).fsub(&delta);
        let y3 = alpha.fmul(&f4(&beta).fsub(&x3)).fsub(&f8(&gamma.fsqr()));
        Jacobian {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    /// Generic Jacobian addition (add-2007-bl). Returns the point and whether
    /// both inputs are the same affine point (in which case the result is
    /// meaningless and the caller must use doubling instead).
    fn add_raw(&self, other: &Self) -> (Self, bool) {
        let z1z1 = self.z.fsqr();
        let z2z2 = other.z.fsqr();
        let u1 = self.x.fmul(&z2z2);
        let u2 = other.x.fmul(&z1z1);
        let s1 = self.y.fmul(&other.z).fmul(&z2z2);
        let s2 = other.y.fmul(&self.z).fmul(&z1z1);
        let h = u2.fsub(&u1);
        let i = f2(&h).fsqr();
        let j = h.fmul(&i);
        let r = f2(&s2.fsub(&s1));
        let v = u1.fmul(&i);
        let x3 = r.fsqr().fsub(&j).fsub(&v).fsub(&v);
        let y3 = r.fmul(&v.fsub(&x3)).fsub(&f2(&s1.fmul(&j)));
        let z3 = self
            .z
            .fadd(&other.z)
            .fsqr()
            .fsub(&z1z1)
            .fsub(&z2z2)
            .fmul(&h);
        let same = u1 == u2 && s1 == s2;
        (
            Jacobian {
                x: x3,
                y: y3,
                z: z3,
            },
            same,
        )
    }

    fn select(a: &Self, b: &Self, choice: u8) -> Self {
        Jacobian {
            x: F::select(&a.x, &b.x, choice),
            y: F::select(&a.y, &b.y, choice),
            z: F::select(&a.z, &b.z, choice),
        }
    }

    /// Branch-free addition: handles doubling and both infinity cases by
    /// computing every candidate and selecting with masks.
    fn add(&self, other: &Self) -> Self {
        let (raw, same) = self.add_raw(other);
        let dbl = self.double();
        let mut r = Self::select(&raw, &dbl, same as u8);
        r = Self::select(&r, other, self.is_infinity() as u8);
        r = Self::select(&r, self, other.is_infinity() as u8);
        r
    }

    fn to_affine(&self) -> Option<Affine<F>> {
        if self.is_infinity() {
            return None;
        }
        let zi = self.z.finv();
        let zi2 = zi.fsqr();
        let zi3 = zi2.fmul(&zi);
        Some(Affine {
            x: self.x.fmul(&zi2),
            y: self.y.fmul(&zi3),
        })
    }
}

fn on_curve<F: ModArith>(p: &Affine<F>, b: &F) -> bool {
    let y2 = p.y.fsqr();
    let x3 = p.x.fsqr().fmul(&p.x);
    let three_x = f2(&p.x).fadd(&p.x);
    y2 == x3.fsub(&three_x).fadd(b)
}

fn parse_sec1<F: ModArith>(bytes: &[u8], b: &F, sqrt_exp: &[u64]) -> Result<Affine<F>> {
    let flen = F::byte_len();
    if bytes.len() == 1 + 2 * flen && bytes[0] == 0x04 {
        let x = F::from_be_exact(&bytes[1..1 + flen])?;
        let y = F::from_be_exact(&bytes[1 + flen..])?;
        let p = Affine { x, y };
        if !on_curve(&p, b) {
            return Err(Error::new("ec: SEC1 point is not on the curve"));
        }
        Ok(p)
    } else if bytes.len() == 1 + flen && (bytes[0] == 0x02 || bytes[0] == 0x03) {
        let x = F::from_be_exact(&bytes[1..])?;
        let rhs = x.fsqr().fmul(&x).fsub(&f2(&x).fadd(&x)).fadd(b);
        let mut y = rhs.fpow(sqrt_exp);
        if y.fsqr() != rhs {
            return Err(Error::new("ec: compressed point has no square root"));
        }
        if y.is_odd() != (bytes[0] == 0x03) {
            y = y.fneg();
        }
        Ok(Affine { x, y })
    } else {
        Err(Error::new("ec: invalid SEC1 point encoding"))
    }
}

fn encode_sec1<F: ModArith>(p: &Affine<F>) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 2 * F::byte_len());
    out.push(0x04);
    out.extend_from_slice(&p.x.to_be_vec());
    out.extend_from_slice(&p.y.to_be_vec());
    out
}

/// Fixed 4-bit window scalar multiplication. The scalar is big-endian.
fn scalar_mul<F: ModArith>(scalar: &[u8], base: &Jacobian<F>) -> Jacobian<F> {
    let mut table = [Jacobian::infinity(); 16];
    table[1] = *base;
    for i in 2..16 {
        table[i] = table[i - 1].add(base);
    }
    let mut acc = Jacobian::infinity();
    for &byte in scalar {
        for half in 0..2u8 {
            acc = acc.double();
            acc = acc.double();
            acc = acc.double();
            acc = acc.double();
            let nib = if half == 0 { byte >> 4 } else { byte & 0x0f };
            let mut sel = Jacobian::infinity();
            for j in 0..16u8 {
                sel = Jacobian::select(&sel, &table[j as usize], ct_eq_u8(nib, j));
            }
            acc = acc.add(&sel);
        }
    }
    acc
}

// ---------------------------------------------------------------------------
// DER ECDSA signatures
// ---------------------------------------------------------------------------

struct DerReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> DerReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        DerReader { data, pos: 0 }
    }

    fn done(&self) -> bool {
        self.pos == self.data.len()
    }

    fn read_tlv(&mut self) -> Result<(u8, &'a [u8])> {
        if self.pos >= self.data.len() {
            return Err(Error::new("ecdsa: truncated DER"));
        }
        let tag = self.data[self.pos];
        self.pos += 1;
        if tag & 0x1f == 0x1f {
            return Err(Error::new("ecdsa: high tag numbers unsupported"));
        }
        if self.pos >= self.data.len() {
            return Err(Error::new("ecdsa: truncated DER length"));
        }
        let first = self.data[self.pos];
        self.pos += 1;
        let len = if first < 0x80 {
            first as usize
        } else if first == 0x80 {
            return Err(Error::new("ecdsa: indefinite length"));
        } else {
            let n = (first & 0x7f) as usize;
            if n == 0 || n > 4 || n > self.data.len() - self.pos {
                return Err(Error::new("ecdsa: bad DER length"));
            }
            let mut v = 0usize;
            for i in 0..n {
                v = (v << 8) | self.data[self.pos + i] as usize;
            }
            self.pos += n;
            v
        };
        if len > self.data.len() - self.pos {
            return Err(Error::new("ecdsa: truncated DER body"));
        }
        let body = &self.data[self.pos..self.pos + len];
        self.pos += len;
        Ok((tag, body))
    }
}

fn der_scalar<S: ModArith>(body: &[u8]) -> Result<S> {
    if body.is_empty() {
        return Err(Error::new("ecdsa: empty INTEGER"));
    }
    if body[0] & 0x80 != 0 {
        return Err(Error::new("ecdsa: negative INTEGER"));
    }
    let mut i = 0;
    while i < body.len() && body[i] == 0 {
        i += 1;
    }
    let mag = &body[i..];
    if mag.is_empty() {
        return Ok(S::zero());
    }
    let n = S::byte_len();
    if mag.len() > n {
        return Err(Error::new("ecdsa: INTEGER larger than the group order"));
    }
    let mut buf = vec![0u8; n];
    buf[n - mag.len()..].copy_from_slice(mag);
    S::from_be_exact(&buf)
}

fn parse_der_signature<S: ModArith>(der: &[u8]) -> Result<(S, S)> {
    let mut outer = DerReader::new(der);
    let (tag, body) = outer.read_tlv()?;
    if tag != 0x30 || !outer.done() {
        return Err(Error::new("ecdsa: signature is not a single SEQUENCE"));
    }
    let mut seq = DerReader::new(body);
    let (t1, r) = seq.read_tlv()?;
    if t1 != 0x02 {
        return Err(Error::new("ecdsa: missing r INTEGER"));
    }
    let (t2, s) = seq.read_tlv()?;
    if t2 != 0x02 || !seq.done() {
        return Err(Error::new("ecdsa: missing s INTEGER"));
    }
    Ok((der_scalar::<S>(r)?, der_scalar::<S>(s)?))
}

/// FIPS 186-4 bits2int for a qlen-bit group order (qlen is a multiple of 8).
fn bits2int<S: ModArith>(digest: &[u8]) -> Result<S> {
    let n = S::byte_len();
    let qlen = n * 8;
    let dlen = digest.len() * 8;
    let mut buf = vec![0u8; n];
    if dlen > qlen {
        buf.copy_from_slice(&digest[..n]);
    } else {
        buf[n - digest.len()..].copy_from_slice(digest);
    }
    S::from_be_reduced(&buf)
}

fn verify_ecdsa<F: ModArith, S: ModArith>(
    q: &Affine<F>,
    g: &Jacobian<F>,
    alg: HashAlg,
    message: &[u8],
    der_signature: &[u8],
) -> Result<bool> {
    let (r, s) = parse_der_signature::<S>(der_signature)?;
    if r.is_zero() || s.is_zero() {
        return Ok(false);
    }
    let digest = alg.digest(message);
    let e = bits2int::<S>(&digest)?;
    let w = s.finv();
    let u1 = e.fmul(&w);
    let u2 = r.fmul(&w);
    let p1 = scalar_mul(&u1.to_be_vec(), g);
    let qj = Jacobian::from_affine(q);
    let p2 = scalar_mul(&u2.to_be_vec(), &qj);
    let sum = p1.add(&p2);
    let aff = match sum.to_affine() {
        Some(a) => a,
        None => return Ok(false),
    };
    let v = S::from_be_reduced(&aff.x.to_be_vec())?;
    Ok(v == r)
}

// ===========================================================================
// NIST P-256
// ===========================================================================

fn p256_b() -> Fp256 {
    Fp256::from_canonical_limbs(P256_B)
}

fn p256_g() -> Jacobian<Fp256> {
    let x = Fp256::from_be_exact(&P256_GX).expect("P-256 base point x");
    let y = Fp256::from_be_exact(&P256_GY).expect("P-256 base point y");
    Jacobian {
        x,
        y,
        z: Fp256::one(),
    }
}

fn scalar256_valid(bytes: &[u8; 32]) -> bool {
    match Scalar256::from_be_exact(bytes) {
        Ok(s) => !s.is_zero(),
        Err(_) => false,
    }
}

#[derive(Clone)]
pub struct P256Private {
    bytes: [u8; 32],
}

impl P256Private {
    pub fn generate() -> Result<Self> {
        for _ in 0..16 {
            let mut bytes = [0u8; 32];
            emerag_util::rand::fill_bytes(&mut bytes)?;
            if scalar256_valid(&bytes) {
                return Ok(P256Private { bytes });
            }
        }
        Err(Error::new(
            "p256: could not generate a valid private scalar",
        ))
    }

    /// 32-byte big-endian scalar; rejects zero and values at or above n.
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self> {
        if !scalar256_valid(bytes) {
            return Err(Error::new("p256: private scalar must be in [1, n-1]"));
        }
        Ok(P256Private { bytes: *bytes })
    }

    pub fn public_key(&self) -> P256Public {
        let p = scalar_mul(&self.bytes, &p256_g());
        let a = p
            .to_affine()
            .expect("a nonzero scalar times the base point is never infinity");
        P256Public { x: a.x, y: a.y }
    }

    pub fn diffie_hellman(&self, peer: &P256Public) -> Result<[u8; 32]> {
        let q = Jacobian {
            x: peer.x,
            y: peer.y,
            z: Fp256::one(),
        };
        let r = scalar_mul(&self.bytes, &q);
        let a = match r.to_affine() {
            Some(a) => a,
            None => return Err(Error::new("p256: ECDH produced the point at infinity")),
        };
        let v = a.x.to_be_vec();
        let mut out = [0u8; 32];
        if v.len() != out.len() {
            return Err(Error::new("p256: bad field encoding"));
        }
        out.copy_from_slice(&v);
        Ok(out)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct P256Public {
    x: Fp256,
    y: Fp256,
}

impl P256Public {
    /// Parse a SEC1 point: uncompressed 0x04 || X || Y, or compressed 0x02/0x03 || X.
    pub fn from_sec1(bytes: &[u8]) -> Result<Self> {
        let p = parse_sec1::<Fp256>(bytes, &p256_b(), &P256_SQRT_EXP)?;
        Ok(P256Public { x: p.x, y: p.y })
    }

    pub fn to_sec1(&self) -> [u8; 65] {
        let mut out = [0u8; 65];
        let p = Affine {
            x: self.x,
            y: self.y,
        };
        let v = encode_sec1(&p);
        if v.len() == out.len() {
            out.copy_from_slice(&v);
        }
        out
    }

    pub fn verify_sha256(&self, message: &[u8], der_signature: &[u8]) -> Result<bool> {
        self.verify_digest(HashAlg::Sha256, message, der_signature)
    }

    /// Verify an ASN.1 DER ECDSA signature over the digest selected by alg.
    pub fn verify_digest(
        &self,
        alg: HashAlg,
        message: &[u8],
        der_signature: &[u8],
    ) -> Result<bool> {
        let q = Affine {
            x: self.x,
            y: self.y,
        };
        verify_ecdsa::<Fp256, Scalar256>(&q, &p256_g(), alg, message, der_signature)
    }
}

// ===========================================================================
// NIST P-384
// ===========================================================================

fn p384_b() -> Fp384 {
    Fp384::from_canonical_limbs(P384_B)
}

fn p384_g() -> Jacobian<Fp384> {
    let x = Fp384::from_be_exact(&P384_GX).expect("P-384 base point x");
    let y = Fp384::from_be_exact(&P384_GY).expect("P-384 base point y");
    Jacobian {
        x,
        y,
        z: Fp384::one(),
    }
}

fn scalar384_valid(bytes: &[u8; 48]) -> bool {
    match Scalar384::from_be_exact(bytes) {
        Ok(s) => !s.is_zero(),
        Err(_) => false,
    }
}

#[derive(Clone)]
pub struct P384Private {
    bytes: [u8; 48],
}

impl P384Private {
    pub fn generate() -> Result<Self> {
        for _ in 0..16 {
            let mut bytes = [0u8; 48];
            emerag_util::rand::fill_bytes(&mut bytes)?;
            if scalar384_valid(&bytes) {
                return Ok(P384Private { bytes });
            }
        }
        Err(Error::new(
            "p384: could not generate a valid private scalar",
        ))
    }

    pub fn from_bytes(bytes: &[u8; 48]) -> Result<Self> {
        if !scalar384_valid(bytes) {
            return Err(Error::new("p384: private scalar must be in [1, n-1]"));
        }
        Ok(P384Private { bytes: *bytes })
    }

    pub fn public_key(&self) -> P384Public {
        let p = scalar_mul(&self.bytes, &p384_g());
        let a = p
            .to_affine()
            .expect("a nonzero scalar times the base point is never infinity");
        P384Public { x: a.x, y: a.y }
    }

    pub fn diffie_hellman(&self, peer: &P384Public) -> Result<[u8; 48]> {
        let q = Jacobian {
            x: peer.x,
            y: peer.y,
            z: Fp384::one(),
        };
        let r = scalar_mul(&self.bytes, &q);
        let a = match r.to_affine() {
            Some(a) => a,
            None => return Err(Error::new("p384: ECDH produced the point at infinity")),
        };
        let v = a.x.to_be_vec();
        let mut out = [0u8; 48];
        if v.len() != out.len() {
            return Err(Error::new("p384: bad field encoding"));
        }
        out.copy_from_slice(&v);
        Ok(out)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct P384Public {
    x: Fp384,
    y: Fp384,
}

impl P384Public {
    pub fn from_sec1(bytes: &[u8]) -> Result<Self> {
        let p = parse_sec1::<Fp384>(bytes, &p384_b(), &P384_SQRT_EXP)?;
        Ok(P384Public { x: p.x, y: p.y })
    }

    pub fn to_sec1(&self) -> [u8; 97] {
        let mut out = [0u8; 97];
        let p = Affine {
            x: self.x,
            y: self.y,
        };
        let v = encode_sec1(&p);
        if v.len() == out.len() {
            out.copy_from_slice(&v);
        }
        out
    }

    pub fn verify_sha384(&self, message: &[u8], der_signature: &[u8]) -> Result<bool> {
        self.verify_digest(HashAlg::Sha384, message, der_signature)
    }

    pub fn verify_digest(
        &self,
        alg: HashAlg,
        message: &[u8],
        der_signature: &[u8],
    ) -> Result<bool> {
        let q = Affine {
            x: self.x,
            y: self.y,
        };
        verify_ecdsa::<Fp384, Scalar384>(&q, &p384_g(), alg, message, der_signature)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::vectors::*;
    use super::*;
    use emerag_util::hex::{decode, encode};

    const G256X: &str = "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296";
    const G256Y: &str = "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5";
    const G256_2X: &str = "7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978";
    const G256_2Y: &str = "07775510db8ed040293d9ac69f7430dbba7dade63ce982299e04b79d227873d1";
    const N256: &str = "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551";
    const G384X: &str = "aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7";
    const G384Y: &str = "3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f";

    fn alg(a: u8) -> HashAlg {
        match a {
            0 => HashAlg::Sha256,
            1 => HashAlg::Sha384,
            _ => HashAlg::Sha512,
        }
    }

    fn arr32(hex_str: &str) -> [u8; 32] {
        let v = decode(hex_str).unwrap();
        let mut a = [0u8; 32];
        a.copy_from_slice(&v);
        a
    }

    fn arr48(hex_str: &str) -> [u8; 48] {
        let v = decode(hex_str).unwrap();
        let mut a = [0u8; 48];
        a.copy_from_slice(&v);
        a
    }

    fn p256_g_sec1() -> Vec<u8> {
        decode(&format!("04{}{}", G256X, G256Y)).unwrap()
    }

    fn p384_g_sec1() -> Vec<u8> {
        decode(&format!("04{}{}", G384X, G384Y)).unwrap()
    }

    // --- X25519 ---------------------------------------------------------

    #[test]
    fn x25519_rfc7748_section_5_2() {
        let k1 = arr32("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
        let u1 = arr32("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
        assert_eq!(
            encode(&x25519(&k1, &u1)),
            "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"
        );

        let k2 = arr32("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d");
        let u2 = arr32("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493");
        assert_eq!(
            encode(&x25519(&k2, &u2)),
            "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957"
        );
    }

    #[test]
    fn x25519_rfc7748_section_6_1() {
        let alice = X25519Private::from_bytes(arr32(
            "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
        ));
        let bob = X25519Private::from_bytes(arr32(
            "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
        ));
        assert_eq!(
            encode(&alice.public_key()),
            "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
        );
        assert_eq!(
            encode(&bob.public_key()),
            "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"
        );
        let s1 = alice.diffie_hellman(&bob.public_key()).unwrap();
        let s2 = bob.diffie_hellman(&alice.public_key()).unwrap();
        assert_eq!(s1, s2);
        assert_eq!(
            encode(&s1),
            "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
        );
    }

    fn x25519_iterated(n: usize) -> [u8; 32] {
        let mut k = [0u8; 32];
        k[0] = 9;
        let mut u = k;
        for _ in 0..n {
            let next = x25519(&k, &u);
            u = k;
            k = next;
        }
        k
    }

    #[test]
    fn x25519_rfc7748_iterated() {
        assert_eq!(
            encode(&x25519_iterated(1)),
            "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079"
        );
        assert_eq!(
            encode(&x25519_iterated(1000)),
            "684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51"
        );
    }

    #[test]
    fn x25519_rejects_low_order_points() {
        let key = X25519Private::from_bytes([0x42u8; 32]);
        let mut one = [0u8; 32];
        one[0] = 1;
        let mut p_minus_1 = [0xffu8; 32];
        p_minus_1[0] = 0xec;
        p_minus_1[31] = 0x7f;
        let mut p = p_minus_1;
        p[0] = 0xed;
        let mut p_plus_1 = p_minus_1;
        p_plus_1[0] = 0xee;
        for u in [[0u8; 32], one, p_minus_1, p, p_plus_1] {
            assert!(key.diffie_hellman(&u).is_err());
        }
    }

    #[test]
    fn x25519_clamping_and_high_bit() {
        let raw = [0xabu8; 32];
        let mut clamped = raw;
        clamped[0] &= 248;
        clamped[31] &= 127;
        clamped[31] |= 64;
        assert_eq!(
            X25519Private::from_bytes(raw).public_key(),
            X25519Private::from_bytes(clamped).public_key()
        );
        // Bit 255 of the peer u-coordinate is ignored.
        let bob = X25519Private::from_bytes(arr32(
            "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
        ));
        let peer = bob.public_key();
        let a = X25519Private::from_bytes([9u8; 32]);
        let s1 = a.diffie_hellman(&peer).unwrap();
        let mut peer_high = peer;
        peer_high[31] |= 0x80;
        assert_eq!(a.diffie_hellman(&peer_high).unwrap(), s1);
    }

    // --- P-256 ----------------------------------------------------------

    #[test]
    fn p256_known_points_and_sec1() {
        let g = P256Public::from_sec1(&p256_g_sec1()).unwrap();
        assert_eq!(g.to_sec1().to_vec(), p256_g_sec1());

        let mut two = [0u8; 32];
        two[31] = 2;
        let two_g = P256Private::from_bytes(&two).unwrap().public_key();
        assert_eq!(
            encode(&two_g.to_sec1()),
            format!("04{}{}", G256_2X, G256_2Y)
        );

        // Compressed round trip (generated vector).
        let comp = P256Public::from_sec1(&decode(P256_COMPRESSED).unwrap()).unwrap();
        assert_eq!(comp.to_sec1().to_vec(), decode(P256_UNCOMPRESSED).unwrap());

        assert!(P256Public::from_sec1(&[0x00]).is_err());
        assert!(P256Public::from_sec1(&[0x05u8; 65]).is_err());
        let mut bad = decode(P256_UNCOMPRESSED).unwrap();
        bad[64] ^= 0x01;
        assert!(P256Public::from_sec1(&bad).is_err());
        // x = p is not a valid coordinate.
        let mut p_bytes = decode(N256).unwrap();
        p_bytes[0] = 0xff;
        p_bytes[1] = 0xff;
        let mut enc = vec![0x04];
        enc.extend_from_slice(&[0xffu8; 32]);
        enc.extend_from_slice(&[0u8; 32]);
        assert!(P256Public::from_sec1(&enc).is_err());
    }

    #[test]
    fn p256_scalar_range() {
        assert!(P256Private::from_bytes(&[0u8; 32]).is_err());
        let n = arr32(N256);
        assert!(P256Private::from_bytes(&n).is_err());
        let mut n_minus_1 = n;
        n_minus_1[31] = 0x50;
        assert!(P256Private::from_bytes(&n_minus_1).is_ok());
        let mut one = [0u8; 32];
        one[31] = 1;
        assert!(P256Private::from_bytes(&one).is_ok());
    }

    #[test]
    fn p256_ecdh_vectors() {
        for (priv_hex, peer_hex, shared_hex) in P256_ECDH {
            let k = P256Private::from_bytes(&arr32(priv_hex)).unwrap();
            let peer = P256Public::from_sec1(&decode(peer_hex).unwrap()).unwrap();
            let shared = k.diffie_hellman(&peer).unwrap();
            assert_eq!(encode(&shared), *shared_hex);
            // Public keys must survive a serialise/parse round trip.
            let pk = k.public_key();
            assert_eq!(P256Public::from_sec1(&pk.to_sec1()).unwrap(), pk);
        }
    }

    #[test]
    fn p256_ecdsa_vectors() {
        for (pub_hex, msg_hex, sig_hex, alg_id) in P256_ECDSA {
            let key = P256Public::from_sec1(&decode(pub_hex).unwrap()).unwrap();
            let msg = decode(msg_hex).unwrap();
            let sig = decode(sig_hex).unwrap();
            assert!(key.verify_digest(alg(*alg_id), &msg, &sig).unwrap());
            let mut bad_msg = msg.clone();
            if bad_msg.is_empty() {
                bad_msg.push(0);
            } else {
                bad_msg[0] ^= 0x01;
            }
            assert!(!key.verify_digest(alg(*alg_id), &bad_msg, &sig).unwrap());
            let mut bad_sig = sig.clone();
            let last = bad_sig.len() - 1;
            bad_sig[last] ^= 0x01;
            assert!(!matches!(
                key.verify_digest(alg(*alg_id), &msg, &bad_sig),
                Ok(true)
            ));
            assert!(!matches!(
                key.verify_digest(alg((*alg_id + 1) % 3), &msg, &sig),
                Ok(true)
            ));
        }
    }

    #[test]
    fn p256_rfc6979_sha256_vector() {
        let key = P256Public::from_sec1(&decode(RFC6979_SAMPLE_PUB).unwrap()).unwrap();
        let sig = decode(RFC6979_SAMPLE_SIG).unwrap();
        assert!(key.verify_sha256(b"sample", &sig).unwrap());
        assert!(!key.verify_sha256(b"samplf", &sig).unwrap());
        assert!(!key.verify_digest(HashAlg::Sha384, b"sample", &sig).unwrap());
        let mut bad = sig.clone();
        bad[36] ^= 0x01;
        assert!(!key.verify_sha256(b"sample", &bad).unwrap());
    }

    #[test]
    fn ecdsa_der_edge_cases() {
        let key = P256Public::from_sec1(&decode(RFC6979_SAMPLE_PUB).unwrap()).unwrap();
        assert!(key.verify_sha256(b"sample", &[]).is_err());
        assert!(key.verify_sha256(b"sample", &[0x30, 0x00]).is_err());
        assert!(key
            .verify_sha256(b"sample", &[0x30, 0x06, 0x02, 0x01, 0x81, 0x02, 0x01, 0x01])
            .is_err());
        let mut trailing = decode(RFC6979_SAMPLE_SIG).unwrap();
        trailing.push(0);
        assert!(key.verify_sha256(b"sample", &trailing).is_err());
        // r = 0 is a structurally valid but invalid signature.
        assert_eq!(
            key.verify_sha256(b"sample", &[0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x01])
                .unwrap(),
            false
        );
        // s = n must be rejected as out of range.
        let mut der = vec![0x30, 0x26, 0x02, 0x01, 0x01, 0x02, 0x21, 0x00];
        der.extend_from_slice(&arr32(N256));
        assert!(key.verify_sha256(b"sample", &der).is_err());
    }

    #[test]
    fn p256_field_arithmetic() {
        let a = Fp256::from_be_exact(&arr32(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        ))
        .unwrap();
        let b = Fp256::from_be_exact(&arr32(
            "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
        ))
        .unwrap();
        assert_eq!(a.fadd(&b).fsub(&b), a);
        assert_eq!(a.fmul(&b).fsub(&b.fmul(&a)), Fp256::zero());
        let inv = a.finv();
        assert_eq!(a.fmul(&inv), Fp256::one());
        assert_eq!(a.fadd(&a.fneg()), Fp256::zero());
        // p itself is out of range.
        assert!(Fp256::from_be_exact(&[0xffu8; 32]).is_err());
    }

    // --- P-384 ----------------------------------------------------------

    #[test]
    fn p384_known_points_and_sec1() {
        let g = P384Public::from_sec1(&p384_g_sec1()).unwrap();
        assert_eq!(g.to_sec1().to_vec(), p384_g_sec1());
        let comp = P384Public::from_sec1(&decode(P384_COMPRESSED).unwrap()).unwrap();
        assert_eq!(comp.to_sec1().to_vec(), decode(P384_UNCOMPRESSED).unwrap());
        let mut bad = decode(P384_UNCOMPRESSED).unwrap();
        bad[96] ^= 0x01;
        assert!(P384Public::from_sec1(&bad).is_err());
        assert!(P384Public::from_sec1(&[0x04u8; 97]).is_err());
    }

    #[test]
    fn p384_ecdh_vectors() {
        for (priv_hex, peer_hex, shared_hex) in P384_ECDH {
            let k = P384Private::from_bytes(&arr48(priv_hex)).unwrap();
            let peer = P384Public::from_sec1(&decode(peer_hex).unwrap()).unwrap();
            let shared = k.diffie_hellman(&peer).unwrap();
            assert_eq!(encode(&shared), *shared_hex);
            let pk = k.public_key();
            assert_eq!(P384Public::from_sec1(&pk.to_sec1()).unwrap(), pk);
        }
    }

    #[test]
    fn p384_ecdsa_vectors() {
        for (pub_hex, msg_hex, sig_hex, alg_id) in P384_ECDSA {
            let key = P384Public::from_sec1(&decode(pub_hex).unwrap()).unwrap();
            let msg = decode(msg_hex).unwrap();
            let sig = decode(sig_hex).unwrap();
            assert!(key.verify_digest(alg(*alg_id), &msg, &sig).unwrap());
            let mut bad_msg = msg.clone();
            if bad_msg.is_empty() {
                bad_msg.push(0);
            } else {
                bad_msg[0] ^= 0x01;
            }
            assert!(!key.verify_digest(alg(*alg_id), &bad_msg, &sig).unwrap());
            let mut bad_sig = sig.clone();
            let last = bad_sig.len() - 1;
            bad_sig[last] ^= 0x01;
            assert!(!matches!(
                key.verify_digest(alg(*alg_id), &msg, &bad_sig),
                Ok(true)
            ));
            assert!(!matches!(
                key.verify_digest(alg((*alg_id + 1) % 3), &msg, &sig),
                Ok(true)
            ));
        }
    }

    #[test]
    fn p384_scalar_range() {
        assert!(P384Private::from_bytes(&[0u8; 48]).is_err());
        let mut one = [0u8; 48];
        one[47] = 1;
        assert!(P384Private::from_bytes(&one).is_ok());
        let mut max = [0xffu8; 48];
        max[0] = 0x7f;
        // Larger than n: n starts with 0xfff...fc763, so all-0xff is >= n.
        assert!(P384Private::from_bytes(&[0xffu8; 48]).is_err());
        assert!(P384Private::from_bytes(&max).is_ok());
    }
}

#[cfg(test)]
mod vectors {

    // (private_scalar_hex, peer_sec1_hex, shared_x_hex)
    pub(super) const P256_ECDH: &[(&str, &str, &str)] = &[
        ("b48c788676c12e51af66251cdda13da352994764283b9f0a6f4e5d26610ada55", "041ebe405c77d45f33a39898905a968b83f13005074de59d7a9cbe00c6fc8ff1ee58f05285a84f357ed30a045cec35ad7b0f91398f7a8d4617f315a70e36772b31", "e3c48caa1189764a8be52effc5086acea2b0db9349444f5b457fba08eec31937"),
        ("ca339456cce4800e02a670e583bc6c2ee4da3d216f363028e1ce496495b7d6e5", "04268c56b02af2aebe23a592eaae37f256d0f0329b6a382b269dd99c7d19c9a3838905e9a1404a47002f54e213a5da4642bf8ec36b994b632e965b788e0c89856a", "8f9ad55b9dab496de36a93747ca1fc0066218ea897610744d320ea9ea954de82"),
        ("5cefc4319e1517e62104f8da11806ebcd776685490d5b49fc69064e5b4b941b1", "04e1659ae9f8dd59250ccefa9516f38b76a6bc776489b6de2a43c44bcbbb617e06bb71748cea618d4dcbbe40b5440f5bdab5a3ddf78ca5d6d280b850c3988c51c9", "8481fc7785dd62b63f1d5c90d3ec47ae998079487a1d470aab877b859064851b"),
        ("d0a03d4fa484ceed42b1e61ea86426ee6b0860e660c1e575cce23a0c344d37c1", "04616d9b21d8e79cacdbebc9092db1b04f57d9117a50f9431866ea8af86543b07ac1c3d2c552fa0c1d302703467a22b561c8088c1a420aeb192a4be6522fcaea30", "5a099f7dfc12f6231cf0680bf9f54060fd0d612320ea945670a96434a1be71ae"),
        ("b3c24e76d5d745359121432c779453cadafc6d3d1c4ce7b0d3e230c433d23829", "04ce9a496120809be55e6d3c7bd49993ae257c792a098fe0f16b0e45891e5cd60a80f47544cea3c7da683989de6d76e6f0a614a5d9e9c0551c4229161e4fdfc62c", "d992a21d0ce538185624416e8657b549e5240760917d02d984f48e1ea192e041"),
        ("2675939a7a2b0ff77064b95704663f0550251b90377f4608abd8104466090efb", "04fae472031e01b018467ce6d26a0f846ed84599b6a4a2d02e15ca3a45e6d5ec19d98d7e645b9e1cea3fb3136d7c4323c4721a7f815f45450e2e52fc63f38163e1", "87f137ed5d000ac86aa7701376c52144f3020b110c00e23bc57709bd13d90844"),
        ("f9b6a9b4c16d6598904176ac50a963739ed3b39a71a96c29a66669f64675b7a6", "023f07f302a1d418e155f0eb1915fde99cdc0e16f312a35f4c034135355c4a6492", "fca31cf96cdb361590a061444e1d9c9df7b8a5133abab22d30f9433292805d45"),
        ("90523689360ec444ad64892f21128c5afca05d49f757fdfacc35076a0ca02993", "034c2cd47ec58100c574b09e749b896e496c9ba34664d64bdabf6b6021396da5e5", "cdcce493c45c2359d43bce6f6b52589f81f6474fb9d041f875ccf4f7f4554fac"),
        ("3898db55019bf94612c4dd10b02b74015c9f4a00bdd74d66829f9534d023d041", "030b8d88ba43841f619e29526969436a0beeb881813b2496559fedc8ab1477b087", "16829567c30116ba5138b36f09aabfbb1abe1d51f72fa30bcbd38d8526b36a8d"),
    ];
    pub(super) const P384_ECDH: &[(&str, &str, &str)] = &[
        ("66f1723c1a38462ee92a950206e2041d29a593e9fd29e5df4d9c95fc53beb8d9000f64263ed7d6a446086235d6e5faa7", "040c3d4dd6534a5c9866875515debc76350713a22e941129e6b22b232f10fbf74195a87148d96dddcbbed774d6c476e1a5d4661de4b1ac9a389f69a076266f9cede10126c0a48c450be2e7a47564561eae136ceb05c7f528f9391104151dfd2fd2", "0c425dd23a5fe023abfd71c0a67413ef6900355bac0b7b08c2b38ace8d85fdbfb808e46a4731aae96dda3b0aa77670fb"),
        ("c1684a2d0b1f3e9a3d20a58d17fa3b9acc6b992d07a7480407767fdd7d6d1395a655ea73823d9dcea840b1265dd7b4b0", "04f8073937c0528bf2e40c85ef8f1aa335954955ee95f8459a1f7ae9774710447b7079533e0326a1f228545a6c3e04bf7349d74c379bdb0f7d4818bad22259c590fb6bd7092e4d78e6bc5008f3107c6525d7bf5ec8e202fb1539ffb81d36abbf7c", "2f9375550517291610a628c72110f824b4c55619c3c9af173322832b1dcdbc77411f532ecf2724464df4ff9a3def65b0"),
        ("eb54ca3ffbdc958350629dea8b9f2fbc5d5c68894747e6eb4fd4f411925d5ac9743a7f82eac807285d925196d841c4ec", "046ba471c87f87c2b461695bafe328ab96e99f1073c4ee6b324dd4ecd5430bcd6171975e237d3abc2077b3c7a10f255d702e4c35aed7b1fe4ab7c296e4a4915c39fd2035fa31f93c00d80ec225aa66020befaf43d7b1a5ad90774907b425b606d9", "b5af6bc0d49b3ded20f6817c870c7a5a935f7fd6b6bb116815fd7c4fb2db2861d70a07c121d975f7ec01650310bb22f8"),
        ("6b9f0dc16351d671b0bf31b0e5406778c4210191f333eff367d63d17497db7ebcaf2993448b63636a0a3da200afbd914", "0476ab734d40dad5b0923442b2c6b1f7b3d1b5936bef9fbea5a79471e8f5d953f32d4ce2f2c1777872c02b1e9d47c8a24b6ea0fb90a51df4ad551cd6711a3441867e5e340e0185f716a8546972b9dafd8e74016f073bd7a69f6e4e600454af2cec", "fbd379a7144d23cfc80b208090a740de2a63a6bdc48caf1f211e4dd5eeff6a3fe27c8eb8f8b68369aea1327157b57129"),
        ("568550f2eeff12bfd4a73d8c7b34d34f2bacf3952756c06509767a78148a63335f172641c9d62b1dcfa40a1d7ccc8202", "049261d9eb2f21b864be81aa7e26f81c154fd3a8ee35de249c2a7b1327d1ce2235fa21cd1621a9e7c8ec7d262365b7d3266b90c66f69b8286632eecc1b5e8f47797bc3151d3e6a7ddada2b3a444c394f414e3f76d26a8abae13b845b63e635345a", "45cee2c377d07a98e190684a570f1452e3c20f2f2b89c2dd8a37c6ad329d8954d708ced80094859dedaff733c3c0b1e5"),
        ("38a729f179bbab07b372ad54e6228f59a4f0f2d11f380ed959f0244a19021b3006ce55e259408a9158d1a4287fb7fa6a", "042059c6efaa7c590993c8a4a14e8d0df1ab24323c61246a0c39f4681647e332e5f4b296c4e576ca846a394720c4ea3f59dd971bb604b80c2a1c9a3acfc6d18fdbe9f911104e5c945f2d17ffe97e4befdcb92811d9c353398b808b707ea9ed4687", "318d61cb5bb5c700920d7c9f6d14ca479cfe82992385ad72f8a235ff5162d3670efac260102b6c941d76c35db82b63ed"),
        ("3b4bf079a818aebdd18b33fae2a078a371c846462531d74c7f19d01ff9019663b68ca6c98da794d02ebb8b165d804338", "024c889eb1e8ed0ac17bf9a8a4fde54c995fcef9685c5526c76d06ffb62081069e216e851134f6dbc910da9449dd40e33a", "e18d750eff874eb433489ba9696639ae39adf8fe776374091f82fc767cfaf57fab441bf8d44dbcec4e43650079336a0e"),
        ("b75cf4b4d3f2cda7e08cbb6eb84a466cc09e9351fe1dd68bec1919fb7c88d5bc6c5cfc66e2506ec978fcbd5dda0f68d5", "02bcfab03cf42d0c1d663aabf5efc1754d4a78f4660c4d9c594b40f343e26379279ffbd19e3764f4f12a9cdbaf7c8b3a03", "d72069ea4d3df201e68fb7b0a4508a31980fd302d2e64a1522a31de39413cedcb71a1865fb3ba36c907c14a898b9693b"),
        ("c3523725ff2628bee525e4bc945b4c32078011d6a6f3c8d1b200286114a3b6080ff510da2c14076b3844e7b955858464", "03b2cc192d1481b4097edf5fd523b7ffd300623b3f100c0a079171c2ee7de6e5ffefb91a207f5e71e2533f79e5a3386dee", "7b6bb97ac9b804f110a752a358db41791e18faf3a2843263cf33e20b46d0c87f970cf5601f2c82feb02b20547893091f"),
    ];
    // (public_sec1_hex, message_hex, der_signature_hex, hash_alg)
    pub(super) const P256_ECDSA: &[(&str, &str, &str, u8)] = &[
        ("041408a5a65d9eb418044b1fd82f1b2cdd278e22ba2304d55537ffcd0cdd74038616e25c1c83313e952ad44e82725d86c6e1a6bbf7639e6551dea40e9606dc50df", "af28c90330e885efc69a6798757d45ab5ea49b87545d2681326613cad8", "3046022100d5e421328624071c27c802f902aa3668481365f6eed91b9fceacdd2d4f8ff821022100fd65075d16a5ba9e971d6aaee16ee07520bb24a1f7ad4befba3e4ffef4db3f5b", 0),
        ("0495697c1bbc4fa4f71f525618ca4a0937732b7eab611ff376e39d297106c3f39b32595623d5074e455e1b1e6da6f99914ac9525d0006cccbe62d548bb05ee9711", "de37083e3d5df07e1eaf547f19941975d5c3bcd6e40ec529a57f061aa85cbf39001c73c2865368420f593f7545c059fbe8be9cbcf897", "304502202e35c87471c96bb26dc78d4ead47515a03f3e24210f840269fdf6d4d2fb6ae04022100f5e8ca96b4107e7c1658ba7dd5be0f731da2c20ed66c298c73afef61aa583d64", 0),
        ("044fff850149054f3bb1ace8bb86a5470d385e43ec7f33e3af669957fb0218fc797a65acfc0a934879577fcbe84731cac0089c7825269ee14cdb194181e4955815", "", "3045022100a8f5839711a23afde0552f546da01c3f4a0ffd1aab7b7182ba491f12faf53146022037ead6b03cacb6567d69819b3888ebfc66cbabcf457b46f292d90cf7a3005bad", 0),
        ("04bb07524f649e17b224f80cc1a5d438d848f4992c7393988ea1d1c773741f5ae721c302e951643946c5bd5058eab975d5ef6a3b386e313f0cb9a256bedb509e7d", "8d6c69829e6004ce6fc46c5068e299b66855b59b", "3046022100d367df2cc852b0ae767ea70736990dfd917ad578cd96fdce8cce00ac702dcd6f02210089f298962f02112b679a662f6dbf4bff953419b8f7d4344cfed4407ddf340c5e", 0),
        ("041e6b6009a3f8b6523e09b8dc630079e6bee5caea490a3305512f2eef88c7de82552ee6db52b4da901ea5122be42cf942a85dad54d87ee4ea3b76bd5e60263643", "85ab2e0950c09f3fedd298b8128c13c985e17a95345149db8ded9ba9a5ebe2c1ce7c843621787a4ee17b536b519cf48c151b6d293974f473e75facc6d62b38012fed1431288b7b0fc2", "30440220775ed7f4a1a1ef62ddbb1a12fa62f3a503921dfc42a702b79e8321b71d719cb3022023aaba9fb7ace3733ca611b7637b81ea232c3fd5c017458270c0881696d9aa76", 0),
        ("04e357ab7c889d0839e23741725e56715ea9dbdd14150f2854ab6459384f0c60bc8a81197bf3fc0e7331feda84786b7ebc2b8b49198ab6f69f6895b4c8d389757c", "014446beb291018904a8dc14b42b719966806a04ab0f66", "30450220055a38909f4c2111b284ed1071b39e76a27e2b7d92fde126cd3014885cbc84c1022100e9fa5dbd86307e6f9c535392adcd376cfc06e35918c0263f4b157605bfa3454a", 0),
    ];
    pub(super) const P384_ECDSA: &[(&str, &str, &str, u8)] = &[
        ("04a1124751b8fd5828907eadf1208626214a2e61b32c0ed33dbb797941becec5c5079c90719adffcc1adc87cd722282dffca1a0dbc84770b9e67cd8eb13bfbc8b2f2ebe1c978c8592bea6382f4f26965d908e6c2769bfa2cc4bd8ee234b2537932", "0eb3d62520b699a33e566efe849443ce9daf03201d3938702ef86837", "3065023003b4f337302d888a6f6c93806f3c6e95c39e885325ef3c180cb26cb7aab314ac6698582cdc0761b1e8f8a33d9d4ed237023100fa3bcd59426635a3e936f02a6f7c905ba01b5f9d138c42f2bd44eca16bd96c77af1759f7b0db1ccb523b8d66c0bc0d51", 1),
        ("04187eafda9b0a9de30bfc06faad599c9d670b969be8d61c9d25f8c1600eb8641ff8c1dcdc89e152d69d49ad198c254d5000a8736fc2338bc12a1f9bd6df531354e4d1118f0970ed772028d7966bb71f313c410dbfd978dc148537e050966ea227", "3f9db4964079", "306402307a15a7aa4246b37eb4d4d8daed08eeadf1120c163dea10fba1493e9172dbe5926d3df27658f91497f1d2685b6af1e6a10230309d83dfde117aba98348f0a6a005873c5c5e3afafbe4cad22e6b0a86cc1160f0a0f62116ba1dc34a6df3c90cc1aad01", 1),
        ("0431f365651d8f55e82d9b5e66640f2701dcf9370f5848f7f05e4bcab4d42b0d4382c968451ad4a3ba2946d1bb05cfe7c51ca8db80322a48f121dc467bb40a8b325000e3f766fd7c90362210719130efbb0447b95881ebb588d02a82404be899f6", "2032e74bc136e9930d83026d200209cc26a405b02bc2959871da2d2c12dc185fb6427f7a24238fe0ba236961c545b9edb37b539a4a961fec79b1", "3065023100ad499520ed629f174363b00d198b536c201ed892416c028339ceafd497c83dd0c21dada30445751fd94e16e91752101d0230689c8e107921421e09b1ac1ba6eda3f25a7c12a4206ef888e0f152c0b63c38c8c88b233470c3ea0b4214a4238053159d", 1),
        ("045a1e459c8551048d713006f235fd6a9d85eecb2b7529f3ce2456d17584a51f34a3e128e67eb5d5f46d09766fea5899d711ec576c38daec59994efd1583c1bcf1e3380697a4c0eb4d9cdef57ce78bc2af9991eda9b2a30e9d3b8b29d4da41f6df", "ace49bbf530b03", "306402304b7ea72b4e58a2377c53f6e55dfa7421ef844adca77b101ae55b57908b52f8b86f56f3c03c26657f65a88167c9efb71b0230041a7c29186c884bbbfdd95bdfc722999de7fcf7e7387117e16e44ff0b33ddf67a22136eed35d572c179c6f14c4fa344", 2),
        ("04398895ea4ae955dace82a61289f0583fe31148a10f72b58643ea3ce44a3c75da2bbdde11e842caf34da805190faa8da012adb5e40a659398dda6381cb4b2d3244d206fcd41fcb6a16536b4e22193b7bce204c179682d5700028368d606d621c7", "4a0b618ea75687ee730ce1be0e4423cc36471f9b15a21a23813352d559ad4fe6843ec79c521870bbe0135f1b9fa09507", "3064023011aec8c9e75a36f7e278f1172358f979dff8d7297246082dfc89f3778ab6e6dc5216e8a08277f8a028191031a162e6bd0230618ee32fbb4ad0f82e71038d467cbf9a7c2009e56619e686f8aadacf71b0855bcb259a16de9ef94152c8be205892683d", 0),
        ("043464e16e902411f7a19880220406b6f2eb7c21db2454e5c9e9be2ee14d17fa04d78eeb4ae3d18f06e47b8e4a4fda4dd9778460438f3838055f22f19c64146ac65333578e81420ec724a454e672efe49024532c38cd01e73d828e4328a0007aef", "ad5aacbdfcdd698d90da02b9fef4bbcc14692a", "3065023004e2dde8f05333192e201af90a9e85278655a07b7aad83262db0c602e94f9c1e131397aab07d58752a89e20418174c64023100f73262786d1085fec56ad0438893f4cda04f0c251696d1993498d09ffd8949f5ab722957cd3ce4f0708738a770b49edd", 1),
    ];
    pub(super) const P256_COMPRESSED: &str =
        "02cdc1fde9e2769c7a2733dfb9024d6530891498d9e512ab6dbb8a77c240a8fd04";
    pub(super) const P256_UNCOMPRESSED: &str = "04cdc1fde9e2769c7a2733dfb9024d6530891498d9e512ab6dbb8a77c240a8fd04af863fc967e2ac7d413eb1afeb962278de03b755ff24f77478ea5841c511449a";
    pub(super) const P384_COMPRESSED: &str = "0287fd016edc516203ba81ff45ed86b34c9e1fd4928e6939c4a0c7ff1d83205a02997bcf64b2f97143e3ec1f261bcdf4a9";
    pub(super) const P384_UNCOMPRESSED: &str = "0487fd016edc516203ba81ff45ed86b34c9e1fd4928e6939c4a0c7ff1d83205a02997bcf64b2f97143e3ec1f261bcdf4a95ca8130de3b386c0e80f0c7ba75b9aa8337736747c4ae6c75f9e855b55d755ba8b699936be4657839bc8709fe5c1b2d6";
    pub(super) const RFC6979_SAMPLE_SIG: &str = "3046022100efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716022100f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8";
    pub(super) const RFC6979_SAMPLE_PUB: &str = "0460fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb67903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299";
}

// ---------------------------------------------------------------------------
// Release-mode performance probes (run with --ignored --nocapture)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod perf {
    use super::vectors::*;
    use super::*;
    use emerag_util::hex::decode;

    fn k32(hex_str: &str) -> [u8; 32] {
        let v = decode(hex_str).unwrap();
        let mut a = [0u8; 32];
        a.copy_from_slice(&v);
        a
    }

    #[test]
    #[ignore]
    fn perf_p256_ecdh() {
        let (priv_hex, peer_hex, _) = P256_ECDH[0];
        let k = P256Private::from_bytes(&k32(priv_hex)).unwrap();
        let peer = P256Public::from_sec1(&decode(peer_hex).unwrap()).unwrap();
        let iters = 200;
        let start = std::time::Instant::now();
        for _ in 0..iters {
            let _ = k.diffie_hellman(&peer).unwrap();
        }
        println!(
            "p256 ecdh (incl. inversion): {:.1} us/op",
            start.elapsed().as_secs_f64() * 1e6 / iters as f64
        );
        let iters = 200;
        let start = std::time::Instant::now();
        for _ in 0..iters {
            let _ = k.public_key();
        }
        println!(
            "p256 public_key: {:.1} us/op",
            start.elapsed().as_secs_f64() * 1e6 / iters as f64
        );
    }
}

// ---------------------------------------------------------------------------
// Published ECDH vectors: RFC 5903 section 8.1 (P-256) and 8.2 (P-384)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod rfc5903 {
    use super::*;
    use emerag_util::hex::{decode, encode};

    fn a32(h: &str) -> [u8; 32] {
        let v = decode(h).unwrap();
        let mut a = [0u8; 32];
        a.copy_from_slice(&v);
        a
    }

    fn a48(h: &str) -> [u8; 48] {
        let v = decode(h).unwrap();
        let mut a = [0u8; 48];
        a.copy_from_slice(&v);
        a
    }

    #[test]
    fn p256_rfc5903_ecdh() {
        let init = P256Private::from_bytes(&a32(
            "c88f01f510d9ac3f70a292daa2316de544e9aab8afe84049c62a9c57862d1433",
        ))
        .unwrap();
        let resp = P256Private::from_bytes(&a32(
            "c6ef9c5d78ae012a011164acb397ce2088685d8f06bf9be0b283ab46476bee53",
        ))
        .unwrap();
        let pi = init.public_key();
        let pr = resp.public_key();
        let pi_sec1 = pi.to_sec1();
        assert_eq!(
            encode(&pi_sec1[1..33]),
            "dad0b65394221cf9b051e1feca5787d098dfe637fc90b9ef945d0c3772581180"
        );
        assert_eq!(
            encode(&pi_sec1[33..]),
            "5271a0461cdb8252d61f1c456fa3e59ab1f45b33accf5f58389e0577b8990bb3"
        );
        let pr_sec1 = pr.to_sec1();
        assert_eq!(
            encode(&pr_sec1[1..33]),
            "d12dfb5289c8d4f81208b70270398c342296970a0bccb74c736fc7554494bf63"
        );
        assert_eq!(
            encode(&pr_sec1[33..]),
            "56fbf3ca366cc23e8157854c13c58d6aac23f046ada30f8353e74f33039872ab"
        );
        let s1 = init.diffie_hellman(&pr).unwrap();
        let s2 = resp.diffie_hellman(&pi).unwrap();
        assert_eq!(s1, s2);
        assert_eq!(
            encode(&s1),
            "d6840f6b42f6edafd13116e0e12565202fef8e9ece7dce03812464d04b9442de"
        );
    }

    #[test]
    fn p384_rfc5903_ecdh() {
        let init = P384Private::from_bytes(&a48(
            "099f3c7034d4a2c699884d73a375a67f7624ef7c6b3c0f160647b67414dce655e35b538041e649ee3faef896783ab194",
        ))
        .unwrap();
        let resp = P384Private::from_bytes(&a48(
            "41cb0779b4bdb85d47846725fbec3c9430fab46cc8dc5060855cc9bda0aa2942e0308312916b8ed2960e4bd55a7448fc",
        ))
        .unwrap();
        let pi = init.public_key();
        let pr = resp.public_key();
        let pi_sec1 = pi.to_sec1();
        assert_eq!(
            encode(&pi_sec1[1..49]),
            "667842d7d180ac2cde6f74f37551f55755c7645c20ef73e31634fe72b4c55ee6de3ac808acb4bdb4c88732aee95f41aa"
        );
        assert_eq!(
            encode(&pi_sec1[49..]),
            "9482ed1fc0eeb9cafc4984625ccfc23f65032149e0e144ada024181535a0f38eeb9fcff3c2c947dae69b4c634573a81c"
        );
        let pr_sec1 = pr.to_sec1();
        assert_eq!(
            encode(&pr_sec1[1..49]),
            "e558dbef53eecde3d3fccfc1aea08a89a987475d12fd950d83cfa41732bc509d0d1ac43a0336def96fda41d0774a3571"
        );
        assert_eq!(
            encode(&pr_sec1[49..]),
            "dcfbec7aacf3196472169e838430367f66eebe3c6e70c416dd5f0c68759dd1fff83fa40142209dff5eaad96db9e6386c"
        );
        let s1 = init.diffie_hellman(&pr).unwrap();
        let s2 = resp.diffie_hellman(&pi).unwrap();
        assert_eq!(s1, s2);
        assert_eq!(
            encode(&s1),
            "11187331c279962d93d604243fd592cb9d0a926f422e47187521287e7156c5c4d603135569b9e9d09cf5d4a270f59746"
        );
    }
}
