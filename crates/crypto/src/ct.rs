//! Constant-time helpers used by AEAD tag checks, signature comparison and
//! padding validation.

/// Compare two byte slices without data-dependent branches on content.
/// Length is not secret in our protocols, so early length exit is acceptable.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Return 1 if a == b else 0, in constant time for equal lengths.
pub fn ct_eq_u8(a: u8, b: u8) -> u8 {
    let x = a ^ b;
    let x = x | x.wrapping_neg();
    ((x >> 7) ^ 1) & 1
}

/// Conditional select: returns a if choice == 0, b if choice == 1.
pub fn ct_select(a: u8, b: u8, choice: u8) -> u8 {
    let mask = 0u8.wrapping_sub(choice & 1);
    (a & !mask) | (b & mask)
}

/// Compare two 32-bit words in constant time; returns 1 when equal, 0 otherwise.
pub fn ct_eq_u32(a: u32, b: u32) -> u8 {
    let x = a ^ b;
    (((x | x.wrapping_neg()) >> 31) ^ 1) as u8
}

/// Compare two 64-bit words in constant time; returns 1 when equal, 0 otherwise.
pub fn ct_eq_u64(a: u64, b: u64) -> u8 {
    let x = a ^ b;
    (((x | x.wrapping_neg()) >> 63) ^ 1) as u8
}

/// Conditional select for 32-bit words: a if choice == 0, b if choice == 1.
pub fn ct_select_u32(a: u32, b: u32, choice: u8) -> u32 {
    let mask = 0u32.wrapping_sub((choice & 1) as u32);
    (a & !mask) | (b & mask)
}

/// Overwrite sensitive memory. Not zeroization guarantees, but avoids leaving
/// keys in buffers that are about to be reused.
///
/// The volatile write is the one unsafe operation in this crate: a normal store
/// could be optimized away because the buffer is dead afterwards, and only a
/// volatile write reliably reaches memory. It is confined to this loop.
pub fn wipe(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        unsafe { core::ptr::write_volatile(b, 0) };
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn equality() {
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"ab"));
        assert!(ct_eq(b"", b""));
    }

    #[test]
    fn selection() {
        assert_eq!(ct_select(0xaa, 0x55, 0), 0xaa);
        assert_eq!(ct_select(0xaa, 0x55, 1), 0x55);
    }

    #[test]
    fn u8_helpers_exhaustive() {
        for a in 0..=255u8 {
            for b in 0..=255u8 {
                let want = if a == b { 1 } else { 0 };
                assert_eq!(ct_eq_u8(a, b), want, "ct_eq_u8({}, {})", a, b);
                for choice in 0..=2u8 {
                    let got = ct_select(a, b, choice);
                    let want = if choice & 1 == 0 { a } else { b };
                    assert_eq!(got, want, "ct_select({}, {}, {})", a, b, choice);
                }
            }
        }
    }

    #[test]
    fn word_helpers() {
        let cases = [
            (0u32, 0u32),
            (1, 1),
            (0x8000_0000, 0x8000_0000),
            (0xffff_ffff, 0xffff_ffff),
            (0, 1),
            (0x8000_0000, 0),
            (0xffff_ffff, 0x7fff_ffff),
        ];
        for &(a, b) in &cases {
            assert_eq!(ct_eq_u32(a, b), if a == b { 1 } else { 0 });
            for choice in 0..=1u8 {
                assert_eq!(ct_select_u32(a, b, choice), if choice == 0 { a } else { b });
            }
        }
        for &(a, b) in &[
            (0u64, 0u64),
            (1, 1),
            (1 << 63, 1 << 63),
            (u64::MAX, u64::MAX),
            (0, 1),
            (1 << 63, 0),
            (u64::MAX, u64::MAX - 1),
        ] {
            assert_eq!(ct_eq_u64(a, b), if a == b { 1 } else { 0 });
        }
    }

    #[test]
    fn equality_over_random_slices() {
        let mut state = 0x243f_6a88_85a3_08d3u64;
        for len in 0..=64usize {
            let mut a = vec![0u8; len];
            let mut b = vec![0u8; len];
            for i in 0..len {
                state = state
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                a[i] = (state >> 33) as u8;
                b[i] = a[i];
            }
            assert!(ct_eq(&a, &b));
            if len != 0 {
                let mut c = b.clone();
                c[len / 2] ^= 1 << (len % 8);
                assert!(!ct_eq(&a, &c), "single bit flip len {}", len);
                assert!(!ct_eq(&a, &b[..len - 1]), "short slice len {}", len);
            }
        }
    }

    #[test]
    fn wipe_clears_bytes() {
        let mut buf = [0xa5u8; 64];
        wipe(&mut buf);
        assert!(buf.iter().all(|&b| b == 0));
        let mut empty: [u8; 0] = [];
        wipe(&mut empty);
    }
}
