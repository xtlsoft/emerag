//! Hex encoding helpers.

use crate::{bail, Result};

pub fn encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 15) as usize] as char);
    }
    out
}

pub fn encode_upper(bytes: &[u8]) -> String {
    encode(bytes).to_ascii_uppercase()
}

fn nibble(c: u8) -> Option<u8> {
    Some(match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        b'A'..=b'F' => c - b'A' + 10,
        _ => return None,
    })
}

pub fn decode(s: &str) -> Result<Vec<u8>> {
    let bytes: Vec<u8> = s.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    if bytes.len() % 2 != 0 {
        bail!("hex: odd number of digits");
    }
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks(2) {
        let hi = nibble(pair[0]).ok_or_else(|| crate::Error::new("hex: invalid digit"))?;
        let lo = nibble(pair[1]).ok_or_else(|| crate::Error::new("hex: invalid digit"))?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let data = [0u8, 1, 15, 16, 127, 128, 255];
        assert_eq!(encode(&data), "00010f107f80ff");
        assert_eq!(decode("00 01 0F 10 7F 80 ff").unwrap(), data);
        assert!(decode("abc").is_err());
        assert!(decode("zz").is_err());
    }
}
