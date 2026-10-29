//! Base64 (RFC 4648), standard and URL-safe alphabets, no dependencies.

use crate::{bail, Result};

const STD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn encode_with(input: &[u8], alphabet: &[u8; 64], pad: bool) -> String {
    let mut out = String::with_capacity((input.len() + 2) / 3 * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(alphabet[(n >> 18) as usize & 63] as char);
        out.push(alphabet[(n >> 12) as usize & 63] as char);
        if chunk.len() > 1 {
            out.push(alphabet[(n >> 6) as usize & 63] as char);
        } else if pad {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(alphabet[n as usize & 63] as char);
        } else if pad {
            out.push('=');
        }
    }
    out
}

pub fn encode(input: &[u8]) -> String {
    encode_with(input, STD, true)
}

pub fn encode_no_pad(input: &[u8]) -> String {
    encode_with(input, STD, false)
}

pub fn encode_url(input: &[u8]) -> String {
    encode_with(input, URL, false)
}

pub fn encode_url_padded(input: &[u8]) -> String {
    encode_with(input, URL, true)
}

fn decode_value(c: u8) -> Option<u8> {
    Some(match c {
        b'A'..=b'Z' => c - b'A',
        b'a'..=b'z' => c - b'a' + 26,
        b'0'..=b'9' => c - b'0' + 52,
        b'+' | b'-' => 62,
        b'/' | b'_' => 63,
        _ => return None,
    })
}

/// Decode base64, accepting both alphabets, optional padding and embedded
/// whitespace (which is common in copy-pasted keys from serial consoles).
pub fn decode(input: &str) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(input.len() / 4 * 3 + 3);
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    let mut padding = 0usize;
    for &b in input.as_bytes() {
        if b.is_ascii_whitespace() {
            continue;
        }
        if b == b'=' {
            padding += 1;
            continue;
        }
        if padding > 0 {
            bail!("base64: data after padding");
        }
        let Some(v) = decode_value(b) else {
            bail!("base64: invalid character");
        };
        acc = (acc << 6) | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    // Leftover bits must be at most 4 for a canonical encoding; be lenient
    // about non-zero trailing bits (many tools emit them).
    if !matches!(bits, 0 | 2 | 4) {
        bail!("base64: truncated input");
    }
    if padding > 2 {
        bail!("base64: too much padding");
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc4648_vectors() {
        for (plain, encoded) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(encode(plain.as_bytes()), encoded);
            assert_eq!(decode(encoded).unwrap(), plain.as_bytes());
        }
    }

    #[test]
    fn url_safe_roundtrip() {
        let data = [0xfb, 0xff, 0xbf, 0x00, 0x01];
        let e = encode_url(&data);
        assert!(!e.contains('=') && !e.contains('+') && !e.contains('/'));
        assert_eq!(decode(&e).unwrap(), data);
    }

    #[test]
    fn whitespace_and_padding_are_lenient() {
        assert_eq!(decode("Zm9v\nYmFy").unwrap(), b"foobar");
        assert!(decode("!!!!").is_err());
    }

    #[test]
    fn roundtrip_all_lengths() {
        let data: Vec<u8> = (0..=255u8).cycle().take(1024).collect();
        for n in 0..300 {
            let slice = &data[..n];
            assert_eq!(decode(&encode(slice)).unwrap(), slice);
        }
    }
}
