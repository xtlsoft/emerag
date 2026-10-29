//! PEM (RFC 7468) decoding/encoding for certificates and keys.

use crate::{Error, Result};

pub struct PemBlock {
    pub label: String,
    pub der: Vec<u8>,
}

/// Parse all PEM blocks in a document. Ignores text before/between blocks and
/// accepts CRLF line endings.
pub fn parse(input: &[u8]) -> Result<Vec<PemBlock>> {
    let text =
        core::str::from_utf8(input).map_err(|_| Error::new("pem: input is not valid UTF-8"))?;
    let mut out = Vec::new();
    let mut rest = text;
    loop {
        let Some(begin) = find(rest, "-----BEGIN ") else {
            break;
        };
        let after = &rest[begin + 11..];
        let Some(label_end) = after.find("-----") else {
            return Err(Error::new("pem: malformed BEGIN line"));
        };
        let label = after[..label_end].trim().to_string();
        let body_start = begin + 11 + label_end + 5;
        let end_marker = format!("-----END {label}-----");
        let Some(end_rel) = rest[body_start..].find(&end_marker) else {
            return Err(Error::new(format!("pem: missing END for {label}")));
        };
        let body = &rest[body_start..body_start + end_rel];
        let b64: String = body.chars().filter(|c| !c.is_whitespace()).collect();
        let der = emerag_util::base64::decode(&b64)
            .map_err(|e| Error::new(format!("pem: bad base64 in {label}: {e}")))?;
        out.push(PemBlock { label, der });
        rest = &rest[body_start + end_rel + end_marker.len()..];
    }
    if out.is_empty() {
        return Err(Error::new("pem: no PEM blocks found"));
    }
    Ok(out)
}

fn find(haystack: &str, needle: &str) -> Option<usize> {
    haystack.find(needle)
}

/// Encode a DER blob as a PEM block (used by tests and key export).
pub fn encode(label: &str, der: &[u8]) -> String {
    let b64 = emerag_util::base64::encode(der);
    let mut out = String::new();
    out.push_str(&format!("-----BEGIN {label}-----\n"));
    for chunk in b64.as_bytes().chunks(64) {
        out.push_str(core::str::from_utf8(chunk).unwrap_or(""));
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----\n"));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let der = vec![1u8, 2, 3, 250, 251];
        let pem = encode("TEST", &der);
        let blocks = parse(pem.as_bytes()).unwrap();
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].label, "TEST");
        assert_eq!(blocks[0].der, der);
    }

    #[test]
    fn parses_multiple_blocks_with_crlf() {
        let text = format!("junk\r\n{}\r\n{}", encode("A", b"one"), encode("B", b"two"));
        let blocks = parse(text.as_bytes()).unwrap();
        assert_eq!(blocks.len(), 2);
        assert_eq!(blocks[1].label, "B");
        assert_eq!(blocks[1].der, b"two");
    }

    #[test]
    fn rejects_garbage() {
        assert!(parse(b"not a pem").is_err());
        assert!(parse(b"-----BEGIN X-----\n!!!\n-----END X-----").is_err());
    }
}
