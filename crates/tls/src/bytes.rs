//! Bounds-checked byte readers and writers for TLS wire formats.
//!
//! Every read is fallible: truncated or over-long length prefixes produce an
//! error that names the message being parsed, never a panic or an implicit
//! clamp. Writers only append; length prefixes are patched by callers that
//! know how many bytes they emitted.

use crate::Error;

/// A cursor over a handshake message or extension block.
pub(crate) struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
    label: &'static str,
}

impl<'a> Reader<'a> {
    pub(crate) fn new(data: &'a [u8], label: &'static str) -> Self {
        Reader {
            data,
            pos: 0,
            label,
        }
    }

    fn err(&self, what: &str) -> Error {
        Error::new(format!(
            "tls: handshake: malformed {}: {}",
            self.label, what
        ))
    }

    pub(crate) fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    pub(crate) fn position(&self) -> usize {
        self.pos
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.pos >= self.data.len()
    }

    pub(crate) fn u8(&mut self) -> Result<u8, Error> {
        let b = *self
            .data
            .get(self.pos)
            .ok_or_else(|| self.err("unexpected end of message"))?;
        self.pos += 1;
        Ok(b)
    }

    pub(crate) fn u16(&mut self) -> Result<u16, Error> {
        let s = self.bytes(2)?;
        Ok(u16::from_be_bytes([s[0], s[1]]))
    }

    pub(crate) fn u24(&mut self) -> Result<usize, Error> {
        let s = self.bytes(3)?;
        Ok(((s[0] as usize) << 16) | ((s[1] as usize) << 8) | (s[2] as usize))
    }

    pub(crate) fn bytes(&mut self, n: usize) -> Result<&'a [u8], Error> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or_else(|| self.err("length overflow"))?;
        if end > self.data.len() {
            return Err(self.err(&format!(
                "truncated (need {} bytes, {} remain)",
                n,
                self.remaining()
            )));
        }
        let out = &self.data[self.pos..end];
        self.pos = end;
        Ok(out)
    }

    /// A vector prefixed with a one-byte length.
    pub(crate) fn vec_u8(&mut self) -> Result<&'a [u8], Error> {
        let n = self.u8()? as usize;
        self.bytes(n)
    }

    /// A vector prefixed with a two-byte length.
    pub(crate) fn vec_u16(&mut self) -> Result<&'a [u8], Error> {
        let n = self.u16()? as usize;
        self.bytes(n)
    }

    /// A vector prefixed with a three-byte length.
    pub(crate) fn vec_u24(&mut self) -> Result<&'a [u8], Error> {
        let n = self.u24()?;
        self.bytes(n)
    }

    pub(crate) fn finish(&self) -> Result<(), Error> {
        if self.pos == self.data.len() {
            Ok(())
        } else {
            Err(self.err(&format!("{} trailing byte(s)", self.remaining())))
        }
    }
}

/// A growable output buffer with the primitive encoders TLS needs.
pub(crate) struct Writer {
    pub(crate) buf: Vec<u8>,
}

impl Writer {
    pub(crate) fn new() -> Self {
        Writer { buf: Vec::new() }
    }

    pub(crate) fn with_capacity(n: usize) -> Self {
        Writer {
            buf: Vec::with_capacity(n),
        }
    }

    pub(crate) fn u8(&mut self, v: u8) {
        self.buf.push(v);
    }

    pub(crate) fn u16(&mut self, v: u16) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }

    pub(crate) fn bytes(&mut self, v: &[u8]) {
        self.buf.extend_from_slice(v);
    }

    pub(crate) fn vec_u8(&mut self, v: &[u8]) {
        self.u8(v.len() as u8);
        self.bytes(v);
    }

    pub(crate) fn vec_u16(&mut self, v: &[u8]) {
        self.u16(v.len() as u16);
        self.bytes(v);
    }

    /// Reserve a two-byte length slot, returning its position.
    pub(crate) fn reserve_u16(&mut self) -> usize {
        let at = self.buf.len();
        self.buf.extend_from_slice(&[0, 0]);
        at
    }

    /// Fill a length slot reserved with reserve_u16().
    pub(crate) fn patch_u16(&mut self, at: usize) {
        let n = self.buf.len().saturating_sub(at + 2);
        let n = if n > u16::MAX as usize {
            u16::MAX
        } else {
            n as u16
        };
        if at + 2 <= self.buf.len() {
            self.buf[at..at + 2].copy_from_slice(&n.to_be_bytes());
        }
    }
}

impl Default for Writer {
    fn default() -> Self {
        Writer::new()
    }
}
