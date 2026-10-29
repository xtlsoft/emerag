//! Response headers and streaming body framing.
//!
//! The body reader implements the three RFC 7230 framings: Content-Length,
//! Transfer-Encoding: chunked (extensions and trailers tolerated) and
//! read-until-close. It is a state machine that never buffers more than one
//! socket read plus one framing line, and it survives io timeouts: a WouldBlock
//! or TimedOut error leaves the framing state untouched so the caller can retry.

use std::io::{self, Read};

use emerag_util::sync::CancelToken;

use crate::conn::Conn;
use crate::error::{cancelled_io, invalid_data, unexpected_eof, Error, Result};
use crate::url::Url;

const MAX_CHUNK_LINE: usize = 8 * 1024;
const MAX_TRAILER_BYTES: usize = 64 * 1024;
const MAX_CHUNK_SIZE: u64 = 1 << 40;
const READ_CHUNK: usize = 8 * 1024;

/// How the response body is framed (RFC 7230 section 3.3.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BodyMode {
    None,
    Length(u64),
    Chunked,
    Close,
}

pub struct Response {
    pub status: u16,
    pub reason: String,
    pub headers: Vec<(String, String)>,
    pub url: Url,
    pub body: Box<dyn Read + Send>,
    /// First bytes of the body captured for status >= 400. These bytes are
    /// still delivered by body; this field is a copy for diagnostics.
    pub early_body: Vec<u8>,
}

impl Response {
    /// Case-insensitive header lookup; the first value wins when duplicated.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// All values of a header, in wire order.
    pub fn header_all(&self, name: &str) -> Vec<&str> {
        self.headers
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
            .collect()
    }

    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }

    pub fn content_type(&self) -> Option<&str> {
        self.header("content-type")
    }

    /// Read one chunk from the body. Timeouts surface as WouldBlock/TimedOut
    /// and the response remains usable; cancellation surfaces as an io error
    /// with the message "cancelled".
    pub fn read_some(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.body.read(buf)
    }

    /// Read the whole body, failing if it grows past limit bytes.
    pub fn read_to_end_limited(&mut self, limit: usize) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        let mut tmp = [0u8; READ_CHUNK];
        loop {
            let n = self.body.read(&mut tmp).map_err(Error::from)?;
            if n == 0 {
                return Ok(out);
            }
            if out.len() + n > limit {
                return Err(Error::new(format!(
                    "response body exceeds the limit of {limit} bytes"
                )));
            }
            out.extend_from_slice(&tmp[..n]);
        }
    }

    /// Same as read_to_end_limited but lossy-decodes the bytes as UTF-8.
    pub fn read_to_string_limited(&mut self, limit: usize) -> Result<String> {
        let bytes = self.read_to_end_limited(limit)?;
        Ok(String::from_utf8_lossy(&bytes).into_owned())
    }

    pub fn into_body(self) -> Box<dyn Read + Send> {
        self.body
    }
}

impl Read for Response {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.body.read(buf)
    }
}

impl core::fmt::Debug for Response {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Response")
            .field("status", &self.status)
            .field("reason", &self.reason)
            .field("headers", &self.headers.len())
            .field("url", &self.url.origin())
            .field("early_body", &self.early_body.len())
            .finish()
    }
}

/// The body reader handed to Response.body.
pub(crate) struct BodyReader {
    conn: Conn,
    mode: BodyMode,
    cancel: CancelToken,
    /// Unconsumed bytes already read from the socket (from the response head
    /// read plus subsequent reads).
    buf: Vec<u8>,
    pos: usize,
    /// Bytes captured during the error-body preview, replayed first so that
    /// early_body does not duplicate the body stream.
    push: Vec<u8>,
    push_pos: usize,
    remaining: u64,
    chunk_phase: u8,
    trailer_bytes: usize,
    done: bool,
}

impl BodyReader {
    pub(crate) fn new(conn: Conn, mode: BodyMode, cancel: CancelToken, leftover: Vec<u8>) -> Self {
        let remaining = match mode {
            BodyMode::Length(length) => length,
            _ => 0,
        };
        BodyReader {
            conn,
            mode,
            cancel,
            buf: leftover,
            pos: 0,
            push: Vec::new(),
            push_pos: 0,
            remaining,
            chunk_phase: 0,
            trailer_bytes: 0,
            done: matches!(mode, BodyMode::None),
        }
    }

    /// Adjust the socket read timeout (used for the short error-body preview).
    pub(crate) fn set_read_timeout(&self, timeout: std::time::Duration) {
        let _ = self.conn.set_read_timeout(timeout);
    }

    /// Replay bytes that were consumed by read_preview.
    pub(crate) fn set_pushback(&mut self, data: &[u8]) {
        if self.push_pos >= self.push.len() {
            self.push.clear();
            self.push_pos = 0;
        }
        self.push.extend_from_slice(data);
    }

    /// Read up to limit bytes, swallowing errors. Used to capture an error
    /// page for diagnostics when status >= 400.
    pub(crate) fn read_preview(&mut self, limit: usize) -> Vec<u8> {
        let mut out = Vec::new();
        let mut tmp = [0u8; 1024];
        while out.len() < limit {
            let want = (limit - out.len()).min(tmp.len());
            match self.read(&mut tmp[..want]) {
                Ok(0) => break,
                Ok(n) => out.extend_from_slice(&tmp[..n]),
                Err(_) => break,
            }
        }
        out
    }

    /// Read more bytes from the socket into buf. Returns 0 on EOF.
    fn pull(&mut self) -> io::Result<usize> {
        if self.pos > 0 && (self.pos == self.buf.len() || self.pos >= READ_CHUNK) {
            self.buf.drain(..self.pos);
            self.pos = 0;
        }
        let mut tmp = [0u8; READ_CHUNK];
        let n = self.conn.read(&mut tmp)?;
        if n > 0 {
            self.buf.extend_from_slice(&tmp[..n]);
        }
        Ok(n)
    }

    /// Take one complete line (without the trailing CRLF) if it is buffered.
    fn take_line(&mut self) -> io::Result<Option<Vec<u8>>> {
        if let Some(i) = self.buf[self.pos..].iter().position(|&b| b == b'\n') {
            let mut line = self.buf[self.pos..self.pos + i].to_vec();
            self.pos += i + 1;
            if line.last() == Some(&b'\r') {
                line.pop();
            }
            return Ok(Some(line));
        }
        if self.buf.len() - self.pos > MAX_CHUNK_LINE {
            return Err(invalid_data("chunked framing line too long"));
        }
        Ok(None)
    }

    fn read_line(&mut self) -> io::Result<Vec<u8>> {
        loop {
            if let Some(line) = self.take_line()? {
                return Ok(line);
            }
            if self.pull()? == 0 {
                return Err(unexpected_eof("connection closed inside chunked framing"));
            }
        }
    }

    fn fill_from_buf(&mut self, out: &mut [u8], max: u64) -> Option<usize> {
        if self.buf.len() <= self.pos {
            return None;
        }
        let avail = (self.buf.len() - self.pos) as u64;
        let n = out.len().min(max.min(avail) as usize);
        out[..n].copy_from_slice(&self.buf[self.pos..self.pos + n]);
        self.pos += n;
        Some(n)
    }

    /// Advance the chunked state machine. Returns Some(n) when it produced
    /// body bytes, None when the body is finished.
    fn chunk_step(&mut self, out: &mut [u8]) -> io::Result<Option<usize>> {
        loop {
            match self.chunk_phase {
                0 => {
                    let line = self.read_line()?;
                    let size = parse_chunk_size(&line)?;
                    self.remaining = size;
                    self.chunk_phase = if size == 0 { 3 } else { 1 };
                }
                1 => {
                    if self.remaining == 0 {
                        self.chunk_phase = 2;
                        continue;
                    }
                    if let Some(n) = self.fill_from_buf(out, self.remaining) {
                        self.remaining -= n as u64;
                        return Ok(Some(n));
                    }
                    if self.pull()? == 0 {
                        return Err(unexpected_eof("connection closed inside a chunk"));
                    }
                }
                2 => {
                    let line = self.read_line()?;
                    if !line.is_empty() {
                        return Err(invalid_data("chunk data not terminated by CRLF"));
                    }
                    self.chunk_phase = 0;
                }
                _ => {
                    let line = self.read_line()?;
                    if line.is_empty() {
                        self.done = true;
                        return Ok(None);
                    }
                    self.trailer_bytes += line.len() + 2;
                    if self.trailer_bytes > MAX_TRAILER_BYTES {
                        return Err(invalid_data("chunked trailers too large"));
                    }
                }
            }
        }
    }
}

impl Read for BodyReader {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        if self.cancel.is_cancelled() {
            return Err(cancelled_io());
        }
        if self.push_pos < self.push.len() {
            let n = out.len().min(self.push.len() - self.push_pos);
            out[..n].copy_from_slice(&self.push[self.push_pos..self.push_pos + n]);
            self.push_pos += n;
            return Ok(n);
        }
        if self.done {
            return Ok(0);
        }
        loop {
            match self.mode {
                BodyMode::None => {
                    self.done = true;
                    return Ok(0);
                }
                BodyMode::Length(_) => {
                    if self.remaining == 0 {
                        self.done = true;
                        return Ok(0);
                    }
                    if let Some(n) = self.fill_from_buf(out, self.remaining) {
                        self.remaining -= n as u64;
                        return Ok(n);
                    }
                    if self.pull()? == 0 {
                        return Err(unexpected_eof(
                            "connection closed before the declared content-length was received",
                        ));
                    }
                }
                BodyMode::Close => {
                    if let Some(n) = self.fill_from_buf(out, u64::MAX) {
                        return Ok(n);
                    }
                    if self.pull()? == 0 {
                        self.done = true;
                        return Ok(0);
                    }
                }
                BodyMode::Chunked => match self.chunk_step(out)? {
                    Some(n) => return Ok(n),
                    None => return Ok(0),
                },
            }
        }
    }
}

fn parse_chunk_size(line: &[u8]) -> io::Result<u64> {
    let end = line.iter().position(|&b| b == b';').unwrap_or(line.len());
    let size_part = &line[..end];
    let s = core::str::from_utf8(size_part).map_err(|_| invalid_data("invalid chunk size"))?;
    let s = s.trim_matches(|c: char| c == ' ' || c == '\t');
    if s.is_empty() || s.len() > 16 {
        return Err(invalid_data("invalid chunk size"));
    }
    let mut value: u64 = 0;
    for b in s.bytes() {
        let digit = match b {
            b'0'..=b'9' => b - b'0',
            b'a'..=b'f' => b - b'a' + 10,
            b'A'..=b'F' => b - b'A' + 10,
            _ => return Err(invalid_data("invalid chunk size")),
        };
        value = value
            .checked_mul(16)
            .and_then(|v| v.checked_add(digit as u64))
            .ok_or_else(|| invalid_data("chunk size overflow"))?;
    }
    if value > MAX_CHUNK_SIZE {
        return Err(invalid_data("chunk size too large"));
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunk_sizes_parse_with_extensions() {
        assert_eq!(parse_chunk_size(b"0").unwrap(), 0);
        assert_eq!(parse_chunk_size(b"a").unwrap(), 10);
        assert_eq!(parse_chunk_size(b"A").unwrap(), 10);
        assert_eq!(parse_chunk_size(b"1f;ext=1;other").unwrap(), 31);
        assert_eq!(parse_chunk_size(b" 10 ").unwrap(), 16);
    }

    #[test]
    fn bad_chunk_sizes_are_rejected() {
        let bad: [&[u8]; 6] = [b"", b"xyz", b"-1", b"0x10", b"10000000000000000", b"1g"];
        for entry in bad {
            assert!(
                parse_chunk_size(entry).is_err(),
                "should reject {:?}",
                entry
            );
        }
    }
}
