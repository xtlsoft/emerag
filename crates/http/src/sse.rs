//! Server-Sent Events decoding (the text/event-stream format used by LLM
//! APIs for token streaming).
//!
//! The decoder is incremental: bytes can be fed in arbitrary fragments
//! (including in the middle of a multi-byte UTF-8 sequence), lines are split
//! on CRLF or LF, comments and blank lines are ignored, and events are
//! dispatched on a blank line. An event larger than 1 MiB is dropped rather
//! than growing memory without bound.

use std::collections::VecDeque;
use std::io::Read;

use crate::error::{Error, Result};
use crate::response::Response;

pub const DEFAULT_MAX_EVENT_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SseEvent {
    pub event: String,
    pub data: String,
    pub id: String,
    pub retry: Option<u64>,
}

impl SseEvent {
    pub fn is_default_message(&self) -> bool {
        self.event == "message"
    }
}

#[derive(Debug)]
pub struct SseDecoder {
    buf: Vec<u8>,
    discarding: bool,
    overflowed: bool,
    event: String,
    data: String,
    has_data: bool,
    id: String,
    retry: Option<u64>,
    last_event_id: String,
    last_retry: Option<u64>,
    event_bytes: usize,
    max_event_bytes: usize,
}

impl SseDecoder {
    pub fn new() -> Self {
        SseDecoder::with_limit(DEFAULT_MAX_EVENT_BYTES)
    }

    pub fn with_limit(max_event_bytes: usize) -> Self {
        SseDecoder {
            buf: Vec::new(),
            discarding: false,
            overflowed: false,
            event: String::new(),
            data: String::new(),
            has_data: false,
            id: String::new(),
            retry: None,
            last_event_id: String::new(),
            last_retry: None,
            event_bytes: 0,
            max_event_bytes,
        }
    }

    /// Feed a fragment of the stream, returning every event completed by it.
    pub fn feed(&mut self, bytes: &[u8]) -> Vec<SseEvent> {
        let mut out = Vec::new();
        if self.discarding {
            match bytes.iter().position(|&b| b == b'\n') {
                Some(i) => {
                    self.discarding = false;
                    self.overflowed = true;
                    self.consume(&bytes[i + 1..], &mut out);
                }
                None => return out,
            }
        } else {
            self.consume(bytes, &mut out);
        }
        if !self.discarding && self.buf.len() > self.max_event_bytes {
            // A single line longer than the cap: drop it and keep going so a
            // hostile or broken stream cannot exhaust memory.
            self.buf.clear();
            self.discarding = true;
            self.overflowed = true;
        }
        out
    }

    pub fn feed_str(&mut self, text: &str) -> Vec<SseEvent> {
        self.feed(text.as_bytes())
    }

    pub fn last_event_id(&self) -> &str {
        &self.last_event_id
    }

    pub fn last_retry_ms(&self) -> Option<u64> {
        self.last_retry
    }

    pub fn buffered_len(&self) -> usize {
        self.buf.len()
    }

    fn consume(&mut self, bytes: &[u8], out: &mut Vec<SseEvent>) {
        self.buf.extend_from_slice(bytes);
        let mut start = 0;
        while let Some(rel) = self.buf[start..].iter().position(|&b| b == b'\n') {
            let end = start + rel;
            let line = self.buf[start..end].to_vec();
            start = end + 1;
            let line = if line.last() == Some(&b'\r') {
                line[..line.len() - 1].to_vec()
            } else {
                line
            };
            self.process_line(&line, out);
        }
        if start > 0 {
            self.buf.drain(..start);
        }
    }

    fn process_line(&mut self, line: &[u8], out: &mut Vec<SseEvent>) {
        if line.is_empty() {
            self.dispatch(out);
            return;
        }
        if line[0] == b':' {
            return; // comment / keep-alive
        }
        let (field, raw_value) = match line.iter().position(|&b| b == b':') {
            Some(i) => (&line[..i], &line[i + 1..]),
            None => (line, &b""[..]),
        };
        let value = if raw_value.first() == Some(&b' ') {
            &raw_value[1..]
        } else {
            raw_value
        };
        match field {
            b"event" => {
                if self.accept_value(value.len()) {
                    self.event = utf8_lossy(value);
                }
            }
            b"data" => {
                if self.overflowed {
                    return;
                }
                if !self.accept_value(value.len() + 1) {
                    return;
                }
                if self.has_data {
                    self.data.push('\n');
                } else {
                    self.has_data = true;
                }
                self.data.push_str(&utf8_lossy(value));
            }
            b"id" => {
                if !self.overflowed && !value.contains(&0) {
                    self.id = utf8_lossy(value);
                }
            }
            b"retry" => {
                if !value.is_empty()
                    && value.len() <= 19
                    && value.iter().all(|b| b.is_ascii_digit())
                {
                    if let Ok(text) = core::str::from_utf8(value) {
                        if let Ok(v) = text.parse::<u64>() {
                            self.retry = Some(v);
                        }
                    }
                }
            }
            _ => {}
        }
    }

    fn accept_value(&mut self, extra: usize) -> bool {
        if self.overflowed {
            return false;
        }
        match self.event_bytes.checked_add(extra) {
            Some(total) if total <= self.max_event_bytes => {
                self.event_bytes = total;
                true
            }
            _ => {
                self.overflowed = true;
                self.data.clear();
                self.event.clear();
                false
            }
        }
    }

    fn dispatch(&mut self, out: &mut Vec<SseEvent>) {
        if self.has_data && !self.overflowed {
            let id = if !self.id.is_empty() {
                self.id.clone()
            } else {
                self.last_event_id.clone()
            };
            if !self.id.is_empty() {
                self.last_event_id = self.id.clone();
            }
            let retry = self.retry.take();
            if retry.is_some() {
                self.last_retry = retry;
            }
            let event = if self.event.is_empty() {
                "message".to_string()
            } else {
                std::mem::take(&mut self.event)
            };
            let mut data = std::mem::take(&mut self.data);
            if data.ends_with('\n') {
                data.pop();
            }
            out.push(SseEvent {
                event,
                data,
                id,
                retry,
            });
        }
        self.event.clear();
        self.data.clear();
        self.has_data = false;
        self.id.clear();
        self.retry = None;
        self.overflowed = false;
        self.event_bytes = 0;
    }
}

impl Default for SseDecoder {
    fn default() -> Self {
        SseDecoder::new()
    }
}

fn utf8_lossy(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// Iterator adapter: yields SseEvent for every event in a reader (usually a
/// Response). A read error is returned as Err and the iterator stays usable, so
/// callers may retry after a timeout.
pub struct SseIter<R: Read> {
    reader: R,
    decoder: SseDecoder,
    pending: VecDeque<SseEvent>,
    done: bool,
}

impl<R: Read> SseIter<R> {
    pub fn new(reader: R) -> Self {
        SseIter {
            reader,
            decoder: SseDecoder::new(),
            pending: VecDeque::new(),
            done: false,
        }
    }

    pub fn with_decoder(reader: R, decoder: SseDecoder) -> Self {
        SseIter {
            reader,
            decoder,
            pending: VecDeque::new(),
            done: false,
        }
    }

    pub fn into_inner(self) -> R {
        self.reader
    }

    pub fn decoder(&self) -> &SseDecoder {
        &self.decoder
    }
}

impl<R: Read> Iterator for SseIter<R> {
    type Item = Result<SseEvent>;

    fn next(&mut self) -> Option<Result<SseEvent>> {
        loop {
            if let Some(ev) = self.pending.pop_front() {
                return Some(Ok(ev));
            }
            if self.done {
                return None;
            }
            let mut buf = [0u8; 4096];
            match self.reader.read(&mut buf) {
                Ok(0) => {
                    self.done = true;
                    // Flush a final event that lacked its terminating blank line.
                    let events = self.decoder.feed(b"\n\n");
                    self.pending.extend(events);
                    if let Some(ev) = self.pending.pop_front() {
                        return Some(Ok(ev));
                    }
                    return None;
                }
                Ok(n) => {
                    let events = self.decoder.feed(&buf[..n]);
                    self.pending.extend(events);
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Some(Err(Error::from(e))),
            }
        }
    }
}

impl Response {
    /// Consume the response as a Server-Sent Events stream.
    pub fn sse_events(self) -> SseIter<Response> {
        SseIter::new(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn feed_all(dec: &mut SseDecoder, chunks: &[&[u8]]) -> Vec<SseEvent> {
        let mut events = Vec::new();
        for chunk in chunks {
            events.extend(dec.feed(chunk));
        }
        events
    }

    #[test]
    fn basic_event() {
        let mut dec = SseDecoder::new();
        let events = dec.feed(b"data: hello\n\n");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].data, "hello");
        assert_eq!(events[0].event, "message");
        assert_eq!(events[0].id, "");
        assert!(events[0].retry.is_none());
    }

    #[test]
    fn multi_line_data_joined_with_newline() {
        let mut dec = SseDecoder::new();
        let events = dec.feed(b"data: a\ndata: b\ndata: c\n\n");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].data, "a\nb\nc");
    }

    #[test]
    fn comments_and_empty_lines_are_ignored() {
        let mut dec = SseDecoder::new();
        let events = dec.feed(b": ping\n\n: another\ndata: x\n\n");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].data, "x");
    }

    #[test]
    fn crlf_and_lf_both_work() {
        let mut dec = SseDecoder::new();
        let events = dec.feed(b"data: one\r\n\r\ndata: two\n\n");
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].data, "one");
        assert_eq!(events[1].data, "two");
    }

    #[test]
    fn event_id_and_retry_fields() {
        let mut dec = SseDecoder::new();
        let events = dec.feed(b"event: delta\nid: 42\nretry: 1000\ndata: x\n\n");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event, "delta");
        assert_eq!(events[0].id, "42");
        assert_eq!(events[0].retry, Some(1000));
        assert_eq!(dec.last_event_id(), "42");
        assert_eq!(dec.last_retry_ms(), Some(1000));
    }

    #[test]
    fn id_persists_across_events() {
        let mut dec = SseDecoder::new();
        let events = dec.feed(b"id: 7\ndata: a\n\ndata: b\n\n");
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].id, "7");
        assert_eq!(events[1].id, "7");
    }

    #[test]
    fn retry_only_applies_to_its_event() {
        let mut dec = SseDecoder::new();
        let events = dec.feed(b"retry: 10\ndata: a\n\ndata: b\n\n");
        assert_eq!(events[0].retry, Some(10));
        assert_eq!(events[1].retry, None);
    }

    #[test]
    fn event_without_data_is_not_dispatched() {
        let mut dec = SseDecoder::new();
        let events = dec.feed(b"event: ping\nid: 1\n\n");
        assert!(events.is_empty());
    }

    #[test]
    fn empty_data_line_dispatches_empty_event() {
        let mut dec = SseDecoder::new();
        let events = dec.feed(b"data:\n\n");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].data, "");
    }

    #[test]
    fn fragmented_across_reads() {
        let mut dec = SseDecoder::new();
        let events = feed_all(&mut dec, &[b"da", b"ta: he", b"llo\n", b"\n"]);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].data, "hello");
        assert_eq!(dec.buffered_len(), 0);
    }

    #[test]
    fn unicode_split_across_reads() {
        let payload = "data: \u{4f60}\u{597d}\n\n".as_bytes();
        let mut dec = SseDecoder::new();
        let split = b"data: ".len() + 1;
        let mut events = dec.feed(&payload[..split]);
        assert!(events.is_empty());
        events.extend(dec.feed(&payload[split..]));
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].data, "\u{4f60}\u{597d}");
    }

    #[test]
    fn data_without_space_after_colon() {
        let mut dec = SseDecoder::new();
        let events = dec.feed(b"data:value\n\n");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].data, "value");
    }

    #[test]
    fn unknown_fields_are_ignored() {
        let mut dec = SseDecoder::new();
        let events = dec.feed(b"foo: bar\ndata: x\n\n");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].data, "x");
    }

    #[test]
    fn oversized_event_is_dropped_and_decoder_recovers() {
        let mut dec = SseDecoder::with_limit(1024);
        let mut payload = Vec::new();
        payload.extend_from_slice(b"data: ");
        payload.extend(std::iter::repeat(b'x').take(2048));
        payload.extend_from_slice(b"\n\ndata: ok\n\n");
        let events = dec.feed(&payload);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].data, "ok");
    }

    #[test]
    fn oversized_line_without_newline_does_not_grow_memory() {
        let mut dec = SseDecoder::with_limit(64);
        let junk = vec![b'x'; 4096];
        let events = dec.feed(&junk);
        assert!(events.is_empty());
        assert_eq!(dec.buffered_len(), 0);
        let events = dec.feed(b"ignored\n\ndata: ok\n\n");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].data, "ok");
    }

    #[test]
    fn bad_retry_values_are_ignored() {
        let mut dec = SseDecoder::new();
        let events = dec.feed(b"retry: abc\ndata: x\n\n");
        assert_eq!(events.len(), 1);
        assert!(events[0].retry.is_none());
    }
}
