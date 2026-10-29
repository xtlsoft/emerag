//! emerag-http - a small, zero-dependency HTTP/1.1 client.
//!
//! The client is deliberately minimal: HTTP/1.1 only, one request per
//! connection (Connection: close), no decompression, no cookies, no HTTP/2.
//! Everything an emergency agent needs and nothing it does not.
//!
//! Design choices that matter for the rest of emerag:
//!
//! * DNS is never a hard dependency: a ResolveTable pins host/port pairs to
//!   literal addresses, so a machine with a broken resolver can still reach an
//!   API endpoint through --resolve.
//! * Response bodies stream through std::io::Read. Timeouts are reported as
//!   io::ErrorKind::WouldBlock/TimedOut and are retryable: the body reader
//!   keeps its framing state, so a slow model stream does not die on one stall.
//! * Cancellation is cooperative: a CancelToken is checked before every read.
//! * No unsafe code at all in this crate.

#![forbid(unsafe_code)]

pub mod client;
mod conn;
pub mod error;
pub mod proxy;
pub mod resolve;
pub mod response;
pub mod sse;
pub mod tlsopts;
pub mod url;

pub use client::{Client, Request};
pub use error::{Error, Result};
pub use proxy::{ProxyConfig, ProxyTarget};
pub use resolve::{ResolveEntry, ResolveTable};
pub use response::Response;
pub use sse::{SseDecoder, SseEvent, SseIter};
pub use tlsopts::{TlsOptions, TlsVerify};
pub use url::Url;
