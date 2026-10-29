//! The HTTP crate error type.
//!
//! emerag keeps one string-based error per crate (plus context prefixes)
//! instead of pulling in anyhow/thiserror: the messages are shown verbatim on
//! a serial console.

use core::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error {
    message: String,
}

impl Error {
    pub fn new(message: impl Into<String>) -> Self {
        Error {
            message: message.into(),
        }
    }

    /// Prefix a layer of context: "sending request: io: broken pipe".
    pub fn context(mut self, ctx: impl fmt::Display) -> Self {
        let mut s = String::with_capacity(self.message.len() + 16);
        s.push_str(&ctx.to_string());
        s.push_str(": ");
        s.push_str(&self.message);
        self.message = s;
        self
    }

    pub fn message(&self) -> &str {
        &self.message
    }

    pub fn into_message(self) -> String {
        self.message
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::new(format!("io: {e}"))
    }
}

impl From<emerag_util::Error> for Error {
    fn from(e: emerag_util::Error) -> Self {
        Error::new(e.to_string())
    }
}

impl From<emerag_tls::Error> for Error {
    fn from(e: emerag_tls::Error) -> Self {
        Error::new(format!("tls: {e}"))
    }
}

pub type Result<T> = core::result::Result<T, Error>;

/// Error used when the cancellation token fires in the middle of a body read.
///
/// ErrorKind::Other is deliberate: std::io::copy and read_to_end retry
/// Interrupted automatically, which would defeat cancellation.
pub(crate) fn cancelled_io() -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, "cancelled")
}

pub(crate) fn invalid_data(msg: impl Into<String>) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, msg.into())
}

pub(crate) fn unexpected_eof(msg: impl Into<String>) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::UnexpectedEof, msg.into())
}
