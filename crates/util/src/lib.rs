//! emerag-util - the zero-dependency foundation layer.
//!
//! Everything in emerag is built on this crate plus std. No third-party
//! crates are used anywhere in the workspace, which keeps builds possible on
//! air-gapped machines, unusual architectures and old toolchains.

#![deny(unsafe_op_in_unsafe_fn)]

pub mod base64;
pub mod fsutil;
pub mod glob;
pub mod hex;
pub mod rand;
pub mod sync;
pub mod sys;
pub mod text;
pub mod time;

use core::fmt;

/// A lightweight, allocation-friendly error type.
///
/// emerag deliberately avoids anyhow/thiserror: errors are strings with
/// context added as they bubble up, which keeps the binary small and makes
/// messages directly presentable in a serial console.
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

    /// Prefix a layer of context, e.g. "reading config".
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

impl From<String> for Error {
    fn from(s: String) -> Self {
        Error::new(s)
    }
}

impl From<&str> for Error {
    fn from(s: &str) -> Self {
        Error::new(s)
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::new(format!("io: {e}"))
    }
}

impl From<fmt::Error> for Error {
    fn from(e: fmt::Error) -> Self {
        Error::new(format!("format: {e}"))
    }
}

impl From<std::str::Utf8Error> for Error {
    fn from(e: std::str::Utf8Error) -> Self {
        Error::new(format!("invalid utf-8: {e}"))
    }
}

impl From<std::string::FromUtf8Error> for Error {
    fn from(e: std::string::FromUtf8Error) -> Self {
        Error::new(format!("invalid utf-8: {e}"))
    }
}

pub type Result<T> = core::result::Result<T, Error>;

/// Attach context to any Result whose error implements Display.
pub fn context<T, E: fmt::Display>(
    res: core::result::Result<T, E>,
    ctx: impl fmt::Display,
) -> Result<T> {
    res.map_err(|e| Error::new(e.to_string()).context(ctx))
}

/// Turn an io::Result into Result with a context message.
pub fn io_context<T>(res: std::io::Result<T>, ctx: impl fmt::Display) -> Result<T> {
    res.map_err(|e| Error::new(format!("io: {e}")).context(ctx))
}

#[macro_export]
macro_rules! bail {
    ($($arg:tt)*) => {
        return Err($crate::Error::new(format!($($arg)*)))
    };
}

#[macro_export]
macro_rules! ensure {
    ($cond:expr, $($arg:tt)*) => {
        if !($cond) {
            $crate::bail!($($arg)*);
        }
    };
}

#[macro_export]
macro_rules! err {
    ($($arg:tt)*) => {
        $crate::Error::new(format!($($arg)*))
    };
}

/// Format bytes in a human friendly unit (used by the status bar / /doctor).
pub fn human_bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = n as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{n} B")
    } else if value >= 100.0 {
        format!("{value:.0} {}", UNITS[unit])
    } else if value >= 10.0 {
        format!("{value:.1} {}", UNITS[unit])
    } else {
        format!("{value:.2} {}", UNITS[unit])
    }
}

/// Format an integer with thousands separators.
pub fn thousands(n: u64) -> String {
    let s = n.to_string();
    let mut out = String::with_capacity(s.len() + s.len() / 3);
    let offset = s.len() % 3;
    for (i, ch) in s.chars().enumerate() {
        if i > 0 && i >= offset && (i - offset) % 3 == 0 {
            out.push(',');
        }
        out.push(ch);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_context_chains() {
        let e = Error::new("inner").context("outer").context("top");
        assert_eq!(e.to_string(), "top: outer: inner");
    }

    #[test]
    fn bytes_are_human() {
        assert_eq!(human_bytes(512), "512 B");
        assert_eq!(human_bytes(1536), "1.50 KiB");
        assert_eq!(human_bytes(15 * 1024), "15.0 KiB");
        assert_eq!(human_bytes(300 * 1024), "300 KiB");
    }

    #[test]
    fn thousands_separates() {
        assert_eq!(thousands(0), "0");
        assert_eq!(thousands(999), "999");
        assert_eq!(thousands(1000), "1,000");
        assert_eq!(thousands(1234567), "1,234,567");
    }
}
