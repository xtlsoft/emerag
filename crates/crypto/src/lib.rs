//! emerag-crypto - cryptographic primitives written from scratch.
//!
//! No OpenSSL, no ring, no third-party crates: emerag must statically link on
//! s390x, loong64 and musl systems where those libraries are unavailable.
//! Correctness is established with published test vectors (NIST, RFC, Wycheproof
//! where feasible) and interop tests against openssl.
//!
//! Modules are owned by different authors; public signatures are frozen.

pub mod aead;
pub mod ct;
pub mod curve;
pub mod hash;
pub mod pem;
pub mod rsa;
pub mod x509;

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

    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for Error {}

impl From<&str> for Error {
    fn from(s: &str) -> Self {
        Error::new(s)
    }
}

impl From<String> for Error {
    fn from(s: String) -> Self {
        Error::new(s)
    }
}

impl From<emerag_util::Error> for Error {
    fn from(e: emerag_util::Error) -> Self {
        Error::new(e.into_message())
    }
}

pub type Result<T> = core::result::Result<T, Error>;

/// Cryptographic operations never report partial success.
pub fn ensure(cond: bool, msg: &str) -> Result<()> {
    if cond {
        Ok(())
    } else {
        Err(Error::new(msg))
    }
}
