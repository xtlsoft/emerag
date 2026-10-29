//! A connection is either a plain TCP socket or a TLS stream.

use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::time::Duration;

pub(crate) enum Conn {
    Plain(TcpStream),
    Tls(Box<emerag_tls::TlsStream>),
}

impl Conn {
    /// Adjust the read timeout for the next read (used when grabbing a short
    /// preview of an error body). A zero duration means "block forever".
    pub(crate) fn set_read_timeout(&self, timeout: Duration) -> io::Result<()> {
        match self {
            Conn::Plain(s) => {
                if timeout.is_zero() {
                    s.set_read_timeout(None)
                } else {
                    s.set_read_timeout(Some(timeout))
                }
            }
            // The timeout was installed on the underlying socket before the
            // handshake; emerag-tls does not expose a setter yet.
            Conn::Tls(_) => Ok(()),
        }
    }
}

impl Read for Conn {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Conn::Plain(s) => s.read(buf),
            Conn::Tls(t) => t.read(buf),
        }
    }
}

impl Write for Conn {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Conn::Plain(s) => s.write(buf),
            Conn::Tls(t) => t.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Conn::Plain(s) => s.flush(),
            Conn::Tls(t) => t.flush(),
        }
    }
}
