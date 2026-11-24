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
        let timeout = if timeout.is_zero() {
            None
        } else {
            Some(timeout)
        };
        match self {
            Conn::Plain(s) => s.set_read_timeout(timeout),
            Conn::Tls(t) => t.set_read_timeout(timeout),
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
