//! emerag-term: the portable terminal layer.
//!
//! The terminal layer has to work on a VT100, a serial console, a dumb
//! terminal, a modern xterm, and the legacy Windows console. It never assumes
//! Unicode, colour, ANSI escapes, or even that a terminal is attached at all:
//! callers get a [Capabilities] value and every renderer degrades to plain
//! line output when [Capabilities::ansi] is false.
//!
//! The crate is deliberately split so the interesting logic is testable
//! without a tty:
//!
//! * [decode_keys] is a pure byte-stream decoder (tests feed escape
//!   sequences directly).
//! * [LineEditor::handle_key] is the pure editing state machine; only
//!   [LineEditor::read_line] touches stdin.
//! * [Screen] writes to any [std::io::Write] through
//!   [Screen::new_with_writer], so escape-free rendering can be asserted.
//!
//! All platform code is hand-written FFI: no third-party crates anywhere.
#![deny(unsafe_op_in_unsafe_fn)]

pub mod editor;
pub mod glyphs;
pub mod keys;
pub mod prompt;
pub mod raw;
pub mod screen;
pub mod width;

pub use editor::{Completer, EditorAction, LineEditor};
pub use glyphs::{ascii_glyph, glyph, Glyphs, GLYPHS};
pub use keys::{decode_keys, read_key, Key, KeyCode};
pub use raw::{raw_mode, RawMode};
pub use screen::Screen;

use core::fmt;

use emerag_util::sys;

/// Category of a terminal error.
///
/// Callers normally only need [Error::is_cancelled]; the kind exists so a
/// wizard can distinguish "user pressed Ctrl+C" from "terminal disappeared".
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorKind {
    /// Underlying I/O failed.
    Io,
    /// The user cancelled the interaction (Ctrl+C).
    Cancelled,
    /// The operation is not available on this platform or target.
    Unsupported,
    /// The operation needs a terminal on stdin but stdin is redirected.
    NotATty,
    /// Input ended (EOF) while a key was expected.
    EndOfInput,
}

/// Error type used by the terminal layer.
///
/// Like the rest of emerag this is a small string error with a kind, rather
/// than a crate. Messages are intended to be printable on a serial console.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Error {
    kind: ErrorKind,
    message: String,
}

impl Error {
    pub fn new(message: impl Into<String>) -> Self {
        Error {
            kind: ErrorKind::Io,
            message: message.into(),
        }
    }

    pub fn with_kind(kind: ErrorKind, message: impl Into<String>) -> Self {
        Error {
            kind,
            message: message.into(),
        }
    }

    pub fn cancelled() -> Self {
        Error::with_kind(ErrorKind::Cancelled, "cancelled")
    }

    pub fn unsupported(what: impl fmt::Display) -> Self {
        Error::with_kind(ErrorKind::Unsupported, format!("unsupported: {what}"))
    }

    pub fn not_a_tty() -> Self {
        Error::with_kind(
            ErrorKind::NotATty,
            "raw mode requires a terminal on stdin; using cooked mode instead",
        )
    }

    pub fn end_of_input() -> Self {
        Error::with_kind(ErrorKind::EndOfInput, "end of input")
    }

    pub fn kind(&self) -> ErrorKind {
        self.kind
    }

    pub fn is_cancelled(&self) -> bool {
        self.kind == ErrorKind::Cancelled
    }

    pub fn message(&self) -> &str {
        &self.message
    }

    /// Prefix context, keeping the error kind.
    pub fn context(mut self, ctx: impl fmt::Display) -> Self {
        self.message = format!("{ctx}: {}", self.message);
        self
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
        Error::with_kind(ErrorKind::Io, format!("io: {e}"))
    }
}

pub type Result<T> = core::result::Result<T, Error>;

/// Terminal capabilities detected once at startup (or injected by tests).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Capabilities {
    /// Columns, never zero (falls back to 80).
    pub width: u16,
    /// Rows, never zero (falls back to 24).
    pub height: u16,
    /// Safe to emit ANSI/VT100 escape sequences on stdout.
    pub ansi: bool,
    /// Safe to use SGR colour sequences.
    pub color: bool,
    /// UTF-8 glyphs are safe to print.
    pub unicode: bool,
    /// stdin and stdout are both terminals.
    pub tty: bool,
}

impl Default for Capabilities {
    fn default() -> Self {
        Capabilities {
            width: 80,
            height: 24,
            ansi: false,
            color: false,
            unicode: false,
            tty: false,
        }
    }
}

impl Capabilities {
    /// Glyph set matching this terminal (ASCII unless unicode is set).
    pub fn glyphs(&self) -> Glyphs {
        Glyphs::new(self.unicode)
    }

    /// Look up one glyph name; see [Glyphs::get].
    pub fn glyph(&self, name: &str) -> &'static str {
        self.glyphs().get(name)
    }

    /// True on a serial/dumb terminal where only plain text is safe.
    pub fn is_dumb(&self) -> bool {
        !self.ansi
    }
}

/// Best effort: switch a Windows console to UTF-8 so Unicode glyphs render.
/// On other platforms this is a no-op. Failure is ignored (an old console
/// simply keeps its code page and the ASCII glyph set is used elsewhere).
fn setup_console_encoding() {
    #[cfg(windows)]
    {
        extern "system" {
            fn SetConsoleOutputCP(code_page: u32) -> i32;
            fn SetConsoleCP(code_page: u32) -> i32;
        }
        const CP_UTF8: u32 = 65001;
        unsafe {
            SetConsoleOutputCP(CP_UTF8);
            SetConsoleCP(CP_UTF8);
        }
    }
}

/// Detect the current terminal. Never panics and never fails: an unknown
/// terminal becomes an 80x24 plain-text terminal.
pub fn detect() -> Capabilities {
    setup_console_encoding();
    let size = sys::term_size();
    let tty_in = sys::is_tty(0);
    let tty_out = sys::is_tty(1);
    detect_from(|name| std::env::var(name).ok(), tty_in, tty_out, size)
}

/// Testable capability detection.
///
/// env is normally std::env::var, but tests can supply a fake environment.
/// size comes from [emerag_util::sys::term_size]. The function is pure with
/// respect to its arguments, which is why it is public.
pub fn detect_from<F>(env: F, tty_in: bool, tty_out: bool, size: Option<(u16, u16)>) -> Capabilities
where
    F: Fn(&str) -> Option<String>,
{
    let (mut width, mut height) = size.unwrap_or((0, 0));
    if width == 0 {
        width = 80;
    }
    if height == 0 {
        height = 24;
    }
    // A terminal we can read keys from and draw on is interactive. If either
    // side is redirected we prefer the line-oriented fallback.
    let tty = tty_in && tty_out;

    // Empty environment variables are treated as unset, matching util::env_var.
    let get = |name: &str| env(name).filter(|value| !value.is_empty());

    let term = get("TERM").unwrap_or_default();
    let term_l = term.trim().to_ascii_lowercase();
    let term_ok = !term_l.is_empty() && term_l != "dumb";

    // Environment markers for terminals that do not set TERM (notably the
    // Windows console / Windows Terminal).
    let ansi_env = get("ANSICON").is_some()
        || get("WT_SESSION").is_some()
        || get("ConEmuANSI")
            .map(|v| v.eq_ignore_ascii_case("ON"))
            .unwrap_or(false)
        || get("TERM_PROGRAM").is_some()
        || get("COLORTERM").is_some();

    let windows_vt = cfg!(windows) && tty && ansi_env;
    let ansi = (term_ok || windows_vt) && (tty || ansi_env);

    let no_color = env("NO_COLOR").is_some();
    let colorterm = get("COLORTERM").unwrap_or_default().to_ascii_lowercase();
    let term_color = term_l.contains("color")
        || term_l.contains("256")
        || term_l.contains("xterm")
        || term_l.contains("screen")
        || term_l.contains("tmux")
        || term_l.contains("rxvt")
        || term_l.contains("cygwin")
        || term_l.contains("ansi")
        || term_l.contains("konsole")
        || term_l == "linux";
    let color =
        ansi && !no_color && (!colorterm.is_empty() || term_color || (cfg!(windows) && tty));

    // Locale precedence follows POSIX: LC_ALL, then LC_CTYPE, then LANG.
    let locale = get("LC_ALL")
        .or_else(|| get("LC_CTYPE"))
        .or_else(|| get("LANG"))
        .unwrap_or_default()
        .to_ascii_lowercase();
    let locale_utf8 = locale.contains("utf-8") || locale.contains("utf8");
    let unicode = locale_utf8 || (cfg!(windows) && tty);

    Capabilities {
        width,
        height,
        ansi,
        color,
        unicode,
        tty,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env_of(pairs: &'static [(&'static str, &'static str)]) -> impl Fn(&str) -> Option<String> {
        move |name| {
            pairs
                .iter()
                .find(|(k, _)| *k == name)
                .map(|(_, v)| (*v).to_string())
        }
    }

    #[test]
    fn dumb_terminal_is_plain() {
        let caps = detect_from(env_of(&[("TERM", "dumb")]), true, true, Some((40, 16)));
        assert_eq!((caps.width, caps.height), (40, 16));
        assert!(caps.tty);
        assert!(!caps.ansi);
        assert!(!caps.color);
        assert!(caps.is_dumb());
    }

    #[test]
    fn empty_term_is_plain() {
        let caps = detect_from(env_of(&[("TERM", "")]), true, true, None);
        assert!(!caps.ansi);
        assert_eq!((caps.width, caps.height), (80, 24));
    }

    #[test]
    fn xterm_gets_ansi_and_colour() {
        let caps = detect_from(
            env_of(&[("TERM", "xterm-256color"), ("LANG", "en_US.UTF-8")]),
            true,
            true,
            Some((120, 30)),
        );
        assert!(caps.ansi);
        assert!(caps.color);
        assert!(caps.unicode);
        assert!(caps.tty);
    }

    #[test]
    fn no_color_wins() {
        let caps = detect_from(
            env_of(&[
                ("TERM", "xterm-256color"),
                ("COLORTERM", "truecolor"),
                ("NO_COLOR", "1"),
            ]),
            true,
            true,
            None,
        );
        assert!(caps.ansi);
        assert!(!caps.color);
    }

    #[test]
    fn redirected_input_forces_cooked_capabilities() {
        let caps = detect_from(env_of(&[("TERM", "xterm")]), false, true, None);
        assert!(!caps.tty);
        // TERM is still an ANSI terminal, but stdin is not a terminal: the
        // caller uses the cooked reader and plain prompt output.
    }

    #[test]
    fn locale_detection_checks_lc_all_first() {
        let caps = detect_from(
            env_of(&[("LC_ALL", "C"), ("LANG", "en_US.UTF-8")]),
            true,
            true,
            None,
        );
        assert!(!caps.unicode);
        let caps = detect_from(env_of(&[("LC_CTYPE", "zh_CN.utf8")]), true, true, None);
        assert!(caps.unicode);
        // An empty LC_ALL must not mask a UTF-8 LANG.
        let caps = detect_from(
            env_of(&[("LC_ALL", ""), ("LANG", "en_US.UTF-8")]),
            true,
            true,
            None,
        );
        assert!(caps.unicode);
    }

    #[test]
    fn glyphs_follow_unicode_capability() {
        let ascii = Capabilities {
            unicode: false,
            ..Capabilities::default()
        };
        let uni = Capabilities {
            unicode: true,
            ..Capabilities::default()
        };
        assert_eq!(ascii.glyph("hline"), "-");
        assert_eq!(uni.glyph("hline"), "─");
        for name in glyphs::NAMES {
            assert!(ascii.glyph(name).is_ascii(), "glyph {name} is not ASCII");
        }
    }
}
