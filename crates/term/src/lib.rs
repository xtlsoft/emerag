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

/// Windows: switch the console to VT output processing and report whether
/// it accepted. Windows 10+ consoles do; Windows 7/8 and legacy-mode consoles
/// refuse, and must then get plain text no matter what the environment
/// claims. None on other platforms, or when stdout is not a console.
fn probe_console_vt() -> Option<bool> {
    #[cfg(windows)]
    {
        use core::ffi::c_void;
        extern "system" {
            fn GetStdHandle(which: u32) -> *mut c_void;
            fn GetConsoleMode(handle: *mut c_void, mode: *mut u32) -> i32;
            fn SetConsoleMode(handle: *mut c_void, mode: u32) -> i32;
        }
        const STD_OUTPUT_HANDLE: u32 = 0xFFFF_FFF5;
        const ENABLE_VIRTUAL_TERMINAL_PROCESSING: u32 = 0x0004;
        unsafe {
            let h = GetStdHandle(STD_OUTPUT_HANDLE);
            if h.is_null() || h as isize == -1 {
                return None;
            }
            let mut mode = 0u32;
            if GetConsoleMode(h, &mut mode) == 0 {
                return None;
            }
            if mode & ENABLE_VIRTUAL_TERMINAL_PROCESSING != 0 {
                return Some(true);
            }
            Some(SetConsoleMode(h, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING) != 0)
        }
    }
    #[cfg(not(windows))]
    {
        None
    }
}

/// Detect the current terminal. Never panics and never fails: an unknown
/// terminal becomes an 80x24 plain-text terminal.
///
/// Overrides for terminals that misreport themselves:
/// EMERAG_PLAIN=1 forces plain ASCII output with no escape sequences, and
/// EMERAG_COOKED=1 forces line-buffered input (no raw mode).
pub fn detect() -> Capabilities {
    setup_console_encoding();
    let size = sys::term_size();
    let tty_in = sys::is_tty(0);
    let tty_out = sys::is_tty(1);
    let vt = probe_console_vt();
    detect_with(|name| std::env::var(name).ok(), tty_in, tty_out, size, vt)
}

/// TERM values that are not ANSI/VT100 compatible, even though they are not
/// "dumb": printing CSI sequences to them produces garbage.
const NON_ANSI_TERMS: &[&str] = &[
    "dumb", "unknown", "vt52", "emacs", "network", "9term", "glasstty", "tty33", "tty43", "lpr",
    "printer",
];

fn env_flag(value: Option<String>) -> bool {
    matches!(
        value
            .as_deref()
            .map(str::trim)
            .map(str::to_ascii_lowercase)
            .as_deref(),
        Some("1" | "true" | "yes" | "on")
    )
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
    detect_with(env, tty_in, tty_out, size, None)
}

/// [detect_from] plus the result of the Windows console VT probe
/// (Some(true) accepted, Some(false) refused, None not applicable).
pub fn detect_with<F>(
    env: F,
    tty_in: bool,
    tty_out: bool,
    size: Option<(u16, u16)>,
    console_vt: Option<bool>,
) -> Capabilities
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
    let real_tty = tty_in && tty_out;
    let mut tty = real_tty;

    // Empty environment variables are treated as unset, matching util::env_var.
    let get = |name: &str| env(name).filter(|value| !value.is_empty());

    let term = get("TERM").unwrap_or_default();
    let term_l = term.trim().to_ascii_lowercase();
    let term_ok = !term_l.is_empty() && !NON_ANSI_TERMS.contains(&term_l.as_str());

    // Emacs M-x shell (comint) and similar front ends edit the line
    // themselves and do not understand raw-mode redraws: read whole lines.
    if term_l == "dumb" && get("INSIDE_EMACS").is_some() {
        tty = false;
    }
    if env_flag(get("EMERAG_COOKED")) {
        tty = false;
    }
    let plain = env_flag(get("EMERAG_PLAIN"));

    // Environment markers for terminals that do not set TERM (notably the
    // Windows console / Windows Terminal).
    let ansi_env = get("ANSICON").is_some()
        || get("WT_SESSION").is_some()
        || get("ConEmuANSI")
            .map(|v| v.eq_ignore_ascii_case("ON"))
            .unwrap_or(false)
        || get("TERM_PROGRAM").is_some()
        || get("COLORTERM").is_some();

    let ansi = match console_vt {
        // A Windows console: trust the probe, not the environment. ANSICON
        // hooks the console API, so it works even where the probe fails.
        Some(vt) => vt || get("ANSICON").is_some(),
        None => term_ok && (real_tty || ansi_env),
    } && !plain;

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
        ansi && !no_color && (!colorterm.is_empty() || term_color || console_vt == Some(true));

    // Locale precedence follows POSIX: LC_ALL, then LC_CTYPE, then LANG.
    let locale = get("LC_ALL")
        .or_else(|| get("LC_CTYPE"))
        .or_else(|| get("LANG"))
        .unwrap_or_default()
        .to_ascii_lowercase();
    let locale_utf8 = locale.contains("utf-8") || locale.contains("utf8");
    // The Linux and BSD text consoles run UTF-8 but their fonts lack most
    // symbols the UI uses (check marks, record dots), which render as
    // diamonds. Windows consoles before VT support (7/8) use raster fonts
    // without them as well.
    let console_font = matches!(term_l.as_str(), "linux" | "cons25" | "vt100" | "vt220")
        || term_l.starts_with("vt1")
        || term_l.starts_with("vt2");
    let unicode = !plain
        && match console_vt {
            Some(vt) => vt,
            None => locale_utf8 && !console_font,
        };

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
    fn non_ansi_terms_are_plain() {
        for term in ["vt52", "unknown", "emacs", "network"] {
            let env = move |name: &str| (name == "TERM").then(|| term.to_string());
            let caps = detect_from(env, true, true, None);
            assert!(!caps.ansi, "{term} must not get escape sequences");
        }
    }

    #[test]
    fn emacs_shell_and_overrides_use_cooked_plain_mode() {
        let caps = detect_from(
            env_of(&[("TERM", "dumb"), ("INSIDE_EMACS", "29.1,comint")]),
            true,
            true,
            None,
        );
        assert!(!caps.tty);
        let caps = detect_from(
            env_of(&[("TERM", "xterm"), ("EMERAG_COOKED", "1")]),
            true,
            true,
            None,
        );
        assert!(!caps.tty && caps.ansi);
        let caps = detect_from(
            env_of(&[
                ("TERM", "xterm"),
                ("LANG", "C.UTF-8"),
                ("EMERAG_PLAIN", "yes"),
            ]),
            true,
            true,
            None,
        );
        assert!(caps.tty && !caps.ansi && !caps.color && !caps.unicode);
    }

    #[test]
    fn windows_console_trusts_the_vt_probe() {
        // Windows 7 console with a stray TERM_PROGRAM: no escapes, no Unicode.
        let caps = detect_with(
            env_of(&[("TERM_PROGRAM", "vscode")]),
            true,
            true,
            None,
            Some(false),
        );
        assert!(!caps.ansi && !caps.color && !caps.unicode);
        // Windows 10 conhost without any marker variable: VT works.
        let caps = detect_with(env_of(&[]), true, true, None, Some(true));
        assert!(caps.ansi && caps.color && caps.unicode);
    }

    #[test]
    fn linux_console_gets_ascii_glyphs() {
        let caps = detect_from(
            env_of(&[("TERM", "linux"), ("LANG", "en_US.UTF-8")]),
            true,
            true,
            None,
        );
        assert!(caps.ansi && caps.color && !caps.unicode);
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
