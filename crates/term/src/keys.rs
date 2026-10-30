//! Key decoding for VT100/xterm/serial input and the Windows console.
//!
//! [decode_keys] is pure: tests can feed arbitrary byte streams and inspect
//! the resulting keys. [read_key] is the blocking wrapper used by the editor.
//!
//! Supported input:
//! * UTF-8 characters, including characters split across reads
//! * Enter, Tab, Backspace, Esc and Ctrl+letter (0x01..0x1a)
//! * CSI arrows, Home/End, PgUp/PgDn, Insert/Delete, F1-F12
//! * SS3 arrows, Home/End, F1-F4
//! * CSI modifier parameters (CSI 1;2P, CSI 1;5D, ...)
//! * Alt+char (ESC prefix)
//! * bracketed paste markers (CSI 200~ / CSI 201~)
//!
//! A lone ESC at the end of a read is reported as [KeyCode::Esc] immediately:
//! the terminal layer has no portable way to wait for the follow-up byte. ESC
//! and the Alt+char therefore need to arrive in the same read, which is what
//! terminals normally do.

use core::cell::RefCell;
use std::collections::VecDeque;
use std::sync::{mpsc, Mutex, OnceLock};

use crate::{Error, Result};

/// Logical key, independent of the byte sequence that produced it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyCode {
    Char(char),
    Enter,
    Tab,
    Backspace,
    Esc,
    Up,
    Down,
    Left,
    Right,
    Home,
    End,
    PageUp,
    PageDown,
    Delete,
    Insert,
    F(u8),
    /// Start of a bracketed-paste payload (CSI 200~).
    PasteStart,
    /// End of a bracketed-paste payload (CSI 201~).
    PasteEnd,
    /// A sequence we recognise as a key but cannot map (or malformed input).
    Unknown,
}

/// A decoded key with modifier state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Key {
    pub code: KeyCode,
    pub ctrl: bool,
    pub alt: bool,
    pub shift: bool,
}

impl Key {
    pub const fn new(code: KeyCode) -> Key {
        Key {
            code,
            ctrl: false,
            alt: false,
            shift: false,
        }
    }

    pub const fn char(c: char) -> Key {
        Key::new(KeyCode::Char(c))
    }

    pub const fn ctrl_char(c: char) -> Key {
        Key {
            code: KeyCode::Char(c),
            ctrl: true,
            alt: false,
            shift: false,
        }
    }

    pub const fn alt_char(c: char) -> Key {
        Key {
            code: KeyCode::Char(c),
            ctrl: false,
            alt: true,
            shift: false,
        }
    }

    /// Builder: mark this key as Ctrl+.
    pub const fn with_ctrl(mut self) -> Key {
        self.ctrl = true;
        self
    }

    /// Builder: mark this key as Alt+.
    pub const fn with_alt(mut self) -> Key {
        self.alt = true;
        self
    }

    /// Builder: mark this key as Shift+.
    pub const fn with_shift(mut self) -> Key {
        self.shift = true;
        self
    }

    /// True if this is Ctrl+the given ASCII letter, case-insensitively.
    pub fn is_ctrl(&self, c: char) -> bool {
        self.ctrl && matches!(self.code, KeyCode::Char(x) if x.eq_ignore_ascii_case(&c))
    }
}

// ---------------------------------------------------------------------------
// Pure decoder
// ---------------------------------------------------------------------------

enum Decoded {
    Key(Key, usize),
    Incomplete,
    Invalid(usize),
}

/// Upper bound for a partial escape sequence held between reads. Prevents a
/// broken or hostile producer from growing the pending buffer without limit.
const MAX_PENDING: usize = 4096;

/// Decode as many complete keys as possible.
///
/// The pending buffer carries an incomplete suffix between calls. It is
/// drained by this function (combined with bytes) and replaced with the new
/// incomplete suffix. No allocation is leaked on malformed input; invalid
/// bytes become [KeyCode::Unknown] and are consumed one at a time.
pub fn decode_keys(bytes: &[u8], pending: &mut Vec<u8>) -> Vec<Key> {
    let mut data = Vec::with_capacity(pending.len().saturating_add(bytes.len()));
    data.append(pending);
    data.extend_from_slice(bytes);

    let mut out = Vec::new();
    let mut i = 0usize;
    while i < data.len() {
        match decode_one(&data[i..]) {
            Decoded::Key(key, n) => {
                out.push(key);
                i += n.max(1);
            }
            Decoded::Invalid(n) => {
                out.push(Key::new(KeyCode::Unknown));
                i += n.max(1);
            }
            Decoded::Incomplete => break,
        }
    }
    let leftover = data.len().saturating_sub(i);
    if leftover > MAX_PENDING {
        // Give up on the oversized sequence; surface one Unknown so the
        // caller is not stuck and resynchronise on the next byte.
        out.push(Key::new(KeyCode::Unknown));
        i = data.len();
    }
    pending.clear();
    if i < data.len() {
        pending.extend_from_slice(&data[i..]);
    }
    out
}

fn decode_one(s: &[u8]) -> Decoded {
    let b = s[0];
    match b {
        0x1b => decode_escape(s),
        0x0d | 0x0a => Decoded::Key(Key::new(KeyCode::Enter), 1),
        0x09 => Decoded::Key(Key::new(KeyCode::Tab), 1),
        0x7f | 0x08 => Decoded::Key(Key::new(KeyCode::Backspace), 1),
        0x00 => Decoded::Key(
            Key {
                code: KeyCode::Char('@'),
                ctrl: true,
                alt: false,
                shift: false,
            },
            1,
        ),
        0x01..=0x1a => match ctrl_letter(b) {
            Some(key) => Decoded::Key(key, 1),
            None => Decoded::Invalid(1),
        },
        0x1c..=0x1f => {
            let c = match b {
                0x1c => '\\',
                0x1d => ']',
                0x1e => '^',
                _ => '_',
            };
            Decoded::Key(
                Key {
                    code: KeyCode::Char(c),
                    ctrl: true,
                    alt: false,
                    shift: false,
                },
                1,
            )
        }
        0x20..=0x7e => Decoded::Key(Key::char(b as char), 1),
        _ => decode_utf8(s),
    }
}

fn ctrl_letter(b: u8) -> Option<Key> {
    if (1..=26).contains(&b) {
        let c = (b'a' + (b - 1)) as char;
        Some(Key {
            code: KeyCode::Char(c),
            ctrl: true,
            alt: false,
            shift: false,
        })
    } else {
        None
    }
}

fn utf8_seq_len(first: u8) -> usize {
    match first {
        0xc2..=0xdf => 2,
        0xe0..=0xef => 3,
        0xf0..=0xf4 => 4,
        _ => 0,
    }
}

fn decode_utf8(s: &[u8]) -> Decoded {
    let n = utf8_seq_len(s[0]);
    if n == 0 {
        return Decoded::Invalid(1);
    }
    if s.len() < n {
        // If a byte that must be a continuation byte is not one, fail early
        // instead of waiting forever.
        if s.iter().skip(1).any(|b| b & 0xc0 != 0x80) {
            return Decoded::Invalid(1);
        }
        return Decoded::Incomplete;
    }
    match core::str::from_utf8(&s[..n]) {
        Ok(text) => match text.chars().next() {
            Some(c) => Decoded::Key(Key::char(c), n),
            None => Decoded::Invalid(1),
        },
        Err(_) => Decoded::Invalid(1),
    }
}

fn decode_escape(s: &[u8]) -> Decoded {
    if s.len() == 1 {
        return Decoded::Key(Key::new(KeyCode::Esc), 1);
    }
    match s[1] {
        b'[' => decode_csi(s),
        b'O' => decode_ss3(s),
        _ => decode_alt(s),
    }
}

fn decode_alt(s: &[u8]) -> Decoded {
    if s.len() < 2 {
        return Decoded::Incomplete;
    }
    let b = s[1];
    let key = match b {
        0x1b => Key {
            code: KeyCode::Esc,
            ctrl: false,
            alt: true,
            shift: false,
        },
        0x0d | 0x0a => Key {
            code: KeyCode::Enter,
            ctrl: false,
            alt: true,
            shift: false,
        },
        0x09 => Key {
            code: KeyCode::Tab,
            ctrl: false,
            alt: true,
            shift: false,
        },
        0x7f | 0x08 => Key {
            code: KeyCode::Backspace,
            ctrl: false,
            alt: true,
            shift: false,
        },
        0x00 => Key {
            code: KeyCode::Char('@'),
            ctrl: true,
            alt: true,
            shift: false,
        },
        0x01..=0x1a => match ctrl_letter(b) {
            Some(k) => Key { alt: true, ..k },
            None => return Decoded::Invalid(2),
        },
        0x1c..=0x1f => {
            let c = match b {
                0x1c => '\\',
                0x1d => ']',
                0x1e => '^',
                _ => '_',
            };
            Key {
                code: KeyCode::Char(c),
                ctrl: true,
                alt: true,
                shift: false,
            }
        }
        0x20..=0x7e => Key::alt_char(b as char),
        _ => match decode_utf8(&s[1..]) {
            Decoded::Key(k, _n) => Key { alt: true, ..k },
            Decoded::Incomplete => return Decoded::Incomplete,
            Decoded::Invalid(_) => return Decoded::Invalid(2),
        },
    };
    Decoded::Key(
        key,
        2 + if b >= 0x80 {
            utf8_seq_len(b).saturating_sub(1)
        } else {
            0
        },
    )
}

fn decode_csi(s: &[u8]) -> Decoded {
    let mut j = 2usize;
    while j < s.len() {
        let b = s[j];
        if (0x40..=0x7e).contains(&b) {
            return Decoded::Key(csi_key(&s[2..j], b), j + 1);
        }
        if b < 0x20 || b == 0x7f {
            // A control byte inside a CSI sequence cancels it. Report Esc and
            // let the control byte be decoded on the next round.
            return Decoded::Key(Key::new(KeyCode::Esc), 2);
        }
        j += 1;
    }
    Decoded::Incomplete
}

fn decode_ss3(s: &[u8]) -> Decoded {
    if s.len() < 3 {
        return Decoded::Incomplete;
    }
    let key = match s[2] {
        b'A' => Key::new(KeyCode::Up),
        b'B' => Key::new(KeyCode::Down),
        b'C' => Key::new(KeyCode::Right),
        b'D' => Key::new(KeyCode::Left),
        b'H' => Key::new(KeyCode::Home),
        b'F' => Key::new(KeyCode::End),
        b'P' => Key::new(KeyCode::F(1)),
        b'Q' => Key::new(KeyCode::F(2)),
        b'R' => Key::new(KeyCode::F(3)),
        b'S' => Key::new(KeyCode::F(4)),
        _ => Key::new(KeyCode::Unknown),
    };
    Decoded::Key(key, 3)
}

fn parse_params(s: &[u8]) -> ([u32; 8], usize) {
    let mut out = [0u32; 8];
    let mut count = 0usize;
    let mut current = 0u32;
    let mut have = false;
    let mut digits = 0u32;
    for &b in s {
        if b == b';' {
            if count < out.len() {
                out[count] = if have { current } else { 0 };
                count += 1;
            }
            current = 0;
            have = false;
            digits = 0;
        } else if b.is_ascii_digit() {
            if digits < 9 {
                current = current.saturating_mul(10).saturating_add((b - b'0') as u32);
                digits += 1;
            }
            have = true;
        } else {
            // '?', '<', '>' and intermediate bytes are not part of a numeric
            // parameter for the keys we understand.
            have = false;
            digits = 0;
        }
    }
    if count < out.len() {
        out[count] = if have { current } else { 0 };
        count += 1;
    }
    (out, count)
}

fn apply_mods(mut key: Key, modifier: u32) -> Key {
    if modifier > 1 {
        let bits = modifier - 1;
        key.shift = bits & 1 != 0;
        key.alt = bits & 2 != 0;
        key.ctrl = bits & 4 != 0;
    }
    key
}

fn csi_key(params: &[u8], final_byte: u8) -> Key {
    let (p, n) = parse_params(params);
    let modifier = if n >= 2 { p[1] } else { 0 };
    let base = match final_byte {
        b'A' => KeyCode::Up,
        b'B' => KeyCode::Down,
        b'C' => KeyCode::Right,
        b'D' => KeyCode::Left,
        b'H' => KeyCode::Home,
        b'F' => KeyCode::End,
        b'Z' => {
            return Key {
                code: KeyCode::Tab,
                ctrl: false,
                alt: false,
                shift: true,
            }
        }
        b'P' => KeyCode::F(1),
        b'Q' => KeyCode::F(2),
        b'R' => KeyCode::F(3),
        b'S' => KeyCode::F(4),
        b'~' => {
            let base = match p[0] {
                1 | 7 => KeyCode::Home,
                2 => KeyCode::Insert,
                3 => KeyCode::Delete,
                4 | 8 => KeyCode::End,
                5 => KeyCode::PageUp,
                6 => KeyCode::PageDown,
                11 => KeyCode::F(1),
                12 => KeyCode::F(2),
                13 => KeyCode::F(3),
                14 => KeyCode::F(4),
                15 => KeyCode::F(5),
                17 => KeyCode::F(6),
                18 => KeyCode::F(7),
                19 => KeyCode::F(8),
                20 => KeyCode::F(9),
                21 => KeyCode::F(10),
                23 => KeyCode::F(11),
                24 => KeyCode::F(12),
                200 => return Key::new(KeyCode::PasteStart),
                201 => return Key::new(KeyCode::PasteEnd),
                _ => KeyCode::Unknown,
            };
            return apply_mods(Key::new(base), modifier);
        }
        _ => KeyCode::Unknown,
    };
    apply_mods(Key::new(base), modifier)
}

// ---------------------------------------------------------------------------
// Blocking reader
// ---------------------------------------------------------------------------

thread_local! {
    static PENDING: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
    static QUEUE: RefCell<VecDeque<Key>> = const { RefCell::new(VecDeque::new()) };
}

/// Read one key, blocking until input is available.
///
/// On a Windows console this uses ReadConsoleInputW so legacy consoles get
/// proper arrow/function keys even without VT input support. On every other
/// platform (and for redirected stdin) it reads bytes and runs [decode_keys].
pub fn read_key() -> Result<Key> {
    #[cfg(windows)]
    {
        // Native consoles give reliable arrow key records. Pipes (ConPTY)
        // fail here and fall through to the byte decoder.
        match win::read_key() {
            Ok(key) => return Ok(key),
            Err(_) => {}
        }
    }
    read_key_bytes()
}

#[cfg(unix)]
fn read_stdin_raw(buf: &mut [u8]) -> std::io::Result<usize> {
    use core::ffi::c_void;
    extern "C" {
        fn read(fd: i32, buf: *mut c_void, count: usize) -> isize;
    }
    loop {
        let n = unsafe { read(0, buf.as_mut_ptr() as *mut c_void, buf.len()) };
        if n >= 0 {
            return Ok(n as usize);
        }
        let err = std::io::Error::last_os_error();
        if err.kind() != std::io::ErrorKind::Interrupted {
            return Err(err);
        }
    }
}

#[cfg(windows)]
fn read_stdin_raw(buf: &mut [u8]) -> std::io::Result<usize> {
    use core::ffi::c_void;
    type Handle = *mut c_void;
    extern "system" {
        fn GetStdHandle(which: u32) -> Handle;
        fn ReadFile(
            handle: Handle,
            buf: *mut c_void,
            len: u32,
            read: *mut u32,
            overlapped: *mut c_void,
        ) -> i32;
    }
    let h = unsafe { GetStdHandle(0xFFFF_FFF6) };
    if h.is_null() || h as isize == -1 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotConnected,
            "no stdin handle",
        ));
    }
    let mut got = 0u32;
    let ok = unsafe {
        ReadFile(
            h,
            buf.as_mut_ptr() as *mut c_void,
            buf.len() as u32,
            &mut got,
            core::ptr::null_mut(),
        )
    };
    if ok == 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(got as usize)
}

#[cfg(not(any(unix, windows)))]
fn read_stdin_raw(buf: &mut [u8]) -> std::io::Result<usize> {
    std::io::stdin().read(buf)
}

fn raw_receiver() -> &'static Mutex<mpsc::Receiver<u8>> {
    static RX: OnceLock<Mutex<mpsc::Receiver<u8>>> = OnceLock::new();
    RX.get_or_init(|| {
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let mut buf = [0u8; 64];
            loop {
                match read_stdin_raw(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        for b in &buf[..n] {
                            if tx.send(*b).is_err() {
                                return;
                            }
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(_) => break,
                }
            }
        });
        Mutex::new(rx)
    })
}

#[cfg(unix)]
fn input_ready(wait_ms: i32) -> bool {
    #[repr(C)]
    struct PollFd {
        fd: i32,
        events: i16,
        revents: i16,
    }
    extern "C" {
        fn poll(fds: *mut PollFd, nfds: usize, timeout: i32) -> i32;
    }
    let mut p = PollFd {
        fd: 0,
        events: 1, // POLLIN
        revents: 0,
    };
    unsafe { poll(&mut p, 1, wait_ms) > 0 }
}

#[cfg(windows)]
fn input_ready(wait_ms: i32) -> bool {
    use core::ffi::c_void;
    type Handle = *mut c_void;
    extern "system" {
        fn GetStdHandle(which: u32) -> Handle;
        fn WaitForSingleObject(handle: Handle, ms: u32) -> u32;
        fn GetNumberOfConsoleInputEvents(handle: Handle, count: *mut u32) -> i32;
        fn PeekNamedPipe(
            handle: Handle,
            buffer: *mut c_void,
            len: u32,
            read: *mut u32,
            available: *mut u32,
            left: *mut u32,
        ) -> i32;
    }
    let h = unsafe { GetStdHandle(0xFFFF_FFF6) };
    if h.is_null() || h as isize == -1 {
        return false;
    }
    // ConPTY can expose stdin as a pipe; a console exposes input events.
    // Waiting alone is not reliable for both, and checking first avoids a
    // 250 ms delay when the rest of ESC [ A is already buffered.
    let mut count = 0u32;
    if unsafe { GetNumberOfConsoleInputEvents(h, &mut count) } != 0 && count > 0 {
        return true;
    }
    let mut available = 0u32;
    if unsafe {
        PeekNamedPipe(
            h,
            core::ptr::null_mut(),
            0,
            core::ptr::null_mut(),
            &mut available,
            core::ptr::null_mut(),
        )
    } != 0
        && available > 0
    {
        return true;
    }
    unsafe { WaitForSingleObject(h, wait_ms.max(0) as u32) == 0 }
}

#[cfg(not(any(unix, windows)))]
fn input_ready(_wait_ms: i32) -> bool {
    false
}

fn read_key_bytes() -> Result<Key> {
    loop {
        if let Some(key) = QUEUE.with(|q| q.borrow_mut().pop_front()) {
            return Ok(key);
        }
        let rx = raw_receiver().lock().unwrap();
        let first = match rx.recv() {
            Ok(b) => b,
            Err(_) => return Err(Error::end_of_input()),
        };
        let mut buf = vec![first];
        // A pipe/ConPTY can return ESC alone and the rest of a VT sequence in
        // a later read. Collect any bytes that follow promptly; a real Esc
        // key only costs this short delay.
        let wait_ms = if first == 0x1b { 250 } else { 2 };
        while buf.len() < 64 {
            match rx.recv_timeout(std::time::Duration::from_millis(wait_ms)) {
                Ok(b) => buf.push(b),
                Err(_) => break,
            }
        }
        let keys = PENDING.with(|p| {
            let mut p = p.borrow_mut();
            decode_keys(&buf, &mut p)
        });
        if keys.is_empty() {
            continue;
        }
        QUEUE.with(|q| {
            let mut q = q.borrow_mut();
            for key in keys {
                q.push_back(key);
            }
        });
    }
}

#[cfg(windows)]
#[allow(dead_code)]
mod win {
    use super::*;
    use core::cell::Cell;
    use core::ffi::c_void;

    type Handle = *mut c_void;

    extern "system" {
        fn GetStdHandle(which: u32) -> Handle;
        fn ReadConsoleInputW(
            handle: Handle,
            records: *mut InputRecord,
            len: u32,
            read: *mut u32,
        ) -> i32;
    }

    const STD_INPUT_HANDLE: u32 = 0xFFFF_FFF6;
    const KEY_EVENT: u16 = 0x0001;

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct KeyEventRecord {
        key_down: i32,
        repeat_count: u16,
        virtual_key: u16,
        scan_code: u16,
        unicode_char: u16,
        control_state: u32,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    union Event {
        key: KeyEventRecord,
        _raw: [u8; 16],
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct InputRecord {
        event_type: u16,
        event: Event,
    }

    const RIGHT_ALT_PRESSED: u32 = 0x0001;
    const LEFT_ALT_PRESSED: u32 = 0x0002;
    const RIGHT_CTRL_PRESSED: u32 = 0x0004;
    const LEFT_CTRL_PRESSED: u32 = 0x0008;
    const SHIFT_PRESSED: u32 = 0x0010;

    thread_local! {
        static HIGH_SURROGATE: Cell<u16> = const { Cell::new(0) };
        static WIN_QUEUE: RefCell<VecDeque<Key>> = const { RefCell::new(VecDeque::new()) };
    }

    fn baseline(control: u32) -> Key {
        Key {
            code: KeyCode::Unknown,
            ctrl: control & (RIGHT_CTRL_PRESSED | LEFT_CTRL_PRESSED) != 0,
            alt: control & (RIGHT_ALT_PRESSED | LEFT_ALT_PRESSED) != 0,
            shift: control & SHIFT_PRESSED != 0,
        }
    }

    fn decode_unit(unit: u16) -> Option<char> {
        let high = HIGH_SURROGATE.with(|h| h.get());
        if (0xd800..=0xdbff).contains(&unit) {
            HIGH_SURROGATE.with(|h| h.set(unit));
            return None;
        }
        if (0xdc00..=0xdfff).contains(&unit) {
            HIGH_SURROGATE.with(|h| h.set(0));
            if high == 0 {
                return None;
            }
            let cp = 0x10000u32 + ((high as u32 - 0xd800) << 10) + (unit as u32 - 0xdc00);
            return char::from_u32(cp);
        }
        HIGH_SURROGATE.with(|h| h.set(0));
        char::from_u32(unit as u32)
    }

    fn map_event(k: KeyEventRecord) -> Option<Key> {
        let mut key = baseline(k.control_state);
        let vk = k.virtual_key;
        // Special keys are reported with virtual key codes; function keys are
        // contiguous at 0x70..0x7b.
        let special = match vk {
            0x26 => Some(KeyCode::Up),
            0x28 => Some(KeyCode::Down),
            0x25 => Some(KeyCode::Left),
            0x27 => Some(KeyCode::Right),
            0x24 => Some(KeyCode::Home),
            0x23 => Some(KeyCode::End),
            0x21 => Some(KeyCode::PageUp),
            0x22 => Some(KeyCode::PageDown),
            0x2d => Some(KeyCode::Insert),
            0x2e => Some(KeyCode::Delete),
            0x08 => Some(KeyCode::Backspace),
            0x09 => Some(KeyCode::Tab),
            0x0d => Some(KeyCode::Enter),
            0x1b => Some(KeyCode::Esc),
            0x70..=0x7b => Some(KeyCode::F((vk - 0x6f) as u8)),
            _ => None,
        };
        if let Some(code) = special {
            key.code = code;
            return Some(key);
        }
        if k.unicode_char == 0 {
            return None;
        }
        let c = decode_unit(k.unicode_char)?;
        // AltGr is reported as RightAlt+LeftCtrl on Windows. It produces text,
        // not a Ctrl/Alt shortcut, so clear those modifier bits for printable
        // characters (non-US keyboard layouts rely on this).
        let altgr =
            k.control_state & RIGHT_ALT_PRESSED != 0 && k.control_state & LEFT_CTRL_PRESSED != 0;
        if altgr && c >= ' ' {
            key.ctrl = false;
            key.alt = false;
        }
        match c {
            '\r' | '\n' => key.code = KeyCode::Enter,
            '\t' => key.code = KeyCode::Tab,
            '\u{8}' | '\u{7f}' => key.code = KeyCode::Backspace,
            '\u{1b}' => key.code = KeyCode::Esc,
            c if c < ' ' => match ctrl_letter(c as u8) {
                Some(mut mapped) => {
                    mapped.alt = key.alt;
                    mapped.shift = key.shift;
                    mapped.ctrl = true;
                    return Some(mapped);
                }
                None => return None,
            },
            c => key.code = KeyCode::Char(c),
        }
        Some(key)
    }

    pub fn read_key() -> Result<Key> {
        let queued = WIN_QUEUE.with(|q| q.borrow_mut().pop_front());
        if let Some(key) = queued {
            return Ok(key);
        }
        let handle = unsafe { GetStdHandle(STD_INPUT_HANDLE) };
        if handle.is_null() || handle as isize == -1 {
            return Err(Error::not_a_tty());
        }
        loop {
            let mut record = unsafe { core::mem::zeroed::<InputRecord>() };
            let mut read = 0u32;
            let ok = unsafe { ReadConsoleInputW(handle, &mut record, 1, &mut read) };
            if ok == 0 {
                return Err(Error::from(std::io::Error::last_os_error()));
            }
            if read == 0 || record.event_type != KEY_EVENT {
                continue;
            }
            let event = unsafe { record.event.key };
            if event.key_down == 0 {
                continue;
            }
            if let Some(key) = map_event(event) {
                let repeat = event.repeat_count.clamp(1, 64);
                if repeat > 1 {
                    WIN_QUEUE.with(|q| {
                        let mut q = q.borrow_mut();
                        for _ in 1..repeat {
                            q.push_back(key);
                        }
                    });
                }
                return Ok(key);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode_all(bytes: &[u8]) -> Vec<Key> {
        let mut pending = Vec::new();
        let keys = decode_keys(bytes, &mut pending);
        assert!(pending.is_empty(), "unexpected pending bytes: {pending:?}");
        keys
    }

    fn one(bytes: &[u8]) -> Key {
        let keys = decode_all(bytes);
        assert_eq!(
            keys.len(),
            1,
            "expected one key for {bytes:?}, got {keys:?}"
        );
        keys[0]
    }

    fn k(code: KeyCode) -> Key {
        Key::new(code)
    }

    #[test]
    fn basic_ascii_and_control_keys() {
        assert_eq!(one(b"a"), k(KeyCode::Char('a')));
        assert_eq!(one(b"Z"), k(KeyCode::Char('Z')));
        assert_eq!(one(b"\r"), k(KeyCode::Enter));
        assert_eq!(one(b"\n"), k(KeyCode::Enter));
        assert_eq!(one(b"\t"), k(KeyCode::Tab));
        assert_eq!(one(b"\x7f"), k(KeyCode::Backspace));
        assert_eq!(one(b"\x08"), k(KeyCode::Backspace));
        assert_eq!(one(b"\x1b"), k(KeyCode::Esc));
        assert_eq!(one(b" "), k(KeyCode::Char(' ')));
    }

    #[test]
    fn ctrl_letters() {
        assert_eq!(
            one(b"\x01"),
            Key {
                code: KeyCode::Char('a'),
                ctrl: true,
                alt: false,
                shift: false
            }
        );
        assert_eq!(one(b"\x03"), Key::ctrl_char('c'));
        assert_eq!(one(b"\x04"), Key::ctrl_char('d'));
        assert_eq!(one(b"\x1a"), Key::ctrl_char('z'));
        assert_eq!(
            one(b"\x00"),
            Key {
                code: KeyCode::Char('@'),
                ctrl: true,
                alt: false,
                shift: false
            }
        );
        assert!(one(b"\x17").is_ctrl('w'));
    }

    #[test]
    fn csi_and_ss3_table() {
        let table: &[(&[u8], KeyCode)] = &[
            (b"\x1b[A", KeyCode::Up),
            (b"\x1b[B", KeyCode::Down),
            (b"\x1b[C", KeyCode::Right),
            (b"\x1b[D", KeyCode::Left),
            (b"\x1b[H", KeyCode::Home),
            (b"\x1b[F", KeyCode::End),
            (b"\x1b[1~", KeyCode::Home),
            (b"\x1b[2~", KeyCode::Insert),
            (b"\x1b[3~", KeyCode::Delete),
            (b"\x1b[4~", KeyCode::End),
            (b"\x1b[5~", KeyCode::PageUp),
            (b"\x1b[6~", KeyCode::PageDown),
            (b"\x1b[7~", KeyCode::Home),
            (b"\x1b[8~", KeyCode::End),
            (b"\x1bOA", KeyCode::Up),
            (b"\x1bOB", KeyCode::Down),
            (b"\x1bOC", KeyCode::Right),
            (b"\x1bOD", KeyCode::Left),
            (b"\x1bOH", KeyCode::Home),
            (b"\x1bOF", KeyCode::End),
        ];
        for (bytes, code) in table {
            assert_eq!(one(bytes), k(*code), "sequence {bytes:?}");
        }
    }

    #[test]
    fn function_keys_all_twelve() {
        let table: &[(&[u8], u8)] = &[
            (b"\x1bOP", 1),
            (b"\x1bOQ", 2),
            (b"\x1bOR", 3),
            (b"\x1bOS", 4),
            (b"\x1b[15~", 5),
            (b"\x1b[17~", 6),
            (b"\x1b[18~", 7),
            (b"\x1b[19~", 8),
            (b"\x1b[20~", 9),
            (b"\x1b[21~", 10),
            (b"\x1b[23~", 11),
            (b"\x1b[24~", 12),
            (b"\x1b[11~", 1),
            (b"\x1b[12~", 2),
            (b"\x1b[13~", 3),
            (b"\x1b[14~", 4),
        ];
        for (bytes, n) in table {
            assert_eq!(one(bytes), k(KeyCode::F(*n)), "sequence {bytes:?}");
        }
    }

    #[test]
    fn modified_keys() {
        assert_eq!(
            one(b"\x1b[1;2P"),
            Key {
                code: KeyCode::F(1),
                ctrl: false,
                alt: false,
                shift: true
            }
        );
        assert_eq!(
            one(b"\x1b[1;5D"),
            Key {
                code: KeyCode::Left,
                ctrl: true,
                alt: false,
                shift: false
            }
        );
        assert_eq!(
            one(b"\x1b[1;3C"),
            Key {
                code: KeyCode::Right,
                ctrl: false,
                alt: true,
                shift: false
            }
        );
        assert_eq!(
            one(b"\x1b[1;2A"),
            Key {
                code: KeyCode::Up,
                ctrl: false,
                alt: false,
                shift: true
            }
        );
        assert_eq!(
            one(b"\x1b[1;5B"),
            Key {
                code: KeyCode::Down,
                ctrl: true,
                alt: false,
                shift: false
            }
        );
        assert_eq!(
            one(b"\x1b[3;5~"),
            Key {
                code: KeyCode::Delete,
                ctrl: true,
                alt: false,
                shift: false
            }
        );
        assert_eq!(
            one(b"\x1b[Z"),
            Key {
                code: KeyCode::Tab,
                ctrl: false,
                alt: false,
                shift: true
            }
        );
        assert_eq!(
            one(b"\x1b[1;5H"),
            Key {
                code: KeyCode::Home,
                ctrl: true,
                alt: false,
                shift: false
            }
        );
    }

    #[test]
    fn alt_prefix() {
        assert_eq!(one(b"\x1bb"), Key::alt_char('b'));
        assert_eq!(one(b"\x1bF"), Key::alt_char('F'));
        assert_eq!(
            one(b"\x1b\x01"),
            Key {
                code: KeyCode::Char('a'),
                ctrl: true,
                alt: true,
                shift: false
            }
        );
        assert_eq!(
            one(b"\x1b\x1b"),
            Key {
                code: KeyCode::Esc,
                ctrl: false,
                alt: true,
                shift: false
            }
        );
    }

    #[test]
    fn bracketed_paste_markers() {
        let keys = decode_all(b"\x1b[200~hi\x1b[201~");
        assert_eq!(
            keys,
            vec![
                k(KeyCode::PasteStart),
                k(KeyCode::Char('h')),
                k(KeyCode::Char('i')),
                k(KeyCode::PasteEnd),
            ]
        );
    }

    #[test]
    fn utf8_split_across_reads() {
        let mut pending = Vec::new();
        assert!(decode_keys(&[0xc3], &mut pending).is_empty());
        assert_eq!(pending, vec![0xc3]);
        let keys = decode_keys(&[0xa9], &mut pending);
        assert_eq!(keys, vec![k(KeyCode::Char('é'))]);
        assert!(pending.is_empty());

        assert!(decode_keys(&[0xe4, 0xb8], &mut pending).is_empty());
        let keys = decode_keys(&[0xad], &mut pending);
        assert_eq!(keys, vec![k(KeyCode::Char('中'))]);
        assert!(pending.is_empty());
    }

    #[test]
    fn escape_sequence_split_across_reads() {
        let mut pending = Vec::new();
        assert!(decode_keys(b"\x1b[1;", &mut pending).is_empty());
        assert_eq!(pending, b"\x1b[1;".to_vec());
        let keys = decode_keys(b"5D", &mut pending);
        assert_eq!(
            keys,
            vec![Key {
                code: KeyCode::Left,
                ctrl: true,
                alt: false,
                shift: false
            }]
        );
        assert!(pending.is_empty());
    }

    #[test]
    fn multiple_keys_in_one_buffer() {
        assert_eq!(
            decode_all(b"a\x1b[A\x1b[3~b"),
            vec![
                k(KeyCode::Char('a')),
                k(KeyCode::Up),
                k(KeyCode::Delete),
                k(KeyCode::Char('b')),
            ]
        );
    }

    #[test]
    fn malformed_input_is_unknown_not_panic() {
        assert_eq!(one(&[0xff]), k(KeyCode::Unknown));
        assert_eq!(one(&[0xc0]), k(KeyCode::Unknown));
        assert_eq!(one(b"\x1b[999z"), k(KeyCode::Unknown));
        assert_eq!(one(b"\x1b[?z"), k(KeyCode::Unknown));
        let mut pending = Vec::new();
        assert!(decode_keys(b"\x1b[", &mut pending).is_empty());
        assert!(!pending.is_empty());
        // A control byte cancels the sequence and is decoded afterwards.
        let keys = decode_keys(b"\x03", &mut pending);
        assert_eq!(keys.first(), Some(&k(KeyCode::Esc)));
        assert!(keys.iter().any(|key| key.is_ctrl('c')));
        assert!(pending.is_empty());
    }

    #[test]
    fn oversized_pending_is_bounded() {
        let mut pending = Vec::new();
        let junk = vec![b'1'; MAX_PENDING + 16];
        let mut data = b"\x1b[".to_vec();
        data.extend_from_slice(&junk);
        let keys = decode_keys(&data, &mut pending);
        assert!(keys.iter().any(|key| key.code == KeyCode::Unknown));
        assert!(pending.len() <= MAX_PENDING);
    }
}
