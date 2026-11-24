//! Raw keyboard mode with RAII restoration.
//!
//! On Unix this is termios (tcgetattr/tcsetattr); on Windows it is
//! SetConsoleMode. Both paths save the previous mode and restore it from Drop,
//! so an early return, an error, or a panic in the caller cannot leave the
//! terminal in raw mode. The functions return a clear error when stdin is not
//! a terminal so callers can fall back to cooked line input.

use crate::{Error, Result};
use emerag_util::sys;

#[cfg(unix)]
mod platform {
    //! termios for every Unix family emerag targets. Only the struct layout
    //! and the flag values differ between them; the logic is shared. The
    //! struct is padded at the end so a libc whose termios is larger than
    //! declared here still writes into owned memory.
    use crate::{Error, Result};
    use core::ffi::c_int;

    #[cfg(any(target_os = "macos", target_os = "ios"))]
    type Flag = core::ffi::c_ulong;
    #[cfg(not(any(target_os = "macos", target_os = "ios")))]
    type Flag = u32;

    // Linux and Android (glibc, musl and bionic agree on the layout below,
    // except that powerpc stores c_cc before c_line).
    #[cfg(all(
        any(target_os = "linux", target_os = "android"),
        not(any(target_arch = "powerpc", target_arch = "powerpc64"))
    ))]
    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct Termios {
        c_iflag: Flag,
        c_oflag: Flag,
        c_cflag: Flag,
        c_lflag: Flag,
        c_line: u8,
        c_cc: [u8; 32],
        c_ispeed: u32,
        c_ospeed: u32,
        _pad: [u8; 64],
    }

    #[cfg(all(
        any(target_os = "linux", target_os = "android"),
        any(target_arch = "powerpc", target_arch = "powerpc64")
    ))]
    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct Termios {
        c_iflag: Flag,
        c_oflag: Flag,
        c_cflag: Flag,
        c_lflag: Flag,
        c_cc: [u8; 32],
        c_line: u8,
        c_ispeed: u32,
        c_ospeed: u32,
        _pad: [u8; 64],
    }

    // 4.4BSD descendants: macOS/iOS, FreeBSD, DragonFly, NetBSD, OpenBSD.
    #[cfg(not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "solaris",
        target_os = "illumos"
    )))]
    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct Termios {
        c_iflag: Flag,
        c_oflag: Flag,
        c_cflag: Flag,
        c_lflag: Flag,
        c_cc: [u8; 20],
        c_ispeed: Flag,
        c_ospeed: Flag,
        _pad: [u8; 64],
    }

    #[cfg(any(target_os = "solaris", target_os = "illumos"))]
    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct Termios {
        c_iflag: Flag,
        c_oflag: Flag,
        c_cflag: Flag,
        c_lflag: Flag,
        c_cc: [u8; 19],
        _pad: [u8; 64],
    }

    /// Flag values. System V / Linux asm-generic numbering...
    #[cfg(any(
        target_os = "solaris",
        target_os = "illumos",
        all(
            any(target_os = "linux", target_os = "android"),
            not(any(target_arch = "powerpc", target_arch = "powerpc64"))
        )
    ))]
    mod flags {
        use super::Flag;
        pub const ISIG: Flag = 0o1;
        pub const ICANON: Flag = 0o2;
        pub const ECHO: Flag = 0o10;
        #[cfg(any(target_arch = "mips", target_arch = "mips64"))]
        pub const IEXTEN: Flag = 0o400;
        #[cfg(not(any(target_arch = "mips", target_arch = "mips64")))]
        pub const IEXTEN: Flag = 0o100000;
        pub const BRKINT: Flag = 0o2;
        pub const ISTRIP: Flag = 0o40;
        pub const INLCR: Flag = 0o100;
        pub const ICRNL: Flag = 0o400;
        pub const IXON: Flag = 0o2000;
        pub const CSIZE: Flag = 0o60;
        pub const CS8: Flag = 0o60;
        #[cfg(any(
            target_os = "solaris",
            target_os = "illumos",
            target_arch = "mips",
            target_arch = "mips64",
            target_arch = "sparc",
            target_arch = "sparc64"
        ))]
        pub const VMIN: usize = 4;
        #[cfg(not(any(
            target_os = "solaris",
            target_os = "illumos",
            target_arch = "mips",
            target_arch = "mips64",
            target_arch = "sparc",
            target_arch = "sparc64"
        )))]
        pub const VMIN: usize = 6;
        pub const VTIME: usize = 5;
    }

    /// ...and the BSD numbering, which Linux also uses on powerpc.
    #[cfg(not(any(
        target_os = "solaris",
        target_os = "illumos",
        all(
            any(target_os = "linux", target_os = "android"),
            not(any(target_arch = "powerpc", target_arch = "powerpc64"))
        )
    )))]
    mod flags {
        use super::Flag;
        pub const ISIG: Flag = 0x80;
        pub const ICANON: Flag = 0x100;
        pub const ECHO: Flag = 0x8;
        pub const IEXTEN: Flag = 0x400;
        pub const BRKINT: Flag = 0x2;
        pub const ISTRIP: Flag = 0x20;
        pub const INLCR: Flag = 0x40;
        pub const ICRNL: Flag = 0x100;
        pub const IXON: Flag = 0x200;
        pub const CSIZE: Flag = 0x300;
        pub const CS8: Flag = 0x300;
        #[cfg(any(target_os = "linux", target_os = "android"))]
        pub const VMIN: usize = 5;
        #[cfg(any(target_os = "linux", target_os = "android"))]
        pub const VTIME: usize = 7;
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        pub const VMIN: usize = 16;
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        pub const VTIME: usize = 17;
    }

    use flags::*;

    // Solaris/illumos encode the tcsetattr actions as ioctl numbers.
    #[cfg(any(target_os = "solaris", target_os = "illumos"))]
    const TCSANOW: c_int = 0x540e;
    #[cfg(not(any(target_os = "solaris", target_os = "illumos")))]
    const TCSANOW: c_int = 0;

    extern "C" {
        fn tcgetattr(fd: c_int, termios_p: *mut Termios) -> c_int;
        fn tcsetattr(fd: c_int, optional_actions: c_int, termios_p: *const Termios) -> c_int;
    }

    pub struct State {
        saved: Termios,
    }

    pub fn enter() -> Result<State> {
        let mut t = unsafe { core::mem::zeroed::<Termios>() };
        if unsafe { tcgetattr(0, &mut t) } != 0 {
            return Err(Error::new(format!(
                "tcgetattr: {}",
                std::io::Error::last_os_error()
            )));
        }
        let saved = t;
        // Canonical mode and echo off; ISIG off so Ctrl+C arrives as a key
        // instead of killing the process. Flow control off so Ctrl+S does
        // not freeze an emergency console. ISTRIP off and CS8 on, as in
        // cfmakeraw, so a serial line configured for 7 bits still passes
        // UTF-8 input through.
        t.c_lflag &= !(ICANON | ECHO | ISIG | IEXTEN);
        t.c_iflag &= !(IXON | ICRNL | INLCR | BRKINT | ISTRIP);
        t.c_cflag = (t.c_cflag & !CSIZE) | CS8;
        t.c_cc[VMIN] = 1;
        t.c_cc[VTIME] = 0;
        if unsafe { tcsetattr(0, TCSANOW, &t) } != 0 {
            return Err(Error::new(format!(
                "tcsetattr: {}",
                std::io::Error::last_os_error()
            )));
        }
        Ok(State { saved })
    }

    pub fn restore(state: &State) {
        let _ = unsafe { tcsetattr(0, TCSANOW, &state.saved) };
    }
}

#[cfg(windows)]
mod platform {
    use crate::{Error, Result};
    use core::ffi::c_void;

    type Handle = *mut c_void;

    extern "system" {
        fn GetStdHandle(which: u32) -> Handle;
        fn GetConsoleMode(handle: Handle, mode: *mut u32) -> i32;
        fn SetConsoleMode(handle: Handle, mode: u32) -> i32;
    }

    const STD_INPUT_HANDLE: u32 = 0xFFFF_FFF6;
    const STD_OUTPUT_HANDLE: u32 = 0xFFFF_FFF5;

    const ENABLE_PROCESSED_INPUT: u32 = 0x0001;
    const ENABLE_LINE_INPUT: u32 = 0x0002;
    const ENABLE_ECHO_INPUT: u32 = 0x0004;
    const ENABLE_QUICK_EDIT_MODE: u32 = 0x0040;
    const ENABLE_EXTENDED_FLAGS: u32 = 0x0080;
    const ENABLE_VIRTUAL_TERMINAL_INPUT: u32 = 0x0200;
    const ENABLE_VIRTUAL_TERMINAL_PROCESSING: u32 = 0x0004;

    fn valid(h: Handle) -> bool {
        !h.is_null() && h as isize != -1
    }

    pub struct State {
        input: Handle,
        saved_input: u32,
        output: Handle,
        saved_output: u32,
        output_changed: bool,
    }

    pub fn enter() -> Result<State> {
        let input = unsafe { GetStdHandle(STD_INPUT_HANDLE) };
        if !valid(input) {
            return Err(Error::not_a_tty());
        }
        let mut saved_input = 0u32;
        if unsafe { GetConsoleMode(input, &mut saved_input) } == 0 {
            return Err(Error::not_a_tty());
        }

        // Keys are read as native console records (ReadConsoleInputW), which
        // carry virtual-key codes for arrows and function keys on every
        // Windows version and under ConPTY. VT input mode is switched OFF on
        // purpose: with it on, the console turns an arrow into three separate
        // records (ESC, '[', 'A') without key codes, which used to reach the
        // editor as Esc plus literal text.
        let new_input = (saved_input
            & !(ENABLE_LINE_INPUT
                | ENABLE_ECHO_INPUT
                | ENABLE_PROCESSED_INPUT
                | ENABLE_QUICK_EDIT_MODE
                | ENABLE_VIRTUAL_TERMINAL_INPUT))
            | ENABLE_EXTENDED_FLAGS;
        if unsafe { SetConsoleMode(input, new_input) } == 0 {
            // Very old consoles reject ENABLE_EXTENDED_FLAGS.
            let fallback = new_input & !(ENABLE_EXTENDED_FLAGS | ENABLE_QUICK_EDIT_MODE);
            if unsafe { SetConsoleMode(input, fallback) } == 0 {
                return Err(Error::new(format!(
                    "SetConsoleMode(input): {}",
                    std::io::Error::last_os_error()
                )));
            }
        }

        // Best effort: make ANSI output work on Windows 10+ consoles. If the
        // console rejects it we simply keep the old mode; Screen still has a
        // plain-text fallback.
        let output = unsafe { GetStdHandle(STD_OUTPUT_HANDLE) };
        let mut saved_output = 0u32;
        let mut output_changed = false;
        if valid(output) && unsafe { GetConsoleMode(output, &mut saved_output) } != 0 {
            if unsafe { SetConsoleMode(output, saved_output | ENABLE_VIRTUAL_TERMINAL_PROCESSING) }
                != 0
            {
                output_changed = true;
            }
        }

        Ok(State {
            input,
            saved_input,
            output,
            saved_output,
            output_changed,
        })
    }

    pub fn restore(state: &State) {
        let _ = unsafe { SetConsoleMode(state.input, state.saved_input) };
        if state.output_changed && valid(state.output) {
            let _ = unsafe { SetConsoleMode(state.output, state.saved_output) };
        }
    }
}

#[cfg(not(any(windows, unix)))]
mod platform {
    use crate::{Error, Result};

    pub struct State;

    pub fn enter() -> Result<State> {
        Err(Error::unsupported("raw mode on this platform"))
    }

    pub fn restore(_state: &State) {}
}

/// RAII guard for raw terminal mode.
///
/// The terminal is restored by [Drop]; [RawMode::restore] can also be called
/// explicitly. Restoration errors are deliberately ignored: the guard must not
/// panic while unwinding.
pub struct RawMode {
    state: platform::State,
    active: bool,
}

impl RawMode {
    /// Explicitly restore the previous terminal mode.
    pub fn restore(&mut self) {
        if self.active {
            platform::restore(&self.state);
            self.active = false;
        }
    }

    pub fn is_active(&self) -> bool {
        self.active
    }
}

impl Drop for RawMode {
    fn drop(&mut self) {
        self.restore();
    }
}

/// Put stdin into raw mode. Fails with [crate::ErrorKind::NotATty] when stdin
/// is redirected, and with a descriptive error when the platform call fails.
#[must_use = "the terminal is restored when the guard is dropped"]
pub fn raw_mode() -> Result<RawMode> {
    if !sys::is_tty(0) {
        return Err(Error::not_a_tty());
    }
    let state = platform::enter()?;
    Ok(RawMode {
        state,
        active: true,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_is_clear_for_non_tty() {
        // cargo test does not normally run with a tty; even if it does this
        // assertion is only about error text, not about entering raw mode.
        let e = Error::not_a_tty();
        assert!(e.to_string().contains("terminal"));
        assert_eq!(e.kind(), crate::ErrorKind::NotATty);
    }
}
