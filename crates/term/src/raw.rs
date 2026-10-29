//! Raw keyboard mode with RAII restoration.
//!
//! On Unix this is termios (tcgetattr/tcsetattr); on Windows it is
//! SetConsoleMode. Both paths save the previous mode and restore it from Drop,
//! so an early return, an error, or a panic in the caller cannot leave the
//! terminal in raw mode. The functions return a clear error when stdin is not
//! a terminal so callers can fall back to cooked line input.

use crate::{Error, Result};
use emerag_util::sys;

#[cfg(all(
    unix,
    any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios"
    )
))]
mod platform {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    mod imp {
        use crate::{Error, Result};
        use core::ffi::c_int;

        #[repr(C)]
        #[derive(Clone, Copy)]
        pub struct Termios {
            pub c_iflag: u32,
            pub c_oflag: u32,
            pub c_cflag: u32,
            pub c_lflag: u32,
            pub c_line: u8,
            pub c_cc: [u8; 32],
            pub c_ispeed: u32,
            pub c_ospeed: u32,
        }

        extern "C" {
            fn tcgetattr(fd: c_int, termios_p: *mut Termios) -> c_int;
            fn tcsetattr(fd: c_int, optional_actions: c_int, termios_p: *const Termios) -> c_int;
        }

        // Linux termios flag values (asm-generic and all supported arches).
        const ICANON: u32 = 0o0000002;
        const ECHO: u32 = 0o0000010;
        const ISIG: u32 = 0o0000001;
        const IEXTEN: u32 = 0o0100000;
        const IXON: u32 = 0o0002000;
        const ICRNL: u32 = 0o0000400;
        const INLCR: u32 = 0o0000100;
        const BRKINT: u32 = 0o0000002;
        const VMIN: usize = 6;
        const VTIME: usize = 5;
        const TCSANOW: c_int = 0;

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
            // not freeze an emergency console.
            t.c_lflag &= !(ICANON | ECHO | ISIG | IEXTEN);
            t.c_iflag &= !(IXON | ICRNL | INLCR | BRKINT);
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

    #[cfg(any(target_os = "macos", target_os = "ios"))]
    mod imp {
        use crate::{Error, Result};
        use core::ffi::c_int;

        #[repr(C)]
        #[derive(Clone, Copy)]
        pub struct Termios {
            pub c_iflag: u64,
            pub c_oflag: u64,
            pub c_cflag: u64,
            pub c_lflag: u64,
            pub c_cc: [u8; 20],
            pub c_ispeed: u64,
            pub c_ospeed: u64,
        }

        extern "C" {
            fn tcgetattr(fd: c_int, termios_p: *mut Termios) -> c_int;
            fn tcsetattr(fd: c_int, optional_actions: c_int, termios_p: *const Termios) -> c_int;
        }

        const ICANON: u64 = 0x0000_0100;
        const ECHO: u64 = 0x0000_0008;
        const ISIG: u64 = 0x0000_0080;
        const IEXTEN: u64 = 0x0000_0400;
        const IXON: u64 = 0x0000_0200;
        const ICRNL: u64 = 0x0000_0100;
        const INLCR: u64 = 0x0000_0040;
        const BRKINT: u64 = 0x0000_0002;
        const VMIN: usize = 16;
        const VTIME: usize = 17;
        const TCSANOW: c_int = 0;

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
            t.c_lflag &= !(ICANON | ECHO | ISIG | IEXTEN);
            t.c_iflag &= !(IXON | ICRNL | INLCR | BRKINT);
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

    pub use imp::{enter, restore, State};
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

        let mut new_input = saved_input
            & !(ENABLE_LINE_INPUT
                | ENABLE_ECHO_INPUT
                | ENABLE_PROCESSED_INPUT
                | ENABLE_QUICK_EDIT_MODE);
        new_input |= ENABLE_EXTENDED_FLAGS;
        new_input |= ENABLE_VIRTUAL_TERMINAL_INPUT;
        if unsafe { SetConsoleMode(input, new_input) } == 0 {
            // Very old Windows consoles reject VIRTUAL_TERMINAL_INPUT.
            let fallback = new_input & !ENABLE_VIRTUAL_TERMINAL_INPUT;
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

#[cfg(not(any(
    windows,
    all(
        unix,
        any(
            target_os = "linux",
            target_os = "android",
            target_os = "macos",
            target_os = "ios"
        )
    )
)))]
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
