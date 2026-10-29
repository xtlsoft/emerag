//! Ctrl+C handling that works during streaming output.
//!
//! The terminal layer polls a process-wide atomic flag. Installing a handler is
//! best-effort: in restricted environments the shell already handles SIGINT.

use std::sync::atomic::{AtomicBool, Ordering};

static INTERRUPTED: AtomicBool = AtomicBool::new(false);

pub fn interrupted() -> bool {
    INTERRUPTED.load(Ordering::SeqCst)
}

pub fn clear() {
    INTERRUPTED.store(false, Ordering::SeqCst);
}

#[cfg(unix)]
pub fn install() {
    type SigHandler = extern "C" fn(i32);
    extern "C" {
        fn signal(signum: i32, handler: SigHandler) -> usize;
    }
    extern "C" fn on_sigint(_sig: i32) {
        INTERRUPTED.store(true, Ordering::SeqCst);
    }
    const SIGINT: i32 = 2;
    unsafe {
        signal(SIGINT, on_sigint);
    }
}

#[cfg(windows)]
pub fn install() {
    use core::ffi::c_void;
    extern "system" {
        fn SetConsoleCtrlHandler(
            handler: Option<unsafe extern "system" fn(u32) -> i32>,
            add: i32,
        ) -> i32;
    }
    unsafe extern "system" fn on_ctrl(_ctrl_type: u32) -> i32 {
        INTERRUPTED.store(true, Ordering::SeqCst);
        1
    }
    unsafe {
        SetConsoleCtrlHandler(Some(on_ctrl), 1);
    }
    let _ = core::mem::size_of::<*mut c_void>();
}

#[cfg(not(any(unix, windows)))]
pub fn install() {}
