//! Platform abstraction: directories, TTYs, terminal size, PATH lookup.
//!
//! Only libc / kernel32 entry points that have existed for decades are used,
//! so binaries keep working on old Linux and old Windows releases.

use crate::{bail, Result};
use std::path::{Path, PathBuf};

pub fn is_windows() -> bool {
    cfg!(windows)
}

pub fn os_name() -> &'static str {
    std::env::consts::OS
}

pub fn arch() -> &'static str {
    std::env::consts::ARCH
}

pub fn pid() -> u32 {
    std::process::id()
}

pub fn env_var(name: &str) -> Option<String> {
    match std::env::var(name) {
        Ok(v) if !v.is_empty() => Some(v),
        _ => None,
    }
}

pub fn env_var_any(names: &[&str]) -> Option<String> {
    for n in names {
        if let Some(v) = env_var(n) {
            return Some(v);
        }
    }
    None
}

#[cfg(unix)]
pub fn is_tty(fd: i32) -> bool {
    extern "C" {
        fn isatty(fd: i32) -> i32;
    }
    unsafe { isatty(fd) == 1 }
}

#[cfg(windows)]
pub fn is_tty(fd: i32) -> bool {
    use core::ffi::c_void;
    extern "system" {
        fn GetStdHandle(which: u32) -> *mut c_void;
        fn GetConsoleMode(handle: *mut c_void, mode: *mut u32) -> i32;
    }
    let which = match fd {
        0 => 0xFFFF_FFF6u32, // STD_INPUT_HANDLE (-10)
        1 => 0xFFFF_FFF5u32, // STD_OUTPUT_HANDLE (-11)
        _ => 0xFFFF_FFF4u32, // STD_ERROR_HANDLE (-12)
    };
    unsafe {
        let h = GetStdHandle(which);
        if h.is_null() || h as isize == -1 {
            return false;
        }
        let mut mode = 0u32;
        GetConsoleMode(h, &mut mode) != 0
    }
}

#[cfg(not(any(unix, windows)))]
pub fn is_tty(_fd: i32) -> bool {
    false
}

/// Terminal size as (columns, rows). Falls back to COLUMNS/LINES then 80x24.
pub fn term_size() -> Option<(u16, u16)> {
    #[cfg(unix)]
    {
        #[repr(C)]
        struct Winsize {
            ws_row: u16,
            ws_col: u16,
            ws_xpixel: u16,
            ws_ypixel: u16,
        }
        extern "C" {
            fn ioctl(fd: i32, request: core::ffi::c_ulong, ...) -> i32;
        }
        #[cfg(all(
            target_os = "linux",
            any(
                target_arch = "powerpc",
                target_arch = "powerpc64",
                target_arch = "mips",
                target_arch = "mips64",
                target_arch = "sparc",
                target_arch = "sparc64"
            )
        ))]
        const TIOCGWINSZ: core::ffi::c_ulong = 0x40087468;
        #[cfg(all(
            target_os = "linux",
            not(any(
                target_arch = "powerpc",
                target_arch = "powerpc64",
                target_arch = "mips",
                target_arch = "mips64",
                target_arch = "sparc",
                target_arch = "sparc64"
            ))
        ))]
        const TIOCGWINSZ: core::ffi::c_ulong = 0x5413;
        #[cfg(not(target_os = "linux"))]
        const TIOCGWINSZ: core::ffi::c_ulong = 0x40087468;

        for fd in [1, 0, 2] {
            let mut ws = Winsize {
                ws_row: 0,
                ws_col: 0,
                ws_xpixel: 0,
                ws_ypixel: 0,
            };
            let rc = unsafe { ioctl(fd, TIOCGWINSZ, &mut ws as *mut Winsize) };
            if rc == 0 && ws.ws_col > 0 && ws.ws_row > 0 {
                return Some((ws.ws_col, ws.ws_row));
            }
        }
    }
    #[cfg(windows)]
    {
        use core::ffi::c_void;
        #[repr(C)]
        struct Coord {
            x: i16,
            y: i16,
        }
        #[repr(C)]
        struct SmallRect {
            left: i16,
            top: i16,
            right: i16,
            bottom: i16,
        }
        #[repr(C)]
        struct ConsoleScreenBufferInfo {
            dw_size: Coord,
            dw_cursor_position: Coord,
            w_attributes: u16,
            sr_window: SmallRect,
            dw_maximum_window_size: Coord,
        }
        extern "system" {
            fn GetStdHandle(which: u32) -> *mut c_void;
            fn GetConsoleScreenBufferInfo(
                handle: *mut c_void,
                info: *mut ConsoleScreenBufferInfo,
            ) -> i32;
        }
        unsafe {
            let h = GetStdHandle(0xFFFF_FFF5u32);
            if !h.is_null() && h as isize != -1 {
                let mut info = core::mem::zeroed::<ConsoleScreenBufferInfo>();
                if GetConsoleScreenBufferInfo(h, &mut info) != 0 {
                    let cols = (info.sr_window.right - info.sr_window.left + 1) as u16;
                    let rows = (info.sr_window.bottom - info.sr_window.top + 1) as u16;
                    if cols > 0 && rows > 0 {
                        return Some((cols, rows));
                    }
                }
            }
        }
    }
    let cols = env_var_any(&["COLUMNS"]).and_then(|v| v.parse::<u16>().ok());
    let rows = env_var_any(&["LINES"]).and_then(|v| v.parse::<u16>().ok());
    match (cols, rows) {
        (Some(c), Some(r)) if c > 0 && r > 0 => Some((c, r)),
        _ => None,
    }
}

pub fn home_dir() -> Option<PathBuf> {
    #[cfg(windows)]
    {
        if let (Some(drive), Some(path)) = (env_var("HOMEDRIVE"), env_var("HOMEPATH")) {
            let joined = PathBuf::from(drive).join(path.trim_start_matches(['\\', '/']));
            return Some(joined);
        }
    }
    for k in ["HOME", "USERPROFILE"] {
        if let Some(v) = env_var(k) {
            let p = PathBuf::from(v);
            if p.is_absolute() || cfg!(windows) {
                return Some(p);
            }
        }
    }
    None
}

pub fn config_dir() -> PathBuf {
    if let Some(v) = env_var("EMERAG_CONFIG_DIR") {
        return PathBuf::from(v);
    }
    if cfg!(windows) {
        if let Some(appdata) = env_var("APPDATA") {
            return PathBuf::from(appdata).join("emerag");
        }
        if let Some(home) = home_dir() {
            return home.join(".emerag");
        }
    } else {
        if let Some(xdg) = env_var("XDG_CONFIG_HOME") {
            return PathBuf::from(xdg).join("emerag");
        }
        if let Some(home) = home_dir() {
            return home.join(".config").join("emerag");
        }
    }
    PathBuf::from(".emerag")
}

pub fn data_dir() -> PathBuf {
    if let Some(v) = env_var("EMERAG_DATA_DIR") {
        return PathBuf::from(v);
    }
    if cfg!(windows) {
        if let Some(appdata) = env_var("APPDATA") {
            return PathBuf::from(appdata).join("emerag");
        }
    } else {
        if let Some(xdg) = env_var("XDG_DATA_HOME") {
            return PathBuf::from(xdg).join("emerag");
        }
        if let Some(home) = home_dir() {
            return home.join(".local").join("share").join("emerag");
        }
    }
    config_dir()
}

pub fn cache_dir() -> PathBuf {
    if let Some(v) = env_var("EMERAG_CACHE_DIR") {
        return PathBuf::from(v);
    }
    if cfg!(windows) {
        if let Some(local) = env_var("LOCALAPPDATA") {
            return PathBuf::from(local).join("emerag").join("cache");
        }
    } else if let Some(home) = home_dir() {
        return home.join(".cache").join("emerag");
    }
    data_dir().join("cache")
}

pub fn temp_dir() -> PathBuf {
    std::env::temp_dir()
}

pub fn current_dir() -> PathBuf {
    std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
}

pub fn exe_path() -> Result<PathBuf> {
    std::env::current_exe().map_err(|e| crate::err!("cannot determine executable path: {e}"))
}

/// Look up an executable on PATH (honouring PATHEXT on Windows).
pub fn which(name: &str) -> Option<PathBuf> {
    let candidate = Path::new(name);
    if candidate.components().count() > 1 || candidate.is_absolute() {
        return if candidate.exists() {
            Some(candidate.to_path_buf())
        } else {
            None
        };
    }
    let path = env_var("PATH").or_else(|| env_var("Path"))?;
    let sep = if cfg!(windows) { ';' } else { ':' };
    let exts: Vec<String> = if cfg!(windows) {
        env_var("PATHEXT")
            .unwrap_or_else(|| ".COM;.EXE;.BAT;.CMD".to_string())
            .split(';')
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .collect()
    } else {
        vec![String::new()]
    };
    for dir in path.split(sep) {
        if dir.is_empty() {
            continue;
        }
        let dir = Path::new(dir);
        for ext in &exts {
            let mut file = dir.join(name);
            if !ext.is_empty() {
                if name
                    .to_ascii_lowercase()
                    .ends_with(&ext.to_ascii_lowercase())
                {
                    file = dir.join(name);
                } else {
                    file = dir.join(format!("{name}{ext}"));
                }
            }
            if file.is_file() {
                return Some(file);
            }
        }
    }
    None
}

#[cfg(unix)]
pub fn hostname() -> String {
    extern "C" {
        fn gethostname(buf: *mut u8, len: usize) -> i32;
    }
    let mut buf = [0u8; 256];
    let rc = unsafe { gethostname(buf.as_mut_ptr(), buf.len()) };
    if rc == 0 {
        let bytes: Vec<u8> = buf.iter().take_while(|c| **c != 0).copied().collect();
        if let Ok(s) = String::from_utf8(bytes) {
            if !s.is_empty() {
                return s;
            }
        }
    }
    "localhost".to_string()
}

#[cfg(windows)]
pub fn hostname() -> String {
    use core::ffi::c_void;
    extern "system" {
        fn GetComputerNameW(buf: *mut u16, len: *mut u32) -> i32;
        fn CloseHandle(h: *mut c_void) -> i32;
    }
    let _ = CloseHandle;
    let mut buf = [0u16; 256];
    let mut len = buf.len() as u32;
    let rc = unsafe { GetComputerNameW(buf.as_mut_ptr(), &mut len) };
    if rc != 0 {
        return String::from_utf16_lossy(&buf[..len as usize]);
    }
    env_var("COMPUTERNAME").unwrap_or_else(|| "localhost".to_string())
}

#[cfg(not(any(unix, windows)))]
pub fn hostname() -> String {
    "localhost".to_string()
}

pub fn username() -> String {
    env_var_any(&["USER", "USERNAME", "LOGNAME"]).unwrap_or_else(|| "user".to_string())
}

pub fn shell_quote(s: &str) -> String {
    if s.is_empty() {
        return "''".to_string();
    }
    if s.chars()
        .all(|c| c.is_ascii_alphanumeric() || "._-/:=@%+,".contains(c))
    {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len() + 2);
    out.push('\'');
    for ch in s.chars() {
        if ch == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(ch);
        }
    }
    out.push('\'');
    out
}

pub fn shell_quote_win(s: &str) -> String {
    if s.is_empty() {
        return "\"\"".to_string();
    }
    if s.chars()
        .all(|c| c.is_ascii_alphanumeric() || "._-/:=@%+,\\".contains(c))
    {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for ch in s.chars() {
        if ch == '"' {
            out.push_str("\\\"");
        } else {
            out.push(ch);
        }
    }
    out.push('"');
    out
}

pub fn expand_tilde(input: &str) -> PathBuf {
    if input == "~" {
        if let Some(h) = home_dir() {
            return h;
        }
    } else if let Some(rest) = input
        .strip_prefix("~/")
        .or_else(|| input.strip_prefix("~\\"))
    {
        if let Some(h) = home_dir() {
            return h.join(rest);
        }
    }
    PathBuf::from(input)
}

/// Absolute path without following symlinks where possible.
pub fn absolutize(path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        current_dir().join(path)
    }
}

pub fn file_exists(path: &Path) -> bool {
    path.is_file()
}

pub fn dir_exists(path: &Path) -> bool {
    path.is_dir()
}

pub fn ensure_readable(path: &Path) -> Result<()> {
    match std::fs::metadata(path) {
        Ok(_) => Ok(()),
        Err(e) => bail!("cannot access {}: {e}", path.display()),
    }
}

/// Bytes available in the unprivileged home dir (a rough proxy for disk space).
pub fn free_space_hint() -> Option<u64> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quoting_roundtrips_shell_safe() {
        assert_eq!(shell_quote("abc"), "abc");
        assert_eq!(shell_quote("a b"), "'a b'");
        assert_eq!(shell_quote("it's"), "'it'\\''s'");
    }

    #[test]
    fn tilde_expands() {
        let home = home_dir().unwrap();
        assert_eq!(expand_tilde("~"), home);
        assert_eq!(expand_tilde("~/x"), home.join("x"));
        assert_eq!(expand_tilde("/abs"), PathBuf::from("/abs"));
    }

    #[test]
    fn which_finds_known_tools() {
        #[cfg(unix)]
        {
            assert!(which("sh").is_some());
            assert!(which("definitely-not-a-real-binary-xyz").is_none());
        }
    }

    #[test]
    fn config_dir_is_absolute() {
        assert!(config_dir().is_absolute() || cfg!(windows));
    }
}
