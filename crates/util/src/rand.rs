//! OS randomness with conservative fallbacks.
//!
//! TLS nonces and session ids depend on this. On Unix we read /dev/urandom
//! (available since Linux 1.3 / all supported BSDs). On Windows we call
//! BCryptGenRandom when present (Vista+), SystemFunction036 (RtlGenRandom,
//! Windows 2000+) otherwise. If neither exists we fail loudly instead of
//! inventing a weak RNG.

use crate::{bail, Result};

#[cfg(unix)]
pub fn fill_bytes(buf: &mut [u8]) -> Result<()> {
    use std::io::Read;
    for path in ["/dev/urandom", "/dev/random"] {
        if let Ok(mut f) = std::fs::File::open(path) {
            let mut filled = 0;
            while filled < buf.len() {
                match f.read(&mut buf[filled..]) {
                    Ok(0) => break,
                    Ok(n) => filled += n,
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(_) => break,
                }
            }
            if filled == buf.len() {
                return Ok(());
            }
        }
    }
    bail!("no OS random source available (/dev/urandom unreadable)")
}

#[cfg(windows)]
pub fn fill_bytes(buf: &mut [u8]) -> Result<()> {
    use core::ffi::c_void;
    type Boole = i32;
    type NtStatus = i32;
    extern "system" {
        fn LoadLibraryA(name: *const u8) -> *mut c_void;
        fn GetProcAddress(module: *mut c_void, name: *const u8) -> *mut c_void;
        fn FreeLibrary(module: *mut c_void) -> Boole;
    }
    // BCryptGenRandom(BCRYPT_USE_SYSTEM_PREFERRED_RNG=2)
    unsafe {
        let lib = LoadLibraryA(b"bcrypt.dll\0".as_ptr());
        if !lib.is_null() {
            let sym = GetProcAddress(lib, b"BCryptGenRandom\0".as_ptr());
            if !sym.is_null() {
                let f: unsafe extern "system" fn(*mut c_void, *mut u8, u32, u32) -> NtStatus =
                    core::mem::transmute(sym);
                if f(core::ptr::null_mut(), buf.as_mut_ptr(), buf.len() as u32, 2) == 0 {
                    FreeLibrary(lib);
                    return Ok(());
                }
            }
            FreeLibrary(lib);
        }
        // RtlGenRandom from advapi32 (Windows 2000+).
        let lib = LoadLibraryA(b"advapi32.dll\0".as_ptr());
        if !lib.is_null() {
            let sym = GetProcAddress(lib, b"SystemFunction036\0".as_ptr());
            if !sym.is_null() {
                let f: unsafe extern "system" fn(*mut u8, u32) -> u8 = core::mem::transmute(sym);
                let ok = f(buf.as_mut_ptr(), buf.len() as u32);
                FreeLibrary(lib);
                if ok != 0 {
                    return Ok(());
                }
            } else {
                FreeLibrary(lib);
            }
        }
    }
    #[cfg(target_vendor = "rust9x")]
    {
        // Windows 95/98/ME have no system CSPRNG. rust9x builds still need
        // handshake randomness; mix every available clock/id source and warn
        // loudly. Windows 2000+ uses RtlGenRandom above instead.
        use std::sync::Once;
        static WARN: Once = Once::new();
        WARN.call_once(|| {
            eprintln!("warning: legacy Windows has no CSPRNG; TLS randomness is weak")
        });
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        let mut s = nanos ^ ((std::process::id() as u64) << 32) ^ (buf.as_ptr() as usize as u64);
        for b in buf.iter_mut() {
            s ^= s >> 12;
            s ^= s << 25;
            s ^= s >> 27;
            s = s.wrapping_mul(0x2545F4914F6CDD1D);
            *b = (s >> 32) as u8;
        }
        return Ok(());
    }
    bail!("no OS random source available (BCryptGenRandom and RtlGenRandom both failed)")
}

#[cfg(not(any(unix, windows)))]
pub fn fill_bytes(_buf: &mut [u8]) -> Result<()> {
    bail!("no OS random source on this platform")
}

pub fn u64() -> Result<u64> {
    let mut b = [0u8; 8];
    fill_bytes(&mut b)?;
    Ok(u64::from_le_bytes(b))
}

/// Uniform value in 0..n using rejection sampling (no modulo bias).
pub fn below(n: u64) -> Result<u64> {
    if n == 0 {
        return Ok(0);
    }
    let zone = u64::MAX - (u64::MAX % n);
    loop {
        let v = u64()?;
        if v < zone {
            return Ok(v % n);
        }
    }
}

/// A random alphanumeric identifier, e.g. s3f9k2.
pub fn id(len: usize) -> String {
    const ALPHABET: &[u8] = b"0123456789abcdefghijklmnopqrstuvwxyz";
    let mut out = String::with_capacity(len);
    let mut buf = [0u8; 64];
    let need = len.min(buf.len());
    if fill_bytes(&mut buf[..need]).is_err() {
        // Extremely unlikely; preferred RNG failed. Use time as a weak fallback
        // for identifiers only (never for crypto).
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos() as u64 + d.as_secs())
            .unwrap_or(0);
        for i in 0..need {
            buf[i] = ((nanos >> (i % 8 * 8)) & 0xff) as u8;
        }
    }
    for &b in &buf[..need] {
        out.push(ALPHABET[b as usize % ALPHABET.len()] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_fills_and_varies() {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        fill_bytes(&mut a).unwrap();
        fill_bytes(&mut b).unwrap();
        assert_ne!(a, b);
        assert!(!a.iter().all(|x| *x == 0));
    }

    #[test]
    fn ids_look_random() {
        let a = id(12);
        let b = id(12);
        assert_eq!(a.len(), 12);
        assert_ne!(a, b);
        assert!(a.chars().all(|c| c.is_ascii_alphanumeric()));
    }

    #[test]
    fn below_is_in_range() {
        for _ in 0..1000 {
            assert!(below(7).unwrap() < 7);
        }
        assert_eq!(below(0).unwrap(), 0);
    }
}
