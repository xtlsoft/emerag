//! Filesystem helpers with conservative limits (agents must never OOM the
//! emergency box by reading a huge file).

use crate::{bail, Result};
use std::io::Write;
use std::path::{Path, PathBuf};

/// Read a text file as lossy UTF-8, refusing files above max_bytes.
pub fn read_text(path: &Path, max_bytes: usize) -> Result<String> {
    let meta =
        std::fs::metadata(path).map_err(|e| crate::err!("cannot stat {}: {e}", path.display()))?;
    if !meta.is_file() {
        bail!("not a regular file: {}", path.display());
    }
    if meta.len() as usize > max_bytes {
        bail!(
            "file too large: {} ({} bytes, limit {} bytes)",
            path.display(),
            meta.len(),
            max_bytes
        );
    }
    let bytes =
        std::fs::read(path).map_err(|e| crate::err!("cannot read {}: {e}", path.display()))?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

/// Read raw bytes with a size limit.
pub fn read_bytes(path: &Path, max_bytes: usize) -> Result<Vec<u8>> {
    let meta =
        std::fs::metadata(path).map_err(|e| crate::err!("cannot stat {}: {e}", path.display()))?;
    if !meta.is_file() {
        bail!("not a regular file: {}", path.display());
    }
    if meta.len() as usize > max_bytes {
        bail!("file too large: {} bytes", meta.len());
    }
    std::fs::read(path).map_err(|e| crate::err!("cannot read {}: {e}", path.display()))
}

/// Write bytes atomically: write to a sibling temp file then rename.
pub fn write_bytes_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    if !parent.exists() {
        std::fs::create_dir_all(parent)
            .map_err(|e| crate::err!("cannot create {}: {e}", parent.display()))?;
    }
    let tmp = parent.join(format!(
        ".{}.tmp-{}",
        path.file_name()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| "file".into()),
        crate::rand::id(6)
    ));
    {
        let mut f = std::fs::File::create(&tmp)
            .map_err(|e| crate::err!("cannot create {}: {e}", tmp.display()))?;
        f.write_all(bytes)
            .map_err(|e| crate::err!("cannot write {}: {e}", tmp.display()))?;
        f.sync_data().ok();
    }
    match std::fs::rename(&tmp, path) {
        Ok(()) => Ok(()),
        Err(rename_err) => {
            // Windows cannot rename over an existing file in all cases.
            let _ = std::fs::remove_file(path);
            std::fs::rename(&tmp, path).map_err(|_| {
                let _ = std::fs::remove_file(&tmp);
                crate::err!("cannot replace {}: {rename_err}", path.display())
            })
        }
    }
}

pub fn write_text_atomic(path: &Path, text: &str) -> Result<()> {
    write_bytes_atomic(path, text.as_bytes())
}

pub fn append_line(path: &Path, line: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() && !parent.exists() {
            std::fs::create_dir_all(parent)
                .map_err(|e| crate::err!("cannot create {}: {e}", parent.display()))?;
        }
    }
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| crate::err!("cannot open {}: {e}", path.display()))?;
    f.write_all(line.as_bytes())
        .map_err(|e| crate::err!("cannot append {}: {e}", path.display()))?;
    f.write_all(b"\n")
        .map_err(|e| crate::err!("cannot append {}: {e}", path.display()))?;
    Ok(())
}

pub fn ensure_dir(path: &Path) -> Result<()> {
    if path.as_os_str().is_empty() {
        return Ok(());
    }
    std::fs::create_dir_all(path)
        .map_err(|e| crate::err!("cannot create dir {}: {e}", path.display()))
}

/// Heuristic binary detection (NUL byte in the first 8 KiB).
pub fn looks_binary(bytes: &[u8]) -> bool {
    bytes.iter().take(8192).any(|b| *b == 0)
}

/// Canonicalize, falling back to an absolutized path when the file is missing.
pub fn canonicalize_lossy(path: &Path) -> PathBuf {
    match std::fs::canonicalize(path) {
        Ok(p) => p,
        Err(_) => crate::sys::absolutize(path),
    }
}

pub fn file_size(path: &Path) -> Option<u64> {
    std::fs::metadata(path).ok().map(|m| m.len())
}

pub fn remove_file_if_exists(path: &Path) -> Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(crate::err!("cannot remove {}: {e}", path.display())),
    }
}

/// List directory entries sorted by name (files and dirs).
pub fn list_dir(path: &Path) -> Result<Vec<(PathBuf, bool)>> {
    let mut out = Vec::new();
    let entries =
        std::fs::read_dir(path).map_err(|e| crate::err!("cannot list {}: {e}", path.display()))?;
    for entry in entries.flatten() {
        let p = entry.path();
        let is_dir = entry.file_type().map(|t| t.is_dir()).unwrap_or(false);
        out.push((p, is_dir));
    }
    out.sort_by(|a, b| a.0.file_name().cmp(&b.0.file_name()));
    Ok(out)
}

/// Replace the home directory prefix with ~ for compact display.
pub fn display_path(path: &Path) -> String {
    if let Some(home) = crate::sys::home_dir() {
        if let Ok(rest) = path.strip_prefix(&home) {
            let s = rest.to_string_lossy();
            if s.is_empty() {
                return "~".to_string();
            }
            return format!("~/{}", s.trim_start_matches(['/', '\\']));
        }
    }
    path.to_string_lossy().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn atomic_write_and_read() {
        let dir = std::env::temp_dir().join(format!("emerag-fs-test-{}", crate::rand::id(8)));
        ensure_dir(&dir).unwrap();
        let p = dir.join("a.txt");
        write_text_atomic(&p, "hello").unwrap();
        assert_eq!(read_text(&p, 100).unwrap(), "hello");
        write_text_atomic(&p, "bye").unwrap();
        assert_eq!(read_text(&p, 100).unwrap(), "bye");
        assert!(read_text(&p, 1).is_err());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn binary_detection() {
        assert!(looks_binary(b"abc\0def"));
        assert!(!looks_binary(b"plain text"));
    }
}
