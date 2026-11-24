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

/// Read a text file that must be valid UTF-8. Use this before writing the
/// text back: [read_text] replaces invalid bytes with U+FFFD, and saving that
/// would silently corrupt a Latin-1 or binary-ish file.
pub fn read_text_strict(path: &Path, max_bytes: usize) -> Result<String> {
    let bytes = read_bytes(path, max_bytes)?;
    String::from_utf8(bytes).map_err(|e| {
        crate::err!(
            "{} is not valid UTF-8 (first bad byte at offset {}); editing it as text would corrupt it",
            path.display(),
            e.utf8_error().valid_up_to()
        )
    })
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
///
/// An existing file keeps its permission bits (and, best effort, its owner);
/// a symlink is followed so the link stays a link and its target is updated.
/// A new file gets the usual umask-derived mode.
pub fn write_bytes_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    write_atomic_impl(path, bytes, false)
}

/// Like [write_bytes_atomic], but a newly created file is readable by the
/// owner only (0600 on Unix) from the first byte: for files holding API
/// keys or conversations. The temp file is never world-readable.
pub fn write_private_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    write_atomic_impl(path, bytes, true)
}

fn write_atomic_impl(path: &Path, bytes: &[u8], private: bool) -> Result<()> {
    // Follow symlinks: renaming over the link would replace it with a regular
    // file and leave the real target untouched. A dangling link is replaced.
    let resolved;
    let path = match std::fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_symlink() => match std::fs::canonicalize(path) {
            Ok(target) => {
                resolved = target;
                resolved.as_path()
            }
            Err(_) => path,
        },
        _ => path,
    };
    let existing = std::fs::metadata(path).ok().filter(|m| m.is_file());
    #[cfg(unix)]
    if let Some(meta) = &existing {
        use std::os::unix::fs::MetadataExt;
        if meta.nlink() > 1 {
            // Renaming a new file into place would detach this name from the
            // other hard links, which would keep the old contents. Rewrite
            // the shared inode in place instead: not atomic, but every link
            // sees the new contents, and mode and owner are untouched.
            return write_in_place(path, bytes);
        }
    }
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let parent = if parent.as_os_str().is_empty() {
        Path::new(".")
    } else {
        parent
    };
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
    #[cfg(not(unix))]
    let _ = (&existing, private);
    let written = (|| -> Result<()> {
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            // Start owner-only whenever the result should not be (or might
            // not be) world-readable; widen afterwards if the old file was.
            if private || existing.is_some() {
                opts.mode(0o600);
            }
        }
        let mut f = opts
            .open(&tmp)
            .map_err(|e| crate::err!("cannot create {}: {e}", tmp.display()))?;
        f.write_all(bytes)
            .map_err(|e| crate::err!("cannot write {}: {e}", tmp.display()))?;
        #[cfg(unix)]
        if let Some(meta) = &existing {
            use std::os::unix::fs::MetadataExt;
            // Best effort: keep the owner when running as root.
            let _ = std::os::unix::fs::fchown(&f, Some(meta.uid()), Some(meta.gid()));
            f.set_permissions(meta.permissions())
                .map_err(|e| crate::err!("cannot set permissions on {}: {e}", tmp.display()))?;
        }
        f.sync_data().ok();
        Ok(())
    })();
    if let Err(e) = written {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
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

/// Truncate and rewrite an existing file through its own inode.
#[cfg(unix)]
fn write_in_place(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(path)
        .map_err(|e| crate::err!("cannot open {}: {e}", path.display()))?;
    f.write_all(bytes)
        .map_err(|e| crate::err!("cannot write {}: {e}", path.display()))?;
    f.sync_data().ok();
    Ok(())
}

pub fn write_text_atomic(path: &Path, text: &str) -> Result<()> {
    write_bytes_atomic(path, text.as_bytes())
}

/// [write_private_atomic] for text.
pub fn write_text_private_atomic(path: &Path, text: &str) -> Result<()> {
    write_private_atomic(path, text.as_bytes())
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

    #[cfg(unix)]
    #[test]
    fn atomic_write_keeps_mode_and_symlinks() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("emerag-fs-test-{}", crate::rand::id(8)));
        ensure_dir(&dir).unwrap();
        let p = dir.join("run.sh");
        write_text_atomic(&p, "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        write_text_atomic(&p, "#!/bin/sh\necho hi\n").unwrap();
        assert_eq!(
            std::fs::metadata(&p).unwrap().permissions().mode() & 0o777,
            0o755
        );

        let link = dir.join("link.sh");
        std::os::unix::fs::symlink(&p, &link).unwrap();
        write_text_atomic(&link, "changed\n").unwrap();
        assert!(std::fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(read_text(&p, 100).unwrap(), "changed\n");

        let secret = dir.join("config.json");
        write_text_private_atomic(&secret, "{}").unwrap();
        assert_eq!(
            std::fs::metadata(&secret).unwrap().permissions().mode() & 0o777,
            0o600
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn strict_read_rejects_invalid_utf8() {
        let dir = std::env::temp_dir().join(format!("emerag-fs-test-{}", crate::rand::id(8)));
        ensure_dir(&dir).unwrap();
        let p = dir.join("latin1.txt");
        std::fs::write(&p, b"caf\xe9").unwrap();
        assert!(read_text_strict(&p, 100).is_err());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn binary_detection() {
        assert!(looks_binary(b"abc\0def"));
        assert!(!looks_binary(b"plain text"));
    }

    #[cfg(unix)]
    #[test]
    fn rewrite_keeps_hard_links() {
        let dir = std::env::temp_dir().join(format!("emerag-hl-{}", crate::rand::id(6)));
        std::fs::create_dir_all(&dir).unwrap();
        let a = dir.join("a.txt");
        let b = dir.join("b.txt");
        std::fs::write(&a, "old").unwrap();
        std::fs::hard_link(&a, &b).unwrap();
        write_text_atomic(&a, "new").unwrap();
        assert_eq!(std::fs::read_to_string(&b).unwrap(), "new");
        std::fs::remove_dir_all(&dir).ok();
    }
}
