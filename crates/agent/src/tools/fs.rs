//! Filesystem tools: read, write, edit, list, glob, grep.
//!
//! All paths are resolved against the session cwd, support ~ expansion, and
//! every read is size-limited so a stray /dev/zero or a 10 GB log cannot take
//! down the agent.

use crate::error::{AgentError, Result};
use emerag_util::fsutil;
use std::path::{Path, PathBuf};

pub const MAX_READ_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_WRITE_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_GREP_FILE_BYTES: u64 = 4 * 1024 * 1024;

pub fn resolve(cwd: &Path, raw: &str) -> PathBuf {
    let raw = raw.trim();
    if raw.is_empty() {
        return cwd.to_path_buf();
    }
    let expanded = emerag_util::sys::expand_tilde(raw);
    if expanded.is_absolute() {
        expanded
    } else {
        cwd.join(expanded)
    }
}

pub fn display(cwd: &Path, path: &Path) -> String {
    match path.strip_prefix(cwd) {
        Ok(rel) if !rel.as_os_str().is_empty() => rel.to_string_lossy().to_string(),
        _ => path.to_string_lossy().to_string(),
    }
}

/// Read a file with line numbers. offset is 1-based.
pub fn read_file(cwd: &Path, path: &str, offset: usize, limit: usize) -> Result<String> {
    let p = resolve(cwd, path);
    if p.is_dir() {
        return Err(AgentError::new(format!(
            "{} is a directory (use list_dir)",
            p.display()
        )));
    }
    let text = fsutil::read_text(&p, MAX_READ_BYTES)?;
    if fsutil::looks_binary(text.as_bytes()) {
        return Err(AgentError::new(format!(
            "{} looks binary ({} bytes); refusing to dump it",
            p.display(),
            text.len()
        )));
    }
    let lines: Vec<&str> = text.lines().collect();
    let total = lines.len();
    let offset = offset.max(1);
    if offset > total && total > 0 {
        return Err(AgentError::new(format!(
            "offset {offset} is past the end ({} lines)",
            total
        )));
    }
    let limit = limit.clamp(1, 2000);
    let end = (offset - 1 + limit).min(total);
    let mut out = String::new();
    for (i, line) in lines.iter().enumerate().take(end).skip(offset - 1) {
        out.push_str(&format!("{:>5}  {}\n", i + 1, line));
    }
    if out.is_empty() && total == 0 {
        out.push_str("(empty file)\n");
    }
    let shown = end.saturating_sub(offset - 1);
    out.push_str(&format!(
        "[{} lines shown of {}; {} bytes]",
        shown,
        total,
        text.len()
    ));
    Ok(out)
}

/// Write content, creating parent directories. Returns a summary.
pub fn write_file(cwd: &Path, path: &str, content: &str) -> Result<String> {
    if content.len() > MAX_WRITE_BYTES {
        return Err(AgentError::new(format!(
            "refusing to write {} bytes (limit {})",
            content.len(),
            MAX_WRITE_BYTES
        )));
    }
    let p = resolve(cwd, path);
    if p.is_dir() {
        return Err(AgentError::new(format!("{} is a directory", p.display())));
    }
    let existed = p.exists();
    let old = if existed {
        std::fs::read(&p).unwrap_or_default()
    } else {
        Vec::new()
    };
    if old == content.as_bytes() {
        return Ok(format!(
            "{} unchanged ({} bytes)",
            display(cwd, &p),
            content.len()
        ));
    }
    fsutil::write_text_atomic(&p, content)?;
    if !existed {
        Ok(format!(
            "created {} ({} bytes)",
            display(cwd, &p),
            content.len()
        ))
    } else {
        Ok(format!(
            "updated {} ({} -> {} bytes)",
            display(cwd, &p),
            old.len(),
            content.len()
        ))
    }
}

/// Exact-string replacement. Returns a summary with replacement count.
pub fn edit_file(
    cwd: &Path,
    path: &str,
    old: &str,
    new: &str,
    replace_all: bool,
) -> Result<String> {
    if old.is_empty() {
        return Err(AgentError::new("old_string must not be empty"));
    }
    let p = resolve(cwd, path);
    let text = fsutil::read_text(&p, MAX_READ_BYTES)?;
    let count = text.matches(old).count();
    if count == 0 {
        return Err(AgentError::new(format!(
            "old_string not found in {} ({} bytes). Read the file and copy the exact text.",
            display(cwd, &p),
            text.len()
        )));
    }
    if count > 1 && !replace_all {
        return Err(AgentError::new(format!(
            "old_string appears {count} times in {}; include more context or set replace_all",
            display(cwd, &p)
        )));
    }
    let updated = if replace_all {
        text.replace(old, new)
    } else {
        text.replacen(old, new, 1)
    };
    fsutil::write_text_atomic(&p, &updated)?;
    Ok(format!(
        "edited {} ({} replacement{}, {} -> {} bytes)",
        display(cwd, &p),
        if replace_all { count } else { 1 },
        if replace_all && count > 1 { "s" } else { "" },
        text.len(),
        updated.len()
    ))
}

/// Directory tree with bounded depth and entry count.
pub fn list_dir(cwd: &Path, path: &str, depth: usize) -> Result<String> {
    let root = resolve(cwd, path);
    if !root.is_dir() {
        return Err(AgentError::new(format!(
            "not a directory: {}",
            root.display()
        )));
    }
    let depth = depth.clamp(1, 6);
    let mut out = String::new();
    out.push_str(&format!("{}\n", display(cwd, &root)));
    let mut count = 0usize;
    walk_tree(&root, "", depth, &mut out, &mut count, cwd);
    if count >= 500 {
        out.push_str("... (listing truncated at 500 entries)\n");
    }
    Ok(out)
}

fn walk_tree(
    dir: &Path,
    prefix: &str,
    depth: usize,
    out: &mut String,
    count: &mut usize,
    cwd: &Path,
) {
    if depth == 0 || *count >= 500 {
        return;
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let mut items: Vec<_> = entries.flatten().collect();
    items.sort_by_key(|e| e.file_name());
    items.retain(|e| !is_noise(&e.file_name().to_string_lossy()));
    let n = items.len();
    for (i, entry) in items.iter().enumerate() {
        if *count >= 500 {
            return;
        }
        *count += 1;
        let last = i + 1 == n;
        let branch = if last { "└── " } else { "├── " };
        let name = entry.file_name().to_string_lossy().to_string();
        let is_dir = entry.file_type().map(|t| t.is_dir()).unwrap_or(false);
        let mut meta = String::new();
        if !is_dir {
            if let Ok(m) = entry.metadata() {
                meta = format!(" ({})", emerag_util::human_bytes(m.len()));
            }
        }
        out.push_str(&format!(
            "{prefix}{branch}{name}{}{meta}\n",
            if is_dir { "/" } else { "" }
        ));
        if is_dir {
            let child_prefix = format!("{prefix}{}", if last { "    " } else { "│   " });
            walk_tree(&entry.path(), &child_prefix, depth - 1, out, count, cwd);
        }
    }
}

fn is_noise(name: &str) -> bool {
    matches!(
        name,
        ".git" | ".hg" | ".svn" | "node_modules" | "__pycache__" | ".cache"
    )
}

/// Glob for files under a root.
pub fn glob(cwd: &Path, pattern: &str, root: Option<&str>, limit: usize) -> Result<String> {
    let base = root
        .map(|r| resolve(cwd, r))
        .unwrap_or_else(|| cwd.to_path_buf());
    if !base.is_dir() {
        return Err(AgentError::new(format!(
            "not a directory: {}",
            base.display()
        )));
    }
    let files = emerag_util::glob::find_files(&base, pattern, limit.clamp(1, 1000))?;
    if files.is_empty() {
        return Ok(format!(
            "no files matched {pattern} under {}",
            display(cwd, &base)
        ));
    }
    let mut out = String::new();
    for f in &files {
        out.push_str(&display(cwd, f));
        out.push('\n');
    }
    out.push_str(&format!("[{} files]", files.len()));
    Ok(out)
}

/// Literal substring grep with optional include filter.
pub fn grep(
    cwd: &Path,
    pattern: &str,
    root: Option<&str>,
    include: Option<&str>,
    ignore_case: bool,
    max_results: usize,
) -> Result<String> {
    if pattern.is_empty() {
        return Err(AgentError::new("empty search pattern"));
    }
    let base = root
        .map(|r| resolve(cwd, r))
        .unwrap_or_else(|| cwd.to_path_buf());
    let needle = if ignore_case {
        pattern.to_lowercase()
    } else {
        pattern.to_string()
    };
    let max_results = max_results.clamp(1, 500);
    let mut results: Vec<String> = Vec::new();
    let mut scanned = 0usize;
    let mut skipped_binary = 0usize;
    let opts = emerag_util::glob::WalkOptions {
        include_hidden: false,
        max_entries: 50_000,
        ..Default::default()
    };
    let include_pattern = include.map(|s| s.to_string());
    emerag_util::glob::walk(&base, &opts, |path, is_dir| {
        if is_dir {
            return true;
        }
        if results.len() >= max_results {
            return false;
        }
        if let Some(inc) = &include_pattern {
            let name = path
                .file_name()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_default();
            let rel = path
                .strip_prefix(&base)
                .unwrap_or(path)
                .to_string_lossy()
                .to_string();
            if !emerag_util::glob::matches(inc, &name) && !emerag_util::glob::matches(inc, &rel) {
                return true;
            }
        }
        if let Ok(meta) = std::fs::metadata(path) {
            if meta.len() > MAX_GREP_FILE_BYTES {
                return true;
            }
        }
        let Ok(bytes) = std::fs::read(path) else {
            return true;
        };
        if fsutil::looks_binary(&bytes) {
            skipped_binary += 1;
            return true;
        }
        scanned += 1;
        let text = String::from_utf8_lossy(&bytes);
        for (i, line) in text.lines().enumerate() {
            let hit = if ignore_case {
                line.to_lowercase().contains(&needle)
            } else {
                line.contains(&needle)
            };
            if hit {
                results.push(format!(
                    "{}:{}: {}",
                    display(cwd, path),
                    i + 1,
                    line.trim_end()
                ));
                if results.len() >= max_results {
                    break;
                }
            }
        }
        true
    })?;
    if results.is_empty() {
        return Ok(format!(
            "no matches for {pattern:?} in {} files ({} binary skipped)",
            scanned, skipped_binary
        ));
    }
    let mut out = results.join("\n");
    out.push_str(&format!(
        "\n[{} matches in {} files]",
        results.len(),
        scanned
    ));
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp() -> PathBuf {
        let d = std::env::temp_dir().join(format!("emerag-fs-{}", emerag_util::rand::id(8)));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn read_write_edit_roundtrip() {
        let d = tmp();
        let msg = write_file(&d, "sub/a.txt", "one\ntwo\nthree\n").unwrap();
        assert!(msg.contains("created"));
        let text = read_file(&d, "sub/a.txt", 2, 2).unwrap();
        assert!(text.contains("2  two"));
        assert!(text.contains("3  three"));
        assert!(!text.contains("1  one"));
        edit_file(&d, "sub/a.txt", "two", "TWO", false).unwrap();
        let text = read_file(&d, "sub/a.txt", 1, 10).unwrap();
        assert!(text.contains("TWO"));
        std::fs::remove_dir_all(d).ok();
    }

    #[test]
    fn edit_requires_uniqueness() {
        let d = tmp();
        write_file(&d, "a", "x x").unwrap();
        assert!(edit_file(&d, "a", "x", "y", false).is_err());
        edit_file(&d, "a", "x", "y", true).unwrap();
        assert_eq!(std::fs::read_to_string(d.join("a")).unwrap(), "y y");
        std::fs::remove_dir_all(d).ok();
    }

    #[test]
    fn glob_and_grep() {
        let d = tmp();
        write_file(&d, "src/main.rs", "fn main() { println!(\"hi\"); }").unwrap();
        write_file(&d, "src/lib.rs", "pub fn helper() {}").unwrap();
        write_file(&d, "README.md", "main docs").unwrap();
        let g = glob(&d, "**/*.rs", None, 10).unwrap();
        assert!(g.contains("src/main.rs"));
        let r = grep(&d, "main", None, Some("*.rs"), false, 10).unwrap();
        assert!(r.contains("src/main.rs:1"));
        assert!(!r.contains("README"));
        std::fs::remove_dir_all(d).ok();
    }

    #[test]
    fn list_tree_shows_children() {
        let d = tmp();
        write_file(&d, "a/b.txt", "x").unwrap();
        let out = list_dir(&d, ".", 2).unwrap();
        assert!(out.contains("a/"));
        assert!(out.contains("b.txt"));
        std::fs::remove_dir_all(d).ok();
    }
}
