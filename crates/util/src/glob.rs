//! Glob matching and directory walking.
//!
//! Supports **, *, ?, [abc], [a-z], [!a] and {a,b} alternation. Matching is
//! path-aware: a single * never crosses a directory separator.

use crate::{bail, Result};
use std::path::{Path, PathBuf};

/// Expand {a,b,c} alternation into multiple patterns (recursive, nested ok).
pub fn expand_braces(pattern: &str) -> Vec<String> {
    let bytes = pattern.as_bytes();
    let mut depth = 0usize;
    let mut start = None;
    let mut i = 0usize;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' => {
                i += 1;
            }
            b'{' => {
                if depth == 0 {
                    start = Some(i);
                }
                depth += 1;
            }
            b'}' => {
                if depth > 0 {
                    depth -= 1;
                    if depth == 0 {
                        let open = start.unwrap();
                        let inner = &pattern[open + 1..i];
                        let mut parts = Vec::new();
                        let mut cur = String::new();
                        let mut inner_depth = 0usize;
                        for ch in inner.chars() {
                            match ch {
                                '{' => {
                                    inner_depth += 1;
                                    cur.push(ch);
                                }
                                '}' => {
                                    inner_depth = inner_depth.saturating_sub(1);
                                    cur.push(ch);
                                }
                                ',' if inner_depth == 0 => {
                                    parts.push(std::mem::take(&mut cur));
                                }
                                c => cur.push(c),
                            }
                        }
                        parts.push(cur);
                        let mut out = Vec::new();
                        for part in parts {
                            let combined =
                                format!("{}{}{}", &pattern[..open], part, &pattern[i + 1..]);
                            out.extend(expand_braces(&combined));
                        }
                        return out;
                    }
                }
            }
            _ => {}
        }
        i += 1;
    }
    vec![pattern.to_string()]
}

fn match_class(class: &[u8], c: u8) -> bool {
    if class.is_empty() {
        return false;
    }
    let (negate, rest) = match class[0] {
        b'!' | b'^' => (true, &class[1..]),
        _ => (false, class),
    };
    let mut matched = false;
    let mut i = 0;
    while i < rest.len() {
        if i + 2 < rest.len() && rest[i + 1] == b'-' && rest[i + 2] != b']' {
            if rest[i] <= c && c <= rest[i + 2] {
                matched = true;
            }
            i += 3;
        } else {
            if rest[i] == c {
                matched = true;
            }
            i += 1;
        }
    }
    matched != negate
}

/// Match a single path segment against a wildcard pattern.
pub fn match_segment(pat: &str, text: &str) -> bool {
    let p = pat.as_bytes();
    let t = text.as_bytes();
    match_seg_rec(p, t)
}

fn match_seg_rec(p: &[u8], t: &[u8]) -> bool {
    if p.is_empty() {
        return t.is_empty();
    }
    match p[0] {
        b'*' => {
            let mut k = 1;
            while k < p.len() && p[k] == b'*' {
                k += 1;
            }
            let rest = &p[k..];
            if rest.is_empty() {
                return true;
            }
            for i in 0..=t.len() {
                if match_seg_rec(rest, &t[i..]) {
                    return true;
                }
            }
            false
        }
        b'?' => !t.is_empty() && match_seg_rec(&p[1..], &t[1..]),
        b'[' => {
            if t.is_empty() {
                return false;
            }
            let mut end = 1;
            while end < p.len() && p[end] != b']' {
                if p[end] == b'\\' {
                    end += 1;
                }
                end += 1;
            }
            if end >= p.len() {
                // Unterminated class: treat '[' literally.
                return t[0] == b'[' && match_seg_rec(&p[1..], &t[1..]);
            }
            let class = &p[1..end];
            if match_class(class, t[0]) {
                match_seg_rec(&p[end + 1..], &t[1..])
            } else {
                false
            }
        }
        b'\\' => {
            if p.len() >= 2 {
                !t.is_empty() && t[0] == p[1] && match_seg_rec(&p[2..], &t[1..])
            } else {
                !t.is_empty() && t[0] == b'\\' && match_seg_rec(&p[1..], &t[1..])
            }
        }
        c => !t.is_empty() && t[0] == c && match_seg_rec(&p[1..], &t[1..]),
    }
}

fn normalize(path: &str) -> String {
    let mut s = path.replace('\\', "/");
    while s.starts_with("./") {
        s = s[2..].to_string();
    }
    s
}

/// Match a full path against a pattern. A pattern without a slash is matched
/// against the basename as well, which is what users expect from "*.rs".
pub fn matches(pattern: &str, path: &str) -> bool {
    let path = normalize(path);
    let pat = normalize(pattern);
    if !pat.contains('/') {
        let base = path.rsplit('/').next().unwrap_or(&path);
        if match_segment(&pat, base) {
            return true;
        }
        // Also allow matching the tail of a path with no slash.
        return path.split('/').any(|part| match_segment(&pat, part));
    }
    let pat_parts: Vec<&str> = pat
        .trim_start_matches('/')
        .split('/')
        .filter(|p| !p.is_empty())
        .collect();
    let path_parts: Vec<&str> = path
        .trim_start_matches('/')
        .split('/')
        .filter(|p| !p.is_empty())
        .collect();
    match_parts(&pat_parts, &path_parts)
}

fn match_parts(pat: &[&str], text: &[&str]) -> bool {
    if pat.is_empty() {
        return text.is_empty();
    }
    if pat[0] == "**" {
        // Zero or more path segments.
        for i in 0..=text.len() {
            if match_parts(&pat[1..], &text[i..]) {
                return true;
            }
        }
        return false;
    }
    if text.is_empty() {
        return false;
    }
    match_segment(pat[0], text[0]) && match_parts(&pat[1..], &text[1..])
}

#[derive(Debug, Clone)]
pub struct WalkOptions {
    pub max_depth: usize,
    pub include_hidden: bool,
    pub follow_links: bool,
    pub skip_dirs: Vec<String>,
    pub max_entries: usize,
}

impl Default for WalkOptions {
    fn default() -> Self {
        WalkOptions {
            max_depth: 32,
            include_hidden: false,
            follow_links: false,
            skip_dirs: vec![
                ".git".into(),
                ".hg".into(),
                ".svn".into(),
                "target".into(),
                "node_modules".into(),
                "__pycache__".into(),
                ".emerag".into(),
                ".cache".into(),
                "dist".into(),
            ],
            max_entries: 200_000,
        }
    }
}

/// Walk a directory tree in deterministic (sorted) order. The callback gets
/// each file; returning false from the directory callback prunes it.
pub fn walk<F>(root: &Path, opts: &WalkOptions, mut f: F) -> Result<()>
where
    F: FnMut(&Path, bool) -> bool,
{
    if !root.exists() {
        bail!("path does not exist: {}", root.display());
    }
    let mut stack: Vec<(PathBuf, usize)> = vec![(root.to_path_buf(), 0)];
    let mut seen = 0usize;
    while let Some((dir, depth)) = stack.pop() {
        let entries = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            Err(_) => continue,
        };
        let mut items: Vec<(PathBuf, bool)> = Vec::new();
        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().to_string();
            if !opts.include_hidden && name.starts_with('.') && depth > 0 {
                continue;
            }
            let meta = match std::fs::symlink_metadata(&path) {
                Ok(m) => m,
                Err(_) => continue,
            };
            let mut is_dir = meta.is_dir();
            if meta.file_type().is_symlink() {
                if opts.follow_links {
                    is_dir = std::fs::metadata(&path)
                        .map(|m| m.is_dir())
                        .unwrap_or(false);
                } else {
                    items.push((path, false));
                    continue;
                }
            }
            items.push((path, is_dir));
        }
        items.sort_by(|a, b| a.0.cmp(&b.0));
        for (path, is_dir) in items {
            seen += 1;
            if seen > opts.max_entries {
                return Ok(());
            }
            if is_dir {
                let name = path
                    .file_name()
                    .map(|s| s.to_string_lossy().to_string())
                    .unwrap_or_default();
                let skip = opts.skip_dirs.iter().any(|s| s == &name);
                if !skip && depth < opts.max_depth && f(&path, true) {
                    stack.push((path, depth + 1));
                }
            } else {
                f(&path, false);
            }
        }
    }
    Ok(())
}

/// Find files under root matching a glob pattern (relative path or filename).
pub fn find_files(root: &Path, pattern: &str, limit: usize) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    if limit == 0 {
        return Ok(out);
    }
    let pats: Vec<String> = {
        let mut v = Vec::new();
        for p in expand_braces(pattern) {
            if p.contains('/') {
                v.push(p);
            } else {
                v.push(format!("**/{p}"));
            }
        }
        v
    };
    let opts = WalkOptions {
        include_hidden: true,
        ..Default::default()
    };
    walk(root, &opts, |path, is_dir| {
        if out.len() >= limit {
            return false;
        }
        if is_dir {
            return true;
        }
        let rel = path
            .strip_prefix(root)
            .unwrap_or(path)
            .to_string_lossy()
            .replace('\\', "/");
        if pats.iter().any(|p| matches(p, &rel)) {
            out.push(path.to_path_buf());
        }
        true
    })?;
    out.sort();
    out.truncate(limit);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn segments() {
        assert!(match_segment("*.rs", "main.rs"));
        assert!(!match_segment("*.rs", "main.py"));
        assert!(match_segment("?ain.rs", "main.rs"));
        assert!(match_segment("[a-c]at", "bat"));
        assert!(!match_segment("[!a-c]at", "bat"));
        assert!(match_segment("a\\*b", "a*b"));
    }

    #[test]
    fn paths_are_aware_of_separators() {
        assert!(matches("src/**/*.rs", "src/a/b/c.rs"));
        assert!(matches("src/*.rs", "src/main.rs"));
        assert!(!matches("src/*.rs", "src/a/main.rs"));
        assert!(matches("**/test_*.py", "x/y/test_foo.py"));
        assert!(matches("*.toml", "nested/dir/Cargo.toml"));
        assert!(matches("./a/b", "a/b"));
    }

    #[test]
    fn braces_expand() {
        let v = expand_braces("*.{rs,toml}");
        assert_eq!(v, vec!["*.rs".to_string(), "*.toml".to_string()]);
        let v = expand_braces("a{b,c{d,e}}");
        assert_eq!(v.len(), 3);
    }

    #[test]
    fn walking_finds_files() {
        let dir = std::env::temp_dir().join(format!("emerag-glob-test-{}", crate::rand::id(8)));
        std::fs::create_dir_all(dir.join("src/deep")).unwrap();
        std::fs::write(dir.join("src/main.rs"), "fn main(){}").unwrap();
        std::fs::write(dir.join("src/deep/lib.rs"), "//").unwrap();
        std::fs::write(dir.join("README.md"), "#").unwrap();
        let found = find_files(&dir, "*.rs", 10).unwrap();
        assert_eq!(found.len(), 2);
        let found = find_files(&dir, "src/**/*.rs", 10).unwrap();
        assert_eq!(found.len(), 2);
        std::fs::remove_dir_all(&dir).ok();
    }
}
