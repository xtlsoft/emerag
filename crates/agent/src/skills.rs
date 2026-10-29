//! Skills are cheap: a directory with a SKILL.md (frontmatter + body) that is
//! listed in the system prompt and loaded on demand by the skill tool.
//!
//! Discovery order: ./.emerag/skills, ~/.config/emerag/skills, extra dirs.
//! A skill may be a directory (SKILL.md inside) or a single .md file.

use crate::error::Result;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct Skill {
    pub name: String,
    pub description: String,
    pub path: PathBuf,
    pub body: String,
}

#[derive(Debug, Clone, Default)]
pub struct SkillRegistry {
    pub skills: Vec<Skill>,
    pub dirs: Vec<PathBuf>,
}

impl SkillRegistry {
    pub fn empty() -> Self {
        SkillRegistry::default()
    }

    /// Discover skills under the given directories. Missing dirs are ignored.
    pub fn discover(dirs: Vec<PathBuf>) -> Self {
        let mut skills = Vec::new();
        for dir in &dirs {
            if !dir.is_dir() {
                continue;
            }
            scan_dir(dir, &mut skills, 0);
        }
        skills.sort_by(|a, b| a.name.cmp(&b.name));
        skills.dedup_by(|a, b| a.name == b.name);
        SkillRegistry { skills, dirs }
    }

    pub fn get(&self, name: &str) -> Option<&Skill> {
        let name = name.trim();
        self.skills
            .iter()
            .find(|s| s.name == name || s.name.eq_ignore_ascii_case(name))
    }

    pub fn names(&self) -> Vec<&str> {
        self.skills.iter().map(|s| s.name.as_str()).collect()
    }

    /// Human-readable catalog for /skills.
    pub fn catalog(&self) -> String {
        if self.skills.is_empty() {
            return "no skills found (looked in .emerag/skills and ~/.config/emerag/skills)"
                .to_string();
        }
        let mut out = String::new();
        for s in &self.skills {
            out.push_str(&format!(
                "{:<20} {}\n",
                s.name,
                emerag_util::text::single_line(&s.description)
            ));
        }
        out
    }
}

fn scan_dir(dir: &Path, out: &mut Vec<Skill>, depth: usize) {
    if depth > 2 {
        return;
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let mut items: Vec<_> = entries.flatten().map(|e| e.path()).collect();
    items.sort();
    for path in items {
        if path.is_dir() {
            let skill_file = path.join("SKILL.md");
            if skill_file.is_file() {
                if let Some(skill) = parse_skill_file(&skill_file, None) {
                    out.push(skill);
                }
            } else {
                scan_dir(&path, out, depth + 1);
            }
        } else if path.extension().map(|e| e == "md").unwrap_or(false) {
            let file_name = path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string();
            let stem = path
                .file_stem()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_else(|| "skill".to_string());
            if file_name.eq_ignore_ascii_case("SKILL.md") {
                if let Some(skill) = parse_skill_file(&path, None) {
                    out.push(skill);
                }
            } else if let Some(skill) = parse_skill_file(&path, Some(stem)) {
                out.push(skill);
            }
        }
    }
}

fn parse_skill_file(path: &Path, fallback_name: Option<String>) -> Option<Skill> {
    let text = std::fs::read_to_string(path).ok()?;
    if text.len() > 512 * 1024 {
        return None;
    }
    let (meta, body) = split_frontmatter(&text);
    let mut name = fallback_name.unwrap_or_else(|| {
        path.parent()
            .and_then(|p| p.file_name())
            .map(|s| s.to_string_lossy().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "skill".to_string())
    });
    let mut description = String::new();
    for line in meta.lines() {
        if let Some((k, v)) = line.split_once(':') {
            let key = k.trim().to_ascii_lowercase();
            let value = v.trim().trim_matches(['"', '\'']).to_string();
            match key.as_str() {
                "name" => name = sanitize_name(&value),
                "description" => description = value,
                _ => {}
            }
        }
    }
    if description.is_empty() {
        description = first_paragraph(body);
    }
    Some(Skill {
        name: sanitize_name(&name),
        description,
        path: path.to_path_buf(),
        body: body.to_string(),
    })
}

fn sanitize_name(s: &str) -> String {
    let mut out = String::new();
    for c in s.chars() {
        if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' {
            out.push(c);
        } else if c.is_whitespace() {
            out.push('-');
        }
    }
    if out.is_empty() {
        "skill".into()
    } else {
        out
    }
}

fn first_paragraph(body: &str) -> String {
    for para in body.split("\n\n") {
        let p = para.trim();
        if !p.is_empty() && !p.starts_with('#') {
            return emerag_util::text::truncate_ellipsis(&emerag_util::text::single_line(p), 160);
        }
    }
    String::new()
}

fn split_frontmatter(text: &str) -> (&str, &str) {
    let trimmed = text.trim_start_matches('\u{feff}');
    if let Some(rest) = trimmed.strip_prefix("---") {
        if let Some(end) = rest.find("\n---") {
            let meta = &rest[..end];
            let body = rest[end + 4..].trim_start_matches(['\r', '\n']);
            return (meta, body);
        }
    }
    ("", trimmed)
}

/// Default skill directories for a working directory.
pub fn default_dirs(cwd: &Path, extra: &[PathBuf]) -> Vec<PathBuf> {
    let mut dirs = vec![cwd.join(".emerag").join("skills")];
    dirs.push(emerag_util::sys::config_dir().join("skills"));
    for d in extra {
        dirs.push(d.clone());
    }
    dirs
}

/// Load a skill body on demand, enforcing a size limit.
pub fn load_body(skill: &Skill) -> Result<String> {
    if skill.body.len() > 256 * 1024 {
        return Err(crate::error::AgentError::new("skill too large"));
    }
    Ok(skill.body.clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(tag: &str) -> PathBuf {
        let d =
            std::env::temp_dir().join(format!("emerag-skills-{tag}-{}", emerag_util::rand::id(6)));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn discovers_directory_and_file_skills() {
        let root = tmpdir("a");
        let dir = root.join(".emerag/skills/foo");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("SKILL.md"),
            "---\nname: foo\ndescription: do foo things\n---\n# Foo\n\nUse foo carefully.\n",
        )
        .unwrap();
        std::fs::write(
            root.join(".emerag/skills/bar.md"),
            "---\nname: bar\ndescription: bar skill\n---\nbody\n",
        )
        .unwrap();
        let reg = SkillRegistry::discover(vec![root.join(".emerag/skills")]);
        assert_eq!(reg.names(), vec!["bar", "foo"]);
        assert_eq!(reg.get("foo").unwrap().description, "do foo things");
        assert!(reg.get("foo").unwrap().body.contains("Use foo"));
        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn missing_dirs_are_fine() {
        let reg = SkillRegistry::discover(vec![PathBuf::from("/nonexistent/xyz")]);
        assert!(reg.skills.is_empty());
        assert!(reg.catalog().contains("no skills"));
    }
}
