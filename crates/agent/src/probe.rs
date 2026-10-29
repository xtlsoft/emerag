//! Cheap environment probe whose results are included in the system prompt.
//!
//! The model should not have to guess whether it is on Android/Termux, a
//! rescue shell, a container, or a normal Linux box. Everything here is read
//! with std or a few /proc files: no shelling out, no side effects.

use std::path::Path;

pub fn summary(cwd: &Path, shell: &str) -> String {
    let mut lines: Vec<String> = Vec::new();

    let (os, android) = os_description();
    let kernel = read_trim("/proc/sys/kernel/osrelease").unwrap_or_else(|| "unknown".into());
    let init = read_trim("/proc/1/comm").unwrap_or_else(|| "unknown".into());
    let arch = std::env::consts::ARCH;
    let user = emerag_util::sys::username();
    let uid = uid_line();
    lines.push(format!("OS: {os} (kernel {kernel}, init {init})"));
    lines.push(format!(
        "Arch: {arch} | user: {user}{} | root: {}",
        uid.map(|u| format!(" (uid {u})")).unwrap_or_default(),
        is_root()
    ));
    if android {
        if let Some(prefix) = std::env::var("PREFIX")
            .ok()
            .filter(|p| p.contains("com.termux"))
        {
            lines.push(format!("Environment: Termux/Android (PREFIX={prefix}); expect no /etc/resolv.conf, no systemd, SELinux restrictions"));
        } else {
            lines.push("Environment: Android; expect no /etc/resolv.conf, no systemd, SELinux restrictions".into());
        }
    }

    let shells = crate::tools::shell::available_shells();
    let shell_names: Vec<String> = shells.iter().map(|s| s.kind.name().to_string()).collect();
    lines.push(format!(
        "Shell: {shell} | detected: {}",
        if shell_names.is_empty() {
            "none".to_string()
        } else {
            shell_names.join(", ")
        }
    ));

    let mut pkg = Vec::new();
    for name in [
        "apk",
        "apt",
        "apt-get",
        "dnf",
        "yum",
        "pacman",
        "zypper",
        "pkg",
        "xbps-install",
    ] {
        if emerag_util::sys::which(name).is_some() {
            pkg.push(name);
        }
    }
    let mut tools = Vec::new();
    for name in [
        "curl",
        "wget",
        "git",
        "ssh",
        "scp",
        "python3",
        "python",
        "perl",
        "openssl",
        "busybox",
        "tar",
        "gzip",
        "vi",
        "nano",
        "ss",
        "ip",
        "systemctl",
        "ps",
        "kill",
    ] {
        if emerag_util::sys::which(name).is_some() {
            tools.push(name);
        }
    }
    lines.push(format!(
        "Package managers: {}",
        if pkg.is_empty() {
            "none found".to_string()
        } else {
            pkg.join(", ")
        }
    ));
    lines.push(format!(
        "Common tools: {}",
        if tools.is_empty() {
            "none found".to_string()
        } else {
            tools.join(", ")
        }
    ));

    let writable = is_writable(cwd);
    let dns = dns_servers();
    lines.push(format!(
        "Cwd: {} (writable: {}) | DNS: {}",
        cwd.display(),
        if writable { "yes" } else { "no" },
        if dns.is_empty() {
            "no /etc/resolv.conf (use --dns or --resolve)".to_string()
        } else {
            dns.join(", ")
        }
    ));

    if let Some(mem) = memory_summary() {
        lines.push(format!("Memory: {mem}"));
    }
    if emerag_util::sys::which("sudo").is_some() {
        lines.push("Elevation: sudo available (ask before using)".into());
    } else if emerag_util::sys::which("doas").is_some() {
        lines.push("Elevation: doas available (ask before using)".into());
    } else {
        lines.push("Elevation: no sudo/doas found".into());
    }
    lines.join("\n")
}

fn os_description() -> (String, bool) {
    if let Ok(text) = std::fs::read_to_string("/etc/os-release") {
        let mut name = None;
        let mut version = None;
        for line in text.lines() {
            if let Some(v) = line.strip_prefix("PRETTY_NAME=") {
                name = Some(v.trim_matches('"').to_string());
            } else if let Some(v) = line.strip_prefix("VERSION=") {
                version = Some(v.trim_matches('"').to_string());
            }
        }
        if let Some(n) = name {
            return (n, false);
        }
        if let Some(v) = version {
            return (v, false);
        }
    }
    if Path::new("/system/build.prop").exists() {
        let release = grep_prop("/system/build.prop", "ro.build.version.release")
            .unwrap_or_else(|| "unknown".into());
        let model = grep_prop("/system/build.prop", "ro.product.model").unwrap_or_default();
        let mut desc = format!("Android {release}");
        if !model.is_empty() {
            desc.push(' ');
            desc.push_str(&model);
        }
        return (desc, true);
    }
    (
        format!(
            "{} {}",
            emerag_util::sys::os_name(),
            emerag_util::sys::arch()
        ),
        false,
    )
}

fn grep_prop(path: &str, key: &str) -> Option<String> {
    let text = std::fs::read_to_string(path).ok()?;
    for line in text.lines() {
        if let Some(v) = line.strip_prefix(&format!("{key}=")) {
            return Some(v.trim().to_string());
        }
    }
    None
}

fn read_trim(path: &str) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn uid_line() -> Option<String> {
    let text = std::fs::read_to_string("/proc/self/status").ok()?;
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("Uid:") {
            return rest.split_whitespace().next().map(str::to_string);
        }
    }
    None
}

fn is_root() -> bool {
    std::env::var("USER").map(|u| u == "root").unwrap_or(false)
        || std::env::var("EUID").map(|u| u == "0").unwrap_or(false)
        || uid_line().map(|u| u == "0").unwrap_or(false)
}

fn is_writable(path: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        extern "C" {
            fn access(path: *const u8, mode: i32) -> i32;
        }
        let mut bytes = path.as_os_str().as_bytes().to_vec();
        if bytes.contains(&0) {
            return false;
        }
        bytes.push(0);
        // W_OK = 2
        unsafe { access(bytes.as_ptr(), 2) == 0 }
    }
    #[cfg(not(unix))]
    {
        std::fs::metadata(path)
            .map(|m| !m.permissions().readonly())
            .unwrap_or(false)
    }
}

fn dns_servers() -> Vec<String> {
    let mut out = Vec::new();
    if let Ok(text) = std::fs::read_to_string("/etc/resolv.conf") {
        for line in text.lines() {
            let line = line.trim();
            if let Some(rest) = line.strip_prefix("nameserver") {
                if let Some(ip) = rest.split_whitespace().next() {
                    out.push(ip.to_string());
                }
            }
        }
    }
    out.truncate(3);
    out
}

fn memory_summary() -> Option<String> {
    let text = std::fs::read_to_string("/proc/meminfo").ok()?;
    let mut total = None;
    let mut avail = None;
    for line in text.lines() {
        if let Some(v) = line.strip_prefix("MemTotal:") {
            total = parse_kb(v);
        } else if let Some(v) = line.strip_prefix("MemAvailable:") {
            avail = parse_kb(v);
        }
    }
    match (total, avail) {
        (Some(t), Some(a)) => Some(format!(
            "{} total, {} available",
            emerag_util::human_bytes(t),
            emerag_util::human_bytes(a)
        )),
        (Some(t), None) => Some(format!("{} total", emerag_util::human_bytes(t))),
        _ => None,
    }
}

fn parse_kb(v: &str) -> Option<u64> {
    let n: u64 = v.split_whitespace().next()?.parse().ok()?;
    Some(n * 1024)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summary_mentions_os_and_dns() {
        let cwd = std::env::current_dir().unwrap();
        let s = summary(&cwd, "test-shell");
        assert!(s.contains("OS:"));
        assert!(s.contains("Cwd:"));
        assert!(s.contains("test-shell"));
    }
}
