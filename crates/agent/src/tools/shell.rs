//! Shell detection and command execution.
//!
//! We support bash, zsh, fish, sh, cmd, PowerShell, Python and PHP. Execution is
//! synchronous with a timeout and cooperative cancellation; output is captured
//! without unbounded memory growth.

use crate::error::{AgentError, Result};
use emerag_util::sync::CancelToken;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShellKind {
    Bash,
    Zsh,
    Fish,
    Sh,
    Cmd,
    PowerShell,
    Python,
    Php,
}

impl ShellKind {
    pub fn name(self) -> &'static str {
        match self {
            ShellKind::Bash => "bash",
            ShellKind::Zsh => "zsh",
            ShellKind::Fish => "fish",
            ShellKind::Sh => "sh",
            ShellKind::Cmd => "cmd",
            ShellKind::PowerShell => "pwsh",
            ShellKind::Python => "python",
            ShellKind::Php => "php",
        }
    }

    pub fn from_name(s: &str) -> Option<ShellKind> {
        match s.trim().to_ascii_lowercase().as_str() {
            "bash" => Some(ShellKind::Bash),
            "zsh" => Some(ShellKind::Zsh),
            "fish" => Some(ShellKind::Fish),
            "sh" | "dash" | "ash" => Some(ShellKind::Sh),
            "cmd" | "cmd.exe" | "command" => Some(ShellKind::Cmd),
            "pwsh" | "powershell" | "powershell.exe" | "ps" => Some(ShellKind::PowerShell),
            "python" | "python3" | "py" => Some(ShellKind::Python),
            "php" => Some(ShellKind::Php),
            _ => None,
        }
    }

    /// Build the argv for running a command line through this shell.
    pub fn argv(self, command: &str) -> Vec<String> {
        match self {
            ShellKind::Bash | ShellKind::Zsh | ShellKind::Fish | ShellKind::Sh => {
                vec!["-c".to_string(), command.to_string()]
            }
            ShellKind::Cmd => vec![
                "/D".to_string(),
                "/S".to_string(),
                "/C".to_string(),
                command.to_string(),
            ],
            ShellKind::PowerShell => vec![
                "-NoLogo".into(),
                "-NoProfile".into(),
                "-NonInteractive".into(),
                "-Command".into(),
                command.into(),
            ],
            ShellKind::Python => vec!["-c".into(), command.into()],
            ShellKind::Php => vec!["-r".into(), command.into()],
        }
    }
}

#[derive(Debug, Clone)]
pub struct ShellInfo {
    pub kind: ShellKind,
    pub path: PathBuf,
    pub note: String,
}

impl ShellInfo {
    pub fn label(&self) -> String {
        format!("{} ({})", self.kind.name(), self.path.display())
    }
}

/// Choose a shell. Preference order: explicit config, $SHELL, platform default.
pub fn detect(preferred: Option<&str>) -> ShellInfo {
    if let Some(p) = preferred {
        let p = p.trim();
        if !p.is_empty() {
            if let Some(kind) = ShellKind::from_name(p) {
                if let Some(path) = find_shell(kind) {
                    return ShellInfo {
                        kind,
                        path,
                        note: "configured".into(),
                    };
                }
            }
            let path = PathBuf::from(p);
            if path.is_file() {
                let kind = path
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .and_then(ShellKind::from_name)
                    .unwrap_or(ShellKind::Sh);
                return ShellInfo {
                    kind,
                    path,
                    note: "configured path".into(),
                };
            }
        }
    }

    if let Some(shell_env) = emerag_util::sys::env_var("SHELL") {
        if let Some(name) = Path::new(&shell_env).file_name().and_then(|s| s.to_str()) {
            if let Some(kind) = ShellKind::from_name(name) {
                if let Some(path) = find_shell(kind) {
                    return ShellInfo {
                        kind,
                        path,
                        note: "from $SHELL".into(),
                    };
                }
            }
        }
        let p = PathBuf::from(&shell_env);
        if p.is_file() {
            return ShellInfo {
                kind: ShellKind::Sh,
                path: p,
                note: "from $SHELL".into(),
            };
        }
    }

    #[cfg(windows)]
    let order = [
        ShellKind::PowerShell,
        ShellKind::Cmd,
        ShellKind::Bash,
        ShellKind::Python,
        ShellKind::Php,
    ];
    #[cfg(not(windows))]
    let order = [
        ShellKind::Bash,
        ShellKind::Zsh,
        ShellKind::Fish,
        ShellKind::Sh,
        ShellKind::Python,
        ShellKind::Php,
    ];

    for kind in order {
        if let Some(path) = find_shell(kind) {
            return ShellInfo {
                kind,
                path,
                note: "auto-detected".into(),
            };
        }
    }
    // Last resort: /bin/sh exists almost everywhere.
    ShellInfo {
        kind: ShellKind::Sh,
        path: PathBuf::from("/bin/sh"),
        note: "fallback".into(),
    }
}

fn find_shell(kind: ShellKind) -> Option<PathBuf> {
    let names: &[&str] = match kind {
        ShellKind::Bash => &["bash"],
        ShellKind::Zsh => &["zsh"],
        ShellKind::Fish => &["fish"],
        ShellKind::Sh => &["sh"],
        ShellKind::Cmd => &["cmd"],
        ShellKind::PowerShell => &["pwsh", "powershell"],
        ShellKind::Python => &["python3", "python"],
        ShellKind::Php => &["php"],
    };
    for n in names {
        if let Some(p) = emerag_util::sys::which(n) {
            return Some(p);
        }
    }
    None
}

/// List shells available on this machine (for /doctor and the wizard).
pub fn available_shells() -> Vec<ShellInfo> {
    let mut out = Vec::new();
    for kind in [
        ShellKind::Bash,
        ShellKind::Zsh,
        ShellKind::Fish,
        ShellKind::Sh,
        ShellKind::Cmd,
        ShellKind::PowerShell,
        ShellKind::Python,
        ShellKind::Php,
    ] {
        if let Some(path) = find_shell(kind) {
            out.push(ShellInfo {
                kind,
                path,
                note: "found".into(),
            });
        }
    }
    out
}

#[derive(Debug, Clone, Default)]
pub struct CommandResult {
    pub stdout: String,
    pub stderr: String,
    pub code: Option<i32>,
    pub timed_out: bool,
    pub cancelled: bool,
    pub duration_ms: u64,
    pub truncated: bool,
}

impl CommandResult {
    pub fn success(&self) -> bool {
        self.code == Some(0) && !self.timed_out && !self.cancelled
    }

    pub fn for_model(&self, max_chars: usize) -> String {
        let mut s = String::new();
        if !self.stdout.trim().is_empty() {
            s.push_str(self.stdout.trim_end());
        }
        if !self.stderr.trim().is_empty() {
            if !s.is_empty() {
                s.push_str("\n");
            }
            s.push_str("[stderr]\n");
            s.push_str(self.stderr.trim_end());
        }
        if s.trim().is_empty() {
            s.push_str("(no output)");
        }
        let mut footer = format!(
            "\n[exit {} in {}ms]",
            self.code
                .map(|c| c.to_string())
                .unwrap_or_else(|| "signal".into()),
            self.duration_ms
        );
        if self.timed_out {
            footer.push_str(" [timed out]");
        }
        if self.cancelled {
            footer.push_str(" [cancelled]");
        }
        if self.truncated {
            footer.push_str(" [output truncated]");
        }
        if s.len() + footer.len() > max_chars {
            s = emerag_util::text::truncate(&s, max_chars.saturating_sub(footer.len())).to_string();
            s.push_str("\n[...]");
        }
        s.push_str(&footer);
        s
    }
}

/// Execute a command line through the selected shell.
pub fn run(
    shell: &ShellInfo,
    command: &str,
    cwd: &Path,
    timeout: Duration,
    env: &[(String, String)],
    max_output: usize,
    cancel: &CancelToken,
) -> Result<CommandResult> {
    run_with_input(shell, command, cwd, timeout, env, max_output, cancel, None)
}

/// Like run, but feeds stdin (used for sudo passwords; never logged).
pub fn run_with_input(
    shell: &ShellInfo,
    command: &str,
    cwd: &Path,
    timeout: Duration,
    env: &[(String, String)],
    max_output: usize,
    cancel: &CancelToken,
    input: Option<Vec<u8>>,
) -> Result<CommandResult> {
    if command.trim().is_empty() {
        return Err(AgentError::new("empty command"));
    }
    let mut cmd = Command::new(&shell.path);
    cmd.args(shell.kind.argv(command))
        .current_dir(cwd)
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (k, v) in default_env() {
        cmd.env(k, v);
    }
    for (k, v) in env {
        cmd.env(k, v);
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }

    let started = Instant::now();
    let mut child = cmd
        .spawn()
        .map_err(|e| AgentError::new(format!("cannot start {}: {e}", shell.path.display())))?;

    if let Some(bytes) = input {
        if let Some(mut si) = child.stdin.take() {
            std::thread::spawn(move || {
                use std::io::Write;
                let _ = si.write_all(&bytes);
            });
        }
    }

    let out_buf = Arc::new(Mutex::new(Vec::<u8>::new()));
    let err_buf = Arc::new(Mutex::new(Vec::<u8>::new()));
    let truncated = Arc::new(AtomicBool::new(false));
    let t1 = spawn_reader(
        child.stdout.take(),
        out_buf.clone(),
        truncated.clone(),
        max_output,
    );
    let t2 = spawn_reader(
        child.stderr.take(),
        err_buf.clone(),
        truncated.clone(),
        max_output,
    );

    let mut timed_out = false;
    let mut cancelled = false;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) => {}
            Err(e) => {
                let _ = child.kill();
                return Err(AgentError::new(format!("waiting for command failed: {e}")));
            }
        }
        if cancel.is_cancelled() {
            cancelled = true;
            let _ = child.kill();
            let _ = child.wait();
            break;
        }
        if started.elapsed() > timeout {
            timed_out = true;
            let _ = child.kill();
            let _ = child.wait();
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let code = child.try_wait().ok().flatten().and_then(|s| s.code());
    if let Some(t) = t1 {
        let _ = t.join();
    }
    if let Some(t) = t2 {
        let _ = t.join();
    }
    let stdout = String::from_utf8_lossy(&emerag_util::sync::lock(&out_buf)).into_owned();
    let stderr = String::from_utf8_lossy(&emerag_util::sync::lock(&err_buf)).into_owned();
    Ok(CommandResult {
        stdout,
        stderr,
        code,
        timed_out,
        cancelled,
        duration_ms: started.elapsed().as_millis() as u64,
        truncated: truncated.load(Ordering::Relaxed),
    })
}

fn spawn_reader(
    reader: Option<impl Read + Send + 'static>,
    buf: Arc<Mutex<Vec<u8>>>,
    truncated: Arc<AtomicBool>,
    max: usize,
) -> Option<std::thread::JoinHandle<()>> {
    let mut reader = reader?;
    Some(std::thread::spawn(move || {
        let mut chunk = [0u8; 8192];
        loop {
            match reader.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => {
                    let mut b = emerag_util::sync::lock(&buf);
                    if b.len() < max {
                        let room = max - b.len();
                        b.extend_from_slice(&chunk[..n.min(room)]);
                        if n > room {
                            truncated.store(true, Ordering::Relaxed);
                        }
                    } else {
                        truncated.store(true, Ordering::Relaxed);
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => break,
            }
        }
    }))
}

fn default_env() -> Vec<(String, String)> {
    vec![
        ("TERM".into(), "dumb".into()),
        ("NO_COLOR".into(), "1".into()),
        ("PAGER".into(), "cat".into()),
        ("GIT_PAGER".into(), "cat".into()),
        ("EMERAG".into(), "1".into()),
        ("CLICOLOR".into(), "0".into()),
    ]
}

/// Kill a spawned process tree as best we can without extra crates.
pub fn terminate(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_a_real_shell() {
        let info = detect(None);
        assert!(info.path.exists() || info.kind == ShellKind::Sh);
        assert!(!info.label().is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn runs_commands_and_captures_output() {
        let shell = detect(Some("sh"));
        let cwd = std::env::temp_dir();
        let c = run(
            &shell,
            "echo hello; echo oops >&2; exit 3",
            &cwd,
            Duration::from_secs(10),
            &[],
            4096,
            &CancelToken::new(),
        )
        .unwrap();
        assert_eq!(c.stdout.trim(), "hello");
        assert_eq!(c.stderr.trim(), "oops");
        assert_eq!(c.code, Some(3));
        assert!(!c.timed_out);
    }

    #[cfg(unix)]
    #[test]
    fn times_out_and_cancels() {
        let shell = detect(Some("sh"));
        let cwd = std::env::temp_dir();
        let c = run(
            &shell,
            "sleep 5",
            &cwd,
            Duration::from_millis(200),
            &[],
            4096,
            &CancelToken::new(),
        )
        .unwrap();
        assert!(c.timed_out);
        let token = CancelToken::new();
        token.cancel();
        let c = run(
            &shell,
            "sleep 5",
            &cwd,
            Duration::from_secs(10),
            &[],
            4096,
            &token,
        )
        .unwrap();
        assert!(c.cancelled);
    }
}
