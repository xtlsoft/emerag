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
    let mut cmd = build_command(shell, command);
    cmd.current_dir(cwd)
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

    let started = Instant::now();
    let mut child = cmd.spawn().map_err(|e| {
        let mut msg = format!("cannot start {}: {e}", shell.path.display());
        if e.raw_os_error() == Some(11)
            || e.kind() == std::io::ErrorKind::WouldBlock
            || e.to_string().to_ascii_lowercase().contains("resource temporarily")
        {
            msg.push_str("; process/PID limit reached? the script tool's fs.* and sys.* functions are forkless");
        }
        AgentError::new(msg)
    })?;
    let tree = ProcessTree::attach(&child);

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
                tree.kill(&mut child);
                return Err(AgentError::new(format!("waiting for command failed: {e}")));
            }
        }
        if cancel.is_cancelled() {
            cancelled = true;
            tree.kill(&mut child);
            break;
        }
        if started.elapsed() > timeout {
            timed_out = true;
            tree.kill(&mut child);
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let code = child.try_wait().ok().flatten().and_then(|s| s.code());
    // A background grandchild ("server &") inherits the pipes and keeps them
    // open after the shell exits. Wait briefly for the readers, then return
    // with what was captured instead of blocking until it exits.
    join_with_deadline(
        [t1, t2],
        Duration::from_millis(if timed_out || cancelled { 2000 } else { 500 }),
    );
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

/// Wait for reader threads until `grace` passes; threads still blocked on a
/// pipe held open by an orphaned grandchild are left to finish on their own.
fn join_with_deadline(handles: [Option<std::thread::JoinHandle<()>>; 2], grace: Duration) {
    let deadline = Instant::now() + grace;
    let mut handles: Vec<_> = handles.into_iter().flatten().collect();
    while !handles.is_empty() {
        let (done, rest): (Vec<_>, Vec<_>) = handles.into_iter().partition(|h| h.is_finished());
        for h in done {
            let _ = h.join();
        }
        handles = rest;
        if handles.is_empty() || Instant::now() >= deadline {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// A Command that runs `command` through `shell`, in its own process group
/// (Unix) so the whole tree can be killed, without a console window
/// (Windows), and with cmd.exe given the command line verbatim.
pub fn build_command(shell: &ShellInfo, command: &str) -> Command {
    let mut cmd = Command::new(&shell.path);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        cmd.creation_flags(CREATE_NO_WINDOW);
        if shell.kind == ShellKind::Cmd {
            // std quotes arguments for the MSVC runtime, which cmd.exe does not
            // use: `dir "C:\Program Files"` would arrive with literal \" in
            // it. With /S, cmd strips exactly one pair of outer quotes.
            cmd.args(["/D", "/S", "/C"]);
            cmd.raw_arg(format!("\"{command}\""));
            return cmd;
        }
    }
    cmd.args(shell.kind.argv(command));
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0);
    }
    cmd
}

/// Handle for killing a child together with everything it started.
///
/// Unix: the child leads its own process group (see [build_command]), and
/// the group is sent SIGKILL. Windows: the child is placed in a Job Object
/// that is terminated; if that fails (a parent job that forbids nesting on
/// Windows 7), `taskkill /T /F` is used.
pub struct ProcessTree {
    #[cfg(windows)]
    job: isize,
}

#[cfg(windows)]
mod winjob {
    use core::ffi::c_void;
    extern "system" {
        pub fn CreateJobObjectW(attrs: *mut c_void, name: *const u16) -> *mut c_void;
        pub fn AssignProcessToJobObject(job: *mut c_void, process: *mut c_void) -> i32;
        pub fn TerminateJobObject(job: *mut c_void, code: u32) -> i32;
        pub fn CloseHandle(h: *mut c_void) -> i32;
    }
}

impl ProcessTree {
    pub fn attach(child: &Child) -> ProcessTree {
        #[cfg(windows)]
        {
            use std::os::windows::io::AsRawHandle;
            unsafe {
                let job = winjob::CreateJobObjectW(core::ptr::null_mut(), core::ptr::null());
                if !job.is_null() {
                    if winjob::AssignProcessToJobObject(job, child.as_raw_handle() as *mut _) != 0 {
                        return ProcessTree { job: job as isize };
                    }
                    winjob::CloseHandle(job);
                }
            }
            ProcessTree { job: 0 }
        }
        #[cfg(not(windows))]
        {
            let _ = child;
            ProcessTree {}
        }
    }

    /// Kill the child and its descendants, then reap the child.
    pub fn kill(&self, child: &mut Child) {
        #[cfg(unix)]
        {
            extern "C" {
                fn kill(pid: i32, sig: i32) -> i32;
            }
            const SIGKILL: i32 = 9;
            let pid = child.id() as i32;
            if pid > 0 {
                unsafe {
                    kill(-pid, SIGKILL);
                }
            }
        }
        #[cfg(windows)]
        {
            let killed =
                self.job != 0 && unsafe { winjob::TerminateJobObject(self.job as *mut _, 1) } != 0;
            if !killed {
                let _ = Command::new("taskkill")
                    .args(["/T", "/F", "/PID", &child.id().to_string()])
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status();
            }
        }
        let _ = child.kill();
        let _ = child.wait();
    }
}

#[cfg(windows)]
impl Drop for ProcessTree {
    fn drop(&mut self) {
        if self.job != 0 {
            unsafe {
                winjob::CloseHandle(self.job as *mut _);
            }
        }
    }
}

// The handle is only used to terminate the job; that is safe from any thread.
unsafe impl Send for ProcessTree {}

/// Kill a spawned process and everything it started. Without a tree handle
/// from spawn time, Windows falls back to `taskkill /T`.
pub fn terminate(child: &mut Child) {
    #[cfg(windows)]
    let tree = ProcessTree { job: 0 };
    #[cfg(not(windows))]
    let tree = ProcessTree {};
    tree.kill(child);
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

    #[cfg(unix)]
    #[test]
    fn timeout_kills_grandchildren_and_background_does_not_block() {
        let shell = detect(Some("sh"));
        let cwd = std::env::temp_dir();
        let t = Instant::now();
        let c = run(
            &shell,
            "sleep 6; true",
            &cwd,
            Duration::from_millis(300),
            &[],
            4096,
            &CancelToken::new(),
        )
        .unwrap();
        assert!(c.timed_out);
        assert!(
            t.elapsed() < Duration::from_secs(4),
            "took {:?}",
            t.elapsed()
        );

        let t = Instant::now();
        let c = run(
            &shell,
            "sleep 6 & echo started",
            &cwd,
            Duration::from_secs(10),
            &[],
            4096,
            &CancelToken::new(),
        )
        .unwrap();
        assert_eq!(c.stdout.trim(), "started");
        assert!(
            t.elapsed() < Duration::from_secs(4),
            "took {:?}",
            t.elapsed()
        );
    }
}
