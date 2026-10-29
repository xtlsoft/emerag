//! Background jobs: start, poll, list, kill.
//!
//! Output is kept in a bounded ring buffer so a chatty job cannot exhaust RAM.
//! This is deliberately process-based (not threads in-process) so a crashed
//! command does not take the agent with it.

use crate::tools::shell::{terminate, ShellInfo};
use emerag_util::sync::CancelToken;
use std::collections::VecDeque;
use std::io::Read;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const MAX_LINES: usize = 2000;
const MAX_BYTES: usize = 512 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobStatus {
    Running,
    Exited(i32),
    Failed,
    Killed,
}

impl JobStatus {
    pub fn label(self) -> String {
        match self {
            JobStatus::Running => "running".into(),
            JobStatus::Exited(0) => "done".into(),
            JobStatus::Exited(c) => format!("exit {c}"),
            JobStatus::Failed => "failed".into(),
            JobStatus::Killed => "killed".into(),
        }
    }
}

struct Inner {
    child: Option<Child>,
    status: JobStatus,
    lines: VecDeque<String>,
    bytes: usize,
    read_offset: usize,
}

pub struct Job {
    pub id: String,
    pub command: String,
    pub cwd: PathBuf,
    pub started: Instant,
    inner: Arc<Mutex<Inner>>,
    cancel: CancelToken,
}

pub struct JobManager {
    jobs: Vec<Arc<Job>>,
    next: u64,
}

impl JobManager {
    pub fn new() -> Self {
        JobManager {
            jobs: Vec::new(),
            next: 1,
        }
    }

    pub fn start(
        &mut self,
        shell: &ShellInfo,
        command: &str,
        cwd: &PathBuf,
        timeout: Option<Duration>,
    ) -> crate::error::Result<String> {
        let mut cmd = Command::new(&shell.path);
        cmd.args(shell.kind.argv(command))
            .current_dir(cwd)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            const CREATE_NO_WINDOW: u32 = 0x0800_0000;
            cmd.creation_flags(CREATE_NO_WINDOW);
        }
        let mut child = cmd
            .spawn()
            .map_err(|e| crate::error::AgentError::new(format!("cannot start job: {e}")))?;
        let stdout = child.stdout.take();
        let stderr = child.stderr.take();
        let inner = Arc::new(Mutex::new(Inner {
            child: Some(child),
            status: JobStatus::Running,
            lines: VecDeque::new(),
            bytes: 0,
            read_offset: 0,
        }));
        if let Some(out) = stdout {
            spawn_reader(out, inner.clone(), "out");
        }
        if let Some(err) = stderr {
            spawn_reader(err, inner.clone(), "err");
        }
        let id = format!("j{}", self.next);
        self.next += 1;
        let job = Arc::new(Job {
            id: id.clone(),
            command: command.to_string(),
            cwd: cwd.clone(),
            started: Instant::now(),
            inner,
            cancel: CancelToken::new(),
        });
        if let Some(t) = timeout {
            let j = job.clone();
            std::thread::spawn(move || {
                std::thread::sleep(t);
                j.cancel.cancel();
                let mut inner = emerag_util::sync::lock(&j.inner);
                if inner.status == JobStatus::Running {
                    if let Some(child) = inner.child.as_mut() {
                        terminate(child);
                    }
                    inner.status = JobStatus::Killed;
                }
            });
        }
        self.jobs.push(job);
        Ok(id)
    }

    pub fn get(&self, id: &str) -> Option<&Arc<Job>> {
        self.jobs.iter().find(|j| j.id == id)
    }

    pub fn list(&self) -> String {
        if self.jobs.is_empty() {
            return "no background jobs".to_string();
        }
        let mut out = String::new();
        for job in &self.jobs {
            let inner = emerag_util::sync::lock(&job.inner);
            out.push_str(&format!(
                "{}  {:<9} {:>6}s  {}\n",
                job.id,
                inner.status.label(),
                job.started.elapsed().as_secs(),
                emerag_util::text::truncate_ellipsis(&job.command, 60)
            ));
        }
        out
    }

    /// Return output produced since the last read (or all output when
    /// everything=true).
    pub fn output(
        &self,
        id: &str,
        wait: Duration,
        everything: bool,
    ) -> crate::error::Result<String> {
        let job = self.get(id).ok_or_else(|| {
            crate::error::AgentError::new(format!("unknown job '{id}' (try job_list)"))
        })?;
        let deadline = Instant::now() + wait;
        loop {
            let mut inner = emerag_util::sync::lock(&job.inner);
            if let Some(child) = inner.child.as_mut() {
                if let Ok(Some(status)) = child.try_wait() {
                    inner.status = match status.code() {
                        Some(0) => JobStatus::Exited(0),
                        Some(c) => JobStatus::Exited(c),
                        None => JobStatus::Failed,
                    };
                }
            }
            let start = if everything {
                0
            } else {
                inner.read_offset.min(inner.lines.len())
            };
            if inner.lines.len() > start
                || inner.status != JobStatus::Running
                || Instant::now() >= deadline
            {
                let mut out = String::new();
                for line in inner.lines.iter().skip(start) {
                    out.push_str(line);
                    out.push('\n');
                }
                if !everything {
                    inner.read_offset = inner.lines.len();
                }
                if out.is_empty() {
                    out.push_str("(no new output)");
                }
                out.push_str(&format!("[{} {}]", job.id, inner.status.label()));
                return Ok(out);
            }
            drop(inner);
            if Instant::now() >= deadline {
                let inner = emerag_util::sync::lock(&job.inner);
                return Ok(format!(
                    "[{} {} (no new output)]",
                    job.id,
                    inner.status.label()
                ));
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    pub fn kill(&mut self, id: &str) -> crate::error::Result<String> {
        let job = self
            .get(id)
            .ok_or_else(|| crate::error::AgentError::new(format!("unknown job '{id}'")))?;
        job.cancel.cancel();
        let mut inner = emerag_util::sync::lock(&job.inner);
        if let Some(child) = inner.child.as_mut() {
            terminate(child);
        }
        if inner.status == JobStatus::Running {
            inner.status = JobStatus::Killed;
        }
        Ok(format!("{} {}", job.id, inner.status.label()))
    }

    pub fn kill_all(&mut self) {
        for job in &self.jobs {
            job.cancel.cancel();
            let mut inner = emerag_util::sync::lock(&job.inner);
            if let Some(child) = inner.child.as_mut() {
                terminate(child);
            }
            inner.status = JobStatus::Killed;
        }
    }

    /// Drop finished jobs older than the last 20 entries.
    pub fn prune(&mut self) {
        if self.jobs.len() > 40 {
            let keep_from = self.jobs.len() - 20;
            self.jobs.drain(0..keep_from);
        }
    }
}

impl Drop for JobManager {
    fn drop(&mut self) {
        self.kill_all();
    }
}

fn spawn_reader(
    mut reader: impl Read + Send + 'static,
    inner: Arc<Mutex<Inner>>,
    tag: &'static str,
) {
    std::thread::spawn(move || {
        let mut buf = [0u8; 4096];
        let mut partial = String::new();
        loop {
            match reader.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    partial.push_str(&String::from_utf8_lossy(&buf[..n]));
                    while let Some(idx) = partial.find('\n') {
                        let line: String = partial.drain(..=idx).collect();
                        push_line(&inner, tag, line.trim_end_matches(['\r', '\n']));
                    }
                    if partial.len() > 64 * 1024 {
                        let line = std::mem::take(&mut partial);
                        push_line(&inner, tag, &line);
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => break,
            }
        }
        if !partial.is_empty() {
            push_line(&inner, tag, &partial);
        }
    });
}

fn push_line(inner: &Arc<Mutex<Inner>>, tag: &str, line: &str) {
    let mut inner = emerag_util::sync::lock(inner);
    let text = format!("[{tag}] {}", emerag_util::text::sanitize(line));
    inner.bytes += text.len();
    inner.lines.push_back(text);
    while inner.lines.len() > MAX_LINES || inner.bytes > MAX_BYTES {
        if let Some(old) = inner.lines.pop_front() {
            inner.bytes = inner.bytes.saturating_sub(old.len());
            inner.read_offset = inner.read_offset.saturating_sub(1);
        } else {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tools::shell::detect;

    #[cfg(unix)]
    #[test]
    fn job_lifecycle() {
        let shell = detect(Some("sh"));
        let mut mgr = JobManager::new();
        let cwd = std::env::temp_dir();
        let id = mgr
            .start(
                &shell,
                "echo one; echo two; sleep 0.1; echo three",
                &cwd,
                None,
            )
            .unwrap();
        std::thread::sleep(Duration::from_millis(300));
        let out = mgr.output(&id, Duration::from_millis(200), false).unwrap();
        assert!(out.contains("one"));
        assert!(out.contains("three"));
        assert!(mgr.list().contains(&id));
        assert!(mgr.kill(&id).is_ok());
    }
}
