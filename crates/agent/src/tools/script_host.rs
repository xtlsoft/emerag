//! Host bindings for the emera script engine.
//!
//! The script engine is the fallback when shells are missing. These bindings
//! expose the minimum an emergency operator needs: read files, write files,
//! inspect processes, run a command if the OS still allows it, hash a blob,
//! and convert JSON.

use crate::error::{AgentError, Result};
use crate::Ui;
use emerag_script::{Limits, ScriptError, Value};
use emerag_util::sync::CancelToken;
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

pub fn run_script(cwd: &Path, source: &str, _ui: &mut dyn Ui, max_output: usize) -> Result<String> {
    let mut host = AgentHost {
        cwd: cwd.to_path_buf(),
        output: String::new(),
        max_output,
        truncated: false,
        fds: HashMap::new(),
        next_fd: 10,
    };
    let limits = Limits {
        max_instructions: 2_000_000,
        max_output_bytes: max_output.max(4096),
        wall_clock_ms: 20_000,
    };
    let value = emerag_script::run(source, &mut host, limits)
        .map_err(|e| AgentError::new(format!("script error: {e}")))?;
    let mut out = host.output;
    if !matches!(value, Value::Nil) {
        if !out.is_empty() {
            out.push('\n');
        }
        out.push_str(&emerag_script::tostring(&value));
    }
    if out.trim().is_empty() {
        out.push_str("(script returned no output)");
    }
    if host.truncated {
        out.push_str("\n[output truncated]");
    }
    Ok(out)
}

struct AgentHost {
    cwd: PathBuf,
    output: String,
    max_output: usize,
    truncated: bool,
    /// Open descriptors for sys.open/sys.read/... (all forkless).
    fds: HashMap<i32, File>,
    next_fd: i32,
}

impl AgentHost {
    fn path_arg(&self, args: &[Value], idx: usize) -> std::result::Result<PathBuf, ScriptError> {
        let raw = args
            .get(idx)
            .and_then(|v| v.as_str())
            .ok_or_else(|| ScriptError::host("expected a path string", 0))?;
        Ok(crate::tools::fs::resolve(&self.cwd, raw))
    }

    fn str_arg(args: &[Value], idx: usize) -> std::result::Result<String, ScriptError> {
        args.get(idx)
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .ok_or_else(|| ScriptError::host("expected a string argument", 0))
    }

    fn push_output(&mut self, text: &str) {
        if self.output.len() >= self.max_output {
            self.truncated = true;
            return;
        }
        let room = self.max_output - self.output.len();
        if text.len() > room {
            self.truncated = true;
            self.output
                .push_str(&emerag_util::text::truncate(text, room));
        } else {
            self.output.push_str(text);
        }
    }
}

fn table_from_json(v: &emerag_json::Value) -> Value {
    match v {
        emerag_json::Value::Null => Value::Nil,
        emerag_json::Value::Bool(b) => Value::Bool(*b),
        emerag_json::Value::Number(n) => Value::Number(n.as_f64()),
        emerag_json::Value::String(s) => Value::Str(s.clone()),
        emerag_json::Value::Array(a) => {
            let mut t = emerag_script::Table::new();
            for (i, item) in a.iter().enumerate() {
                t.set(Value::Number((i + 1) as f64), table_from_json(item));
            }
            Value::Table(std::rc::Rc::new(std::cell::RefCell::new(t)))
        }
        emerag_json::Value::Object(m) => {
            let mut t = emerag_script::Table::new();
            for (k, item) in m.iter() {
                t.set(Value::Str(k.clone()), table_from_json(item));
            }
            Value::Table(std::rc::Rc::new(std::cell::RefCell::new(t)))
        }
    }
}

fn json_from_value(v: &Value) -> emerag_json::Value {
    match v {
        Value::Nil => emerag_json::Value::Null,
        Value::Bool(b) => emerag_json::Value::Bool(*b),
        Value::Number(n) => emerag_json::Value::Number(emerag_json::Number::Float(*n)),
        Value::Str(s) => emerag_json::Value::String(s.clone()),
        Value::Function(_) => emerag_json::Value::String("[function]".into()),
        Value::Table(t) => {
            let t = t.borrow();
            let entries = t.iter();
            let is_array = !entries.is_empty()
                && entries.iter().enumerate().all(|(i, (k, _))| match k {
                    Value::Number(n) => (*n - (i + 1) as f64).abs() < f64::EPSILON,
                    _ => false,
                });
            if is_array {
                emerag_json::Value::Array(entries.iter().map(|(_, v)| json_from_value(v)).collect())
            } else {
                let mut m = emerag_json::Map::new();
                for (k, v) in entries {
                    let key = match &k {
                        Value::Str(s) => s.clone(),
                        other => emerag_script::tostring(other),
                    };
                    m.insert(key, json_from_value(&v));
                }
                emerag_json::Value::Object(m)
            }
        }
    }
}

impl AgentHost {
    fn pid_limit_table(&self) -> Value {
        let text = std::fs::read_to_string("/proc/self/limits").unwrap_or_default();
        let mut t = emerag_script::Table::new();
        for line in text.lines() {
            if !line.starts_with("Max processes") {
                continue;
            }
            let parts: Vec<&str> = line.split_whitespace().collect();
            let parse =
                |s: Option<&&str>| -> f64 { s.and_then(|x| x.parse::<f64>().ok()).unwrap_or(-1.0) };
            t.set_str("soft", Value::Number(parse(parts.get(2))));
            t.set_str("hard", Value::Number(parse(parts.get(3))));
            t.set_str("raw", Value::Str(line.trim().to_string()));
            return Value::Table(std::rc::Rc::new(std::cell::RefCell::new(t)));
        }
        t.set_str("soft", Value::Number(-1.0));
        t.set_str("hard", Value::Number(-1.0));
        t.set_str("raw", Value::Str("not available".into()));
        Value::Table(std::rc::Rc::new(std::cell::RefCell::new(t)))
    }
}

impl emerag_script::Host for AgentHost {
    fn call(&mut self, name: &str, args: Vec<Value>) -> std::result::Result<Value, ScriptError> {
        match name {
            "fs.read" => {
                let p = self.path_arg(&args, 0)?;
                let text = emerag_util::fsutil::read_text(&p, 2 * 1024 * 1024)
                    .map_err(|e| ScriptError::host(e.to_string(), 0))?;
                Ok(Value::Str(text))
            }
            "fs.write" => {
                let p = self.path_arg(&args, 0)?;
                let content = Self::str_arg(&args, 1)?;
                emerag_util::fsutil::write_text_atomic(&p, &content)
                    .map_err(|e| ScriptError::host(e.to_string(), 0))?;
                Ok(Value::Number(content.len() as f64))
            }
            "fs.append" => {
                let p = self.path_arg(&args, 0)?;
                let content = Self::str_arg(&args, 1)?;
                emerag_util::fsutil::append_line(&p, content.trim_end_matches('\n'))
                    .map_err(|e| ScriptError::host(e.to_string(), 0))?;
                Ok(Value::Nil)
            }
            "fs.list" => {
                let p = self.path_arg(&args, 0)?;
                let mut t = emerag_script::Table::new();
                for (i, (path, is_dir)) in emerag_util::fsutil::list_dir(&p)
                    .map_err(|e| ScriptError::host(e.to_string(), 0))?
                    .iter()
                    .enumerate()
                {
                    let mut e = emerag_script::Table::new();
                    e.set_str(
                        "name",
                        Value::Str(
                            path.file_name()
                                .unwrap_or_default()
                                .to_string_lossy()
                                .to_string(),
                        ),
                    );
                    e.set_str("dir", Value::Bool(*is_dir));
                    e.set_str(
                        "size",
                        Value::Number(emerag_util::fsutil::file_size(path).unwrap_or(0) as f64),
                    );
                    t.set(
                        Value::Number((i + 1) as f64),
                        Value::Table(std::rc::Rc::new(std::cell::RefCell::new(e))),
                    );
                }
                Ok(Value::Table(std::rc::Rc::new(std::cell::RefCell::new(t))))
            }
            "fs.mkdir" => {
                let p = self.path_arg(&args, 0)?;
                emerag_util::fsutil::ensure_dir(&p)
                    .map_err(|e| ScriptError::host(e.to_string(), 0))?;
                Ok(Value::Nil)
            }
            "fs.remove" => {
                let p = self.path_arg(&args, 0)?;
                let res = if p.is_dir() {
                    std::fs::remove_dir_all(&p)
                } else {
                    std::fs::remove_file(&p)
                };
                res.map_err(|e| ScriptError::host(format!("remove {}: {e}", p.display()), 0))?;
                Ok(Value::Nil)
            }
            "fs.rename" => {
                let from = self.path_arg(&args, 0)?;
                let to = self.path_arg(&args, 1)?;
                std::fs::rename(&from, &to).map_err(|e| ScriptError::host(e.to_string(), 0))?;
                Ok(Value::Nil)
            }
            "fs.exists" => {
                let p = self.path_arg(&args, 0)?;
                Ok(Value::Bool(p.exists()))
            }
            "fs.stat" => {
                let p = self.path_arg(&args, 0)?;
                let meta = std::fs::metadata(&p)
                    .map_err(|e| ScriptError::host(format!("stat {}: {e}", p.display()), 0))?;
                let mut t = emerag_script::Table::new();
                t.set_str("size", Value::Number(meta.len() as f64));
                t.set_str("dir", Value::Bool(meta.is_dir()));
                t.set_str("file", Value::Bool(meta.is_file()));
                if let Ok(modified) = meta.modified() {
                    if let Ok(d) = modified.duration_since(std::time::UNIX_EPOCH) {
                        t.set_str("mtime_ms", Value::Number(d.as_millis() as f64));
                    }
                }
                Ok(Value::Table(std::rc::Rc::new(std::cell::RefCell::new(t))))
            }
            "env.get" => {
                let key = Self::str_arg(&args, 0)?;
                Ok(match std::env::var(&key) {
                    Ok(v) => Value::Str(v),
                    Err(_) => Value::Nil,
                })
            }
            "proc.run" => {
                let command = Self::str_arg(&args, 0)?;
                let timeout_ms = args
                    .get(1)
                    .and_then(|v| v.as_f64())
                    .map(|f| f.max(1.0) as u64)
                    .unwrap_or(30_000);
                let shell = crate::tools::shell::detect(None);
                let result = crate::tools::shell::run(
                    &shell,
                    &command,
                    &self.cwd,
                    Duration::from_millis(timeout_ms.min(600_000)),
                    &[],
                    512 * 1024,
                    &CancelToken::new(),
                )
                .map_err(|e| ScriptError::host(e.to_string(), 0))?;
                let mut t = emerag_script::Table::new();
                t.set_str(
                    "code",
                    result
                        .code
                        .map(|c| Value::Number(c as f64))
                        .unwrap_or(Value::Nil),
                );
                t.set_str("stdout", Value::Str(result.stdout));
                t.set_str("stderr", Value::Str(result.stderr));
                t.set_str("timed_out", Value::Bool(result.timed_out));
                Ok(Value::Table(std::rc::Rc::new(std::cell::RefCell::new(t))))
            }
            "time.now_ms" => Ok(Value::Number(emerag_util::time::now_ms() as f64)),
            "sleep.ms" => {
                let ms = args
                    .get(0)
                    .and_then(|v| v.as_f64())
                    .unwrap_or(0.0)
                    .clamp(0.0, 60_000.0);
                std::thread::sleep(Duration::from_millis(ms as u64));
                Ok(Value::Nil)
            }
            "json.encode" => {
                let v = args.get(0).cloned().unwrap_or(Value::Nil);
                Ok(Value::Str(emerag_json::to_string(&json_from_value(&v))))
            }
            "json.decode" => {
                let s = Self::str_arg(&args, 0)?;
                let parsed = emerag_json::parse(&s)
                    .map_err(|e| ScriptError::host(format!("json.decode: {e}"), 0))?;
                Ok(table_from_json(&parsed))
            }
            "hash.sha256" => {
                let s = Self::str_arg(&args, 0)?;
                Ok(Value::Str(emerag_util::hex::encode(&emerag_crypto_sha256(
                    s.as_bytes(),
                ))))
            }
            "base64.encode" => {
                let s = Self::str_arg(&args, 0)?;
                Ok(Value::Str(emerag_util::base64::encode(s.as_bytes())))
            }
            "base64.decode" => {
                let s = Self::str_arg(&args, 0)?;
                let bytes = emerag_util::base64::decode(&s)
                    .map_err(|e| ScriptError::host(e.to_string(), 0))?;
                Ok(Value::Str(String::from_utf8_lossy(&bytes).into_owned()))
            }
            // ---- syscall-level, forkless primitives -----------------------
            // These use Rust std directly. No shell, no Command, no fork.
            "sys.pid" => Ok(Value::Number(std::process::id() as f64)),
            "sys.ppid" => Ok(Value::Number(ppid() as f64)),
            "sys.uid" => Ok(Value::Number(proc_status_id("Uid") as f64)),
            "sys.gid" => Ok(Value::Number(proc_status_id("Gid") as f64)),
            "sys.open" => {
                let p = self.path_arg(&args, 0)?;
                let mode = Self::str_arg(&args, 1).unwrap_or_else(|_| "r".into());
                let mut opts = OpenOptions::new();
                match mode.as_str() {
                    "r" | "rb" => {
                        opts.read(true);
                    }
                    "w" | "wb" => {
                        opts.write(true).create(true).truncate(true);
                    }
                    "a" | "ab" => {
                        opts.append(true).create(true);
                    }
                    "r+" | "rb+" => {
                        opts.read(true).write(true);
                    }
                    "w+" | "wb+" => {
                        opts.read(true).write(true).create(true).truncate(true);
                    }
                    "a+" | "ab+" => {
                        opts.read(true).append(true).create(true);
                    }
                    _ => return Err(ScriptError::host("sys.open mode must be r/w/a/r+/w+/a+", 0)),
                }
                let f = opts
                    .open(&p)
                    .map_err(|e| ScriptError::host(format!("open {}: {e}", p.display()), 0))?;
                let fd = self.next_fd;
                self.next_fd += 1;
                self.fds.insert(fd, f);
                Ok(Value::Number(fd as f64))
            }
            "sys.read" => {
                let fd = args.get(0).and_then(|v| v.as_f64()).unwrap_or(-1.0) as i32;
                let max = args
                    .get(1)
                    .and_then(|v| v.as_f64())
                    .unwrap_or(65536.0)
                    .clamp(1.0, 1024.0 * 1024.0) as usize;
                let f = self
                    .fds
                    .get_mut(&fd)
                    .ok_or_else(|| ScriptError::host("sys.read: bad descriptor", 0))?;
                let mut buf = vec![0u8; max];
                let n = f
                    .read(&mut buf)
                    .map_err(|e| ScriptError::host(format!("read: {e}"), 0))?;
                Ok(Value::Str(String::from_utf8_lossy(&buf[..n]).into_owned()))
            }
            "sys.write" => {
                let fd = args.get(0).and_then(|v| v.as_f64()).unwrap_or(-1.0) as i32;
                let data = Self::str_arg(&args, 1)?;
                let f = self
                    .fds
                    .get_mut(&fd)
                    .ok_or_else(|| ScriptError::host("sys.write: bad descriptor", 0))?;
                f.write_all(data.as_bytes())
                    .map_err(|e| ScriptError::host(format!("write: {e}"), 0))?;
                Ok(Value::Number(data.len() as f64))
            }
            "sys.seek" => {
                let fd = args.get(0).and_then(|v| v.as_f64()).unwrap_or(-1.0) as i32;
                let off = args.get(1).and_then(|v| v.as_f64()).unwrap_or(0.0) as i64;
                let whence = Self::str_arg(&args, 2).unwrap_or_else(|_| "set".into());
                let f = self
                    .fds
                    .get_mut(&fd)
                    .ok_or_else(|| ScriptError::host("sys.seek: bad descriptor", 0))?;
                let pos = match whence.as_str() {
                    "cur" | "current" => f.seek(SeekFrom::Current(off)),
                    "end" => f.seek(SeekFrom::End(off)),
                    _ => f.seek(SeekFrom::Start(off.max(0) as u64)),
                }
                .map_err(|e| ScriptError::host(format!("seek: {e}"), 0))?;
                Ok(Value::Number(pos as f64))
            }
            "sys.close" => {
                let fd = args.get(0).and_then(|v| v.as_f64()).unwrap_or(-1.0) as i32;
                Ok(Value::Bool(self.fds.remove(&fd).is_some()))
            }
            "sys.fsync" => {
                let fd = args.get(0).and_then(|v| v.as_f64()).unwrap_or(-1.0) as i32;
                let f = self
                    .fds
                    .get_mut(&fd)
                    .ok_or_else(|| ScriptError::host("sys.fsync: bad descriptor", 0))?;
                f.sync_all()
                    .map_err(|e| ScriptError::host(format!("fsync: {e}"), 0))?;
                Ok(Value::Nil)
            }
            "sys.read_at" => {
                let p = self.path_arg(&args, 0)?;
                let off = args.get(1).and_then(|v| v.as_f64()).unwrap_or(0.0).max(0.0) as u64;
                let len = args
                    .get(2)
                    .and_then(|v| v.as_f64())
                    .unwrap_or(65536.0)
                    .clamp(1.0, 1024.0 * 1024.0) as usize;
                let mut f = OpenOptions::new()
                    .read(true)
                    .open(&p)
                    .map_err(|e| ScriptError::host(format!("open {}: {e}", p.display()), 0))?;
                f.seek(SeekFrom::Start(off))
                    .map_err(|e| ScriptError::host(format!("seek: {e}"), 0))?;
                let mut buf = vec![0u8; len];
                let n = f
                    .read(&mut buf)
                    .map_err(|e| ScriptError::host(format!("read: {e}"), 0))?;
                Ok(Value::Str(String::from_utf8_lossy(&buf[..n]).into_owned()))
            }
            "sys.write_at" => {
                let p = self.path_arg(&args, 0)?;
                let off = args.get(1).and_then(|v| v.as_f64()).unwrap_or(0.0).max(0.0) as u64;
                let data = Self::str_arg(&args, 2)?;
                let mut f = OpenOptions::new()
                    .write(true)
                    .open(&p)
                    .map_err(|e| ScriptError::host(format!("open {}: {e}", p.display()), 0))?;
                f.seek(SeekFrom::Start(off))
                    .map_err(|e| ScriptError::host(format!("seek: {e}"), 0))?;
                f.write_all(data.as_bytes())
                    .map_err(|e| ScriptError::host(format!("write: {e}"), 0))?;
                Ok(Value::Number(data.len() as f64))
            }
            "sys.truncate" => {
                let p = self.path_arg(&args, 0)?;
                let size = args.get(1).and_then(|v| v.as_f64()).unwrap_or(0.0).max(0.0) as u64;
                let f = OpenOptions::new()
                    .write(true)
                    .open(&p)
                    .map_err(|e| ScriptError::host(format!("open {}: {e}", p.display()), 0))?;
                f.set_len(size)
                    .map_err(|e| ScriptError::host(format!("truncate: {e}"), 0))?;
                Ok(Value::Nil)
            }
            "sys.chmod" => {
                let p = self.path_arg(&args, 0)?;
                let mode = args.get(1).and_then(|v| v.as_f64()).unwrap_or(0.0) as u32;
                set_mode(&p, mode)?;
                Ok(Value::Nil)
            }
            "sys.symlink" => {
                let target = self.path_arg(&args, 0)?;
                let link = self.path_arg(&args, 1)?;
                make_symlink(&target, &link)?;
                Ok(Value::Nil)
            }
            "sys.readlink" => {
                let p = self.path_arg(&args, 0)?;
                let target = std::fs::read_link(&p)
                    .map_err(|e| ScriptError::host(format!("readlink {}: {e}", p.display()), 0))?;
                Ok(Value::Str(target.to_string_lossy().into_owned()))
            }
            "sys.link" => {
                let from = self.path_arg(&args, 0)?;
                let to = self.path_arg(&args, 1)?;
                std::fs::hard_link(&from, &to)
                    .map_err(|e| ScriptError::host(format!("link: {e}"), 0))?;
                Ok(Value::Nil)
            }
            "sys.kill" => {
                let pid = args.get(0).and_then(|v| v.as_f64()).unwrap_or(0.0) as i32;
                let sig = signal_number(args.get(1).and_then(|v| v.as_str()).unwrap_or("TERM"));
                kill_pid(pid, sig)?;
                Ok(Value::Nil)
            }
            "sys.pid_limit" => Ok(self.pid_limit_table()),
            "sys.loadavg" => {
                let text = std::fs::read_to_string("/proc/loadavg").unwrap_or_default();
                let mut t = emerag_script::Table::new();
                for (i, part) in text.split_whitespace().take(3).enumerate() {
                    if let Ok(v) = part.parse::<f64>() {
                        t.set_str(["one", "five", "fifteen"][i], Value::Number(v));
                    }
                }
                Ok(Value::Table(std::rc::Rc::new(std::cell::RefCell::new(t))))
            }
            "sys.uptime_ms" => {
                let text = std::fs::read_to_string("/proc/uptime").unwrap_or_default();
                let secs = text
                    .split_whitespace()
                    .next()
                    .and_then(|x| x.parse::<f64>().ok())
                    .unwrap_or(0.0);
                Ok(Value::Number(secs * 1000.0))
            }
            "sys.meminfo" => {
                let text = std::fs::read_to_string("/proc/meminfo").unwrap_or_default();
                let mut t = emerag_script::Table::new();
                for line in text.lines() {
                    if let Some((key, rest)) = line.split_once(':') {
                        let kb = rest
                            .split_whitespace()
                            .next()
                            .and_then(|x| x.parse::<f64>().ok())
                            .unwrap_or(0.0);
                        t.set_str(key.trim(), Value::Number(kb * 1024.0));
                    }
                }
                Ok(Value::Table(std::rc::Rc::new(std::cell::RefCell::new(t))))
            }
            "sys.random_hex" => {
                let n = args
                    .get(0)
                    .and_then(|v| v.as_f64())
                    .unwrap_or(16.0)
                    .clamp(1.0, 4096.0) as usize;
                let mut bytes = vec![0u8; n];
                emerag_util::rand::fill_bytes(&mut bytes)
                    .map_err(|e| ScriptError::host(format!("random: {e}"), 0))?;
                Ok(Value::Str(emerag_util::hex::encode(&bytes)))
            }
            "sys.os" => Ok(Value::Str(emerag_util::sys::os_name().into())),
            "sys.arch" => Ok(Value::Str(emerag_util::sys::arch().into())),
            "sys.cwd" => Ok(Value::Str(self.cwd.to_string_lossy().into())),
            other => Err(ScriptError::host(
                format!("unknown host function '{other}'"),
                0,
            )),
        }
    }

    fn print(&mut self, text: &str) {
        self.push_output(text);
        if !text.ends_with('\n') {
            self.push_output("\n");
        }
    }
}

/// SHA-256 without pulling the whole crypto crate into the agent's dependency
/// list: the script tool is allowed to be slow, so this delegates to the
/// crypto crate through a tiny wrapper module.
fn emerag_crypto_sha256(data: &[u8]) -> [u8; 32] {
    emerag_crypto::hash::sha256(data)
}

fn ppid() -> u32 {
    let text = std::fs::read_to_string("/proc/self/stat").unwrap_or_default();
    let rest = match text.rsplit_once(')') {
        Some((_, r)) => r,
        None => return 0,
    };
    // state, ppid, ...
    rest.split_whitespace()
        .nth(1)
        .and_then(|x| x.parse().ok())
        .unwrap_or(0)
}

fn proc_status_id(key: &str) -> u32 {
    let text = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix(key) {
            if let Some(rest) = rest.strip_prefix(':') {
                if let Some(v) = rest.split_whitespace().next() {
                    if let Ok(n) = v.parse() {
                        return n;
                    }
                }
            }
        }
    }
    0
}

fn signal_number(name: &str) -> i32 {
    match name.to_ascii_uppercase().as_str() {
        "HUP" => 1,
        "INT" => 2,
        "QUIT" => 3,
        "KILL" => 9,
        "USR1" => 10,
        "USR2" => 12,
        "TERM" => 15,
        "CONT" => 18,
        "STOP" => 19,
        _ => name.parse::<i32>().unwrap_or(15),
    }
}

#[cfg(unix)]
fn kill_pid(pid: i32, sig: i32) -> std::result::Result<(), ScriptError> {
    extern "C" {
        fn kill(pid: i32, sig: i32) -> i32;
    }
    let rc = unsafe { kill(pid, sig) };
    if rc == 0 {
        Ok(())
    } else {
        Err(ScriptError::host(
            format!("kill {pid}: {}", std::io::Error::last_os_error()),
            0,
        ))
    }
}

#[cfg(not(unix))]
fn kill_pid(_pid: i32, _sig: i32) -> std::result::Result<(), ScriptError> {
    Err(ScriptError::host(
        "sys.kill is not supported on this platform",
        0,
    ))
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> std::result::Result<(), ScriptError> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .map_err(|e| ScriptError::host(format!("chmod {}: {e}", path.display()), 0))
}

#[cfg(not(unix))]
fn set_mode(path: &Path, _mode: u32) -> std::result::Result<(), ScriptError> {
    Err(ScriptError::host(
        format!(
            "sys.chmod is not supported on this platform: {}",
            path.display()
        ),
        0,
    ))
}

#[cfg(unix)]
fn make_symlink(target: &Path, link: &Path) -> std::result::Result<(), ScriptError> {
    std::os::unix::fs::symlink(target, link)
        .map_err(|e| ScriptError::host(format!("symlink {}: {e}", link.display()), 0))
}

#[cfg(not(unix))]
fn make_symlink(_target: &Path, link: &Path) -> std::result::Result<(), ScriptError> {
    Err(ScriptError::host(
        format!(
            "sys.symlink is not supported on this platform: {}",
            link.display()
        ),
        0,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::NullUi;

    #[test]
    fn forkless_fd_and_syscalls_work() {
        let dir = std::env::temp_dir().join(format!("emerag-sys-{}", emerag_util::rand::id(6)));
        std::fs::create_dir_all(&dir).unwrap();
        let mut ui = NullUi::default();
        let script = r#"
            local fd = sys.open('a.bin', 'w+')
            sys.write(fd, 'abc')
            sys.seek(fd, 0)
            local head = sys.read(fd, 3)
            sys.seek(fd, 3)
            sys.write(fd, 'd')
            sys.fsync(fd)
            sys.close(fd)
            local tail = sys.read_at('a.bin', 1, 8)
            sys.write_at('a.bin', 4, 'e')
            return head .. '|' .. tail .. '|' .. tostring(sys.pid() > 0) .. '|' .. tostring(sys.pid_limit().soft)
        "#;
        let out = run_script(&dir, script, &mut ui, 65536).unwrap();
        assert!(out.starts_with("abc|bcd|true|"));
        assert_eq!(std::fs::read_to_string(dir.join("a.bin")).unwrap(), "abcde");
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn runs_script_with_fs_host() {
        let dir = std::env::temp_dir().join(format!("emerag-script-{}", emerag_util::rand::id(6)));
        std::fs::create_dir_all(&dir).unwrap();
        let mut ui = NullUi::default();
        let out = run_script(
            &dir,
            "fs.write('a.txt', 'hello') return fs.read('a.txt')",
            &mut ui,
            65536,
        )
        .unwrap();
        assert!(out.contains("hello"));
        std::fs::remove_dir_all(dir).ok();
    }
}
