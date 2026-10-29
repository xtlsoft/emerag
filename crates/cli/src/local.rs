//! Local model management and the self-extracting offline release.
//!
//! The offline release is a normal emerag binary with a payload appended and a
//! 64-byte trailer at EOF:
//!
//!   0..8   magic  "EMERAGPK"
//!   8..16  payload offset, little endian u64
//!  16..24  payload length, little endian u64
//!  24..56  SHA-256 of the payload
//!  56..64  reserved (zero)
//!
//! The payload is a simple container:
//!
//!   "EMERAGBD" (8) | version u32 | entry count u32
//!   repeated: name_len u16 | name | mode u32 | size u64 | bytes
//!
//! Appending to ELF/PE/Mach-O binaries is safe as long as the file is signed
//! *after* bundling; see docs/LOCAL-MODELS.md.

use crate::config::Config;
use emerag_util::sys;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

const MAGIC: &[u8; 8] = b"EMERAGPK";
const TRAILER_LEN: u64 = 64;
const BUNDLE_MAGIC: &[u8; 8] = b"EMERAGBD";
const MAX_PAYLOAD: u64 = 32 * 1024 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Payload {
    pub offset: u64,
    pub length: u64,
    pub sha256: [u8; 32],
}

/// Parse the 64-byte trailer. Pure function, unit-tested.
pub fn parse_trailer(tail: &[u8]) -> Option<Payload> {
    if tail.len() < 64 {
        return None;
    }
    let t = &tail[tail.len() - 64..];
    if &t[..8] != MAGIC {
        return None;
    }
    let offset = u64::from_le_bytes(t[8..16].try_into().ok()?);
    let length = u64::from_le_bytes(t[16..24].try_into().ok()?);
    if length == 0 || length > MAX_PAYLOAD {
        return None;
    }
    let mut sha = [0u8; 32];
    sha.copy_from_slice(&t[24..56]);
    Some(Payload {
        offset,
        length,
        sha256: sha,
    })
}

fn exe_path() -> Result<PathBuf, String> {
    sys::exe_path().map_err(|e| e.to_string())
}

pub fn find_payload() -> Option<(PathBuf, Payload)> {
    let exe = exe_path().ok()?;
    let mut f = std::fs::File::open(&exe).ok()?;
    let len = f.metadata().ok()?.len();
    if len < TRAILER_LEN {
        return None;
    }
    let mut tail = [0u8; 64];
    f.seek(SeekFrom::End(-(TRAILER_LEN as i64))).ok()?;
    f.read_exact(&mut tail).ok()?;
    let payload = parse_trailer(&tail)?;
    if payload.offset.checked_add(payload.length)? > len - TRAILER_LEN {
        return None;
    }
    Some((exe, payload))
}

/// Verify the payload hash without loading the whole thing into memory.
pub fn verify_payload(exe: &Path, payload: &Payload) -> Result<(), String> {
    let mut f = std::fs::File::open(exe).map_err(|e| format!("open {}: {e}", exe.display()))?;
    f.seek(SeekFrom::Start(payload.offset))
        .map_err(|e| e.to_string())?;
    let mut hasher = emerag_crypto::hash::Sha256::new();
    let mut buf = vec![0u8; 256 * 1024];
    let mut remaining = payload.length;
    while remaining > 0 {
        let want = remaining.min(buf.len() as u64) as usize;
        f.read_exact(&mut buf[..want]).map_err(|e| e.to_string())?;
        hasher.update(&buf[..want]);
        remaining -= want as u64;
    }
    let got = hasher.finalize();
    if got != payload.sha256 {
        return Err("offline payload checksum mismatch (truncated or modified file)".into());
    }
    Ok(())
}

fn cache_dir(hash: &[u8; 32]) -> PathBuf {
    let short: String = hash.iter().take(6).map(|b| format!("{b:02x}")).collect();
    sys::cache_dir().join("offline").join(short)
}

struct Entry {
    name: String,
    #[cfg_attr(windows, allow(dead_code))]
    mode: u32,
    data: Vec<u8>,
}

fn parse_bundle(bytes: &[u8]) -> Result<Vec<Entry>, String> {
    if bytes.len() < 16 || &bytes[..8] != BUNDLE_MAGIC {
        return Err("offline payload has an unknown format".into());
    }
    let version = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
    if version != 1 {
        return Err(format!(
            "offline payload version {version} is not supported"
        ));
    }
    let count = u32::from_le_bytes(bytes[12..16].try_into().unwrap()) as usize;
    if count > 10_000 {
        return Err("offline payload has too many entries".into());
    }
    let mut pos = 16usize;
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        if pos + 2 > bytes.len() {
            return Err("truncated offline payload".into());
        }
        let name_len = u16::from_le_bytes(bytes[pos..pos + 2].try_into().unwrap()) as usize;
        pos += 2;
        if name_len == 0 || name_len > 1024 || pos + name_len + 12 > bytes.len() {
            return Err("invalid entry in offline payload".into());
        }
        let name = String::from_utf8(bytes[pos..pos + name_len].to_vec())
            .map_err(|_| "entry name is not UTF-8".to_string())?;
        pos += name_len;
        let mode = u32::from_le_bytes(bytes[pos..pos + 4].try_into().unwrap());
        pos += 4;
        let size = u64::from_le_bytes(bytes[pos..pos + 8].try_into().unwrap());
        pos += 8;
        if size > bytes.len() as u64 || pos + size as usize > bytes.len() {
            return Err("truncated entry data in offline payload".into());
        }
        let data = bytes[pos..pos + size as usize].to_vec();
        pos += size as usize;
        if name.contains("..") || name.starts_with('/') || name.contains('\\') {
            return Err(format!("refusing unsafe entry name '{name}'"));
        }
        out.push(Entry { name, mode, data });
    }
    Ok(out)
}

fn read_payload(exe: &Path, payload: &Payload) -> Result<Vec<u8>, String> {
    let mut f = std::fs::File::open(exe).map_err(|e| e.to_string())?;
    f.seek(SeekFrom::Start(payload.offset))
        .map_err(|e| e.to_string())?;
    let mut bytes = vec![0u8; payload.length as usize];
    f.read_exact(&mut bytes).map_err(|e| e.to_string())?;
    Ok(bytes)
}

/// Extract the bundle once and return the directory.
pub fn extract() -> Result<PathBuf, String> {
    let (exe, payload) =
        find_payload().ok_or_else(|| "this binary has no offline payload".to_string())?;
    let dir = cache_dir(&payload.sha256);
    let done = dir.join(".complete");
    if done.exists() {
        return Ok(dir);
    }
    verify_payload(&exe, &payload)?;
    let bytes = read_payload(&exe, &payload)?;
    let entries = parse_bundle(&bytes)?;
    emerag_util::fsutil::ensure_dir(&dir).map_err(|e| e.to_string())?;
    for entry in entries {
        let path = dir.join(&entry.name);
        if let Some(parent) = path.parent() {
            emerag_util::fsutil::ensure_dir(parent).map_err(|e| e.to_string())?;
        }
        std::fs::write(&path, &entry.data)
            .map_err(|e| format!("extract {}: {e}", path.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(
                &path,
                std::fs::Permissions::from_mode(entry.mode & 0o777),
            );
        }
    }
    let mut marker = std::fs::File::create(&done).map_err(|e| e.to_string())?;
    let _ = marker.write_all(b"ok");
    Ok(dir)
}

fn find_in(dir: &Path, predicate: impl Fn(&str) -> bool) -> Option<PathBuf> {
    let entries = std::fs::read_dir(dir).ok()?;
    for e in entries.flatten() {
        let name = e.file_name().to_string_lossy().to_string();
        if predicate(&name) {
            return Some(e.path());
        }
    }
    None
}

pub fn status(cfg: &Config) {
    println!("local models");
    println!("============");
    for (label, bin, url) in [
        (
            "llama.cpp server",
            "llama-server",
            "http://127.0.0.1:9931/v1",
        ),
        ("ollama", "ollama", "http://127.0.0.1:11434/v1"),
        ("lmstudio", "lms", "http://127.0.0.1:1234/v1"),
    ] {
        let found = sys::which(bin).map(|p| p.display().to_string());
        println!(
            "{:<16} {:<40} {}",
            label,
            found.unwrap_or_else(|| "not found".into()),
            url
        );
    }
    match find_payload() {
        Some((exe, p)) => {
            println!();
            println!(
                "offline payload: {} ({} bytes, sha256 {}..)",
                exe.display(),
                p.length,
                emerag_util::hex::encode(&p.sha256[..4])
            );
            match extract() {
                Ok(dir) => {
                    println!("extracted to:   {}", dir.display());
                    if let Some(model) = find_in(&dir, |n| n.ends_with(".gguf")) {
                        println!("model:          {}", model.display());
                    }
                }
                Err(e) => println!("extract failed: {e}"),
            }
        }
        None => {
            println!();
            println!("no offline payload in this binary (standard build)");
        }
    }
    println!();
    println!(
        "current endpoint: {}",
        if cfg.base_url.is_empty() {
            "(none)"
        } else {
            &cfg.base_url
        }
    );
    println!();
    println!("Use an existing server:");
    println!("  emerag --base-url http://127.0.0.1:9931/v1 --model <model>");
}

fn pid_file() -> PathBuf {
    sys::cache_dir().join("local-server.pid")
}

pub fn stop() -> Result<(), String> {
    let path = pid_file();
    let pid = std::fs::read_to_string(&path).map_err(|_| "no local server pid file".to_string())?;
    let pid: u32 = pid.trim().parse().map_err(|_| "bad pid file".to_string())?;
    #[cfg(unix)]
    {
        let rc = unsafe { kill(pid as i32, 15) };
        if rc != 0 {
            return Err(format!("cannot signal pid {pid}"));
        }
    }
    #[cfg(windows)]
    {
        let _ = std::process::Command::new("taskkill")
            .args(["/PID", &pid.to_string(), "/F"])
            .status();
    }
    let _ = std::fs::remove_file(&path);
    println!("stopped local server (pid {pid})");
    Ok(())
}

#[cfg(unix)]
extern "C" {
    #[link_name = "kill"]
    fn kill(pid: i32, sig: i32) -> i32;
}

pub fn up(model_arg: Option<&str>) -> Result<(), String> {
    // 1. Self-extracting offline payload.
    if let Some(_) = find_payload() {
        let dir = extract()?;
        let server = find_in(&dir, |n| n.starts_with("llama-server"))
            .or_else(|| find_in(&dir, |n| n == "llama-server.exe"))
            .ok_or_else(|| "offline payload has no llama-server binary".to_string())?;
        let model = match model_arg {
            Some(m) if m.ends_with(".gguf") => PathBuf::from(m),
            _ => find_in(&dir, |n| n.ends_with(".gguf"))
                .ok_or_else(|| "offline payload has no .gguf model".to_string())?,
        };
        return launch(&server, &model);
    }
    // 2. System-installed server.
    if let Some(bin) = sys::which("llama-server") {
        let model = model_arg
            .map(PathBuf::from)
            .or_else(|| find_in(Path::new("."), |n| n.ends_with(".gguf")))
            .ok_or_else(|| "no model file: emerag local up --model /path/model.gguf".to_string())?;
        return launch(&bin, &model);
    }
    if sys::which("ollama").is_some() {
        println!("ollama is installed. Pull a model, then point emerag at it:");
        println!("  ollama pull qwen3:0.6b");
        println!("  emerag --provider ollama --model qwen3:0.6b");
        return Ok(());
    }
    Err("no local runtime found. Use the offline release or install llama.cpp/ollama.".into())
}

fn launch(server: &Path, model: &Path) -> Result<(), String> {
    let port = 9931u16;
    println!("starting {} with {}", server.display(), model.display());
    let mut cmd = std::process::Command::new(server);
    cmd.args([
        "-m",
        &model.display().to_string(),
        "--host",
        "127.0.0.1",
        "--port",
        &port.to_string(),
        "-c",
        "4096",
        "--no-webui",
    ]);
    let child = cmd
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|e| format!("cannot start {}: {e}", server.display()))?;
    emerag_util::fsutil::ensure_dir(&sys::cache_dir()).ok();
    let _ = std::fs::write(pid_file(), child.id().to_string());
    print!("waiting for the server on 127.0.0.1:{port} ");
    let deadline = Instant::now() + Duration::from_secs(90);
    while Instant::now() < deadline {
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
            println!("ready");
            println!();
            println!("use it with:");
            let name = model
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default();
            println!("  emerag --provider llamacpp --model \"{name}\"");
            println!("or:  emerag --base-url http://127.0.0.1:{port}/v1 --model local");
            println!("stop with: emerag local stop");
            return Ok(());
        }
        print!(".");
        let _ = std::io::stdout().flush();
        std::thread::sleep(Duration::from_millis(500));
    }
    Err("server did not become ready within 90s".into())
}

pub fn models() -> Result<(), String> {
    let mut found = Vec::new();
    for dir in [
        PathBuf::from("."),
        sys::home_dir().unwrap_or_default().join("models"),
    ] {
        if let Ok(entries) = std::fs::read_dir(&dir) {
            for e in entries.flatten() {
                let p = e.path();
                if p.extension()
                    .map(|x| x.eq_ignore_ascii_case("gguf"))
                    .unwrap_or(false)
                {
                    found.push(p);
                }
            }
        }
    }
    if found.is_empty() {
        println!("no .gguf files in ./ or ~/models");
    } else {
        for p in found {
            println!("{}", p.display());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trailer_requires_magic_and_bounds() {
        let mut tail = [0u8; 64];
        assert!(parse_trailer(&tail).is_none());
        tail[..8].copy_from_slice(MAGIC);
        tail[8..16].copy_from_slice(&100u64.to_le_bytes());
        tail[16..24].copy_from_slice(&50u64.to_le_bytes());
        let p = parse_trailer(&tail).unwrap();
        assert_eq!(p.offset, 100);
        assert_eq!(p.length, 50);
        tail[16..24].copy_from_slice(&0u64.to_le_bytes());
        assert!(parse_trailer(&tail).is_none());
    }

    #[test]
    fn bundle_parser_roundtrips() {
        let mut b = Vec::new();
        b.extend_from_slice(BUNDLE_MAGIC);
        b.extend_from_slice(&1u32.to_le_bytes());
        b.extend_from_slice(&1u32.to_le_bytes());
        b.extend_from_slice(&4u16.to_le_bytes());
        b.extend_from_slice(b"main");
        b.extend_from_slice(&0o755u32.to_le_bytes());
        b.extend_from_slice(&3u64.to_le_bytes());
        b.extend_from_slice(b"abc");
        let entries = parse_bundle(&b).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "main");
        assert_eq!(entries[0].data, b"abc");
    }

    #[test]
    fn bundle_rejects_traversal() {
        let mut b = Vec::new();
        b.extend_from_slice(BUNDLE_MAGIC);
        b.extend_from_slice(&1u32.to_le_bytes());
        b.extend_from_slice(&1u32.to_le_bytes());
        b.extend_from_slice(&8u16.to_le_bytes());
        b.extend_from_slice(b"../evil");
        b.extend_from_slice(&0u32.to_le_bytes());
        b.extend_from_slice(&0u64.to_le_bytes());
        assert!(parse_bundle(&b).is_err());
    }
}
