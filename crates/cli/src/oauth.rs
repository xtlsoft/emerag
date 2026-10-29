//! DeepSeek account sign-in over a loopback browser callback.
//!
//! Works without an editor or clipboard: print a URL, wait for the platform to
//! redirect to 127.0.0.1, exchange the code, store the grant. On Termux the
//! phone's browser can reach the loopback listener directly, and on a desktop
//! the default browser is opened automatically.

use crate::config::Config;
use emerag_llm::deepseek_auth::{self, DEFAULT_PLATFORM};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc;
use std::time::{Duration, Instant};

const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(600);

pub fn login_deepseek(cfg: &mut Config, save: bool) -> Result<(), String> {
    let listener = TcpListener::bind("127.0.0.1:0")
        .map_err(|e| format!("cannot open the local sign-in callback listener: {e}"))?;
    let port = listener
        .local_addr()
        .map_err(|e| format!("cannot read callback port: {e}"))?
        .port();
    let redirect_uri = format!("http://127.0.0.1:{port}/oauth/callback");
    let start = deepseek_auth::start_login(DEFAULT_PLATFORM, &redirect_uri)
        .map_err(|e| format!("DeepSeek sign-in did not start: {e}"))?;

    println!();
    println!("Sign in to DeepSeek");
    println!("===================");
    println!("Open this URL in a browser on this device (or on a phone):");
    println!();
    println!("  {}", start.authorize_url);
    println!();
    println!("The browser must be able to reach 127.0.0.1:{port} on this machine.");
    println!(
        "Waiting up to {} seconds for the sign-in to finish...",
        start.expires_in.min(600)
    );
    try_open(&start.authorize_url);

    listener.set_nonblocking(true).ok();
    let (tx, rx) = mpsc::channel();
    let deadline =
        Instant::now() + ATTEMPT_TIMEOUT.min(Duration::from_secs(start.expires_in.max(60)));
    let expected_state = start.state.clone();
    std::thread::spawn(move || callback_loop(listener, tx, deadline, expected_state));

    let started = Instant::now();
    let mut last_tick = Instant::now();
    let code = loop {
        match rx.recv_timeout(Duration::from_millis(500)) {
            Ok(Ok((code, state))) => {
                if state.len() != start.state.len()
                    || !eq_ct(state.as_bytes(), start.state.as_bytes())
                {
                    eprintln!("ignoring a callback with a mismatched state (possible forgery)");
                    continue;
                }
                break code;
            }
            Ok(Err(e)) => {
                deepseek_auth::cancel_login(&start);
                return Err(e);
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                if started.elapsed() > ATTEMPT_TIMEOUT {
                    deepseek_auth::cancel_login(&start);
                    return Err("timed out waiting for browser sign-in".into());
                }
                if last_tick.elapsed() >= Duration::from_secs(10) {
                    last_tick = Instant::now();
                    println!("  still waiting ({}s) ...", started.elapsed().as_secs());
                }
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                deepseek_auth::cancel_login(&start);
                return Err("sign-in listener stopped unexpectedly".into());
            }
        }
    };

    println!("Callback received; exchanging the code...");
    let grant =
        deepseek_auth::exchange_code(&start, &code).map_err(|e| format!("sign-in failed: {e}"))?;
    cfg.account_token = grant.token;
    cfg.provider = "deepseek-account".into();
    cfg.base_url = "https://api.deepseek.com".into();
    cfg.api = "chat".into();
    cfg.model.clear();

    let name = user_label(&grant.user);
    println!(
        "Signed in{}",
        if name.is_empty() {
            String::new()
        } else {
            format!(" as {name}")
        }
    );
    if save {
        if cfg.no_write {
            println!("--no-write: the login is kept in memory for this run only.");
        } else {
            let path = Config::config_path();
            cfg.save(&path)
                .map_err(|e| format!("signed in, but saving the config failed: {e}"))?;
            println!("Saved credentials to {}", path.display());
        }
    }
    Ok(())
}

pub fn logout(cfg: &mut Config) -> Result<(), String> {
    if cfg.account_token.is_empty() {
        println!("not signed in with a DeepSeek account");
        return Ok(());
    }
    let platform = "https://platform.deepseek.com";
    let token = cfg.account_token.clone();
    cfg.account_token.clear();
    if !cfg.no_write {
        let _ = cfg.save(&Config::config_path());
    }
    let _ = deepseek_auth::logout(platform, &token);
    println!("signed out (local grant removed)");
    Ok(())
}

fn callback_loop(
    listener: TcpListener,
    tx: mpsc::Sender<Result<(String, String), String>>,
    deadline: Instant,
    expected_state: String,
) {
    while Instant::now() < deadline {
        match listener.accept() {
            Ok((mut stream, _)) => {
                let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
                let request = read_request(&mut stream);
                if let Some(err) = callback_error(&request) {
                    let _ = respond(&mut stream, 400, &format!("sign-in failed: {err}"));
                    let _ = tx.send(Err(format!("sign-in was not completed: {err}")));
                    return;
                }
                let Some((path, code, state)) = parse_callback(&request) else {
                    let _ = respond(&mut stream, 404, "Not found");
                    continue;
                };
                if path != "/oauth/callback" {
                    let _ = respond(&mut stream, 404, "Not found");
                    continue;
                }
                if state.len() != expected_state.len()
                    || !eq_ct(state.as_bytes(), expected_state.as_bytes())
                {
                    let _ = respond(&mut stream, 400, "state mismatch; start the sign-in again");
                    continue;
                }
                let _ = respond(
                    &mut stream,
                    200,
                    "emerag: callback received. Return to the terminal for the result.",
                );
                let _ = tx.send(Ok((code, state)));
                return;
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(200));
            }
            Err(e) => {
                let _ = tx.send(Err(format!("callback listener: {e}")));
                return;
            }
        }
    }
    let _ = tx.send(Err("timed out waiting for browser sign-in".into()));
}

fn read_request(stream: &mut TcpStream) -> String {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                buf.extend_from_slice(&chunk[..n]);
                if buf.windows(4).any(|w| w == b"\r\n\r\n") || buf.len() > 16 * 1024 {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    String::from_utf8_lossy(&buf).into_owned()
}

fn callback_error(request: &str) -> Option<String> {
    let target = request.lines().next()?.split_whitespace().nth(1)?;
    let (_, query) = target.split_once('?')?;
    for pair in query.split('&') {
        let (k, v) = pair.split_once('=')?;
        if k == "error" || k == "error_description" {
            let v = percent_decode(v);
            if !v.is_empty() {
                return Some(v);
            }
        }
    }
    None
}

fn parse_callback(request: &str) -> Option<(String, String, String)> {
    let line = request.lines().next()?;
    let mut parts = line.split_whitespace();
    let method = parts.next()?;
    let target = parts.next()?;
    if method != "GET" {
        return None;
    }
    let (path, query) = match target.split_once('?') {
        Some((p, q)) => (p, q),
        None => (target, ""),
    };
    let mut code = None;
    let mut state = None;
    for pair in query.split('&') {
        let (k, v) = match pair.split_once('=') {
            Some(kv) => kv,
            None => continue,
        };
        let value = percent_decode(v);
        match k {
            "code" => code = Some(value),
            "state" => state = Some(value),
            _ => {}
        }
    }
    Some((path.to_string(), code?, state?))
}

fn eq_ct(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                let hi = hex_val(bytes[i + 1]);
                let lo = hex_val(bytes[i + 2]);
                if let (Some(h), Some(l)) = (hi, lo) {
                    out.push((h << 4) | l);
                    i += 3;
                    continue;
                }
                out.push(bytes[i]);
                i += 1;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn respond(stream: &mut TcpStream, status: u16, body: &str) -> std::io::Result<()> {
    let reason = if status == 200 { "OK" } else { "Not Found" };
    let response = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\n\r\n{}",
        body.len(),
        body
    );
    stream.write_all(response.as_bytes())?;
    stream.flush()
}

fn try_open(url: &str) {
    let candidates: &[(&str, &[&str])] = &[
        ("termux-open-url", &[]),
        ("xdg-open", &[]),
        ("open", &[]),
        ("wslview", &[]),
    ];
    for (bin, args) in candidates {
        if emerag_util::sys::which(bin).is_none() {
            continue;
        }
        let mut cmd = std::process::Command::new(bin);
        for a in *args {
            cmd.arg(a);
        }
        cmd.arg(url);
        cmd.stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        if cmd.spawn().is_ok() {
            return;
        }
    }
    #[cfg(windows)]
    {
        let _ = std::process::Command::new("cmd")
            .args(["/C", "start", "", url])
            .spawn();
    }
}

fn user_label(user: &emerag_json::Value) -> String {
    for key in ["name", "display_name", "email", "phone", "uid"] {
        if let Some(v) = user.get(key).and_then(|v| v.as_str()) {
            if !v.is_empty() {
                return emerag_util::text::truncate_ellipsis(v, 80);
            }
        }
    }
    String::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_callback_query() {
        let req = "GET /oauth/callback?code=abc123&state=xyz HTTP/1.1\r\nHost: x\r\n\r\n";
        let (path, code, state) = parse_callback(req).unwrap();
        assert_eq!(path, "/oauth/callback");
        assert_eq!(code, "abc123");
        assert_eq!(state, "xyz");
    }

    #[test]
    fn decodes_percent_escapes() {
        assert_eq!(percent_decode("a%20b%2Fc+d"), "a b/c d");
    }
}
