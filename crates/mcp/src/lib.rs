//! emerag-mcp - a minimal Model Context Protocol client over stdio.
//!
//! Only what a coding agent needs: spawn a server, initialize, list tools,
//! call tools. No subscriptions, resources or prompts yet (they are cheap to
//! add later; tools are what matter in an emergency).
//!
//! Servers are configured as plain commands, e.g.
//!   [{"name":"fs","command":"npx","args":["-y","@modelcontextprotocol/server-filesystem","/tmp"]}]
//! but emerag also understands hand-written shell scripts that speak JSON-RPC
//! on stdin/stdout, which is the air-gapped-friendly form.

use emerag_json::{json, Map, Value};
use emerag_util::sync::CancelToken;
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{channel, Receiver, RecvTimeoutError};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error {
    pub message: String,
}

impl Error {
    pub fn new(message: impl Into<String>) -> Self {
        Error {
            message: message.into(),
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for Error {}

impl From<emerag_util::Error> for Error {
    fn from(e: emerag_util::Error) -> Self {
        Error::new(e.into_message())
    }
}

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub name: String,
    pub command: String,
    pub args: Vec<String>,
    pub env: Vec<(String, String)>,
    pub cwd: Option<std::path::PathBuf>,
    /// Per-request timeout, including the initialize handshake.
    pub timeout: Duration,
}

impl ServerConfig {
    pub fn new(name: impl Into<String>, command: impl Into<String>) -> Self {
        ServerConfig {
            name: name.into(),
            command: command.into(),
            args: Vec::new(),
            env: Vec::new(),
            cwd: None,
            timeout: Duration::from_secs(20),
        }
    }

    pub fn args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.args = args.into_iter().map(Into::into).collect();
        self
    }

    pub fn env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.env.push((key.into(), value.into()));
        self
    }

    pub fn cwd(mut self, dir: impl Into<std::path::PathBuf>) -> Self {
        self.cwd = Some(dir.into());
        self
    }

    pub fn timeout(mut self, d: Duration) -> Self {
        self.timeout = d;
        self
    }
}

#[derive(Debug, Clone)]
pub struct McpTool {
    pub name: String,
    pub description: String,
    pub input_schema: Value,
    /// Raw server-side name (before namespacing).
    pub server: String,
}

impl McpTool {
    /// Name exposed to the model: mcp__server__tool (only [A-Za-z0-9_-]).
    pub fn qualified_name(&self) -> String {
        format!("mcp__{}__{}", sanitize(&self.server), sanitize(&self.name))
    }
}

fn sanitize(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if c.is_ascii_alphanumeric() || c == '_' || c == '-' {
            out.push(c);
        } else {
            out.push('_');
        }
    }
    if out.is_empty() {
        out.push('_');
    }
    out
}

enum Pending {
    Response(Value),
    // Notifications are ignored for now.
}

pub struct McpClient {
    config: ServerConfig,
    child: Child,
    stdin: ChildStdin,
    rx: Receiver<Pending>,
    next_id: u64,
    pub tools: Vec<McpTool>,
    stderr_tail: Arc<Mutex<Vec<String>>>,
    closed: bool,
}

impl McpClient {
    /// Spawn the server and perform the MCP handshake (initialize +
    /// notifications/initialized + tools/list).
    pub fn start(config: ServerConfig) -> Result<Self> {
        let mut cmd = Command::new(&config.command);
        cmd.args(&config.args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for (k, v) in &config.env {
            cmd.env(k, v);
        }
        if let Some(dir) = &config.cwd {
            cmd.current_dir(dir);
        }
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            const CREATE_NO_WINDOW: u32 = 0x0800_0000;
            cmd.creation_flags(CREATE_NO_WINDOW);
        }
        let mut child = cmd.spawn().map_err(|e| {
            Error::new(format!(
                "mcp '{}': cannot start '{}': {e} (is it installed and on PATH?)",
                config.name, config.command
            ))
        })?;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| Error::new("mcp: child stdin unavailable"))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| Error::new("mcp: child stdout unavailable"))?;
        let stderr = child.stderr.take();
        let (tx, rx) = channel();
        let server_name = config.name.clone();
        std::thread::Builder::new()
            .name(format!("mcp-{}", sanitize(&server_name)))
            .spawn(move || {
                let reader = BufReader::new(stdout);
                for line in reader.lines() {
                    let Ok(line) = line else { break };
                    if line.trim().is_empty() {
                        continue;
                    }
                    match emerag_json::parse(&line) {
                        Ok(value) => {
                            let is_response = value.get("id").is_some()
                                && (value.get("result").is_some() || value.get("error").is_some());
                            if is_response {
                                if tx.send(Pending::Response(value)).is_err() {
                                    break;
                                }
                            }
                            // Server-initiated notifications/requests are ignored:
                            // we advertise no client capabilities.
                        }
                        Err(_) => {
                            // Non-JSON noise on stdout is common with wrappers.
                            continue;
                        }
                    }
                }
            })
            .map_err(|e| Error::new(format!("mcp: cannot spawn reader thread: {e}")))?;

        let tail = Arc::new(Mutex::new(Vec::new()));
        if let Some(stderr) = stderr {
            let tail_clone = tail.clone();
            std::thread::Builder::new()
                .name(format!("mcp-{}-err", sanitize(&server_name)))
                .spawn(move || {
                    let reader = BufReader::new(stderr);
                    for line in reader.lines().map_while(std::result::Result::ok) {
                        let mut t = emerag_util::sync::lock(&tail_clone);
                        if t.len() >= 40 {
                            t.remove(0);
                        }
                        t.push(line);
                    }
                })
                .ok();
        }

        let mut client = McpClient {
            config,
            child,
            stdin,
            rx,
            next_id: 1,
            tools: Vec::new(),
            stderr_tail: tail,
            closed: false,
        };
        client.handshake()?;
        client.tools = client.list_tools()?;
        Ok(client)
    }

    fn handshake(&mut self) -> Result<()> {
        let mut client_info = Map::new();
        client_info.insert("name".into(), Value::String("emerag".into()));
        client_info.insert(
            "version".into(),
            Value::String(env!("CARGO_PKG_VERSION").to_string()),
        );
        let mut params = Map::new();
        params.insert("protocolVersion".into(), Value::String("2025-06-18".into()));
        params.insert("capabilities".into(), Value::Object(Map::new()));
        params.insert("clientInfo".into(), Value::Object(client_info));
        let params = Value::Object(params);
        let result = self.request("initialize", params)?;
        // Some old servers only implement 2024-11-05; we accept whatever they
        // negotiate and continue. If initialize failed, start() already errored.
        let _ = result;
        self.notify("notifications/initialized", Value::Null)?;
        Ok(())
    }

    pub fn list_tools(&mut self) -> Result<Vec<McpTool>> {
        let result = self.request("tools/list", Value::Object(Map::new()))?;
        let mut out = Vec::new();
        if let Some(items) = result.get("tools").and_then(|v| v.as_array()) {
            for item in items {
                let Some(name) = item.get("name").and_then(|v| v.as_str()) else {
                    continue;
                };
                let description = item
                    .get("description")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let schema = item
                    .get("inputSchema")
                    .cloned()
                    .unwrap_or_else(|| json!({"type":"object","properties":{}}));
                out.push(McpTool {
                    name: name.to_string(),
                    description,
                    input_schema: schema,
                    server: self.config.name.clone(),
                });
            }
        }
        Ok(out)
    }

    /// Call a tool and return its textual content. Tool-level errors are
    /// returned as Err with the server's message.
    pub fn call_tool(&mut self, name: &str, arguments: &Value) -> Result<String> {
        let mut params = Map::new();
        params.insert("name".into(), Value::String(name.to_string()));
        params.insert("arguments".into(), arguments.clone());
        let result = self.request("tools/call", Value::Object(params))?;
        let is_error = result
            .get("isError")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let mut text = String::new();
        if let Some(content) = result.get("content").and_then(|v| v.as_array()) {
            for part in content {
                match part.get("type").and_then(|v| v.as_str()) {
                    Some("text") => {
                        if let Some(t) = part.get("text").and_then(|v| v.as_str()) {
                            if !text.is_empty() {
                                text.push('\n');
                            }
                            text.push_str(t);
                        }
                    }
                    Some("image") => {
                        if !text.is_empty() {
                            text.push('\n');
                        }
                        text.push_str("[image content omitted: emerag v1 is text-only]");
                    }
                    Some(other) => {
                        if !text.is_empty() {
                            text.push('\n');
                        }
                        text.push_str(&format!("[{other} content]"));
                    }
                    None => {}
                }
            }
        }
        if text.is_empty() {
            text = emerag_json::to_string(&result);
        }
        if is_error {
            return Err(Error::new(format!("mcp tool '{}' failed: {}", name, text)));
        }
        Ok(text)
    }

    fn request(&mut self, method: &str, params: Value) -> Result<Value> {
        let id = self.next_id;
        self.next_id += 1;
        let mut msg = Map::new();
        msg.insert("jsonrpc".into(), Value::String("2.0".into()));
        msg.insert("id".into(), json!(id as i64));
        msg.insert("method".into(), Value::String(method.to_string()));
        if !params.is_null() {
            msg.insert("params".into(), params);
        }
        self.send(&Value::Object(msg))?;
        let deadline = Instant::now() + self.config.timeout;
        loop {
            let now = Instant::now();
            if now >= deadline {
                return Err(Error::new(format!(
                    "mcp '{}': timeout waiting for {}",
                    self.config.name, method
                )));
            }
            match self.rx.recv_timeout(deadline - now) {
                Ok(Pending::Response(value)) => {
                    let rid = value.get("id").and_then(|v| v.as_i64()).unwrap_or(-1);
                    if rid != id as i64 {
                        continue;
                    }
                    if let Some(err) = value.get("error") {
                        let msg = err
                            .get("message")
                            .and_then(|v| v.as_str())
                            .unwrap_or("unknown JSON-RPC error");
                        return Err(Error::new(format!(
                            "mcp '{}': {} failed: {}",
                            self.config.name, method, msg
                        )));
                    }
                    return Ok(value.get("result").cloned().unwrap_or(Value::Null));
                }
                Err(RecvTimeoutError::Timeout) => {
                    return Err(Error::new(format!(
                        "mcp '{}': timeout waiting for {}",
                        self.config.name, method
                    )))
                }
                Err(RecvTimeoutError::Disconnected) => {
                    let tail = emerag_util::sync::lock(&self.stderr_tail).join("; ");
                    return Err(Error::new(format!(
                        "mcp '{}': server exited during {} (stderr: {})",
                        self.config.name,
                        method,
                        if tail.is_empty() { "none" } else { &tail }
                    )));
                }
            }
        }
    }

    fn notify(&mut self, method: &str, params: Value) -> Result<()> {
        let mut msg = Map::new();
        msg.insert("jsonrpc".into(), Value::String("2.0".into()));
        msg.insert("method".into(), Value::String(method.to_string()));
        if !params.is_null() {
            msg.insert("params".into(), params);
        }
        self.send(&Value::Object(msg))
    }

    fn send(&mut self, value: &Value) -> Result<()> {
        let line = emerag_json::to_string(value);
        if line.len() > 8 * 1024 * 1024 {
            return Err(Error::new("mcp: request too large"));
        }
        self.stdin
            .write_all(line.as_bytes())
            .and_then(|_| self.stdin.write_all(b"\n"))
            .and_then(|_| self.stdin.flush())
            .map_err(|e| Error::new(format!("mcp '{}': write failed: {e}", self.config.name)))
    }

    pub fn stderr_tail(&self) -> Vec<String> {
        emerag_util::sync::lock(&self.stderr_tail).clone()
    }

    pub fn pid(&self) -> u32 {
        self.child.id()
    }

    pub fn close(&mut self) {
        if self.closed {
            return;
        }
        self.closed = true;
        let _ = self.notify("notifications/cancelled", Value::Null);
        let _ = self.child.kill();
        let _ = self.child.wait();
    }

    /// Send a cancellation for an in-flight request (best effort), used when
    /// the user presses Ctrl+C.
    pub fn cancel_all(&mut self, token: &CancelToken) {
        if token.is_cancelled() {
            self.close();
        }
    }
}

impl Drop for McpClient {
    fn drop(&mut self) {
        self.close();
    }
}

/// Parse the config JSON format used by emerag for MCP servers:
/// {"servers":[{"name":"fs","command":"server","args":[],"env":{},"cwd":"/tmp","timeout_secs":20}]}
pub fn parse_server_configs(value: &Value) -> Result<Vec<ServerConfig>> {
    let items: Vec<Value> = if let Some(arr) = value.get("servers").and_then(|v| v.as_array()) {
        arr.clone()
    } else if let Some(arr) = value.as_array() {
        arr.clone()
    } else if let Some(map) = value
        .get("mcpServers")
        .or_else(|| value.get("servers"))
        .and_then(|v| v.as_object())
    {
        // Object form: {"fs": {"command": "...", "args": [...]}}
        map.iter()
            .map(|(name, cfg)| {
                let mut cfg = cfg.clone();
                if let Some(obj) = cfg.as_object_mut() {
                    obj.insert("name".into(), Value::String(name.clone()));
                }
                cfg
            })
            .collect()
    } else {
        Vec::new()
    };
    let mut out = Vec::new();
    for item in items {
        let Some(name) = item.get("name").and_then(|v| v.as_str()) else {
            continue;
        };
        let Some(command) = item.get("command").and_then(|v| v.as_str()) else {
            return Err(Error::new(format!("mcp server '{name}' has no command")));
        };
        let mut cfg = ServerConfig::new(name, command);
        cfg.args = item
            .get("args")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
        if let Some(env) = item.get("env").and_then(|v| v.as_object()) {
            for (k, v) in env.iter() {
                if let Some(val) = v.as_str() {
                    cfg.env.push((k.clone(), val.to_string()));
                }
            }
        }
        if let Some(cwd) = item.get("cwd").and_then(|v| v.as_str()) {
            cfg.cwd = Some(emerag_util::sys::expand_tilde(cwd));
        }
        if let Some(secs) = item.get("timeout_secs").and_then(|v| v.as_u64()) {
            cfg.timeout = Duration::from_secs(secs.max(1));
        }
        cfg.timeout = Duration::from_millis(
            item.get("timeout_ms")
                .and_then(|v| v.as_u64())
                .unwrap_or(cfg.timeout.as_millis() as u64),
        );
        out.push(cfg);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn qualified_names_are_sanitized() {
        let t = McpTool {
            name: "read file".into(),
            description: String::new(),
            input_schema: Value::Null,
            server: "my-server".into(),
        };
        assert_eq!(t.qualified_name(), "mcp__my-server__read_file");
    }

    #[test]
    fn config_parsing_supports_both_shapes() {
        let v = json!({"servers":[{"name":"a","command":"srv","args":["x"],"env":{"K":"V"},"timeout_secs":5}]});
        let cfgs = parse_server_configs(&v).unwrap();
        assert_eq!(cfgs.len(), 1);
        assert_eq!(cfgs[0].args, vec!["x"]);
        assert_eq!(cfgs[0].timeout, Duration::from_secs(5));

        let v = json!({"mcpServers":{"b":{"command":"srv2"}}});
        let cfgs = parse_server_configs(&v).unwrap();
        assert_eq!(cfgs[0].name, "b");
        assert_eq!(cfgs[0].command, "srv2");
    }

    #[test]
    fn jsonrpc_framing_roundtrip() {
        let msg = json!({"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}});
        let line = emerag_json::to_string(&msg);
        assert!(!line.contains('\n'));
        assert_eq!(
            emerag_json::parse(&line).unwrap()["method"].as_str(),
            Some("tools/list")
        );
    }
}
