//! Multi-session state, persistence and background-turn plumbing.
//!
//! A session is the conversation plus the model that was active for it. The
//! agent itself stays in the App for the foreground turn; background turns get
//! their own Agent built from the same configuration and report events through
//! a channel, so they can run while another session is being used.

use std::path::Path;
use std::sync::mpsc::{Receiver, Sender};

use emerag_agent::session::Session;
use emerag_agent::{Answer, Question, Ui, UiEvent};
use emerag_json::{Map, Value};
use emerag_llm::{Message, Role, ToolCall, Usage};
use emerag_util::sync::CancelToken;

#[derive(Clone)]
pub struct ChatSession {
    /// Stable identity used to merge with other emerag processes that share
    /// the same sessions file.
    pub id: String,
    pub name: String,
    pub model: String,
    pub session: Session,
    pub busy: Option<usize>,
    /// Events produced while this session was not the visible one.
    pub output: Vec<OwnedEvent>,
    /// Serialized form at the last load or save. A session whose current form
    /// still equals this has not been changed by this process.
    saved: Option<String>,
    /// Deleted by another process while unchanged here: not written back
    /// unless this process changes it again.
    gone: bool,
}

impl ChatSession {
    pub fn new(name: impl Into<String>, model: impl Into<String>, session: Session) -> Self {
        ChatSession {
            id: emerag_util::rand::id(12),
            name: name.into(),
            model: model.into(),
            session,
            busy: None,
            output: Vec::new(),
            saved: None,
            gone: false,
        }
    }

    pub fn summary(&self) -> String {
        let first = self
            .session
            .messages
            .iter()
            .find(|m| m.role == Role::User)
            .map(|m| emerag_util::text::single_line(&m.content))
            .unwrap_or_else(|| "(empty)".into());
        let first: String = first.chars().take(48).collect();
        format!(
            "{}: {} msgs, {} turns, model {} - {}",
            self.name,
            self.session.messages.len(),
            self.session.turns,
            if self.model.is_empty() {
                "(unset)"
            } else {
                &self.model
            },
            first
        )
    }
}

#[derive(Clone, Debug)]
pub enum OwnedEvent {
    Text(String),
    Reasoning(String),
    ToolStart {
        name: String,
        args_preview: String,
    },
    ToolEnd {
        name: String,
        ok: bool,
        summary: String,
        duration_ms: u64,
    },
    Notice(String),
    Status(String),
    Retry {
        attempt: u32,
        delay_ms: u64,
        reason: String,
    },
    Usage(Usage),
    Assistant(String),
}

impl OwnedEvent {
    pub fn from_event(ev: UiEvent<'_>) -> Self {
        match ev {
            UiEvent::Text(t) => OwnedEvent::Text(t.to_string()),
            UiEvent::Reasoning(t) => OwnedEvent::Reasoning(t.to_string()),
            UiEvent::ToolStart { name, args_preview } => OwnedEvent::ToolStart {
                name: name.to_string(),
                args_preview,
            },
            UiEvent::ToolEnd {
                name,
                ok,
                summary,
                duration_ms,
            } => OwnedEvent::ToolEnd {
                name: name.to_string(),
                ok,
                summary,
                duration_ms,
            },
            UiEvent::Notice(n) => OwnedEvent::Notice(n),
            UiEvent::Status(s) => OwnedEvent::Status(s),
            UiEvent::Retry {
                attempt,
                delay_ms,
                reason,
            } => OwnedEvent::Retry {
                attempt,
                delay_ms,
                reason,
            },
            UiEvent::Usage(u) => OwnedEvent::Usage(u),
            UiEvent::Assistant(t) => OwnedEvent::Assistant(t.to_string()),
        }
    }

    pub fn emit(&self, ui: &mut dyn Ui) {
        match self {
            OwnedEvent::Text(t) => ui.event(UiEvent::Text(t)),
            OwnedEvent::Reasoning(t) => ui.event(UiEvent::Reasoning(t)),
            OwnedEvent::ToolStart { name, args_preview } => ui.event(UiEvent::ToolStart {
                name,
                args_preview: args_preview.clone(),
            }),
            OwnedEvent::ToolEnd {
                name,
                ok,
                summary,
                duration_ms,
            } => ui.event(UiEvent::ToolEnd {
                name,
                ok: *ok,
                summary: summary.clone(),
                duration_ms: *duration_ms,
            }),
            OwnedEvent::Notice(n) => ui.event(UiEvent::Notice(n.clone())),
            OwnedEvent::Status(s) => ui.event(UiEvent::Status(s.clone())),
            OwnedEvent::Retry {
                attempt,
                delay_ms,
                reason,
            } => ui.event(UiEvent::Retry {
                attempt: *attempt,
                delay_ms: *delay_ms,
                reason: reason.clone(),
            }),
            OwnedEvent::Usage(u) => ui.event(UiEvent::Usage(*u)),
            OwnedEvent::Assistant(t) => ui.event(UiEvent::Assistant(t)),
        }
    }
}

pub enum BgMessage {
    Event(OwnedEvent),
    Ask(Question, Sender<Answer>),
    Done {
        session: Option<Session>,
        error: Option<String>,
        cancelled: bool,
    },
}

pub struct BgHandle {
    pub id: usize,
    pub session_index: usize,
    pub cancel: CancelToken,
    pub rx: Receiver<BgMessage>,
    pub buffer: Vec<OwnedEvent>,
    pub pending: Option<(Question, Sender<Answer>)>,
    pub done: bool,
}

pub struct WorkerUi {
    pub tx: Sender<BgMessage>,
    pub cancel: CancelToken,
}

impl Ui for WorkerUi {
    fn event(&mut self, ev: UiEvent<'_>) {
        let _ = self.tx.send(BgMessage::Event(OwnedEvent::from_event(ev)));
    }

    fn ask(&mut self, question: &Question) -> Answer {
        let (tx, rx) = std::sync::mpsc::channel();
        if self.tx.send(BgMessage::Ask(question.clone(), tx)).is_err() {
            return Answer::No;
        }
        rx.recv().unwrap_or(Answer::No)
    }

    fn is_cancelled(&self) -> bool {
        self.cancel.is_cancelled()
    }
}

fn entry_json(s: &ChatSession) -> Value {
    let mut o = Map::new();
    o.insert("id".into(), Value::String(s.id.clone()));
    o.insert("name".into(), Value::String(s.name.clone()));
    o.insert("model".into(), Value::String(s.model.clone()));
    o.insert("session".into(), session_json(&s.session));
    Value::Object(o)
}

fn entry_from_json(item: &Value) -> ChatSession {
    let name = item
        .get("name")
        .and_then(|x| x.as_str())
        .unwrap_or("session");
    let model = item.get("model").and_then(|x| x.as_str()).unwrap_or("");
    let session = item
        .get("session")
        .map(session_from_json)
        .unwrap_or_default();
    let mut s = ChatSession::new(name, model, session);
    if let Some(id) = item
        .get("id")
        .and_then(|x| x.as_str())
        .filter(|x| !x.is_empty())
    {
        s.id = id.to_string();
    }
    s.saved = Some(emerag_json::to_string(&entry_json(&s)));
    s
}

/// Exclusive lock on the sessions file, held while it is read, merged and
/// rewritten. A lock file (created with create_new) works on every platform
/// and filesystem without FFI; one left behind by a crashed process is taken
/// over once it is older than STALE.
struct FileLock {
    path: std::path::PathBuf,
}

impl FileLock {
    const STALE: std::time::Duration = std::time::Duration::from_secs(10);

    fn acquire(target: &Path) -> Option<FileLock> {
        let mut name = target.file_name()?.to_os_string();
        name.push(".lock");
        let path = target.with_file_name(name);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
        loop {
            match std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
            {
                Ok(mut f) => {
                    use std::io::Write;
                    let _ = write!(f, "{}", std::process::id());
                    return Some(FileLock { path });
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    let stale = std::fs::metadata(&path)
                        .and_then(|m| m.modified())
                        .ok()
                        .and_then(|t| t.elapsed().ok())
                        .is_some_and(|age| age > Self::STALE);
                    if stale {
                        let _ = std::fs::remove_file(&path);
                        continue;
                    }
                    if std::time::Instant::now() >= deadline {
                        return None;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(20));
                }
                // Read-only directory and the like: save without a lock
                // rather than not at all.
                Err(_) => return None,
            }
        }
    }
}

impl Drop for FileLock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Entries currently on disk, by id. Missing or unreadable files count as
/// empty here; [load] is what reports and quarantines a corrupt file.
fn read_disk(path: &Path) -> Vec<ChatSession> {
    let Ok(text) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    let Ok(v) = emerag_json::parse(&text) else {
        return Vec::new();
    };
    v.get("sessions")
        .and_then(|x| x.as_array())
        .map(|arr| arr.iter().map(entry_from_json).collect())
        .unwrap_or_default()
}

/// Save the sessions, merging with whatever other emerag processes wrote to
/// the same file since this one last loaded or saved it:
///
/// * a session changed here is written as it is here (per session, last
///   writer wins);
/// * a session not changed here takes the version on disk, so another
///   process's progress is not overwritten with a stale copy; the active
///   and busy sessions keep their in-memory state, the rest are refreshed;
/// * sessions created elsewhere are appended to `sessions`;
/// * ids in `deleted` are removed from the file and `deleted` is cleared;
/// * a session deleted elsewhere and unchanged here is not written back.
///
/// Indices of existing entries in `sessions` never change, so `active` and
/// background-turn indices stay valid.
pub fn save(
    path: &Path,
    sessions: &mut Vec<ChatSession>,
    active: usize,
    deleted: &mut Vec<String>,
) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        emerag_util::fsutil::ensure_dir(parent).map_err(|e| e.to_string())?;
    }
    let _lock = FileLock::acquire(path);
    let disk = read_disk(path);
    let mut on_disk: std::collections::HashMap<String, ChatSession> =
        disk.iter().cloned().map(|s| (s.id.clone(), s)).collect();

    let mut arr = Vec::new();
    for (i, s) in sessions.iter_mut().enumerate() {
        let current = entry_json(s);
        let text = emerag_json::to_string(&current);
        let changed = s.saved.as_deref() != Some(text.as_str());
        let theirs = on_disk.remove(&s.id);
        if changed {
            s.gone = false;
            arr.push(current);
            s.saved = Some(text);
            continue;
        }
        match theirs {
            Some(other) => {
                let keep_mine = i == active || s.busy.is_some();
                let other_json = entry_json(&other);
                if !keep_mine {
                    s.name = other.name;
                    s.model = other.model;
                    s.session = other.session;
                }
                s.saved = Some(emerag_json::to_string(&other_json));
                arr.push(other_json);
            }
            None if s.saved.is_some() => {
                // Was on disk, unchanged here, now gone: deleted elsewhere.
                s.gone = true;
            }
            None => {
                if !s.gone {
                    arr.push(current);
                    s.saved = Some(text);
                }
            }
        }
    }
    // Sessions another process created.
    for other in disk {
        if on_disk.contains_key(&other.id) && !deleted.contains(&other.id) {
            arr.push(entry_json(&other));
            sessions.push(other);
        }
    }
    deleted.clear();

    let active_id = sessions
        .get(active)
        .map(|s| s.id.clone())
        .unwrap_or_default();
    let active_pos = arr
        .iter()
        .position(|e| e.get("id").and_then(|x| x.as_str()) == Some(active_id.as_str()))
        .unwrap_or(0);
    let mut root = Map::new();
    root.insert("version".into(), Value::Number(emerag_json::Number::Int(2)));
    root.insert(
        "active".into(),
        Value::Number(emerag_json::Number::Int(active_pos as i64)),
    );
    root.insert("active_id".into(), Value::String(active_id));
    root.insert("sessions".into(), Value::Array(arr));
    let text = emerag_json::to_string_pretty(&Value::Object(root));
    emerag_util::fsutil::write_text_private_atomic(path, &text).map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

/// Move an unreadable state file aside so the next save cannot destroy it.
/// Returns where it went.
pub fn quarantine(path: &Path) -> Option<std::path::PathBuf> {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let mut name = path.file_name()?.to_os_string();
    name.push(format!(".corrupt-{ts}"));
    let dest = path.with_file_name(name);
    std::fs::rename(path, &dest).ok()?;
    Some(dest)
}

pub fn load(path: &Path) -> Option<(Vec<ChatSession>, usize)> {
    let bytes = std::fs::read(path).ok()?;
    let parsed = std::str::from_utf8(&bytes)
        .map_err(|e| e.to_string())
        .and_then(|text| emerag_json::parse(text).map_err(|e| e.to_string()));
    let v = match parsed {
        Ok(v) => v,
        Err(e) => {
            // A truncated or corrupt file used to be silently replaced by a
            // fresh "main" session on the next save, losing every
            // conversation. Keep it for recovery instead.
            match quarantine(path) {
                Some(dest) => eprintln!(
                    "emerag: {} is unreadable ({e}); moved it to {} and started fresh",
                    path.display(),
                    dest.display()
                ),
                None => eprintln!("emerag: {} is unreadable ({e})", path.display()),
            }
            return None;
        }
    };
    let arr = v.get("sessions")?.as_array()?;
    let out: Vec<ChatSession> = arr.iter().map(entry_from_json).collect();
    if out.is_empty() {
        return None;
    }
    let by_id = v
        .get("active_id")
        .and_then(|x| x.as_str())
        .and_then(|id| out.iter().position(|s| s.id == id));
    let active = by_id
        .unwrap_or_else(|| v.get("active").and_then(|x| x.as_u64()).unwrap_or(0) as usize)
        .min(out.len() - 1);
    Some((out, active))
}

fn session_json(s: &Session) -> Value {
    let mut o = Map::new();
    o.insert(
        "messages".into(),
        Value::Array(s.messages.iter().map(message_json).collect()),
    );
    let mut u = Map::new();
    u.insert(
        "input".into(),
        Value::Number(emerag_json::Number::Int(s.usage.input_tokens as i64)),
    );
    u.insert(
        "output".into(),
        Value::Number(emerag_json::Number::Int(s.usage.output_tokens as i64)),
    );
    u.insert(
        "cached".into(),
        Value::Number(emerag_json::Number::Int(s.usage.cached_input_tokens as i64)),
    );
    u.insert(
        "reasoning".into(),
        Value::Number(emerag_json::Number::Int(s.usage.reasoning_tokens as i64)),
    );
    o.insert("usage".into(), Value::Object(u));
    o.insert(
        "turns".into(),
        Value::Number(emerag_json::Number::Int(s.turns as i64)),
    );
    if let Some(summary) = &s.summary {
        o.insert("summary".into(), Value::String(summary.clone()));
    }
    Value::Object(o)
}

fn session_from_json(v: &Value) -> Session {
    let mut s = Session::new();
    if let Some(arr) = v.get("messages").and_then(|x| x.as_array()) {
        for m in arr {
            if let Some(msg) = message_from_json(m) {
                s.messages.push(msg);
            }
        }
    }
    if let Some(u) = v.get("usage") {
        s.usage = Usage {
            input_tokens: u.get("input").and_then(|x| x.as_u64()).unwrap_or(0) as u32,
            output_tokens: u.get("output").and_then(|x| x.as_u64()).unwrap_or(0) as u32,
            cached_input_tokens: u.get("cached").and_then(|x| x.as_u64()).unwrap_or(0) as u32,
            reasoning_tokens: u.get("reasoning").and_then(|x| x.as_u64()).unwrap_or(0) as u32,
        };
    }
    s.turns = v.get("turns").and_then(|x| x.as_u64()).unwrap_or(0) as u32;
    s.summary = v
        .get("summary")
        .and_then(|x| x.as_str())
        .map(str::to_string);
    s
}

fn message_json(m: &Message) -> Value {
    let mut o = Map::new();
    o.insert("role".into(), Value::String(m.role.as_str().into()));
    o.insert("content".into(), Value::String(m.content.clone()));
    if let Some(r) = &m.reasoning {
        o.insert("reasoning".into(), Value::String(r.clone()));
    }
    if !m.tool_calls.is_empty() {
        let calls = m
            .tool_calls
            .iter()
            .map(|c| {
                let mut co = Map::new();
                co.insert("id".into(), Value::String(c.id.clone()));
                co.insert("name".into(), Value::String(c.name.clone()));
                co.insert("arguments".into(), Value::String(c.arguments.clone()));
                Value::Object(co)
            })
            .collect();
        o.insert("tool_calls".into(), Value::Array(calls));
    }
    if let Some(id) = &m.tool_call_id {
        o.insert("tool_call_id".into(), Value::String(id.clone()));
    }
    if let Some(n) = &m.name {
        o.insert("name".into(), Value::String(n.clone()));
    }
    Value::Object(o)
}

fn message_from_json(v: &Value) -> Option<Message> {
    let role = match v.get("role")?.as_str()? {
        "system" => Role::System,
        "user" => Role::User,
        "assistant" => Role::Assistant,
        "tool" => Role::Tool,
        _ => return None,
    };
    let mut m = Message::user("");
    m.role = role;
    m.content = v
        .get("content")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string();
    m.reasoning = v
        .get("reasoning")
        .and_then(|x| x.as_str())
        .map(str::to_string);
    if let Some(arr) = v.get("tool_calls").and_then(|x| x.as_array()) {
        for c in arr {
            m.tool_calls.push(ToolCall {
                id: c.get("id").and_then(|x| x.as_str()).unwrap_or("").into(),
                name: c.get("name").and_then(|x| x.as_str()).unwrap_or("").into(),
                arguments: c
                    .get("arguments")
                    .and_then(|x| x.as_str())
                    .unwrap_or("")
                    .into(),
            });
        }
    }
    m.tool_call_id = v
        .get("tool_call_id")
        .and_then(|x| x.as_str())
        .map(str::to_string);
    m.name = v.get("name").and_then(|x| x.as_str()).map(str::to_string);
    Some(m)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_file(tag: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("emerag-sess-{tag}-{}", emerag_util::rand::id(6)));
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("sessions.json")
    }

    fn user(text: &str) -> Message {
        Message::user(text)
    }

    #[test]
    fn concurrent_processes_merge_instead_of_clobbering() {
        let path = tmp_file("merge");
        // Process A creates two sessions.
        let mut a = vec![
            ChatSession::new("main", "m", Session::new()),
            ChatSession::new("side", "m", Session::new()),
        ];
        let mut del_a = Vec::new();
        save(&path, &mut a, 0, &mut del_a).unwrap();

        // Process B starts from the same file.
        let (mut b, b_active) = load(&path).unwrap();
        let mut del_b = Vec::new();
        assert_eq!(b.len(), 2);

        // A works in "side"; B works in "main" and adds a session.
        a[1].session.push(user("from A"));
        save(&path, &mut a, 1, &mut del_a).unwrap();
        b[0].session.push(user("from B"));
        b.push(ChatSession::new("third", "m", Session::new()));
        save(&path, &mut b, b_active, &mut del_b).unwrap();

        let (disk, _) = load(&path).unwrap();
        let names: Vec<_> = disk.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(names, ["main", "side", "third"]);
        assert_eq!(disk[0].session.messages.len(), 1, "B's work in main kept");
        assert_eq!(disk[1].session.messages.len(), 1, "A's work in side kept");
        // B's unchanged, inactive copy of "side" picked up A's message.
        assert_eq!(b[1].session.messages.len(), 1);

        // A saves again: adopts "third", keeps B's main, keeps its own side.
        save(&path, &mut a, 1, &mut del_a).unwrap();
        assert_eq!(a.len(), 3);
        let (disk, active) = load(&path).unwrap();
        assert_eq!(disk.len(), 3);
        assert_eq!(disk[active].name, "side");
        assert_eq!(disk[0].session.messages.len(), 1);

        // B deletes "third"; A must not resurrect it.
        let third = b.remove(2);
        del_b.push(third.id);
        save(&path, &mut b, 0, &mut del_b).unwrap();
        save(&path, &mut a, 1, &mut del_a).unwrap();
        let (disk, _) = load(&path).unwrap();
        assert_eq!(disk.len(), 2);
        assert!(!path.with_file_name("sessions.json.lock").exists());
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
    }

    #[test]
    fn session_json_roundtrip() {
        let mut s = Session::new();
        s.push(Message::user("hello"));
        let mut a = Message::assistant("world");
        a.reasoning = Some("thinking".into());
        a.tool_calls.push(ToolCall::new("1", "read_file", "{}"));
        s.push(a);
        s.turns = 1;
        s.usage.input_tokens = 4;
        let v = session_json(&s);
        let back = session_from_json(&v);
        assert_eq!(back.messages.len(), 2);
        assert_eq!(back.messages[1].reasoning.as_deref(), Some("thinking"));
        assert_eq!(back.messages[1].tool_calls[0].name, "read_file");
        assert_eq!(back.turns, 1);
        assert_eq!(back.usage.input_tokens, 4);
    }
}
