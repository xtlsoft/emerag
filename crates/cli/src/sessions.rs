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
    pub name: String,
    pub model: String,
    pub session: Session,
    pub busy: Option<usize>,
    /// Events produced while this session was not the visible one.
    pub output: Vec<OwnedEvent>,
}

impl ChatSession {
    pub fn new(name: impl Into<String>, model: impl Into<String>, session: Session) -> Self {
        ChatSession {
            name: name.into(),
            model: model.into(),
            session,
            busy: None,
            output: Vec::new(),
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

pub fn save(path: &Path, sessions: &[ChatSession], active: usize) -> Result<(), String> {
    let mut root = Map::new();
    root.insert("version".into(), Value::Number(emerag_json::Number::Int(1)));
    root.insert(
        "active".into(),
        Value::Number(emerag_json::Number::Int(active as i64)),
    );
    let mut arr = Vec::new();
    for s in sessions {
        let mut o = Map::new();
        o.insert("name".into(), Value::String(s.name.clone()));
        o.insert("model".into(), Value::String(s.model.clone()));
        o.insert("session".into(), session_json(&s.session));
        arr.push(Value::Object(o));
    }
    root.insert("sessions".into(), Value::Array(arr));
    let text = emerag_json::to_string_pretty(&Value::Object(root));
    if let Some(parent) = path.parent() {
        emerag_util::fsutil::ensure_dir(parent).map_err(|e| e.to_string())?;
    }
    emerag_util::fsutil::write_text_atomic(path, &text).map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

pub fn load(path: &Path) -> Option<(Vec<ChatSession>, usize)> {
    let text = std::fs::read_to_string(path).ok()?;
    let v = emerag_json::parse(&text).ok()?;
    let active = v.get("active").and_then(|x| x.as_u64()).unwrap_or(0) as usize;
    let arr = v.get("sessions")?.as_array()?;
    let mut out = Vec::new();
    for item in arr {
        let name = item
            .get("name")
            .and_then(|x| x.as_str())
            .unwrap_or("session");
        let model = item.get("model").and_then(|x| x.as_str()).unwrap_or("");
        let session = item
            .get("session")
            .map(session_from_json)
            .unwrap_or_default();
        out.push(ChatSession::new(name, model, session));
    }
    if out.is_empty() {
        None
    } else {
        let idx = active.min(out.len() - 1);
        Some((out, idx))
    }
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
