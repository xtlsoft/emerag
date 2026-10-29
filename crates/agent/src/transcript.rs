//! JSONL transcripts: one record per message or event.
//!
//! Transcripts are optional. When --no-write is active and no explicit path is
//! given, nothing is written to disk.

use emerag_json::{Map, Value};
use emerag_llm::Message;
use std::io::Write;
use std::path::PathBuf;

pub struct Transcript {
    file: Option<std::fs::File>,
    enabled: bool,
}

impl Transcript {
    pub fn new(path: Option<PathBuf>, no_write: bool) -> Self {
        let enabled = path.is_some() || !no_write;
        let open_path = path.clone();
        let mut t = Transcript {
            file: None,
            enabled,
        };
        if let Some(p) = open_path {
            t.open(&p);
        }
        t
    }

    fn open(&mut self, path: &std::path::Path) {
        if let Some(parent) = path.parent() {
            let _ = emerag_util::fsutil::ensure_dir(parent);
        }
        match std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
        {
            Ok(f) => self.file = Some(f),
            Err(_) => self.enabled = false,
        }
    }

    pub fn is_active(&self) -> bool {
        self.file.is_some()
    }

    pub fn record_message(&mut self, msg: &Message) {
        if !self.enabled || self.file.is_none() {
            return;
        }
        let mut m = Map::new();
        m.insert(
            "ts".into(),
            Value::String(emerag_util::time::format_rfc3339(
                emerag_util::time::now_ms(),
            )),
        );
        m.insert("kind".into(), Value::String("message".into()));
        m.insert("role".into(), Value::String(msg.role.as_str().into()));
        m.insert("content".into(), Value::String(msg.content.clone()));
        if let Some(r) = &msg.reasoning {
            m.insert("reasoning".into(), Value::String(r.clone()));
        }
        if !msg.tool_calls.is_empty() {
            let mut calls = Vec::new();
            for c in &msg.tool_calls {
                let mut cm = Map::new();
                cm.insert("id".into(), Value::String(c.id.clone()));
                cm.insert("name".into(), Value::String(c.name.clone()));
                cm.insert("arguments".into(), Value::String(c.arguments.clone()));
                calls.push(Value::Object(cm));
            }
            m.insert("tool_calls".into(), Value::Array(calls));
        }
        if let Some(id) = &msg.tool_call_id {
            m.insert("tool_call_id".into(), Value::String(id.clone()));
        }
        self.write_line(&Value::Object(m));
    }

    pub fn record_meta(&mut self, key: &str, value: Value) {
        if !self.enabled || self.file.is_none() {
            return;
        }
        let mut m = Map::new();
        m.insert(
            "ts".into(),
            Value::String(emerag_util::time::format_rfc3339(
                emerag_util::time::now_ms(),
            )),
        );
        m.insert("kind".into(), Value::String("meta".into()));
        m.insert(key.into(), value);
        self.write_line(&Value::Object(m));
    }

    fn write_line(&mut self, value: &Value) {
        let Some(file) = self.file.as_mut() else {
            return;
        };
        let line = emerag_json::to_string(value);
        if file.write_all(line.as_bytes()).is_ok() && file.write_all(b"\n").is_ok() {
            let _ = file.flush();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use emerag_json::json;

    #[test]
    fn writes_jsonl_messages() {
        let dir = std::env::temp_dir().join(format!("emerag-tr-{}", emerag_util::rand::id(6)));
        let path = dir.join("s.jsonl");
        let mut t = Transcript::new(Some(path.clone()), false);
        t.record_message(&Message::user("hello"));
        t.record_meta("model", json!("x"));
        let text = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2);
        let v = emerag_json::parse(lines[0]).unwrap();
        assert_eq!(v["role"].as_str(), Some("user"));
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn disabled_when_no_write() {
        let t = Transcript::new(None, true);
        assert!(!t.is_active());
    }
}
