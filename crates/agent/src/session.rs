//! Conversation state, token estimation and compaction.

use emerag_llm::{Message, Role, Usage};

#[derive(Debug, Clone, Default)]
pub struct Session {
    pub messages: Vec<Message>,
    pub usage: Usage,
    pub turns: u32,
    /// Compacted summaries prepended to the next request as a user message.
    pub summary: Option<String>,
}

impl Session {
    pub fn new() -> Self {
        Session::default()
    }

    pub fn push(&mut self, message: Message) {
        if message.role == Role::User {
            self.turns += 1;
        }
        self.messages.push(message);
    }

    pub fn is_empty(&self) -> bool {
        self.messages.is_empty()
    }

    pub fn estimated_tokens(&self) -> usize {
        let body: usize = self.messages.iter().map(|m| m.estimated_tokens()).sum();
        body + self.summary.as_ref().map(|s| s.len() / 4).unwrap_or(0)
    }

    /// Remove the oldest complete exchange groups until under the budget.
    /// Always keeps the last two messages and never leaves an assistant tool
    /// call without its tool results.
    pub fn trim_oldest(&mut self, target_tokens: usize) -> usize {
        let mut removed = 0;
        while self.estimated_tokens() > target_tokens && self.messages.len() > 4 {
            let cut = next_group_boundary(&self.messages);
            if cut == 0 {
                break;
            }
            for _ in 0..cut {
                self.messages.remove(0);
            }
            removed += cut;
        }
        removed
    }

    /// Replace large tool outputs with a short placeholder. This is the
    /// cheapest way to reclaim context without losing the conversation shape.
    pub fn elide_tool_outputs(&mut self, keep_chars: usize) -> usize {
        let mut saved = 0;
        for m in self.messages.iter_mut() {
            if m.role == Role::Tool && m.content.len() > keep_chars {
                saved += m.content.len() - keep_chars;
                let head: String = m.content.chars().take(keep_chars).collect();
                m.content = format!(
                    "{head}\n[output elided: {} chars removed to save context]",
                    saved
                );
            }
        }
        saved
    }

    /// Keep only the last n messages (used as a last resort).
    pub fn hard_trim(&mut self, keep: usize) {
        if self.messages.len() > keep {
            let start = self.messages.len() - keep;
            self.messages.drain(0..start);
        }
    }
}

/// Find the index of the start of the next user turn, so trimming never
/// separates an assistant tool call from its result.
fn next_group_boundary(messages: &[Message]) -> usize {
    for (i, m) in messages.iter().enumerate().skip(1) {
        if m.role == Role::User {
            return i;
        }
    }
    // No user message: cut everything except the last two messages.
    messages.len().saturating_sub(2)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trimming_respects_turns() {
        let mut s = Session::new();
        for i in 0..10 {
            s.push(Message::user(format!("question {i}")));
            s.push(Message::assistant("answer".repeat(100)));
        }
        let before = s.messages.len();
        s.trim_oldest(100);
        assert!(s.messages.len() < before);
        assert!(s.messages.len() >= 4);
        assert_eq!(s.messages[0].role, Role::User);
    }

    #[test]
    fn tool_outputs_are_elided() {
        let mut s = Session::new();
        s.push(Message::user("run it"));
        s.push(Message::tool("1", "x".repeat(10_000)));
        s.elide_tool_outputs(100);
        assert!(s.messages[1].content.len() < 1000);
        assert!(s.messages[1].content.contains("elided"));
    }

    #[test]
    fn hard_trim_keeps_tail() {
        let mut s = Session::new();
        for i in 0..20 {
            s.push(Message::user(format!("u{i}")));
        }
        s.hard_trim(5);
        assert_eq!(s.messages.len(), 5);
        assert_eq!(s.messages[4].content, "u19");
    }
}
