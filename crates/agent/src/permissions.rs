//! Permission modes, session rules and risk classification.

use crate::{Answer, Question, QuestionKind, Ui};
use emerag_json::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Ask,
    Auto,
    ReadOnly,
    Yolo,
}

impl Mode {
    pub fn parse(s: &str) -> Option<Mode> {
        match s.trim().to_ascii_lowercase().as_str() {
            "ask" | "manual" | "default" => Some(Mode::Ask),
            "auto" | "accept" | "yes" => Some(Mode::Auto),
            "read-only" | "readonly" | "ro" | "plan" => Some(Mode::ReadOnly),
            "yolo" | "danger" | "all" => Some(Mode::Yolo),
            _ => None,
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Mode::Ask => "ask",
            Mode::Auto => "auto",
            Mode::ReadOnly => "read-only",
            Mode::Yolo => "yolo",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Risk {
    /// Reads only, no side effects.
    Read,
    /// Writes files or starts processes.
    Write,
    /// Destructive or privileged.
    Destructive,
}

#[derive(Debug, Clone)]
pub struct PermissionEngine {
    pub mode: Mode,
    /// Session-scoped approvals, keyed by tool + short argument signature.
    session_allow: Vec<String>,
    /// Tools that are always denied (config, e.g. "shell:rm -rf *").
    deny: Vec<String>,
}

impl PermissionEngine {
    pub fn new(mode: Mode) -> Self {
        PermissionEngine {
            mode,
            session_allow: Vec::new(),
            deny: Vec::new(),
        }
    }

    pub fn set_mode(&mut self, mode: Mode) {
        self.mode = mode;
    }

    pub fn allow_session(&mut self, key: String) {
        if !self.session_allow.contains(&key) {
            self.session_allow.push(key);
        }
    }

    pub fn set_deny_rules(&mut self, rules: Vec<String>) {
        self.deny = rules;
    }

    pub fn signature(tool: &str, args: &Value) -> String {
        let detail = short_args(args);
        format!("{tool} {detail}")
    }

    /// Decide whether a tool call may run. May ask the user.
    pub fn check(&mut self, tool: &str, risk: Risk, args: &Value, ui: &mut dyn Ui) -> bool {
        let sig = Self::signature(tool, args);
        if self.deny.iter().any(|rule| matches_rule(rule, &sig)) {
            ui.event(crate::UiEvent::Notice(format!("blocked by rule: {sig}")));
            return false;
        }
        if self.mode == Mode::Yolo {
            return true;
        }
        // Elevated operations always need an explicit yes unless yolo.
        let elevated = tool == "run_elevated";
        if self.mode == Mode::Auto && !elevated {
            return true;
        }
        if self.mode == Mode::ReadOnly {
            if risk == Risk::Read && !elevated {
                return true;
            }
            ui.event(crate::UiEvent::Notice(format!(
                "read-only mode: denied {tool} (switch with /mode auto)"
            )));
            return false;
        }
        if self.session_allow.iter().any(|s| s == &sig) {
            return true;
        }
        let question = Question {
            id: format!("perm-{}", emerag_util::sync::next_id()),
            prompt: format!("Allow {}?", describe_call(tool, args)),
            kind: QuestionKind::Approval {
                tool: tool.to_string(),
                detail: sig.clone(),
                risk,
            },
        };
        match ui.ask(&question) {
            Answer::Yes => true,
            Answer::AllowSession => {
                self.allow_session(sig);
                true
            }
            Answer::No | Answer::Cancel | Answer::Text(_) => false,
            Answer::Index(_) => false,
        }
    }
}

fn matches_rule(rule: &str, sig: &str) -> bool {
    // Rules look like "shell:rm -rf *" or "write_file:*".
    if let Some((tool, pat)) = rule.split_once(':') {
        let mut sig_tool = sig.split_once(' ').map(|(t, _)| t).unwrap_or(sig);
        if sig_tool.ends_with(':') {
            sig_tool = &sig_tool[..sig_tool.len() - 1];
        }
        tool == sig_tool || tool == "*" && emerag_util::glob::matches(pat, sig)
    } else {
        emerag_util::glob::matches(rule, sig)
    }
}

fn short_args(args: &Value) -> String {
    let text = match args {
        Value::Object(map) => map
            .iter()
            .map(|(k, v)| match v {
                Value::String(s) => format!("{k}={}", emerag_util::text::single_line(s)),
                _ => format!("{k}={}", emerag_json::to_string(v)),
            })
            .collect::<Vec<_>>()
            .join(" "),
        _ => emerag_json::to_string(args),
    };
    emerag_util::text::truncate_ellipsis(&text, 160)
}

pub fn describe_call(tool: &str, args: &Value) -> String {
    let get = |k: &str| args.get(k).and_then(|v| v.as_str()).unwrap_or("");
    match tool {
        "shell" | "run_elevated" => {
            let cmd = get("command");
            format!("{tool}: {}", emerag_util::text::truncate_ellipsis(cmd, 300))
        }
        "write_file" => format!("write {}", get("path")),
        "edit_file" => format!("edit {}", get("path")),
        "read_file" => format!("read {}", get("path")),
        "list_dir" => format!("list {}", get("path")),
        "glob" => format!("glob {} in {}", get("pattern"), get("path")),
        "grep" => format!("grep {} in {}", get("pattern"), get("path")),
        "script" => "run a script".to_string(),
        "ask_user" => "ask you a question".to_string(),
        "task" => format!("subagent: {}", get("description")),
        "job_start" => format!(
            "background job: {}",
            emerag_util::text::truncate_ellipsis(get("command"), 200)
        ),
        _ => {
            if let Some(mcp) = tool.strip_prefix("mcp__") {
                format!("MCP tool {mcp}")
            } else {
                tool.to_string()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Answer, Question};
    use emerag_json::json;

    struct AlwaysYes;
    impl Ui for AlwaysYes {
        fn event(&mut self, _ev: crate::UiEvent<'_>) {}
        fn ask(&mut self, _q: &Question) -> Answer {
            Answer::Yes
        }
        fn is_cancelled(&self) -> bool {
            false
        }
    }

    #[test]
    fn modes_behave() {
        let mut ui = AlwaysYes;
        let args = json!({"command": "ls"});
        assert!(PermissionEngine::new(Mode::Auto).check("shell", Risk::Write, &args, &mut ui));
        assert!(!PermissionEngine::new(Mode::ReadOnly).check("shell", Risk::Write, &args, &mut ui));
        assert!(PermissionEngine::new(Mode::ReadOnly).check(
            "read_file",
            Risk::Read,
            &args,
            &mut ui
        ));
        assert!(PermissionEngine::new(Mode::Ask).check("shell", Risk::Write, &args, &mut ui));
    }

    #[test]
    fn session_allow_is_sticky() {
        let mut ui = AlwaysYes;
        let mut p = PermissionEngine::new(Mode::Ask);
        p.allow_session(PermissionEngine::signature(
            "shell",
            &json!({"command": "ls"}),
        ));
        assert!(p.check("shell", Risk::Write, &json!({"command": "ls"}), &mut ui));
        assert!(
            !p.check(
                "shell",
                Risk::Write,
                &json!({"command": "rm -rf /"}),
                &mut ui
            ) == false
        );
    }

    #[test]
    fn deny_rules_win() {
        let mut p = PermissionEngine::new(Mode::Yolo);
        p.set_deny_rules(vec!["shell:rm -rf *".into()]);
        assert!(!p.check(
            "shell",
            Risk::Destructive,
            &json!({"command": "rm -rf /"}),
            &mut AlwaysYes
        ));
    }
}
