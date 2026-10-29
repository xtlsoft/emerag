//! Tool catalog: JSON schemas and risk classification.
//!
//! Tool names are short on purpose: models on small context windows spend
//! tokens on names too.

pub mod fs;
pub mod jobs;
pub mod script_host;
pub mod shell;

use crate::permissions::Risk;
use emerag_json::{json, Map, Value};
use emerag_llm::ToolSpec;

pub const SHELL: &str = "shell";
pub const READ_FILE: &str = "read_file";
pub const WRITE_FILE: &str = "write_file";
pub const EDIT_FILE: &str = "edit_file";
pub const LIST_DIR: &str = "list_dir";
pub const GLOB: &str = "glob";
pub const GREP: &str = "grep";
pub const SCRIPT: &str = "script";
pub const ASK_USER: &str = "ask_user";
pub const TASK: &str = "task";
pub const JOB_START: &str = "job_start";
pub const JOB_OUTPUT: &str = "job_output";
pub const JOB_LIST: &str = "job_list";
pub const JOB_KILL: &str = "job_kill";
pub const SKILL: &str = "skill";
pub const RUN_ELEVATED: &str = "run_elevated";

fn obj(props: Value, required: &[&str]) -> Value {
    let mut m = Map::new();
    m.insert("type".into(), Value::String("object".into()));
    m.insert("properties".into(), props);
    m.insert(
        "required".into(),
        Value::Array(
            required
                .iter()
                .map(|s| Value::String(s.to_string()))
                .collect(),
        ),
    );
    m.insert("additionalProperties".into(), Value::Bool(false));
    Value::Object(m)
}

pub fn all_specs() -> Vec<ToolSpec> {
    vec![
        ToolSpec::new(
            SHELL,
            "Run a command in the configured shell and return stdout/stderr.              Commands run non-interactively with a timeout. Use job_start for long-running work.              Shells may be bash, zsh, fish, sh, cmd, pwsh, python or php (see environment).",
            obj(
                json!({
                    "command": {"type": "string", "description": "Command line to run"},
                    "cwd": {"type": "string", "description": "Working directory (defaults to session cwd)"},
                    "timeout_ms": {"type": "integer", "description": "Timeout in milliseconds (default 120000)"}
                }),
                &["command"],
            ),
        ),
        ToolSpec::new(
            READ_FILE,
            "Read a text file with line numbers. Use offset/limit for large files.",
            obj(
                json!({
                    "path": {"type": "string"},
                    "offset": {"type": "integer", "description": "1-based first line"},
                    "limit": {"type": "integer", "description": "max lines (default 400)"}
                }),
                &["path"],
            ),
        ),
        ToolSpec::new(
            WRITE_FILE,
            "Create or overwrite a file with the given content. Parent directories are created.",
            obj(json!({"path": {"type": "string"}, "content": {"type": "string"}}), &["path", "content"]),
        ),
        ToolSpec::new(
            EDIT_FILE,
            "Replace an exact string in a file. old_string must appear exactly once unless replace_all is true.              Include enough surrounding context to be unique.",
            obj(
                json!({
                    "path": {"type": "string"},
                    "old_string": {"type": "string"},
                    "new_string": {"type": "string"},
                    "replace_all": {"type": "boolean"}
                }),
                &["path", "old_string", "new_string"],
            ),
        ),
        ToolSpec::new(
            LIST_DIR,
            "List a directory as a tree (bounded depth). Hidden files are included.",
            obj(
                json!({
                    "path": {"type": "string"},
                    "depth": {"type": "integer", "description": "max depth, default 2"}
                }),
                &["path"],
            ),
        ),
        ToolSpec::new(
            GLOB,
            "Find files by glob pattern (supports **, *, ?, [a-z], {a,b}). Example: src/**/*.rs",
            obj(
                json!({
                    "pattern": {"type": "string"},
                    "path": {"type": "string", "description": "root directory, default cwd"},
                    "limit": {"type": "integer", "description": "default 200"}
                }),
                &["pattern"],
            ),
        ),
        ToolSpec::new(
            GREP,
            "Search file contents for a literal substring (not regex). Returns file:line: text.              Use include to filter by glob.",
            obj(
                json!({
                    "pattern": {"type": "string"},
                    "path": {"type": "string"},
                    "include": {"type": "string", "description": "glob like *.rs"},
                    "ignore_case": {"type": "boolean"},
                    "max_results": {"type": "integer", "description": "default 100"}
                }),
                &["pattern"],
            ),
        ),
        ToolSpec::new(
            SCRIPT,
            "Run a small Lua-subset script when a shell is unavailable or unsafe.              Forkless globals: fs.*, sys.* (descriptors, read_at/write_at, stat, chmod, symlink, kill, pid/limits).              Forking: proc.run needs a child process. Also env.get, json, hash, time, sleep, print.",
            obj(
                json!({
                    "source": {"type": "string", "description": "script source"},
                    "path": {"type": "string", "description": "or a script file to run"},
                    "timeout_ms": {"type": "integer"}
                }),
                &[],
            ),
        ),
        ToolSpec::new(
            ASK_USER,
            "Ask the user a question and return their answer. Use for genuine choices or missing facts, not for confirmation.",
            obj(
                json!({
                    "question": {"type": "string"},
                    "options": {"type": "array", "items": {"type": "string"}, "description": "optional choices"}
                }),
                &["question"],
            ),
        ),
        ToolSpec::new(
            TASK,
            "Delegate a self-contained task to a subagent with a fresh context. Returns its final report.              Use for large searches or independent subtasks; do not use for trivial work.",
            obj(
                json!({
                    "description": {"type": "string", "description": "short task name"},
                    "prompt": {"type": "string", "description": "complete instructions for the subagent"}
                }),
                &["description", "prompt"],
            ),
        ),
        ToolSpec::new(
            JOB_START,
            "Start a command in the background. Returns a job id; poll with job_output.",
            obj(
                json!({
                    "command": {"type": "string"},
                    "cwd": {"type": "string"},
                    "timeout_ms": {"type": "integer", "description": "optional hard limit"}
                }),
                &["command"],
            ),
        ),
        ToolSpec::new(
            JOB_OUTPUT,
            "Read new output from a background job. Set wait_ms to block briefly for more output.",
            obj(json!({"id": {"type": "string"}, "wait_ms": {"type": "integer"}}), &["id"]),
        ),
        ToolSpec::new(JOB_LIST, "List background jobs with status.", obj(json!({}), &[])),
        ToolSpec::new(
            JOB_KILL,
            "Terminate a background job.",
            obj(json!({"id": {"type": "string"}}), &["id"]),
        ),
        ToolSpec::new(
            SKILL,
            "Load a skill by name. Skills are instruction documents discovered from .emerag/skills.",
            obj(json!({"name": {"type": "string"}}), &["name"]),
        ),
        ToolSpec::new(
            RUN_ELEVATED,
            "Run a command with elevated privileges (sudo/doas/pkexec). The user is always asked;              the password is never stored. Prefer non-privileged alternatives.",
            obj(
                json!({
                    "command": {"type": "string"},
                    "reason": {"type": "string", "description": "why elevation is needed"}
                }),
                &["command"],
            ),
        ),
    ]
}

pub fn risk(tool: &str) -> Risk {
    match tool {
        READ_FILE | LIST_DIR | GLOB | GREP | JOB_LIST | JOB_OUTPUT | SKILL | ASK_USER => Risk::Read,
        WRITE_FILE | EDIT_FILE | SHELL | SCRIPT | JOB_START | JOB_KILL | TASK => Risk::Write,
        RUN_ELEVATED => Risk::Destructive,
        t if t.starts_with("mcp__") => Risk::Write,
        _ => Risk::Write,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn specs_are_well_formed() {
        let specs = all_specs();
        assert!(specs.len() >= 12);
        for s in &specs {
            assert!(!s.name.is_empty());
            assert!(s.description.len() > 10);
            assert_eq!(s.parameters["type"].as_str(), Some("object"));
            assert!(s.parameters["properties"].is_object());
        }
    }

    #[test]
    fn risk_classification() {
        assert_eq!(risk(READ_FILE), Risk::Read);
        assert_eq!(risk(WRITE_FILE), Risk::Write);
        assert_eq!(risk(RUN_ELEVATED), Risk::Destructive);
        assert_eq!(risk("mcp__fs__read"), Risk::Write);
    }
}
