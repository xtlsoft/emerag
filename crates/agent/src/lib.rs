//! emerag-agent - the agent loop, tools, permissions, jobs and subagents.
//!
//! The UI is abstracted behind the Ui trait so the same core drives the TUI,
//! one-shot CLI mode, subagents and tests. No terminal code lives here.

pub mod error;
pub mod permissions;
pub mod probe;
pub mod prompt;
pub mod session;
pub mod skills;
pub mod tools;
pub mod transcript;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use emerag_json::Value;
use emerag_llm::Provider;
use emerag_mcp::{McpClient, McpTool, ServerConfig};

use crate::error::{AgentError, Result};
use crate::permissions::{Mode, PermissionEngine, Risk};
use crate::session::Session;
use crate::skills::SkillRegistry;
use crate::tools::jobs::JobManager;
use crate::tools::shell::ShellInfo;
use crate::transcript::Transcript;

pub use emerag_llm::types::*;

#[derive(Debug, Clone)]
pub struct AgentConfig {
    pub model: String,
    pub mode: Mode,
    pub max_turns: u32,
    pub context_limit: u32,
    pub max_output_tokens: Option<u32>,
    pub temperature: Option<f32>,
    pub cwd: PathBuf,
    pub shell: Option<String>,
    pub system_extra: String,
    pub no_write: bool,
    pub max_tool_output: usize,
    pub command_timeout: Duration,
    pub transcript_path: Option<PathBuf>,
    pub skill_dirs: Vec<PathBuf>,
    pub mcp_servers: Vec<ServerConfig>,
    pub deny_rules: Vec<String>,
    pub allow_elevation: bool,
}

impl Default for AgentConfig {
    fn default() -> Self {
        AgentConfig {
            model: String::new(),
            mode: Mode::Ask,
            max_turns: 32,
            context_limit: 96_000,
            max_output_tokens: None,
            temperature: None,
            cwd: emerag_util::sys::current_dir(),
            shell: None,
            system_extra: String::new(),
            no_write: false,
            max_tool_output: 24_000,
            command_timeout: Duration::from_secs(120),
            transcript_path: None,
            skill_dirs: Vec::new(),
            mcp_servers: Vec::new(),
            deny_rules: Vec::new(),
            allow_elevation: true,
        }
    }
}

#[derive(Debug, Clone)]
pub enum UiEvent<'a> {
    Text(&'a str),
    Reasoning(&'a str),
    ToolStart {
        name: &'a str,
        args_preview: String,
    },
    ToolEnd {
        name: &'a str,
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
    Assistant(&'a str),
}

#[derive(Debug, Clone)]
pub struct Question {
    pub id: String,
    pub prompt: String,
    pub kind: QuestionKind,
}

#[derive(Debug, Clone)]
pub enum QuestionKind {
    YesNo {
        default: bool,
    },
    Choice {
        options: Vec<String>,
        default: usize,
    },
    Text {
        secret: bool,
    },
    Approval {
        tool: String,
        detail: String,
        risk: Risk,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Answer {
    Yes,
    No,
    AllowSession,
    Text(String),
    Index(usize),
    Cancel,
}

pub trait Ui {
    fn event(&mut self, ev: UiEvent<'_>);
    fn ask(&mut self, question: &Question) -> Answer;
    /// Polled by streams and tool loops; set by Ctrl+C in the terminal layer.
    fn is_cancelled(&self) -> bool;
}

/// A Ui for headless use (tests, subagents).
pub struct NullUi {
    pub cancelled: bool,
    pub lines: Vec<String>,
    pub auto_yes: bool,
}

impl Default for NullUi {
    fn default() -> Self {
        NullUi {
            cancelled: false,
            lines: Vec::new(),
            auto_yes: true,
        }
    }
}

impl Ui for NullUi {
    fn event(&mut self, ev: UiEvent<'_>) {
        match ev {
            UiEvent::Text(t) => self.lines.push(t.to_string()),
            UiEvent::Notice(t) => self.lines.push(t),
            UiEvent::Assistant(t) => self.lines.push(t.to_string()),
            _ => {}
        }
    }
    fn ask(&mut self, _q: &Question) -> Answer {
        if self.auto_yes {
            Answer::Yes
        } else {
            Answer::No
        }
    }
    fn is_cancelled(&self) -> bool {
        self.cancelled
    }
}

#[derive(Debug, Clone, Default)]
pub struct TurnResult {
    pub content: String,
    pub tool_calls: usize,
    pub turns: u32,
    pub cancelled: bool,
    pub stop: Option<StopReason>,
}

pub struct McpManager {
    clients: Vec<McpClient>,
    pub tools: Vec<McpTool>,
    pub errors: Vec<String>,
}

impl McpManager {
    pub fn empty() -> Self {
        McpManager {
            clients: Vec::new(),
            tools: Vec::new(),
            errors: Vec::new(),
        }
    }

    pub fn start(configs: &[ServerConfig]) -> Self {
        let mut mgr = McpManager::empty();
        for cfg in configs {
            match McpClient::start(cfg.clone()) {
                Ok(client) => {
                    mgr.tools.extend(client.tools.iter().cloned());
                    mgr.clients.push(client);
                }
                Err(e) => mgr.errors.push(format!("{}: {e}", cfg.name)),
            }
        }
        mgr
    }

    pub fn specs(&self) -> Vec<ToolSpec> {
        self.tools
            .iter()
            .map(|t| {
                ToolSpec::new(
                    t.qualified_name(),
                    format!("[MCP {}] {}", t.server, t.description),
                    t.input_schema.clone(),
                )
            })
            .collect()
    }

    pub fn names(&self) -> Vec<String> {
        self.tools.iter().map(|t| t.qualified_name()).collect()
    }

    pub fn call(&mut self, qualified: &str, args: &Value) -> Result<String> {
        let (server, tool) = parse_mcp_name(qualified)
            .ok_or_else(|| AgentError::new(format!("bad MCP tool name '{qualified}'")))?;
        for client in self.clients.iter_mut() {
            if client
                .tools
                .iter()
                .any(|t| t.name == tool && t.server == server)
            {
                return client.call_tool(&tool, args).map_err(Into::into);
            }
        }
        Err(AgentError::new(format!(
            "MCP tool '{qualified}' is not available (server not running?)"
        )))
    }

    pub fn close(&mut self) {
        for c in self.clients.iter_mut() {
            c.close();
        }
        self.clients.clear();
    }
}

fn parse_mcp_name(qualified: &str) -> Option<(String, String)> {
    let rest = qualified.strip_prefix("mcp__")?;
    let (server, tool) = rest.split_once("__")?;
    Some((server.to_string(), tool.to_string()))
}

pub struct Agent {
    pub config: AgentConfig,
    pub session: Session,
    pub perms: PermissionEngine,
    pub jobs: JobManager,
    pub skills: SkillRegistry,
    pub mcp: McpManager,
    pub shell: ShellInfo,
    provider: Arc<dyn Provider>,
    transcript: Transcript,
    depth: u8,
    env_summary: String,
    /// Shared cancellation flag; the terminal layer holds a clone.
    pub cancel: emerag_util::sync::CancelToken,
}

impl Agent {
    pub fn new(
        config: AgentConfig,
        provider: Arc<dyn Provider>,
        mcp_servers: &[ServerConfig],
    ) -> Result<Self> {
        let shell = tools::shell::detect(config.shell.as_deref());
        let env_summary = probe::summary(&config.cwd, &shell.label());
        let mut skill_dirs = skills::default_dirs(&config.cwd, &config.skill_dirs);
        skill_dirs.dedup();
        let skills = SkillRegistry::discover(skill_dirs);
        let mcp = McpManager::start(mcp_servers);
        let mut perms = PermissionEngine::new(config.mode);
        perms.set_deny_rules(config.deny_rules.clone());
        let transcript = Transcript::new(config.transcript_path.clone(), config.no_write);
        Ok(Agent {
            config,
            session: Session::new(),
            perms,
            jobs: JobManager::new(),
            skills,
            mcp,
            shell,
            provider,
            transcript,
            depth: 0,
            env_summary,
            cancel: emerag_util::sync::CancelToken::new(),
        })
    }

    pub fn set_mode(&mut self, mode: Mode) {
        self.perms.set_mode(mode);
        self.config.mode = mode;
    }

    pub fn set_model(&mut self, model: impl Into<String>) {
        self.config.model = model.into();
    }

    pub fn set_provider(&mut self, provider: Arc<dyn Provider>) {
        self.provider = provider;
    }

    pub fn set_system_extra(&mut self, extra: impl Into<String>) {
        self.config.system_extra = extra.into();
    }

    pub fn clear_session(&mut self) {
        self.session = Session::new();
    }

    /// Replace the conversation (used when switching stored sessions).
    pub fn set_session(&mut self, session: Session) {
        self.session = session;
    }

    /// Clone the conversation for a fork or a background worker.
    pub fn session_snapshot(&self) -> Session {
        self.session.clone()
    }

    /// Force a context compaction pass (used by /compact).
    pub fn compact_now(&mut self, ui: &mut dyn Ui) {
        let system = self.system_prompt();
        self.session.elide_tool_outputs(500);
        self.maybe_compact(&system, ui);
    }

    pub fn usage_total(&self) -> Usage {
        self.session.usage
    }

    pub fn system_prompt(&self) -> String {
        let ctx = prompt::PromptContext {
            cwd: &self.config.cwd,
            shell: &self.shell.label(),
            mode: self.config.mode.as_str(),
            skills: &self.skills,
            mcp_tools: &self.mcp.names(),
            extra: &self.config.system_extra,
            model: &self.config.model,
            is_subagent: self.depth > 0,
            env: &self.env_summary,
        };
        prompt::build(&ctx)
    }

    pub fn all_specs(&self) -> Vec<ToolSpec> {
        let mut specs = tools::all_specs();
        specs.extend(self.mcp.specs());
        specs
    }

    /// Run one user turn to completion, executing tools until the model stops.
    pub fn run_turn(&mut self, input: &str, ui: &mut dyn Ui) -> Result<TurnResult> {
        let system = self.system_prompt();
        self.session.push(Message::user(input));
        self.transcript
            .record_message(&self.session.messages[self.session.messages.len() - 1]);
        let mut out = TurnResult::default();
        let max_turns = self.config.max_turns.max(1);

        while out.turns < max_turns {
            out.turns += 1;
            if self.cancelled(ui) {
                out.cancelled = true;
                break;
            }
            self.maybe_compact(&system, ui);

            let messages = self.request_messages();
            let mut req = ChatRequest::new(&self.config.model, &system, messages);
            req.tools = self.all_specs();
            req.stream = true;
            req.temperature = self.config.temperature;
            req.max_output_tokens = self.config.max_output_tokens;

            let started = std::time::Instant::now();
            ui.event(UiEvent::Status(format!(
                "waiting for {} ...",
                self.config.model
            )));
            let response = self.stream_with_retry(&req, ui)?;
            ui.event(UiEvent::Status(format!(
                "model replied in {}",
                emerag_util::time::fmt_duration_ms(started.elapsed().as_millis() as u64)
            )));
            if self.cancelled(ui) {
                out.cancelled = true;
                break;
            }

            let mut assistant = Message::assistant(response.content.clone());
            assistant.tool_calls = response.tool_calls.clone();
            if !response.reasoning.is_empty() {
                assistant.reasoning = Some(response.reasoning.clone());
            }
            self.session.usage.input_tokens += response.usage.input_tokens;
            self.session.usage.output_tokens += response.usage.output_tokens;
            self.session.usage.cached_input_tokens += response.usage.cached_input_tokens;
            self.session.usage.reasoning_tokens += response.usage.reasoning_tokens;
            ui.event(UiEvent::Usage(response.usage));

            let calls = response.tool_calls.clone();
            self.session.push(assistant.clone());
            self.transcript.record_message(&assistant);
            if !response.content.trim().is_empty() {
                out.content.push_str(&response.content);
                ui.event(UiEvent::Assistant(&response.content));
            }
            if calls.is_empty() {
                out.stop = response.stop.clone();
                break;
            }
            out.tool_calls += calls.len();
            for call in calls {
                if self.cancelled(ui) {
                    out.cancelled = true;
                    break;
                }
                let tool_started = std::time::Instant::now();
                let result_text = self.execute_tool(&call.name, &call.arguments, &call.id, ui);
                let (text, ok) = match result_text {
                    Ok(t) => (t, true),
                    Err(e) => (format!("Error: {e}"), false),
                };
                let tool_msg = Message::tool(call.id.clone(), text);
                self.session.push(tool_msg.clone());
                self.transcript.record_message(&tool_msg);
                ui.event(UiEvent::ToolEnd {
                    name: &call.name,
                    ok,
                    summary: tool_summary(&tool_msg.content),
                    duration_ms: tool_started.elapsed().as_millis() as u64,
                });
            }
            if out.cancelled {
                break;
            }
            if response.stop == Some(StopReason::MaxTokens) {
                ui.event(UiEvent::Notice(
                    "model hit the output limit; continuing with a new turn".into(),
                ));
            }
        }

        if out.turns >= max_turns && out.stop.is_none() && !out.cancelled {
            ui.event(UiEvent::Notice(format!(
                "stopped after {} turns (--max-turns); ask me to continue",
                max_turns
            )));
        }
        Ok(out)
    }

    fn cancelled(&self, ui: &dyn Ui) -> bool {
        self.cancel.is_cancelled() || ui.is_cancelled()
    }

    fn request_messages(&self) -> Vec<Message> {
        let mut msgs = Vec::with_capacity(self.session.messages.len() + 1);
        if let Some(summary) = &self.session.summary {
            msgs.push(Message::user(format!(
                "[Summary of earlier conversation]\n{summary}"
            )));
        }
        msgs.extend(self.session.messages.iter().cloned());
        msgs
    }

    fn stream_with_retry(&mut self, req: &ChatRequest, ui: &mut dyn Ui) -> Result<ChatResponse> {
        let mut attempt = 0u32;
        let cancel = self.cancel.clone();
        loop {
            attempt += 1;
            let mut content = String::new();
            let mut reasoning = String::new();
            let mut calls: Vec<ToolCall> = Vec::new();
            let mut usage = Usage::default();
            let mut stop = None;
            let mut stream_error: Option<emerag_llm::Error> = None;
            let mut emitted = false;

            {
                let mut sink = |ev: StreamEvent| -> bool {
                    match ev {
                        StreamEvent::Text(t) => {
                            emitted = true;
                            content.push_str(&t);
                            ui.event(UiEvent::Text(&t));
                        }
                        StreamEvent::Reasoning(r) => {
                            reasoning.push_str(&r);
                            ui.event(UiEvent::Reasoning(&r));
                        }
                        StreamEvent::ToolCall(c) => calls.push(c),
                        StreamEvent::Usage(u) => usage = u,
                        StreamEvent::Done(s) => stop = Some(s),
                        StreamEvent::Error(e) => {
                            stream_error = Some(emerag_llm::Error::protocol(e))
                        }
                    }
                    !(cancel.is_cancelled() || ui.is_cancelled())
                };
                match self.provider.stream(req, &mut sink) {
                    Ok(mut resp) => {
                        if content.is_empty() {
                            content = std::mem::take(&mut resp.content);
                        }
                        if reasoning.is_empty() {
                            reasoning = std::mem::take(&mut resp.reasoning);
                        }
                        if calls.is_empty() {
                            calls = std::mem::take(&mut resp.tool_calls);
                        }
                        if usage.total() == 0 {
                            usage = resp.usage;
                        }
                        if stop.is_none() {
                            stop = resp.stop.take();
                        }
                    }
                    Err(e) => {
                        if e.kind == emerag_llm::ErrorKind::Cancelled || ui.is_cancelled() {
                            return Ok(ChatResponse {
                                content,
                                reasoning,
                                tool_calls: calls,
                                usage,
                                stop: Some(StopReason::Other("cancelled".into())),
                            });
                        }
                        if e.retryable() && attempt <= 3 && !emitted {
                            let delay = 800u64 * attempt as u64;
                            ui.event(UiEvent::Retry {
                                attempt,
                                delay_ms: delay,
                                reason: e.message.clone(),
                            });
                            std::thread::sleep(Duration::from_millis(delay));
                            continue;
                        }
                        return Err(e.into());
                    }
                }
            }
            if let Some(e) = stream_error {
                if attempt <= 3 && !emitted {
                    ui.event(UiEvent::Retry {
                        attempt,
                        delay_ms: 800,
                        reason: e.message.clone(),
                    });
                    std::thread::sleep(Duration::from_millis(800));
                    continue;
                }
                return Err(e.into());
            }
            return Ok(ChatResponse {
                content,
                reasoning,
                tool_calls: calls,
                usage,
                stop,
            });
        }
    }

    fn maybe_compact(&mut self, _system: &str, ui: &mut dyn Ui) {
        let limit = self.config.context_limit as usize;
        if limit == 0 {
            return;
        }
        let budget = limit * 3 / 4;
        if self.session.estimated_tokens() <= budget {
            return;
        }
        ui.event(UiEvent::Status("compacting conversation...".into()));
        self.session.elide_tool_outputs(1500);
        if self.session.estimated_tokens() <= budget {
            return;
        }
        // Summarize everything except the last few messages.
        let keep = 6usize;
        if self.session.messages.len() > keep {
            let split = self.session.messages.len() - keep;
            let older = &self.session.messages[..split];
            let mut transcript = String::new();
            for m in older {
                let text = if m.content.len() > 1500 {
                    format!("{}...", emerag_util::text::truncate(&m.content, 1500))
                } else {
                    m.content.clone()
                };
                transcript.push_str(&format!("{}: {text}\n", m.role.as_str()));
            }
            let summary_prompt = format!(
                "Summarize the following agent transcript for continuation. Keep facts, file paths, commands, \
                 decisions and open problems. Max 400 words.\n\n{transcript}"
            );
            let req = ChatRequest {
                model: self.config.model.clone(),
                system: "You compress conversation history for another AI agent.".into(),
                messages: vec![Message::user(summary_prompt)],
                tools: Vec::new(),
                tool_choice: emerag_llm::ToolChoice::None,
                temperature: Some(0.2),
                max_output_tokens: Some(700),
                stop: Vec::new(),
                stream: true,
                extra_body: emerag_json::Map::new(),
            };
            let mut got = String::new();
            let mut sink = |ev: StreamEvent| -> bool {
                if let StreamEvent::Text(t) = ev {
                    got.push_str(&t);
                }
                true
            };
            if self.provider.stream(&req, &mut sink).is_ok() && !got.trim().is_empty() {
                self.session.summary = Some(got);
                self.session.messages.drain(0..split);
                self.session.elide_tool_outputs(3000);
                return;
            }
        }
        self.session.trim_oldest(budget);
        if self.session.estimated_tokens() > limit {
            self.session.hard_trim(4);
        }
    }

    fn approvals(&mut self, name: &str, args: &Value, ui: &mut dyn Ui) -> bool {
        let risk = tools::risk(name);
        if self.perms.check(name, risk, args, ui) {
            true
        } else {
            false
        }
    }

    fn execute_tool(
        &mut self,
        name: &str,
        arguments: &str,
        _call_id: &str,
        ui: &mut dyn Ui,
    ) -> Result<String> {
        let args = parse_args(arguments);
        ui.event(UiEvent::ToolStart {
            name,
            args_preview: emerag_util::text::truncate_ellipsis(&preview_args(name, &args), 180),
        });
        if !self.approvals(name, &args, ui) {
            return Err(AgentError::new(format!(
                "denied by user or permission mode ({name})"
            )));
        }
        let cwd = self.config.cwd.clone();
        let get = |k: &str| args.get(k).and_then(|v| v.as_str()).map(str::to_string);
        let get_u = |k: &str| args.get(k).and_then(|v| v.as_u64());

        match name {
            tools::SHELL => {
                let command = require_str(&args, "command")?;
                let dir = get("cwd")
                    .map(|c| tools::fs::resolve(&cwd, &c))
                    .unwrap_or(cwd.clone());
                let timeout = Duration::from_millis(
                    get_u("timeout_ms").unwrap_or(self.config.command_timeout.as_millis() as u64),
                );
                let result = tools::shell::run(
                    &self.shell,
                    &command,
                    &dir,
                    timeout,
                    &[],
                    self.config.max_tool_output * 4,
                    &self.cancel,
                )?;
                Ok(result.for_model(self.config.max_tool_output))
            }
            tools::READ_FILE => {
                let path = require_str(&args, "path")?;
                let out = tools::fs::read_file(
                    &cwd,
                    &path,
                    get_u("offset").unwrap_or(1) as usize,
                    get_u("limit").unwrap_or(400) as usize,
                )?;
                Ok(out)
            }
            tools::WRITE_FILE => {
                let path = require_str(&args, "path")?;
                let content = require_str(&args, "content")?;
                tools::fs::write_file(&cwd, &path, &content)
            }
            tools::EDIT_FILE => {
                let path = require_str(&args, "path")?;
                let old = require_str(&args, "old_string")?;
                let new = require_str(&args, "new_string")?;
                let all = args
                    .get("replace_all")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                tools::fs::edit_file(&cwd, &path, &old, &new, all)
            }
            tools::LIST_DIR => {
                let path = get("path").unwrap_or_else(|| ".".into());
                tools::fs::list_dir(&cwd, &path, get_u("depth").unwrap_or(2) as usize)
            }
            tools::GLOB => {
                let pattern = require_str(&args, "pattern")?;
                let root = get("path");
                tools::fs::glob(
                    &cwd,
                    &pattern,
                    root.as_deref(),
                    get_u("limit").unwrap_or(200) as usize,
                )
            }
            tools::GREP => {
                let pattern = require_str(&args, "pattern")?;
                let root = get("path");
                let include = get("include");
                let ic = args
                    .get("ignore_case")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                tools::fs::grep(
                    &cwd,
                    &pattern,
                    root.as_deref(),
                    include.as_deref(),
                    ic,
                    get_u("max_results").unwrap_or(100) as usize,
                )
            }
            tools::SCRIPT => {
                let source = match (get("source"), get("path")) {
                    (Some(s), _) => s,
                    (None, Some(p)) => {
                        let path = tools::fs::resolve(&cwd, &p);
                        emerag_util::fsutil::read_text(&path, 512 * 1024)?
                    }
                    _ => return Err(AgentError::new("script needs source or path")),
                };
                tools::script_host::run_script(&cwd, &source, ui, self.config.max_tool_output)
            }
            tools::ASK_USER => {
                let prompt = require_str(&args, "question")?;
                let options: Vec<String> = args
                    .get("options")
                    .and_then(|v| v.as_array())
                    .map(|a| {
                        a.iter()
                            .filter_map(|v| v.as_str().map(str::to_string))
                            .collect()
                    })
                    .unwrap_or_default();
                let q = Question {
                    id: format!("q-{}", emerag_util::sync::next_id()),
                    prompt,
                    kind: if options.is_empty() {
                        QuestionKind::Text { secret: false }
                    } else {
                        QuestionKind::Choice {
                            options,
                            default: 0,
                        }
                    },
                };
                match ui.ask(&q) {
                    Answer::Text(t) => Ok(t),
                    Answer::Index(i) => Ok(format!("user chose option {}", i + 1)),
                    Answer::Yes => Ok("yes".into()),
                    Answer::No => Ok("no".into()),
                    Answer::Cancel => Err(AgentError::new("user cancelled the question")),
                    Answer::AllowSession => Ok("yes".into()),
                }
            }
            tools::TASK => {
                let description = get("description").unwrap_or_else(|| "subtask".into());
                let prompt = require_str(&args, "prompt")?;
                self.run_subagent(&description, &prompt, ui)
            }
            tools::JOB_START => {
                let command = require_str(&args, "command")?;
                let dir = get("cwd")
                    .map(|c| tools::fs::resolve(&cwd, &c))
                    .unwrap_or(cwd.clone());
                let timeout = get_u("timeout_ms").map(Duration::from_millis);
                let id = self.jobs.start(&self.shell, &command, &dir, timeout)?;
                self.jobs.prune();
                Ok(format!(
                    "started job {id}\nPoll with job_output id={id}, or job_list to see all."
                ))
            }
            tools::JOB_OUTPUT => {
                let id = require_str(&args, "id")?;
                let wait = Duration::from_millis(get_u("wait_ms").unwrap_or(0).min(30_000));
                self.jobs.output(&id, wait, false)
            }
            tools::JOB_LIST => Ok(self.jobs.list()),
            tools::JOB_KILL => {
                let id = require_str(&args, "id")?;
                self.jobs.kill(&id)
            }
            tools::SKILL => {
                let name = require_str(&args, "name")?;
                match self.skills.get(&name) {
                    Some(skill) => {
                        let body = skills::load_body(skill)?;
                        Ok(format!("[skill: {}]\n{body}", skill.name))
                    }
                    None => Err(AgentError::new(format!(
                        "unknown skill '{name}'; available: {}",
                        self.skills.names().join(", ")
                    ))),
                }
            }
            tools::RUN_ELEVATED => {
                if !self.config.allow_elevation {
                    return Err(AgentError::new("elevation is disabled in this session"));
                }
                let command = require_str(&args, "command")?;
                let reason = get("reason").unwrap_or_default();
                self.run_elevated(&command, &reason, ui)
            }
            other if other.starts_with("mcp__") => self.mcp.call(other, &args),
            other => Err(AgentError::new(format!("unknown tool '{other}'"))),
        }
    }

    fn run_elevated(&mut self, command: &str, reason: &str, ui: &mut dyn Ui) -> Result<String> {
        let cwd = self.config.cwd.clone();
        let quoted = emerag_util::sys::shell_quote(command);
        let has_sudo = emerag_util::sys::which("sudo").is_some();
        let has_doas = emerag_util::sys::which("doas").is_some();

        // First, check whether sudo already has a valid timestamp. This is the
        // normal passwordless case (NOPASSWD or a recent sudo -v). It must not
        // run the requested command: a failing command is not an auth failure,
        // and running it twice would be a serious surprise.
        if has_sudo {
            let probe = tools::shell::run(
                &self.shell,
                "sudo -n -v",
                &cwd,
                self.config.command_timeout,
                &[],
                4096,
                &self.cancel,
            )?;
            if probe.code == Some(0) {
                let result = tools::shell::run(
                    &self.shell,
                    &format!("sudo -n -- sh -c {quoted}"),
                    &cwd,
                    self.config.command_timeout,
                    &[],
                    self.config.max_tool_output * 2,
                    &self.cancel,
                )?;
                return Self::elevated_result("sudo", reason, result, self.config.max_tool_output);
            }
        }

        // doas has no portable stdin-password mode. Only use its noninteractive
        // form; never let it grab the TUI's terminal for a password prompt.
        if !has_sudo && has_doas {
            let result = tools::shell::run(
                &self.shell,
                &format!("doas -n sh -c {quoted}"),
                &cwd,
                self.config.command_timeout,
                &[],
                self.config.max_tool_output * 2,
                &self.cancel,
            )?;
            if result.code == Some(0) {
                return Self::elevated_result("doas", reason, result, self.config.max_tool_output);
            }
        }

        if !has_sudo {
            return Err(AgentError::new(if has_doas {
                "doas needs a password but has no stdin mode; no sudo available to elevate"
            } else {
                "no sudo/doas available; cannot elevate on this system"
            }));
        }

        // Ask for the password only when sudo itself says the cached credential
        // is not valid. Validate it with sudo -v, then run the command exactly
        // once with sudo -n.
        let answer = ui.ask(&Question {
            id: format!("sudopw-{}", emerag_util::sync::next_id()),
            prompt: "sudo password".to_string(),
            kind: QuestionKind::Text { secret: true },
        });
        let password = match answer {
            Answer::Text(t) => t,
            _ => return Err(AgentError::new("elevation cancelled")),
        };
        let validate = tools::shell::run_with_input(
            &self.shell,
            "sudo -S -p '' -v",
            &cwd,
            self.config.command_timeout,
            &[],
            4096,
            &self.cancel,
            Some(
                format!(
                    "{password}
"
                )
                .into_bytes(),
            ),
        )?;
        if validate.code != Some(0) {
            return Err(AgentError::new(format!(
                "sudo authentication failed: {}",
                emerag_util::text::truncate(&validate.stderr, 300)
            )));
        }
        let result = tools::shell::run(
            &self.shell,
            &format!("sudo -n -- sh -c {quoted}"),
            &cwd,
            self.config.command_timeout,
            &[],
            self.config.max_tool_output * 2,
            &self.cancel,
        )?;
        Self::elevated_result("sudo", reason, result, self.config.max_tool_output)
    }

    fn elevated_result(
        program: &str,
        reason: &str,
        result: tools::shell::CommandResult,
        max_output: usize,
    ) -> Result<String> {
        if result.code == Some(0) {
            Ok(format!(
                "[elevated via {program}]{}{}
{}",
                if reason.is_empty() { "" } else { ": " },
                reason,
                result.for_model(max_output)
            ))
        } else {
            Err(AgentError::new(format!(
                "{program} command failed (exit {:?}); output: {}",
                result.code,
                emerag_util::text::truncate(&result.stderr, 500)
            )))
        }
    }
    fn run_subagent(
        &mut self,
        description: &str,
        prompt: &str,
        parent_ui: &mut dyn Ui,
    ) -> Result<String> {
        if self.depth >= 1 {
            return Err(AgentError::new("subagents cannot spawn subagents"));
        }
        parent_ui.event(UiEvent::Status(format!("subagent: {description}")));
        let mut cfg = self.config.clone();
        cfg.max_turns = 12;
        cfg.mode = Mode::Auto;
        cfg.mcp_servers = Vec::new();
        cfg.transcript_path = None;
        let mut child = Agent::new(cfg, self.provider.clone(), &[])?;
        child.depth = self.depth + 1;
        let mut ui = NullUi {
            auto_yes: true,
            ..Default::default()
        };
        let result = child.run_turn(prompt, &mut ui)?;
        let mut out = String::new();
        out.push_str(&format!(
            "[subagent {} finished after {} turns, {} tool calls]\n",
            description, result.turns, result.tool_calls
        ));
        if result.content.trim().is_empty() {
            out.push_str("(no final message; last tool outputs below)\n");
            for line in ui.lines.iter().rev().take(20).rev() {
                out.push_str(&emerag_util::text::truncate(line, 400));
                out.push('\n');
            }
        } else {
            out.push_str(&result.content);
        }
        Ok(out)
    }

    pub fn shutdown(&mut self) {
        self.jobs.kill_all();
        self.mcp.close();
    }
}

impl Drop for Agent {
    fn drop(&mut self) {
        self.jobs.kill_all();
    }
}

fn parse_args(raw: &str) -> Value {
    if raw.trim().is_empty() {
        return Value::Object(emerag_json::Map::new());
    }
    match emerag_json::parse(raw) {
        Ok(v) => v,
        Err(_) => emerag_json::parse_prefix(raw)
            .map(|(v, _)| v)
            .unwrap_or(Value::Null),
    }
}

fn require_str(args: &Value, key: &str) -> Result<String> {
    args.get(key)
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .ok_or_else(|| AgentError::new(format!("missing required argument '{key}'")))
}

fn preview_args(name: &str, args: &Value) -> String {
    permissions::describe_call(name, args)
}

fn tool_summary(text: &str) -> String {
    let first = text.lines().find(|l| !l.trim().is_empty()).unwrap_or("");
    emerag_util::text::truncate_ellipsis(first, 120)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mcp_names_parse() {
        assert_eq!(
            parse_mcp_name("mcp__fs__read_file"),
            Some(("fs".to_string(), "read_file".to_string()))
        );
        assert!(parse_mcp_name("shell").is_none());
    }

    #[test]
    fn args_parse_tolerates_noise() {
        assert_eq!(parse_args("{\"a\":1} x")["a"].as_i64(), Some(1));
        assert!(parse_args("").is_object());
    }
}
