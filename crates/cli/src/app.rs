//! Interactive session: prompt loop and slash commands.

use crate::args::{self, Cli};
use crate::config::{Config, PermissionMode};
use crate::ui::{Input, TermUi};
use emerag_agent::{Agent, Answer, Question, QuestionKind, Ui};
use emerag_llm::Provider;
use emerag_term::prompt;
use std::io::Write;
use std::sync::Arc;

pub struct App {
    pub cfg: Config,
    pub cli: Cli,
    pub ui: TermUi,
    pub agent: Agent,
}

impl App {
    pub fn banner(&self) {
        if self.cli.quiet {
            return;
        }
        let ascii = self.ui.ascii;
        let rule = if ascii {
            "-".repeat(40)
        } else {
            "─".repeat(40)
        };
        println!("{rule}");
        println!(
            " emerag {}  {}",
            env!("CARGO_PKG_VERSION"),
            if ascii { "" } else { "" }
        );
        println!(" model   {}", display_or(&self.cfg.model, "(not set)"));
        println!(" endpoint {}", display_or(&self.cfg.base_url, "(not set)"));
        println!(" mode    {}", self.cfg.mode.as_str());
        println!(
            " cwd     {}",
            self.cfg
                .workdir
                .clone()
                .unwrap_or_else(emerag_util::sys::current_dir)
                .display()
        );
        println!(" shell   {}", self.agent.shell.label());
        if !self.agent.skills.skills.is_empty() {
            println!(" skills  {} loaded", self.agent.skills.skills.len());
        }
        if !self.agent.mcp.tools.is_empty() {
            println!(" mcp     {} tools", self.agent.mcp.tools.len());
        }
        println!("{rule}");
        println!(" /help for commands, /wizard for setup, /quit to exit");
        if self.cfg.mode == PermissionMode::Ask {
            println!(" ask mode: tool calls need approval (y/n)");
        }
        if self.cfg.no_write {
            println!(" --no-write: nothing is saved to disk");
        }
        if self.cfg.network.insecure {
            println!(" WARNING: TLS verification disabled (--insecure)");
        }
        println!();
    }

    pub fn run(&mut self) -> Result<(), String> {
        self.banner();
        loop {
            let prompt_text = self.prompt();
            let input = match self.ui.read_input(&prompt_text) {
                Ok(i) => i,
                Err(e) if e.is_cancelled() => continue,
                Err(e) => return Err(e.to_string()),
            };
            match input {
                Input::Eof => {
                    println!();
                    break;
                }
                Input::Cancelled => {
                    crate::signals::clear();
                    self.agent.cancel.reset();
                    continue;
                }
                Input::Command(cmd) => {
                    if !self.handle_command(&cmd)? {
                        break;
                    }
                }
                Input::Line(line) => {
                    let line = line.trim().to_string();
                    if line.is_empty() {
                        continue;
                    }
                    if line.starts_with('/') {
                        if !self.handle_command(&line)? {
                            break;
                        }
                    } else {
                        self.run_turn(&line)?;
                    }
                }
            }
        }
        self.agent.shutdown();
        Ok(())
    }

    fn prompt(&self) -> String {
        let mode = self.cfg.mode.as_str();
        if self.ui.width >= 60 {
            format!("emerag[{mode}]> ")
        } else {
            "> ".to_string()
        }
    }

    fn run_turn(&mut self, text: &str) -> Result<(), String> {
        crate::signals::clear();
        self.agent.cancel.reset();
        self.ui.token.reset();
        let result = self.agent.run_turn(text, &mut self.ui);
        crate::signals::clear();
        self.agent.cancel.reset();
        self.ui.token.reset();
        match result {
            Ok(r) => {
                if r.cancelled {
                    println!("(cancelled)");
                }
                if let Some(u) = self.ui.last_usage() {
                    if self.cli.verbose {
                        println!(
                            "(tokens: {} in / {} out, {} total)",
                            u.input_tokens,
                            u.output_tokens,
                            u.total()
                        );
                    }
                }
                Ok(())
            }
            Err(e) => {
                println!("error: {e}");
                Ok(())
            }
        }
    }

    /// Returns false when the session should end.
    pub fn handle_command(&mut self, raw: &str) -> Result<bool, String> {
        let raw = raw.trim();
        let (cmd, rest) = match raw.split_once(char::is_whitespace) {
            Some((c, r)) => (c, r.trim()),
            None => (raw, ""),
        };
        let cmd = cmd.trim_start_matches('/').to_ascii_lowercase();
        let cmd = resolve_command(&cmd);
        match cmd {
            "" => {}
            "help" | "h" | "?" => {
                print!("{}", args::HELP);
                crate::keys_card::print();
            }
            "keys" => crate::keys_card::print(),
            "guide" => {
                let _ = crate::guide::run();
            }
            "quit" | "exit" | "q" => return Ok(false),
            "clear" | "cls" => {
                self.agent.clear_session();
                println!("conversation cleared (system prompt and skills kept)");
            }
            "compact" => {
                self.agent.compact_now(&mut self.ui);
                println!("context compacted");
            }
            "mode" | "perm" | "permissions" => {
                let options = ["ask", "auto", "read-only", "yolo"];
                let current = self.cfg.mode.as_str();
                let default = options.iter().position(|o| *o == current).unwrap_or(0);
                match prompt::prompt_choice_caps(self.ui.caps, "Permission mode", &options, default)
                {
                    Ok(i) => {
                        let mode = match i {
                            1 => PermissionMode::Auto,
                            2 => PermissionMode::ReadOnly,
                            3 => PermissionMode::Yolo,
                            _ => PermissionMode::Ask,
                        };
                        self.cfg.mode = mode.clone();
                        self.agent.set_mode(match mode {
                            PermissionMode::Ask => emerag_agent::permissions::Mode::Ask,
                            PermissionMode::Auto => emerag_agent::permissions::Mode::Auto,
                            PermissionMode::ReadOnly => emerag_agent::permissions::Mode::ReadOnly,
                            PermissionMode::Yolo => emerag_agent::permissions::Mode::Yolo,
                        });
                        println!("mode: {} - {}", mode.as_str(), mode.describe());
                    }
                    Err(_) => println!("(cancelled)"),
                }
            }
            "model" | "m" => {
                let provider: Box<dyn Provider> = crate::providers::build(&self.cfg, &self.cli)
                    .map_err(|e| format!("provider: {e}"))?;
                print!("listing models ... ");
                let _ = std::io::stdout().flush();
                match provider.list_models() {
                    Ok(list) if !list.is_empty() => {
                        println!("{} found", list.len());
                        let mut options: Vec<String> =
                            list.iter().take(80).map(|m| m.id.clone()).collect();
                        options.push("(type a model name)".into());
                        match prompt::prompt_choice_caps(self.ui.caps, "Model", &options, 0) {
                            Ok(i) if i < options.len() - 1 => {
                                let model = options[i].clone();
                                self.cfg.model = model.clone();
                                self.agent.set_model(model.clone());
                                println!("model: {model}");
                            }
                            Ok(_) => {
                                let name = self.ask_text("Model name: ")?;
                                if !name.trim().is_empty() {
                                    self.cfg.model = name.trim().to_string();
                                    self.agent.set_model(name.trim());
                                }
                            }
                            Err(_) => {}
                        }
                    }
                    Ok(_) => println!("provider returned no models"),
                    Err(e) => {
                        println!("cannot list models: {e}");
                        let name = self.ask_text("Model name: ")?;
                        if !name.trim().is_empty() {
                            self.cfg.model = name.trim().to_string();
                            self.agent.set_model(name.trim());
                        }
                    }
                }
            }
            "provider" | "p" => {
                let profiles = emerag_llm::catalog::all();
                let labels: Vec<String> = profiles.iter().map(|p| p.label.to_string()).collect();
                if let Ok(i) = prompt::prompt_choice_caps(self.ui.caps, "Provider", &labels, 0) {
                    let p = &profiles[i];
                    self.cfg.provider = p.id.into();
                    self.cfg.base_url = p.base_url.into();
                    self.cfg.api = p.api.as_str().into();
                    if self.cfg.model.is_empty() {
                        self.cfg.model = p.default_model().into();
                        self.agent.set_model(&self.cfg.model);
                    }
                    println!("provider: {} ({})", p.label, p.base_url);
                    println!("use /auth to set the key, /model to pick a model");
                }
            }
            "auth" | "k" | "key" => {
                let answer = self.ui.ask(&Question {
                    id: "auth".into(),
                    prompt: "API key".into(),
                    kind: QuestionKind::Text { secret: true },
                });
                if let Answer::Text(key) = answer {
                    let key = key.trim().to_string();
                    if !key.is_empty() {
                        self.cfg.api_key = key;
                        self.rebuild_agent()?;
                        println!(
                            "key set for this session ({})",
                            emerag_llm::redact(&self.cfg.api_key)
                        );
                    }
                }
            }
            "wizard" | "w" | "setup" => {
                crate::wizard::run(&mut self.cfg, &self.cli, &mut self.ui)?;
                self.rebuild_agent()?;
                println!("configuration active: {}", self.cfg.redacted_summary());
            }
            "config" | "c" => {
                let v = self.cfg.to_json(false);
                println!("{}", emerag_json::to_string_pretty(&v));
            }
            "doctor" | "d" => {
                let report = crate::doctor::run(&self.cfg, self.ui.ascii, self.ui.color);
                crate::doctor::render(&report, self.ui.ascii, self.ui.color);
            }
            "skills" | "s" => {
                println!("{}", self.agent.skills.catalog());
                for d in &self.agent.skills.dirs {
                    println!("  dir: {}", d.display());
                }
                if rest == "reload" {
                    self.rebuild_agent()?;
                    println!("skills reloaded");
                }
            }
            "mcp" => {
                if self.agent.mcp.tools.is_empty() && self.agent.mcp.errors.is_empty() {
                    println!("no MCP servers configured (add mcp.servers to config.json)");
                }
                for t in &self.agent.mcp.tools {
                    println!(
                        "{:<32} {}",
                        t.qualified_name(),
                        emerag_util::text::single_line(&t.description)
                    );
                }
                for e in &self.agent.mcp.errors {
                    println!("error: {e}");
                }
            }
            "jobs" | "j" => {
                let mut parts = rest.splitn(2, char::is_whitespace);
                let sub = parts.next().unwrap_or("");
                let arg = parts.next().unwrap_or("").trim();
                match sub {
                    "" | "list" => println!("{}", self.agent.jobs.list()),
                    "output" | "out" if !arg.is_empty() => {
                        match self
                            .agent
                            .jobs
                            .output(arg, std::time::Duration::from_millis(0), true)
                        {
                            Ok(o) => println!("{o}"),
                            Err(e) => println!("{e}"),
                        }
                    }
                    "kill" if !arg.is_empty() => match self.agent.jobs.kill(arg) {
                        Ok(o) => println!("{o}"),
                        Err(e) => println!("{e}"),
                    },
                    _ => println!("usage: /jobs [list | output ID | kill ID]"),
                }
            }
            "agents" | "a" => {
                println!("subagents run inline and return a report; none are active now.");
                println!("ask the model to use the task tool for long side work.");
            }
            "transcript" | "t" => {
                match &self.cli.transcript {
                    Some(p) => println!("transcript: {}", p.display()),
                    None => println!("no transcript file (use --transcript PATH, or config)"),
                }
                println!(
                    "messages: {} (about {} tokens)",
                    self.agent.session.messages.len(),
                    self.agent.session.estimated_tokens()
                );
            }
            "cost" | "usage" => {
                let u = self.agent.usage_total();
                println!(
                    "tokens: {} in / {} out / {} cached",
                    u.input_tokens, u.output_tokens, u.cached_input_tokens
                );
            }
            "script" | "x" => {
                let path = if rest.is_empty() {
                    self.ask_text("script path: ")?
                } else {
                    rest.to_string()
                };
                let path = emerag_util::sys::expand_tilde(path.trim());
                match std::fs::read_to_string(&path) {
                    Ok(src) => match emerag_agent::tools::script_host::run_script(
                        &emerag_util::sys::current_dir(),
                        &src,
                        &mut self.ui,
                        65536,
                    ) {
                        Ok(out) => println!("{out}"),
                        Err(e) => println!("error: {e}"),
                    },
                    Err(e) => println!("cannot read {}: {e}", path.display()),
                }
            }
            "local" => {
                crate::local::status(&self.cfg);
            }
            "resume" => println!("session resume is not implemented yet (transcripts are JSONL)"),
            "redraw" => println!(),
            other => {
                println!("unknown command /{other} (try /help)");
            }
        }
        Ok(true)
    }

    fn ask_text(&mut self, prompt_text: &str) -> Result<String, String> {
        match self.ui.read_input(prompt_text) {
            Ok(Input::Line(s)) => Ok(s),
            Ok(Input::Eof) | Ok(Input::Cancelled) => Ok(String::new()),
            Ok(Input::Command(_)) => Ok(String::new()),
            Err(e) => Err(e.to_string()),
        }
    }

    pub fn rebuild_agent(&mut self) -> Result<(), String> {
        let provider =
            crate::providers::build(&self.cfg, &self.cli).map_err(|e| format!("provider: {e}"))?;
        self.agent.set_provider(Arc::from(provider));
        self.agent.set_model(self.cfg.model.clone());
        Ok(())
    }
}

fn resolve_command(cmd: &str) -> &str {
    const ALIASES: &[(&str, &str)] = &[
        ("h", "help"),
        ("?", "help"),
        ("q", "quit"),
        ("exit", "quit"),
        ("cls", "clear"),
        ("perm", "mode"),
        ("permissions", "mode"),
        ("m", "model"),
        ("p", "provider"),
        ("k", "auth"),
        ("key", "auth"),
        ("w", "wizard"),
        ("setup", "wizard"),
        ("c", "config"),
        ("d", "doctor"),
        ("s", "skills"),
        ("j", "jobs"),
        ("a", "agents"),
        ("t", "transcript"),
        ("x", "script"),
        ("usage", "cost"),
    ];
    for (alias, target) in ALIASES {
        if cmd == *alias {
            return target;
        }
    }
    cmd
}

fn display_or<'a>(value: &'a str, fallback: &'a str) -> &'a str {
    if value.is_empty() {
        fallback
    } else {
        value
    }
}

/// One-shot mode: run a single turn and print machine-readable output on demand.
pub fn run_one_shot(
    _cfg: &mut Config,
    cli: &Cli,
    mut agent: Agent,
    prompt_text: &str,
) -> Result<i32, String> {
    use emerag_agent::{NullUi, UiEvent};
    let mut ui = OneShotUi::new(!cli.json_output);
    let result = agent
        .run_turn(prompt_text, &mut ui)
        .map_err(|e| e.to_string())?;
    if !cli.json_output && !ui.printed && !result.content.trim().is_empty() {
        println!("{}", result.content);
    }
    if cli.json_output {
        let mut m = emerag_json::Map::new();
        m.insert(
            "content".into(),
            emerag_json::Value::String(result.content.clone()),
        );
        m.insert("turns".into(), emerag_json::json!(result.turns));
        m.insert("tool_calls".into(), emerag_json::json!(result.tool_calls));
        m.insert(
            "cancelled".into(),
            emerag_json::Value::Bool(result.cancelled),
        );
        let mut u = emerag_json::Map::new();
        u.insert("input".into(), emerag_json::json!(ui.usage.input_tokens));
        u.insert("output".into(), emerag_json::json!(ui.usage.output_tokens));
        m.insert("usage".into(), emerag_json::Value::Object(u));
        println!(
            "{}",
            emerag_json::to_string_pretty(&emerag_json::Value::Object(m))
        );
    }
    let _ = UiEvent::Assistant("");
    let _ = NullUi::default();
    Ok(if result.cancelled { 130 } else { 0 })
}

struct OneShotUi {
    usage: emerag_llm::Usage,
    stream: bool,
    printed: bool,
}

impl OneShotUi {
    fn new(stream: bool) -> Self {
        OneShotUi {
            usage: emerag_llm::Usage::default(),
            stream,
            printed: false,
        }
    }
}

impl Ui for OneShotUi {
    fn event(&mut self, ev: emerag_agent::UiEvent<'_>) {
        match ev {
            emerag_agent::UiEvent::Text(t) if self.stream => {
                if !self.printed {
                    self.printed = true;
                }
                print!("{t}");
                let _ = std::io::stdout().flush();
            }
            emerag_agent::UiEvent::ToolStart { name, args_preview } => {
                if self.stream {
                    eprintln!("[tool] {name}: {args_preview}");
                }
            }
            emerag_agent::UiEvent::Assistant(t) => {
                if self.stream && !t.is_empty() {
                    println!();
                }
            }
            emerag_agent::UiEvent::Usage(u) => self.usage = u,
            emerag_agent::UiEvent::Notice(n) | emerag_agent::UiEvent::Status(n) => {
                if self.stream {
                    eprintln!("[emerag] {n}");
                }
            }
            _ => {}
        }
    }
    fn ask(&mut self, q: &Question) -> Answer {
        eprintln!("[emerag] {q:?} (denied: one-shot mode has no UI)");
        Answer::No
    }
    fn is_cancelled(&self) -> bool {
        crate::signals::interrupted()
    }
}
