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
    pub sessions: Vec<crate::sessions::ChatSession>,
    pub active_session: usize,
    pub background: Vec<crate::sessions::BgHandle>,
    next_bg: usize,
    session_persist: bool,
}

impl App {
    pub fn new(mut cfg: Config, cli: Cli, ui: TermUi, mut agent: Agent) -> Self {
        let mut sessions = Vec::new();
        let mut active = 0usize;
        if !cfg.no_write {
            if let Some((list, idx)) = crate::sessions::load(&cfg.sessions_file()) {
                sessions = list;
                active = idx;
            }
        }
        if sessions.is_empty() {
            sessions.push(crate::sessions::ChatSession::new(
                "main",
                cfg.model.clone(),
                agent.session_snapshot(),
            ));
        }
        if let Some(s) = sessions.get_mut(active) {
            if s.model.is_empty() && !cfg.model.is_empty() {
                s.model = cfg.model.clone();
            }
            agent.set_session(s.session.clone());
            agent.set_model(s.model.clone());
            cfg.model = s.model.clone();
        }
        let session_persist = !cfg.no_write;
        App {
            cfg,
            cli,
            ui,
            agent,
            sessions,
            active_session: active,
            background: Vec::new(),
            next_bg: 1,
            session_persist,
        }
    }

    fn sync_active_session(&mut self) {
        if let Some(s) = self.sessions.get_mut(self.active_session) {
            s.session = self.agent.session_snapshot();
            s.model = self.cfg.model.clone();
        }
    }

    fn sync_and_save(&mut self) {
        self.sync_active_session();
        self.persist_sessions();
    }

    fn persist_sessions(&mut self) {
        if self.cfg.no_write || !self.session_persist {
            return;
        }
        if let Err(e) = crate::sessions::save(
            &self.cfg.sessions_file(),
            &self.sessions,
            self.active_session,
        ) {
            self.session_persist = false;
            eprintln!(
                "sessions: cannot write {} ({e}); keeping sessions in memory",
                self.cfg.sessions_file().display()
            );
        }
    }

    fn activate_session(&mut self, idx: usize) -> Result<(), String> {
        if idx >= self.sessions.len() {
            return Err(format!("no session {}", idx + 1));
        }
        if idx == self.active_session {
            return Ok(());
        }
        self.sync_active_session();
        self.active_session = idx;
        let s = &self.sessions[idx];
        self.agent.set_session(s.session.clone());
        self.agent.set_model(s.model.clone());
        self.cfg.model = s.model.clone();
        self.replay_output(idx);
        self.persist_sessions();
        println!(
            "session: {} ({} msgs)",
            self.sessions[idx].name,
            self.sessions[idx].session.messages.len()
        );
        Ok(())
    }

    fn replay_output(&mut self, idx: usize) {
        if idx >= self.sessions.len() {
            return;
        }
        let mut events = std::mem::take(&mut self.sessions[idx].output);
        for bg in &mut self.background {
            if bg.session_index == idx && !bg.done {
                events.append(&mut bg.buffer);
            }
        }
        for e in &events {
            e.emit(&mut self.ui);
        }
        let ask = self
            .background
            .iter_mut()
            .find(|b| b.session_index == idx && b.pending.is_some())
            .and_then(|b| b.pending.take());
        if let Some((q, reply)) = ask {
            let answer = self.ui.ask(&q);
            let _ = reply.send(answer);
        }
    }

    fn poll_background(&mut self) {
        let active = self.active_session;
        let mut events = Vec::new();
        let mut asks = Vec::new();
        let mut done = Vec::new();
        for bg in &mut self.background {
            loop {
                match bg.rx.try_recv() {
                    Ok(crate::sessions::BgMessage::Event(e)) => {
                        if bg.session_index == active {
                            events.push(e);
                        } else {
                            bg.buffer.push(e);
                        }
                    }
                    Ok(crate::sessions::BgMessage::Ask(q, reply)) => {
                        if bg.session_index == active {
                            asks.push((q, reply));
                        } else {
                            bg.pending = Some((q, reply));
                        }
                    }
                    Ok(crate::sessions::BgMessage::Done {
                        session,
                        error,
                        cancelled,
                    }) => {
                        bg.done = true;
                        done.push((
                            bg.id,
                            bg.session_index,
                            session,
                            error,
                            cancelled,
                            std::mem::take(&mut bg.buffer),
                        ));
                        break;
                    }
                    Err(std::sync::mpsc::TryRecvError::Empty) => break,
                    Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                        bg.done = true;
                        done.push((
                            bg.id,
                            bg.session_index,
                            None,
                            Some("background worker stopped unexpectedly".into()),
                            false,
                            std::mem::take(&mut bg.buffer),
                        ));
                        break;
                    }
                }
            }
        }
        for e in events {
            e.emit(&mut self.ui);
        }
        for (q, reply) in asks {
            let answer = self.ui.ask(&q);
            let _ = reply.send(answer);
        }
        for (id, idx, session, error, cancelled, buffered) in done {
            let name = self
                .sessions
                .get(idx)
                .map(|s| s.name.clone())
                .unwrap_or_else(|| format!("session {}", idx + 1));
            if let Some(s) = session {
                if let Some(cs) = self.sessions.get_mut(idx) {
                    cs.session = s;
                    cs.busy = None;
                }
            } else if let Some(cs) = self.sessions.get_mut(idx) {
                cs.busy = None;
            }
            if idx == active {
                if let Some(cs) = self.sessions.get(idx) {
                    self.agent.set_session(cs.session.clone());
                    self.agent.set_model(cs.model.clone());
                }
                for e in &buffered {
                    e.emit(&mut self.ui);
                }
            } else if let Some(cs) = self.sessions.get_mut(idx) {
                cs.output.extend(buffered);
            }
            if let Some(err) = error {
                println!("background {name} (id {id}) failed: {err}");
            } else if cancelled {
                println!("background {name} (id {id}) cancelled");
            } else {
                println!("background {name} (id {id}) finished");
            }
        }
        self.background.retain(|b| !b.done);
        self.sync_active_session();
        self.persist_sessions();
    }

    fn start_background(&mut self, text: &str) -> Result<(), String> {
        let text = text.trim();
        if text.is_empty() {
            return Err("empty prompt".into());
        }
        if self.sessions[self.active_session].busy.is_some() {
            return Err("this session is already running; switch with /session or wait".into());
        }
        let idx = self.active_session;
        let id = self.next_bg;
        self.next_bg += 1;
        let cancel = emerag_util::sync::CancelToken::new();
        let (tx, rx) = std::sync::mpsc::channel();
        let mut cfg = self.cfg.clone();
        cfg.model = self.sessions[idx].model.clone();
        let mut cli = self.cli.clone();
        cli.transcript = None;
        let session = self.agent.session_snapshot();
        let prompt = text.to_string();
        let worker_cancel = cancel.clone();
        std::thread::spawn(move || {
            let (session, error) = match crate::build_agent(&cfg, &cli) {
                Ok(mut agent) => {
                    agent.set_session(session);
                    agent.cancel = worker_cancel.clone();
                    let mut ui = crate::sessions::WorkerUi {
                        tx: tx.clone(),
                        cancel: worker_cancel.clone(),
                    };
                    let result = agent.run_turn(&prompt, &mut ui);
                    let session = agent.session_snapshot();
                    agent.shutdown();
                    let error = result.err().map(|e| e.to_string());
                    (Some(session), error)
                }
                Err(e) => (None, Some(e)),
            };
            let cancelled = worker_cancel.is_cancelled();
            let _ = tx.send(crate::sessions::BgMessage::Done {
                session,
                error,
                cancelled,
            });
        });
        self.sessions[idx].busy = Some(id);
        self.background.push(crate::sessions::BgHandle {
            id,
            session_index: idx,
            cancel,
            rx,
            buffer: Vec::new(),
            pending: None,
            done: false,
        });
        if self.cfg.mode == PermissionMode::Ask {
            println!("note: approvals for this background turn wait until it is foreground (/session or /wait).");
        }
        println!(
            "started background session {} (id {}); output is buffered until you switch or /wait",
            self.sessions[idx].name, id
        );
        Ok(())
    }

    fn wait_background(&mut self, id: Option<usize>) -> Result<(), String> {
        loop {
            self.poll_background();
            let running = self
                .background
                .iter()
                .any(|b| id.map(|x| b.id == x).unwrap_or(true) && !b.done);
            if !running {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(120));
        }
        Ok(())
    }

    fn session_index(&self, arg: &str) -> Option<usize> {
        if let Ok(n) = arg.parse::<usize>() {
            if n >= 1 && n <= self.sessions.len() {
                return Some(n - 1);
            }
        }
        self.sessions.iter().position(|s| s.name == arg)
    }

    fn list_sessions(&self) {
        for (i, s) in self.sessions.iter().enumerate() {
            let mark = if i == self.active_session { "*" } else { " " };
            let busy = s
                .busy
                .map(|id| format!("  [background id {id}]"))
                .unwrap_or_default();
            println!("{mark} {}. {}{}", i + 1, s.summary(), busy);
        }
    }

    fn new_session(&mut self, name: &str) -> Result<(), String> {
        self.sync_active_session();
        let name = if name.trim().is_empty() {
            format!("session-{}", self.sessions.len() + 1)
        } else {
            name.trim().to_string()
        };
        if self.sessions.iter().any(|s| s.name == name) {
            return Err(format!("session '{name}' already exists"));
        }
        self.sessions.push(crate::sessions::ChatSession::new(
            name.clone(),
            self.cfg.model.clone(),
            emerag_agent::session::Session::new(),
        ));
        self.active_session = self.sessions.len() - 1;
        self.agent.clear_session();
        println!("new session: {name}");
        self.persist_sessions();
        Ok(())
    }

    fn fork_session(&mut self, name: &str) -> Result<(), String> {
        self.sync_active_session();
        let base = self.sessions[self.active_session].clone();
        let name = if name.trim().is_empty() {
            format!("fork-{}", self.sessions.len() + 1)
        } else {
            name.trim().to_string()
        };
        if self.sessions.iter().any(|s| s.name == name) {
            return Err(format!("session '{name}' already exists"));
        }
        let mut forked = crate::sessions::ChatSession::new(name.clone(), base.model, base.session);
        forked.output.clear();
        self.sessions.push(forked);
        self.active_session = self.sessions.len() - 1;
        self.agent
            .set_session(self.sessions[self.active_session].session.clone());
        self.cfg.model = self.sessions[self.active_session].model.clone();
        self.agent.set_model(self.cfg.model.clone());
        println!("forked session: {name}");
        self.persist_sessions();
        Ok(())
    }

    fn configure_new_provider(&mut self) -> Result<(), String> {
        let profiles = emerag_llm::catalog::all();
        let labels: Vec<String> = profiles.iter().map(|p| p.label.to_string()).collect();
        let i = match prompt::prompt_choice_caps(self.ui.caps, "Provider catalog", &labels, 0) {
            Ok(i) => i,
            Err(_) => return Ok(()),
        };
        let p = &profiles[i];
        let mut id = p.id.to_string();
        let mut name = p.label.to_string();
        if p.id == "custom" {
            name = self.ask_text("Provider name: ")?;
            if name.trim().is_empty() {
                name = "Custom endpoint".into();
            }
            id = crate::providers::custom_id(&self.cfg, &name);
            let endpoint = self.ask_text("Endpoint: ")?;
            if endpoint.trim().is_empty() {
                return Err("endpoint is required".into());
            }
            self.cfg.base_url = crate::wizard::normalize_endpoint(&endpoint)?;
            let kinds = [
                "Chat Completions (OpenAI-compatible)",
                "Responses (OpenAI Responses API)",
                "Anthropic Messages",
            ];
            let idx = prompt::prompt_choice_caps(self.ui.caps, "API style", &kinds, 0)
                .map_err(|e| e.to_string())?;
            self.cfg.api = match idx {
                1 => "responses".into(),
                2 => "anthropic".into(),
                _ => "chat".into(),
            };
            self.cfg.model.clear();
        } else {
            self.cfg.base_url = p.base_url.to_string();
            self.cfg.api = p.api.as_str().to_string();
            self.cfg.model = p.default_model().to_string();
        }
        self.cfg.provider = id;
        self.cfg.provider_name = name.clone();
        crate::providers::remember(&mut self.cfg);
        self.rebuild_agent()?;
        if !self.cfg.no_write {
            let _ = self.cfg.save(&Config::config_path());
        }
        println!("provider: {name} ({})", self.cfg.base_url);
        println!("use /login deepseek or /auth for an API key, then /model");
        Ok(())
    }

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
        println!(" provider {}", crate::providers::display_name(&self.cfg));
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
        if self.sessions.len() > 1 {
            println!(
                " sessions {} (active: {})",
                self.sessions.len(),
                self.sessions[self.active_session].name
            );
        }
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
            self.poll_background();
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
                    } else if let Some(bg) = line.strip_suffix(" &") {
                        if !bg.trim().is_empty() {
                            if let Err(e) = self.start_background(bg) {
                                println!("{e}");
                            }
                        }
                    } else {
                        self.run_turn(&line)?;
                    }
                }
            }
        }
        self.sync_active_session();
        self.persist_sessions();
        for bg in &self.background {
            bg.cancel.cancel();
        }
        self.agent.shutdown();
        Ok(())
    }

    fn prompt(&self) -> String {
        let mode = self.cfg.mode.as_str();
        let name = self
            .sessions
            .get(self.active_session)
            .map(|s| s.name.as_str())
            .unwrap_or("main");
        if self.ui.width >= 60 {
            if self.sessions.len() > 1 {
                format!("emerag[{name}][{mode}]> ")
            } else {
                format!("emerag[{mode}]> ")
            }
        } else {
            "> ".to_string()
        }
    }

    fn run_turn(&mut self, text: &str) -> Result<(), String> {
        if self.sessions[self.active_session].busy.is_some() {
            println!("this session is running in the background; /wait or switch sessions");
            return Ok(());
        }
        crate::signals::clear();
        self.agent.cancel.reset();
        self.ui.token.reset();
        let result = self.agent.run_turn(text, &mut self.ui);
        crate::signals::clear();
        self.agent.cancel.reset();
        self.ui.token.reset();
        self.sync_active_session();
        self.persist_sessions();
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
            "new" => {
                self.new_session(rest)?;
            }
            "session" | "sessions" => {
                if rest.is_empty() {
                    self.list_sessions();
                } else if let Some(idx) = self.session_index(rest) {
                    self.activate_session(idx)?;
                } else {
                    println!("unknown session '{rest}' (use /sessions)");
                }
            }
            "fork" => {
                self.fork_session(rest)?;
            }
            "bg" => {
                if rest.is_empty() {
                    println!("usage: /bg <prompt>");
                } else if let Err(e) = self.start_background(rest) {
                    println!("{e}");
                }
            }
            "wait" => {
                let id = rest.parse::<usize>().ok();
                self.wait_background(id)?;
            }
            "kill" => {
                let id = match rest.parse::<usize>() {
                    Ok(n) => Some(n),
                    Err(_) if rest.is_empty() => self.sessions[self.active_session].busy,
                    Err(_) => {
                        println!("usage: /kill <background id>");
                        None
                    }
                };
                if let Some(id) = id {
                    if let Some(bg) = self.background.iter_mut().find(|b| b.id == id) {
                        if let Some((_, reply)) = bg.pending.take() {
                            let _ = reply.send(Answer::Cancel);
                        }
                        bg.cancel.cancel();
                        println!("cancel requested for background id {id}");
                    } else {
                        println!("no background id {id}");
                    }
                }
            }
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
                if let Some(s) = self.sessions.get_mut(self.active_session) {
                    s.output.clear();
                }
                self.sync_and_save();
                println!("conversation cleared (system prompt and skills kept)");
            }
            "compact" => {
                self.agent.compact_now(&mut self.ui);
                self.sync_and_save();
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
                self.sync_and_save();
            }
            "provider" | "p" => {
                let configured = crate::providers::configured(&self.cfg);
                let mut labels: Vec<String> = configured
                    .iter()
                    .enumerate()
                    .map(|(i, p)| {
                        format!("{}{} ({})", if i == 0 { "* " } else { "  " }, p.name, p.id)
                    })
                    .collect();
                labels.push("Configure another provider...".into());
                match prompt::prompt_choice_caps(self.ui.caps, "Providers", &labels, 0) {
                    Ok(i) if i < configured.len() => {
                        crate::providers::apply(&mut self.cfg, &configured[i]);
                        crate::providers::remember(&mut self.cfg);
                        self.rebuild_agent()?;
                        if !self.cfg.no_write {
                            let _ = self.cfg.save(&Config::config_path());
                        }
                        println!(
                            "provider: {} ({})",
                            crate::providers::display_name(&self.cfg),
                            self.cfg.base_url
                        );
                    }
                    Ok(_) => self.configure_new_provider()?,
                    Err(_) => {}
                }
                self.sync_and_save();
            }
            "auth" | "k" | "key" => {
                let deepseek = self.cfg.provider.starts_with("deepseek")
                    || self.cfg.base_url.contains("deepseek.com");
                if deepseek {
                    let options = [
                        "Sign in with a DeepSeek account (OAuth, no key needed)",
                        "Use a DeepSeek API key",
                        "Cancel",
                    ];
                    match prompt::prompt_choice_caps(
                        self.ui.caps,
                        "DeepSeek authentication",
                        &options,
                        0,
                    ) {
                        Ok(0) => {
                            crate::oauth::login_deepseek(&mut self.cfg, true)?;
                            self.rebuild_agent()?;
                            self.sync_and_save();
                            println!("signed in; use /model to pick a model");
                        }
                        Ok(1) => {
                            if self.cfg.provider == "deepseek-account" {
                                self.cfg.provider = "deepseek".into();
                                self.cfg.base_url = "https://api.deepseek.com".into();
                                self.cfg.api = "chat".into();
                                self.cfg.model.clear();
                            }
                            self.ask_api_key()?;
                        }
                        _ => {}
                    }
                } else {
                    self.ask_api_key()?;
                }
            }
            "login" | "signin" => {
                if !rest.is_empty() && !rest.starts_with("deepseek") {
                    println!("only 'deepseek' account login is supported: /login deepseek");
                } else {
                    crate::oauth::login_deepseek(&mut self.cfg, true)?;
                    self.rebuild_agent()?;
                    self.sync_and_save();
                    println!("signed in; use /model to pick a model");
                }
            }
            "logout" | "signout" => {
                crate::oauth::logout(&mut self.cfg)?;
                self.rebuild_agent()?;
                self.sync_and_save();
            }
            "wizard" | "w" | "setup" => {
                crate::wizard::run(&mut self.cfg, &self.cli, &mut self.ui)?;
                self.rebuild_agent()?;
                self.sync_and_save();
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

    fn ask_api_key(&mut self) -> Result<(), String> {
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
        Ok(())
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
    reasoning_open: bool,
}

impl OneShotUi {
    fn new(stream: bool) -> Self {
        OneShotUi {
            usage: emerag_llm::Usage::default(),
            stream,
            printed: false,
            reasoning_open: false,
        }
    }
}

impl Ui for OneShotUi {
    fn event(&mut self, ev: emerag_agent::UiEvent<'_>) {
        match ev {
            emerag_agent::UiEvent::Text(t) if self.stream => {
                if self.reasoning_open {
                    eprintln!();
                    self.reasoning_open = false;
                }
                if !self.printed {
                    self.printed = true;
                }
                print!("{t}");
                let _ = std::io::stdout().flush();
            }
            emerag_agent::UiEvent::Reasoning(t) if self.stream => {
                // Same reasoning visibility as the TUI, but on stderr so
                // stdout stays a clean answer for pipes.
                eprint!("{t}");
                self.reasoning_open = true;
                let _ = std::io::stderr().flush();
            }
            emerag_agent::UiEvent::ToolStart { name, args_preview } => {
                if self.stream {
                    if self.reasoning_open {
                        eprintln!();
                        self.reasoning_open = false;
                    }
                    eprintln!("[tool] {name}: {args_preview}");
                }
            }
            emerag_agent::UiEvent::Assistant(t) => {
                if self.stream {
                    if self.reasoning_open {
                        eprintln!();
                        self.reasoning_open = false;
                    }
                    if !t.is_empty() {
                        println!();
                    }
                }
            }
            emerag_agent::UiEvent::Usage(u) => self.usage = u,
            emerag_agent::UiEvent::Notice(n) | emerag_agent::UiEvent::Status(n) => {
                if self.stream {
                    if self.reasoning_open {
                        eprintln!();
                        self.reasoning_open = false;
                    }
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
