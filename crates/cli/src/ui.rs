//! Terminal UI: streaming renderer, approvals, prompts.
//!
//! Everything degrades gracefully: no color, no Unicode, no raw mode, no
//! alt-screen. The same code prints a usable session on a 40-column serial
//! console.

use crate::signals;
use emerag_agent::{Answer, Question, QuestionKind, Ui, UiEvent};
use emerag_llm::Usage;
use emerag_term::{Capabilities, Key, KeyCode, LineEditor};
use emerag_util::text;
use std::io::Write;

pub enum Input {
    Line(String),
    Eof,
    Cancelled,
    /// Ctrl+X chord, normalized to a slash command.
    Command(String),
}

pub struct TermUi {
    pub caps: Capabilities,
    pub color: bool,
    pub ascii: bool,
    pub width: usize,
    /// Kept for callers that tune diagnostics; reasoning is always shown.
    #[allow(dead_code)]
    pub verbose: bool,
    pub token: emerag_util::sync::CancelToken,
    editor: LineEditor,
    pending: String,
    reasoning_pending: String,
    reasoning_header: bool,
    last_usage: Option<Usage>,
    at_line_start: bool,
}

impl TermUi {
    pub fn new(
        caps: Capabilities,
        color: bool,
        ascii: bool,
        force_width: Option<u16>,
        verbose: bool,
        token: emerag_util::sync::CancelToken,
    ) -> Self {
        let width = force_width
            .map(|w| w as usize)
            .unwrap_or(caps.width as usize)
            .max(20);
        let color = color && caps.color && !caps.is_dumb();
        let ascii = ascii || !caps.unicode || caps.is_dumb();
        let editor = LineEditor::new(caps);
        TermUi {
            caps,
            color,
            ascii,
            width,
            verbose,
            token,
            editor,
            pending: String::new(),
            reasoning_pending: String::new(),
            reasoning_header: false,
            last_usage: None,
            at_line_start: true,
        }
    }

    pub fn last_usage(&self) -> Option<Usage> {
        self.last_usage
    }

    fn paint(&self, code: &str, text: &str) -> String {
        if self.color && self.caps.ansi {
            format!("\x1b[{code}m{text}\x1b[0m")
        } else {
            text.to_string()
        }
    }

    fn mark(&self, ch: &str) -> &'static str {
        if self.ascii {
            match ch {
                "ok" => "OK",
                "fail" => "!!",
                "tool" => "*",
                "note" => "!",
                "dot" => "-",
                _ => "?",
            }
        } else {
            match ch {
                "ok" => "✓",
                "fail" => "✗",
                "tool" => "⏺",
                "note" => "!",
                "dot" => "·",
                _ => "?",
            }
        }
    }

    /// Print a complete line, wrapping to the terminal width.
    pub fn println(&mut self, text: &str) {
        let mut out = std::io::stdout();
        for line in text.split('\n') {
            for wrapped in text::wrap(line, self.width) {
                let _ = out.write_all(wrapped.as_bytes());
                let _ = out.write_all(b"\r\n");
            }
        }
        let _ = out.flush();
        self.at_line_start = true;
    }

    /// Print raw text without wrapping (used for streamed deltas).
    fn stream_text(&mut self, delta: &str) {
        self.pending.push_str(delta);
        let mut out = std::io::stdout();
        while let Some(idx) = self.pending.find('\n') {
            let line: String = self.pending.drain(..=idx).collect();
            let clean = text::sanitize(line.trim_end_matches(['\n', '\r']));
            for wrapped in text::wrap(&clean, self.width) {
                let _ = out.write_all(wrapped.as_bytes());
                let _ = out.write_all(b"\r\n");
            }
        }
        // Emit partial line immediately if it is already too wide.
        if text::width(&self.pending) >= self.width {
            let clean = text::sanitize(&self.pending);
            let _ = out.write_all(clean.as_bytes());
            let _ = out.write_all(b"\r\n");
            self.pending.clear();
        }
        let _ = out.flush();
        self.at_line_start = self.pending.is_empty();
    }

    fn stream_reasoning(&mut self, delta: &str) {
        if !self.reasoning_header {
            self.println(&self.paint("2", &format!("{} thinking", self.mark("dot"))));
            self.reasoning_header = true;
        }
        self.reasoning_pending.push_str(delta);
        let avail = self.width.saturating_sub(4).max(12);
        while let Some(idx) = self.reasoning_pending.find('\n') {
            let line: String = self.reasoning_pending.drain(..=idx).collect();
            self.print_reasoning_line(line.trim_end_matches(['\n', '\r']));
        }
        if text::width(&self.reasoning_pending) >= avail {
            let lines = text::wrap(&self.reasoning_pending, avail);
            if lines.len() > 1 {
                let last = lines.last().cloned().unwrap_or_default();
                for l in &lines[..lines.len() - 1] {
                    self.print_reasoning_line(l);
                }
                self.reasoning_pending = last;
            }
        }
    }

    fn print_reasoning_line(&mut self, line: &str) {
        let clean = text::sanitize(line);
        let styled = self.paint("2", &format!("  {clean}"));
        self.println(&styled);
    }

    fn flush_reasoning(&mut self) {
        if !self.reasoning_pending.is_empty() {
            let line = std::mem::take(&mut self.reasoning_pending);
            self.print_reasoning_line(&line);
        }
        self.reasoning_header = false;
    }

    fn flush_pending(&mut self) {
        self.flush_reasoning();
        if !self.pending.is_empty() {
            let line = std::mem::take(&mut self.pending);
            let clean = text::sanitize(&line);
            self.println(&clean);
        }
    }

    /// Read a line with slash/chord support.
    pub fn read_input(&mut self, prompt: &str) -> emerag_term::Result<Input> {
        if !self.caps.tty {
            return self.read_cooked(prompt);
        }
        let guard = emerag_term::raw_mode();
        let Ok(_guard) = guard else {
            return self.read_cooked(prompt);
        };
        self.editor.begin(prompt)?;
        loop {
            let key = match emerag_term::read_key() {
                Ok(key) => key,
                Err(e) if e.kind() == emerag_term::ErrorKind::EndOfInput => {
                    return Ok(Input::Eof);
                }
                Err(_) => {
                    // A broken console handle must not terminate the whole
                    // session. Re-enter cooked mode and keep the prompt alive.
                    drop(_guard);
                    return self.read_cooked(prompt);
                }
            };
            if key.ctrl && matches!(key.code, KeyCode::Char('x')) {
                self.editor.begin(&format!("{prompt}^X "))?;
                let next = emerag_term::read_key()?;
                if next.ctrl && matches!(next.code, KeyCode::Char('x')) {
                    continue;
                }
                let cmd = chord_to_command(&next);
                let mut out = std::io::stdout();
                let _ = out.write_all(b"\r\n");
                let _ = out.flush();
                return match cmd {
                    Some(c) => Ok(Input::Command(c.to_string())),
                    None => {
                        self.println("unknown Ctrl+X chord (Ctrl+X H for help)");
                        self.editor.begin(prompt)?;
                        continue;
                    }
                };
            }
            match self.editor.handle_key(key)? {
                emerag_term::EditorAction::Continue => {}
                emerag_term::EditorAction::Submit => {
                    let line = self.editor.buffer();
                    let mut out = std::io::stdout();
                    let _ = out.write_all(b"\r\n");
                    let _ = out.flush();
                    return Ok(Input::Line(line));
                }
                emerag_term::EditorAction::Cancelled => {
                    let mut out = std::io::stdout();
                    let _ = out.write_all(b"^C\r\n");
                    let _ = out.flush();
                    return Ok(Input::Cancelled);
                }
                emerag_term::EditorAction::Eof => {
                    let mut out = std::io::stdout();
                    let _ = out.write_all(b"\r\n");
                    let _ = out.flush();
                    return Ok(Input::Eof);
                }
            }
        }
    }

    fn read_cooked(&mut self, prompt: &str) -> emerag_term::Result<Input> {
        use std::io::BufRead;
        print!("{prompt}");
        let _ = std::io::stdout().flush();
        let mut line = String::new();
        match std::io::stdin().lock().read_line(&mut line) {
            Ok(0) => Ok(Input::Eof),
            Ok(_) => {
                let trimmed = line.trim_end_matches(['\n', '\r']).to_string();
                if trimmed.starts_with("^X") || trimmed.starts_with("\u{18}") {
                    let rest = trimmed
                        .trim_start_matches("^X")
                        .trim_start_matches('\u{18}')
                        .trim();
                    if let Some(ch) = rest.chars().next() {
                        let key = Key {
                            code: KeyCode::Char(ch),
                            ctrl: false,
                            alt: false,
                            shift: false,
                        };
                        if let Some(cmd) = chord_to_command(&key) {
                            return Ok(Input::Command(cmd.to_string()));
                        }
                    }
                }
                Ok(Input::Line(trimmed))
            }
            Err(e) => Err(emerag_term::Error::new(format!("input: {e}"))),
        }
    }

    /// Interactive yes/no using the terminal prompt when possible.
    fn ask_yes_no(&mut self, prompt: &str, default: bool) -> bool {
        match emerag_term::prompt::prompt_yes_no_caps(self.caps, prompt, default) {
            Ok(v) => v,
            Err(_) => default,
        }
    }
}

fn chord_to_command(key: &Key) -> Option<&'static str> {
    let KeyCode::Char(c) = key.code else {
        return None;
    };
    Some(match c.to_ascii_lowercase() {
        'h' => "/help",
        'w' => "/wizard",
        'm' => "/model",
        'a' => "/auth",
        'p' => "/mode",
        'j' => "/jobs",
        'g' => "/agents",
        's' => "/skills",
        't' => "/transcript",
        'c' => "/compact",
        'l' => "/redraw",
        'q' => "/quit",
        '?' => "/keys",
        _ => return None,
    })
}

impl Ui for TermUi {
    fn event(&mut self, ev: UiEvent<'_>) {
        if signals::interrupted() {
            self.token.cancel();
        }
        match ev {
            UiEvent::Text(t) => {
                self.flush_reasoning();
                self.stream_text(t);
            }
            UiEvent::Reasoning(t) => self.stream_reasoning(t),
            UiEvent::ToolStart { name, args_preview } => {
                self.flush_pending();
                let line = format!("{} {}: {}", self.mark("tool"), name, args_preview);
                self.println(&self.paint("36", &line));
            }
            UiEvent::ToolEnd {
                name: _,
                ok,
                summary,
                duration_ms,
            } => {
                self.flush_pending();
                let mark = if ok {
                    self.mark("ok")
                } else {
                    self.mark("fail")
                };
                let took = if duration_ms >= 100 {
                    format!(" ({})", emerag_util::time::fmt_duration_ms(duration_ms))
                } else {
                    String::new()
                };
                let line = format!("  {mark} {summary}{took}");
                let color = if ok { "32" } else { "31" };
                self.println(&self.paint(color, &line));
            }
            UiEvent::Notice(n) => {
                self.flush_pending();
                self.println(&self.paint("33", &format!("{} {n}", self.mark("note"))));
            }
            UiEvent::Status(s) => {
                self.flush_pending();
                self.println(&self.paint("2", &format!("{} {s}", self.mark("dot"))));
            }
            UiEvent::Retry {
                attempt,
                delay_ms,
                reason,
            } => {
                self.flush_pending();
                self.println(&self.paint(
                    "33",
                    &format!(
                        "{} retry {attempt} in {delay_ms}ms: {reason}",
                        self.mark("dot")
                    ),
                ));
            }
            UiEvent::Usage(u) => {
                self.last_usage = Some(u);
            }
            UiEvent::Assistant(t) => {
                self.flush_pending();
                let _ = t;
            }
        }
    }

    fn ask(&mut self, q: &Question) -> Answer {
        self.flush_pending();
        match &q.kind {
            QuestionKind::Approval { tool, risk, .. } => {
                let risk_label = match risk {
                    emerag_agent::permissions::Risk::Read => "read",
                    emerag_agent::permissions::Risk::Write => "write",
                    emerag_agent::permissions::Risk::Destructive => "DESTRUCTIVE",
                };
                println!();
                println!(
                    "{}",
                    self.paint("33;1", &format!("{} {}", self.mark("note"), q.prompt))
                );
                println!(
                    "{}",
                    self.paint("2", &format!("   type: {tool}  risk: {risk_label}"))
                );
                let options = ["yes, once", "yes, and stop asking for this", "no"];
                match emerag_term::prompt::prompt_choice_caps(self.caps, "Run it?", &options, 0) {
                    Ok(0) => Answer::Yes,
                    Ok(1) => Answer::AllowSession,
                    Ok(_) => Answer::No,
                    Err(_) => Answer::No,
                }
            }
            QuestionKind::Choice { options, default } => {
                println!();
                println!("{}", q.prompt);
                match emerag_term::prompt::prompt_choice_caps(
                    self.caps, "Choose", options, *default,
                ) {
                    Ok(i) => Answer::Index(i),
                    Err(_) => Answer::Cancel,
                }
            }
            QuestionKind::YesNo { default } => {
                if self.ask_yes_no(&q.prompt, *default) {
                    Answer::Yes
                } else {
                    Answer::No
                }
            }
            QuestionKind::Text { secret } => {
                self.editor.set_password(*secret);
                let result = self.editor.read_line(&format!("{}: ", q.prompt));
                self.editor.set_password(false);
                match result {
                    Ok(Some(s)) => Answer::Text(s),
                    Ok(None) => Answer::Cancel,
                    Err(_) => Answer::Cancel,
                }
            }
        }
    }

    fn is_cancelled(&self) -> bool {
        if signals::interrupted() {
            self.token.cancel();
        }
        self.token.is_cancelled()
    }
}
