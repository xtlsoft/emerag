//! A small line editor that works on ANSI terminals and dumb terminals.
//!
//! [LineEditor::handle_key] is the whole editing state machine and does not
//! touch the keyboard, so tests can drive it one key at a time.
//! [LineEditor::read_line] enters raw mode (when possible), renders, and loops.
//! When stdin is not a terminal, or raw mode fails, it falls back to cooking
//! with std::io::stdin().read_line.

use std::io::{self, Write};

use crate::keys::{read_key, Key, KeyCode};
use crate::raw::raw_mode;
use crate::width::{char_width, display_width, strip_ansi, truncate_to_width};
use crate::{Capabilities, Error, ErrorKind, Result};

/// Completion callback: given the current line, return candidate strings.
pub type Completer = Box<dyn Fn(&str) -> Vec<String>>;

/// Maximum number of history entries retained.
pub const MAX_HISTORY: usize = 200;
/// Maximum line length accepted from typing or paste. Prevents an unbounded
/// paste from exhausting memory on a small emergency machine.
pub const MAX_LINE: usize = 32768;

/// What a key did to the editor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EditorAction {
    /// Keep editing.
    Continue,
    /// Enter was pressed; the buffer is the result.
    Submit,
    /// Ctrl+C was pressed; the buffer is preserved.
    Cancelled,
    /// Ctrl+D on an empty buffer.
    Eof,
}

/// Interactive single-line editor with history, paste and completion.
pub struct LineEditor {
    caps: Capabilities,
    out: Box<dyn Write>,
    prompt: String,
    buffer: Vec<char>,
    cursor: usize,
    password: bool,
    history: Vec<String>,
    hist_index: Option<usize>,
    draft: String,
    kill: String,
    completer: Option<Completer>,
    pasting: bool,
    last_completions: Vec<String>,
    last_width: usize,
}

impl LineEditor {
    /// Create an editor writing to stdout.
    pub fn new(caps: Capabilities) -> LineEditor {
        LineEditor::new_with_writer(caps, Box::new(io::stdout()))
    }

    /// Create an editor with an injected writer, for headless tests.
    pub fn new_with_writer(caps: Capabilities, out: Box<dyn Write>) -> LineEditor {
        LineEditor {
            caps,
            out,
            prompt: String::new(),
            buffer: Vec::new(),
            cursor: 0,
            password: false,
            history: Vec::new(),
            hist_index: None,
            draft: String::new(),
            kill: String::new(),
            completer: None,
            pasting: false,
            last_completions: Vec::new(),
            last_width: 0,
        }
    }

    pub fn caps(&self) -> Capabilities {
        self.caps
    }

    /// Replace the output sink (useful for tests and log capture).
    pub fn set_writer(&mut self, out: Box<dyn Write>) {
        self.out = out;
    }

    /// Enable or disable password masking. In password mode the buffer is
    /// never written to the terminal, history is not recorded, and completion
    /// is disabled.
    pub fn set_password(&mut self, password: bool) {
        self.password = password;
    }

    pub fn password(&self) -> bool {
        self.password
    }

    /// Current buffer contents, without masking.
    pub fn buffer(&self) -> String {
        self.buffer.iter().collect()
    }

    /// Cursor position as a char index into [LineEditor::buffer].
    pub fn cursor(&self) -> usize {
        self.cursor
    }

    /// Programmatically replace the line (cursor moves to the end).
    pub fn set_buffer(&mut self, text: &str) {
        self.set_buffer_internal(text);
    }

    pub fn set_prompt(&mut self, prompt: &str) {
        self.prompt = prompt.to_string();
    }

    pub fn history(&self) -> &[String] {
        &self.history
    }

    pub fn clear_history(&mut self) {
        self.history.clear();
        self.hist_index = None;
    }

    /// Matches from the most recent Tab press that could not be extended.
    pub fn last_completions(&self) -> &[String] {
        &self.last_completions
    }

    /// Install a completion callback. It receives the current line and returns
    /// candidate strings. A single candidate is inserted; several candidates
    /// extend the line to their common prefix and are then listed.
    pub fn set_completer(&mut self, f: Completer) {
        self.completer = Some(f);
    }

    /// Reset editor state, render the prompt, and prepare for [LineEditor::handle_key].
    ///
    /// This is the headless entry point used by tests. [LineEditor::read_line]
    /// calls the same reset path and then reads real keys.
    pub fn begin(&mut self, prompt: &str) -> Result<()> {
        self.reset(prompt);
        self.refresh()
    }

    fn reset(&mut self, prompt: &str) {
        self.prompt = prompt.to_string();
        self.buffer.clear();
        self.cursor = 0;
        self.hist_index = None;
        self.draft.clear();
        self.kill.clear();
        self.pasting = false;
        self.last_completions.clear();
        self.last_width = 0;
    }

    /// Read one line interactively. Returns Ok(None) on Ctrl+D with an empty
    /// buffer (or EOF), and Err(Cancelled) on Ctrl+C.
    pub fn read_line(&mut self, prompt: &str) -> Result<Option<String>> {
        self.reset(prompt);
        if !self.caps.tty {
            return self.read_line_cooked(prompt);
        }
        match raw_mode() {
            Ok(_guard) => {
                self.refresh()?;
                self.read_line_raw()
            }
            Err(_) => {
                // Raw mode is unavailable (old terminal, redirected stdin that
                // raced capability detection, restricted console). A clear
                // error was available from raw_mode(); here the friendly
                // behaviour is to continue in cooked mode.
                self.read_line_cooked(prompt)
            }
        }
    }

    fn read_line_raw(&mut self) -> Result<Option<String>> {
        loop {
            let key = match read_key() {
                Ok(key) => key,
                Err(e) if e.kind() == ErrorKind::EndOfInput => {
                    self.newline()?;
                    return Ok(None);
                }
                Err(e) => return Err(e),
            };
            match self.handle_key(key)? {
                EditorAction::Continue => {}
                EditorAction::Submit => {
                    self.newline()?;
                    return Ok(Some(self.buffer()));
                }
                EditorAction::Cancelled => {
                    self.write_str("^C")?;
                    self.newline()?;
                    return Err(Error::cancelled());
                }
                EditorAction::Eof => {
                    self.newline()?;
                    return Ok(None);
                }
            }
        }
    }

    fn read_line_cooked(&mut self, prompt: &str) -> Result<Option<String>> {
        let shown = if self.caps.ansi {
            sanitize_text_keep_ansi(prompt)
        } else {
            strip_ansi(&sanitize_text_keep_ansi(prompt))
        };
        self.write_str(&shown)?;
        self.flush()?;
        let mut line = String::new();
        match io::stdin().read_line(&mut line) {
            Ok(0) => Ok(None),
            Ok(_) => {
                while line.ends_with('\n') || line.ends_with('\r') {
                    line.pop();
                }
                self.buffer = line.chars().collect();
                self.cursor = self.buffer.len();
                if !self.password {
                    self.add_history(&line);
                }
                Ok(Some(line))
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => Err(Error::cancelled()),
            Err(e) => Err(Error::from(e)),
        }
    }

    /// Process one key, updating state and rendering. Returns what the editor
    /// wants the caller to do next.
    pub fn handle_key(&mut self, key: Key) -> Result<EditorAction> {
        let action = self.apply_key(key)?;
        if action == EditorAction::Continue {
            self.refresh()?;
        }
        Ok(action)
    }

    fn apply_key(&mut self, key: Key) -> Result<EditorAction> {
        if self.pasting {
            match key.code {
                KeyCode::PasteEnd => self.pasting = false,
                KeyCode::PasteStart => {}
                KeyCode::Enter => self.insert('\n'),
                KeyCode::Tab => self.insert('\t'),
                KeyCode::Char('\r') => {}
                KeyCode::Char(c) => self.insert(c),
                _ => {}
            }
            return Ok(EditorAction::Continue);
        }

        if key.ctrl {
            if let KeyCode::Char(c) = key.code {
                match c.to_ascii_lowercase() {
                    'a' => self.move_home(),
                    'b' => self.move_left(),
                    'c' => return Ok(EditorAction::Cancelled),
                    'd' => {
                        if self.buffer.is_empty() {
                            return Ok(EditorAction::Eof);
                        }
                        self.delete_at_cursor();
                    }
                    'e' => self.move_end(),
                    'f' => self.move_right(),
                    'h' => self.backspace(),
                    'k' => self.kill_to_end(),
                    'l' => {
                        if self.caps.ansi {
                            self.write_str("\x1b[2J\x1b[H")?;
                        }
                        self.last_width = 0;
                    }
                    'u' => self.kill_to_start(),
                    'w' => self.kill_word_back(),
                    'y' => self.yank(),
                    _ => {}
                }
                return Ok(EditorAction::Continue);
            }
        }

        if key.alt {
            if let KeyCode::Char(c) = key.code {
                match c.to_ascii_lowercase() {
                    'b' => self.move_word_left(),
                    'f' => self.move_word_right(),
                    'd' => self.kill_word_forward(),
                    _ => {}
                }
                return Ok(EditorAction::Continue);
            }
        }

        match key.code {
            KeyCode::Char(c) => {
                if !c.is_control() {
                    self.insert(c);
                }
            }
            KeyCode::Enter => {
                if !self.password {
                    let line = self.buffer();
                    self.add_history(&line);
                }
                return Ok(EditorAction::Submit);
            }
            KeyCode::Tab => {
                if key.shift {
                    self.move_word_left();
                } else if !self.password {
                    self.complete()?;
                }
            }
            KeyCode::Backspace => self.backspace(),
            KeyCode::Delete => self.delete_at_cursor(),
            KeyCode::Left => {
                if key.ctrl {
                    self.move_word_left();
                } else {
                    self.move_left();
                }
            }
            KeyCode::Right => {
                if key.ctrl {
                    self.move_word_right();
                } else {
                    self.move_right();
                }
            }
            KeyCode::Home => self.move_home(),
            KeyCode::End => self.move_end(),
            KeyCode::Up | KeyCode::PageUp => {
                if !self.password {
                    self.history_prev();
                }
            }
            KeyCode::Down | KeyCode::PageDown => {
                if !self.password {
                    self.history_next();
                }
            }
            KeyCode::PasteStart => self.pasting = true,
            KeyCode::PasteEnd => {}
            KeyCode::Esc | KeyCode::Insert | KeyCode::F(_) | KeyCode::Unknown => {}
        }
        Ok(EditorAction::Continue)
    }

    // -- editing operations ------------------------------------------------

    fn insert(&mut self, c: char) {
        if self.buffer.len() >= MAX_LINE {
            return;
        }
        if self.cursor > self.buffer.len() {
            self.cursor = self.buffer.len();
        }
        self.buffer.insert(self.cursor, c);
        self.cursor += 1;
        self.hist_index = None;
    }

    fn insert_str(&mut self, text: &str) {
        for c in text.chars() {
            self.insert(c);
            if self.buffer.len() >= MAX_LINE {
                break;
            }
        }
    }

    fn backspace(&mut self) {
        if self.cursor > 0 && self.cursor <= self.buffer.len() {
            self.cursor -= 1;
            self.buffer.remove(self.cursor);
            self.hist_index = None;
        }
    }

    fn delete_at_cursor(&mut self) {
        if self.cursor < self.buffer.len() {
            self.buffer.remove(self.cursor);
            self.hist_index = None;
        }
    }

    fn move_left(&mut self) {
        if self.cursor > 0 {
            self.cursor -= 1;
        }
    }

    fn move_right(&mut self) {
        if self.cursor < self.buffer.len() {
            self.cursor += 1;
        }
    }

    fn move_home(&mut self) {
        self.cursor = 0;
    }

    fn move_end(&mut self) {
        self.cursor = self.buffer.len();
    }

    fn move_word_left(&mut self) {
        if self.cursor == 0 {
            return;
        }
        let mut i = self.cursor;
        while i > 0 && self.buffer[i - 1].is_whitespace() {
            i -= 1;
        }
        while i > 0 && !self.buffer[i - 1].is_whitespace() {
            i -= 1;
        }
        self.cursor = i;
    }

    fn move_word_right(&mut self) {
        let len = self.buffer.len();
        let mut i = self.cursor;
        if i < len && self.buffer[i].is_whitespace() {
            while i < len && self.buffer[i].is_whitespace() {
                i += 1;
            }
        }
        while i < len && !self.buffer[i].is_whitespace() {
            i += 1;
        }
        self.cursor = i;
    }

    fn kill_to_end(&mut self) {
        if self.cursor < self.buffer.len() {
            let removed: Vec<char> = self.buffer.split_off(self.cursor);
            self.kill = removed.iter().collect();
            self.hist_index = None;
        }
    }

    fn kill_to_start(&mut self) {
        if self.cursor > 0 {
            let removed: Vec<char> = self.buffer.drain(..self.cursor).collect();
            self.cursor = 0;
            self.kill = removed.iter().collect();
            self.hist_index = None;
        }
    }

    fn kill_word_back(&mut self) {
        if self.cursor == 0 {
            return;
        }
        let mut start = self.cursor;
        while start > 0 && self.buffer[start - 1].is_whitespace() {
            start -= 1;
        }
        while start > 0 && !self.buffer[start - 1].is_whitespace() {
            start -= 1;
        }
        let removed: Vec<char> = self.buffer.drain(start..self.cursor).collect();
        self.cursor = start;
        self.kill = removed.iter().collect();
        self.hist_index = None;
    }

    fn kill_word_forward(&mut self) {
        let len = self.buffer.len();
        if self.cursor >= len {
            return;
        }
        let mut end = self.cursor;
        while end < len && self.buffer[end].is_whitespace() {
            end += 1;
        }
        while end < len && !self.buffer[end].is_whitespace() {
            end += 1;
        }
        let removed: Vec<char> = self.buffer.drain(self.cursor..end).collect();
        self.kill = removed.iter().collect();
        self.hist_index = None;
    }

    fn yank(&mut self) {
        if self.kill.is_empty() {
            return;
        }
        let text = self.kill.clone();
        self.insert_str(&text);
    }

    fn set_buffer_internal(&mut self, text: &str) {
        self.buffer = text.chars().take(MAX_LINE).collect();
        self.cursor = self.buffer.len();
        self.hist_index = None;
    }

    // -- history -----------------------------------------------------------

    /// Append to history, de-duplicating and keeping the newest 200 entries.
    pub fn add_history(&mut self, line: &str) {
        if line.is_empty() || self.password {
            return;
        }
        if self
            .history
            .last()
            .map(|last| last == line)
            .unwrap_or(false)
        {
            return;
        }
        if let Some(pos) = self.history.iter().position(|old| old == line) {
            self.history.remove(pos);
        }
        self.history.push(line.to_string());
        if self.history.len() > MAX_HISTORY {
            let drop_count = self.history.len() - MAX_HISTORY;
            self.history.drain(0..drop_count);
        }
    }

    fn history_prev(&mut self) {
        if self.history.is_empty() {
            return;
        }
        let index = match self.hist_index {
            None => {
                self.draft = self.buffer();
                self.history.len() - 1
            }
            Some(0) => 0,
            Some(i) => i - 1,
        };
        self.hist_index = Some(index);
        let entry = self.history[index].clone();
        self.set_buffer_internal(&entry);
        self.hist_index = Some(index);
    }

    fn history_next(&mut self) {
        match self.hist_index {
            None => {}
            Some(i) if i + 1 < self.history.len() => {
                let index = i + 1;
                self.hist_index = Some(index);
                let entry = self.history[index].clone();
                self.set_buffer_internal(&entry);
                self.hist_index = Some(index);
            }
            Some(_) => {
                let draft = self.draft.clone();
                self.hist_index = None;
                self.set_buffer_internal(&draft);
            }
        }
    }

    // -- completion --------------------------------------------------------

    fn complete(&mut self) -> Result<()> {
        let input = self.buffer();
        let list = match self.completer.as_ref() {
            Some(f) => f(&input),
            None => return Ok(()),
        };
        let mut list: Vec<String> = list.into_iter().filter(|s| !s.is_empty()).collect();
        list.sort();
        list.dedup();
        if list.is_empty() {
            return Ok(());
        }
        if list.len() == 1 {
            let only = list[0].clone();
            self.replace_buffer(&only);
            return Ok(());
        }
        let prefix = common_prefix(&list);
        if prefix.len() > input.len() && prefix.starts_with(&input) {
            self.replace_buffer(&prefix);
        } else {
            self.last_completions = list;
            self.show_completions()?;
        }
        Ok(())
    }

    fn replace_buffer(&mut self, text: &str) {
        self.set_buffer_internal(text);
    }

    fn show_completions(&mut self) -> Result<()> {
        let width = self.term_width();
        let mut text = String::new();
        text.push_str("\r\n");
        for item in &self.last_completions {
            // Completion candidates can come from file names, which are
            // untrusted: never let them inject terminal escapes.
            let mut line = strip_ansi(&sanitize_text_keep_ansi(item));
            line = truncate_to_width(&line, width);
            text.push_str(&line);
            text.push_str("\r\n");
        }
        self.write_str(&text)?;
        self.flush()
    }

    // -- rendering ---------------------------------------------------------

    fn term_width(&self) -> usize {
        let w = self.caps.width as usize;
        if w == 0 {
            80
        } else {
            w
        }
    }

    fn refresh(&mut self) -> Result<()> {
        let width = self.term_width();
        if self.caps.ansi {
            self.refresh_ansi(width)
        } else {
            self.refresh_plain(width)
        }
    }

    fn layout(&self, width: usize) -> (String, String, usize, usize) {
        let width = width.max(1);
        let mut prompt = sanitize_text_keep_ansi(&self.prompt);
        let mut prompt_width = display_width(&prompt);
        let avail = if prompt_width >= width {
            // Keep at least one column for the cursor and mark truncation.
            prompt = truncate_to_width(&prompt, width.saturating_sub(1));
            prompt.push('>');
            prompt_width = display_width(&prompt);
            0
        } else {
            width - prompt_width
        };

        let cells: Vec<(char, usize)> = self
            .buffer
            .iter()
            .map(|&c| {
                if self.password {
                    ('*', 1)
                } else {
                    let shown = if c.is_control() { '?' } else { c };
                    (shown, char_width(shown))
                }
            })
            .collect();
        let total: usize = cells.iter().map(|(_, w)| *w).sum();
        let cursor_index = self.cursor.min(cells.len());

        let (start, end) = if total <= avail {
            (0, cells.len())
        } else {
            let reserve = if cursor_index < cells.len() {
                cells[cursor_index].1
            } else {
                0
            };
            let back_budget = avail.saturating_sub(reserve);
            let mut start = cursor_index;
            let mut used = 0usize;
            while start > 0 {
                let w = cells[start - 1].1;
                if used.saturating_add(w) > back_budget {
                    break;
                }
                used += w;
                start -= 1;
            }
            let mut end = cursor_index;
            while end < cells.len() && used.saturating_add(cells[end].1) <= avail {
                used += cells[end].1;
                end += 1;
            }
            (start, end)
        };

        let cursor = cursor_index.max(start).min(end);
        let visible: String = cells[start..end].iter().map(|(c, _)| *c).collect();
        let before: usize = cells[start..cursor].iter().map(|(_, w)| *w).sum();
        let visible_width: usize = cells[start..end].iter().map(|(_, w)| *w).sum();
        (
            prompt,
            visible,
            prompt_width + before,
            prompt_width + visible_width,
        )
    }

    fn refresh_ansi(&mut self, width: usize) -> Result<()> {
        let (prompt, visible, cursor_col, line_width) = self.layout(width);
        let mut out = String::with_capacity(prompt.len() + visible.len() + 16);
        out.push('\r');
        out.push_str("\x1b[K");
        out.push_str(&prompt);
        out.push_str(&visible);
        let back = line_width.saturating_sub(cursor_col);
        if back > 0 {
            out.push_str("\x1b[");
            out.push_str(&back.to_string());
            out.push('D');
        }
        self.write_str(&out)?;
        self.flush()
    }

    fn refresh_plain(&mut self, width: usize) -> Result<()> {
        let (prompt, visible, cursor_col, line_width) = self.layout(width);
        let prompt = strip_ansi(&prompt);
        let line = format!("{prompt}{visible}");
        let line_width = line_width.max(display_width(&line));
        let mut out = String::with_capacity(line.len() + 16);
        out.push('\r');
        out.push_str(&line);
        let pad = self.last_width.saturating_sub(line_width);
        for _ in 0..pad {
            out.push(' ');
        }
        let total = line_width + pad;
        let back = total.saturating_sub(cursor_col);
        for _ in 0..back {
            out.push('\x08');
        }
        self.last_width = total;
        self.write_str(&out)?;
        self.flush()
    }

    fn write_str(&mut self, text: &str) -> Result<()> {
        self.out.write_all(text.as_bytes()).map_err(Error::from)
    }

    fn flush(&mut self) -> Result<()> {
        self.out.flush().map_err(Error::from)
    }

    fn newline(&mut self) -> Result<()> {
        self.write_str("\r\n")?;
        self.flush()
    }
}

fn sanitize_text_keep_ansi(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '\r' | '\n' | '\t' => out.push(' '),
            _ => out.push(c),
        }
    }
    out
}

fn common_prefix(items: &[String]) -> String {
    if items.is_empty() {
        return String::new();
    }
    let first = items[0].as_bytes();
    let mut end = 0usize;
    for (i, b) in first.iter().enumerate() {
        if items.iter().all(|s| s.as_bytes().get(i) == Some(b)) {
            end = i + 1;
        } else {
            break;
        }
    }
    while end > 0 && !items[0].is_char_boundary(end) {
        end -= 1;
    }
    items[0][..end].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;

    #[derive(Clone)]
    struct Sink(Rc<RefCell<Vec<u8>>>);

    impl Write for Sink {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.borrow_mut().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn caps(ansi: bool, width: u16) -> Capabilities {
        Capabilities {
            width,
            height: 24,
            ansi,
            color: ansi,
            unicode: true,
            tty: false,
        }
    }

    fn editor(caps: Capabilities) -> (LineEditor, Rc<RefCell<Vec<u8>>>) {
        let data = Rc::new(RefCell::new(Vec::new()));
        let out = Box::new(Sink(data.clone()));
        (LineEditor::new_with_writer(caps, out), data)
    }

    fn type_str(ed: &mut LineEditor, text: &str) {
        for c in text.chars() {
            ed.handle_key(Key::char(c)).unwrap();
        }
    }

    fn key(ed: &mut LineEditor, code: KeyCode) {
        ed.handle_key(Key::new(code)).unwrap();
    }

    fn ctrl(ed: &mut LineEditor, c: char) {
        ed.handle_key(Key::ctrl_char(c)).unwrap();
    }

    #[test]
    fn typing_and_cursor_movement() {
        let (mut ed, _out) = editor(caps(true, 80));
        ed.begin("> ").unwrap();
        type_str(&mut ed, "hello");
        assert_eq!(ed.buffer(), "hello");
        assert_eq!(ed.cursor(), 5);
        key(&mut ed, KeyCode::Left);
        key(&mut ed, KeyCode::Left);
        assert_eq!(ed.cursor(), 3);
        type_str(&mut ed, "X");
        assert_eq!(ed.buffer(), "helXlo");
        key(&mut ed, KeyCode::Home);
        assert_eq!(ed.cursor(), 0);
        key(&mut ed, KeyCode::End);
        assert_eq!(ed.cursor(), 6);
        key(&mut ed, KeyCode::Backspace);
        assert_eq!(ed.buffer(), "helXl");
        key(&mut ed, KeyCode::Home);
        key(&mut ed, KeyCode::Delete);
        assert_eq!(ed.buffer(), "elXl");
    }

    #[test]
    fn word_operations_and_kill_yank() {
        let (mut ed, _out) = editor(caps(true, 80));
        ed.begin("> ").unwrap();
        type_str(&mut ed, "hello big world");
        ctrl(&mut ed, 'w');
        assert_eq!(ed.buffer(), "hello big ");
        ctrl(&mut ed, 'w');
        assert_eq!(ed.buffer(), "hello ");
        ctrl(&mut ed, 'y');
        assert_eq!(ed.buffer(), "hello big ");
        ctrl(&mut ed, 'u');
        assert_eq!(ed.buffer(), "");
        assert_eq!(ed.cursor(), 0);
        ctrl(&mut ed, 'y');
        assert_eq!(ed.buffer(), "hello big ");
        key(&mut ed, KeyCode::Home);
        ed.handle_key(Key::new(KeyCode::Char('f')).with_alt())
            .unwrap();
        assert_eq!(ed.cursor(), 5);
        ctrl(&mut ed, 'k');
        assert_eq!(ed.buffer(), "hello");
        assert_eq!(ed.cursor(), 5);
    }

    #[test]
    fn history_recall_dedupe_and_limit() {
        let (mut ed, _out) = editor(caps(true, 80));
        ed.begin("> ").unwrap();
        ed.add_history("one");
        ed.add_history("two");
        ed.add_history("two");
        assert_eq!(ed.history(), &["one".to_string(), "two".to_string()]);
        ed.add_history("one");
        assert_eq!(ed.history(), &["two".to_string(), "one".to_string()]);
        key(&mut ed, KeyCode::Up);
        assert_eq!(ed.buffer(), "one");
        key(&mut ed, KeyCode::Up);
        assert_eq!(ed.buffer(), "two");
        key(&mut ed, KeyCode::Down);
        assert_eq!(ed.buffer(), "one");
        key(&mut ed, KeyCode::Down);
        assert_eq!(ed.buffer(), "");
        ed.clear_history();
        assert!(ed.history().is_empty());
        for i in 0..(MAX_HISTORY + 25) {
            ed.add_history(&format!("line{i}"));
        }
        assert_eq!(ed.history().len(), MAX_HISTORY);
        assert_eq!(ed.history()[0], "line25");
    }

    #[test]
    fn submit_records_history_and_ctrl_c_preserves_buffer() {
        let (mut ed, _out) = editor(caps(true, 80));
        ed.begin("> ").unwrap();
        type_str(&mut ed, "keep me");
        assert_eq!(
            ed.handle_key(Key::new(KeyCode::Enter)).unwrap(),
            EditorAction::Submit
        );
        assert_eq!(ed.history(), &["keep me".to_string()]);

        ed.begin("> ").unwrap();
        type_str(&mut ed, "draft");
        assert_eq!(
            ed.handle_key(Key::ctrl_char('c')).unwrap(),
            EditorAction::Cancelled
        );
        assert_eq!(ed.buffer(), "draft");
        assert_eq!(ed.cursor(), 5);
    }

    #[test]
    fn ctrl_l_clears_screen_and_alt_b_moves_word() {
        let (mut ed, out) = editor(caps(true, 80));
        ed.begin("> ").unwrap();
        type_str(&mut ed, "one two three");
        ed.handle_key(Key::alt_char('b')).unwrap();
        assert_eq!(ed.cursor(), 8);
        ed.handle_key(Key::alt_char('b')).unwrap();
        assert_eq!(ed.cursor(), 4);
        ctrl(&mut ed, 'l');
        let rendered = String::from_utf8(out.borrow().clone()).unwrap();
        assert!(rendered.contains("\x1b[2J\x1b[H"));
    }

    #[test]
    fn ctrl_d_is_eof_only_on_empty_buffer() {
        let (mut ed, _out) = editor(caps(true, 80));
        ed.begin("> ").unwrap();
        assert_eq!(
            ed.handle_key(Key::ctrl_char('d')).unwrap(),
            EditorAction::Eof
        );
        type_str(&mut ed, "x");
        key(&mut ed, KeyCode::Home);
        assert_eq!(
            ed.handle_key(Key::ctrl_char('d')).unwrap(),
            EditorAction::Continue
        );
        assert_eq!(ed.buffer(), "");
    }

    #[test]
    fn bracketed_paste_inserts_verbatim_and_strips_cr() {
        let (mut ed, _out) = editor(caps(true, 80));
        ed.begin("> ").unwrap();
        key(&mut ed, KeyCode::PasteStart);
        for c in "a\rb".chars() {
            ed.handle_key(Key::char(c)).unwrap();
        }
        key(&mut ed, KeyCode::Enter);
        key(&mut ed, KeyCode::Tab);
        key(&mut ed, KeyCode::PasteEnd);
        type_str(&mut ed, "!");
        assert_eq!(ed.buffer(), "ab\n\t!");
    }

    #[test]
    fn password_is_never_emitted() {
        let (mut ed, out) = editor(caps(true, 80));
        ed.set_password(true);
        ed.begin("Password: ").unwrap();
        type_str(&mut ed, "hunter2");
        let rendered = String::from_utf8(out.borrow().clone()).unwrap();
        assert!(!rendered.contains("hunter2"), "secret leaked: {rendered:?}");
        assert!(rendered.contains("*******"));
        assert_eq!(ed.buffer(), "hunter2");
        // History and completion are disabled in password mode.
        assert!(ed.handle_key(Key::new(KeyCode::Enter)).unwrap() == EditorAction::Submit);
        assert!(ed.history().is_empty());
    }

    #[test]
    fn password_plain_mode_also_masks() {
        let (mut ed, out) = editor(caps(false, 80));
        ed.set_password(true);
        ed.begin("Password: ").unwrap();
        type_str(&mut ed, "s3cret");
        let rendered = String::from_utf8(out.borrow().clone()).unwrap();
        assert!(!rendered.contains("s3cret"));
        assert!(!rendered.as_bytes().contains(&0x1b));
    }

    #[test]
    fn redraw_is_truncated_at_forty_columns() {
        let (mut ed, out) = editor(caps(true, 40));
        ed.begin("> ").unwrap();
        type_str(&mut ed, &"x".repeat(60));
        let rendered = String::from_utf8(out.borrow().clone()).unwrap();
        let last = rendered.rsplit('\r').next().unwrap_or("");
        let visible = strip_ansi(last);
        assert!(
            display_width(&visible) <= 40,
            "rendered line too wide ({}): {visible:?}",
            display_width(&visible)
        );
        assert_eq!(ed.buffer().len(), 60);
        // The window must include the end of the buffer.
        assert!(visible.ends_with("xxx"));
    }

    #[test]
    fn tiny_width_does_not_break() {
        for width in [1u16, 3, 10, 19, 20] {
            let (mut ed, out) = editor(caps(true, width));
            ed.begin("Prompt that is long: ").unwrap();
            type_str(&mut ed, "abcdefghij");
            let rendered = String::from_utf8(out.borrow().clone()).unwrap();
            let last = rendered.rsplit('\r').next().unwrap_or("");
            let visible = strip_ansi(last);
            assert!(
                display_width(&visible) <= width as usize + 1,
                "width {width} rendered {visible:?}"
            );
        }
    }

    #[test]
    fn non_ansi_mode_emits_no_escape_bytes() {
        let (mut ed, out) = editor(caps(false, 40));
        ed.begin("> ").unwrap();
        type_str(&mut ed, "abc");
        key(&mut ed, KeyCode::Backspace);
        key(&mut ed, KeyCode::Left);
        type_str(&mut ed, "Z");
        let bytes = out.borrow().clone();
        assert!(
            !bytes.contains(&0x1b),
            "escape byte in plain output: {bytes:?}"
        );
        assert!(
            !bytes.contains(&b'\n'),
            "plain single-line output contained LF"
        );
    }

    #[test]
    fn completion_single_and_prefix() {
        let (mut ed, _out) = editor(caps(true, 80));
        ed.set_completer(Box::new(|input: &str| {
            ["alpha", "alphabet", "beta"]
                .iter()
                .filter(|c| c.starts_with(input))
                .map(|c| c.to_string())
                .collect()
        }));
        ed.begin("> ").unwrap();
        type_str(&mut ed, "a");
        key(&mut ed, KeyCode::Tab);
        assert_eq!(ed.buffer(), "alpha");
        type_str(&mut ed, "b");
        key(&mut ed, KeyCode::Tab);
        assert_eq!(ed.buffer(), "alphabet");

        ed.begin("> ").unwrap();
        type_str(&mut ed, "alpha");
        key(&mut ed, KeyCode::Tab);
        assert_eq!(ed.buffer(), "alpha");
        assert_eq!(
            ed.last_completions(),
            &["alpha".to_string(), "alphabet".to_string()]
        );
        // The ambiguous list is printed, then the line is redrawn.
        assert!(ed.last_completions().len() == 2);
    }

    #[test]
    fn prompt_is_sanitised_and_ansi_safe() {
        let (mut ed, out) = editor(caps(false, 40));
        ed.begin("a\nb\x1b[31m: ").unwrap();
        let rendered = String::from_utf8(out.borrow().clone()).unwrap();
        assert!(!rendered.as_bytes().contains(&0x1b));
        assert!(!rendered.contains('\n'));
        assert!(rendered.contains("a b"));
    }
}
