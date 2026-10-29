//! Wizard frame painter.
//!
//! [Screen] writes to any [std::io::Write]. When capabilities say ANSI is not
//! available it strips escape sequences from every call, so a serial console
//! receives plain lines only. It can optionally use the alternate screen, but
//! never requires it.

use std::io::{self, Write};

use crate::glyphs::Glyphs;
use crate::width::{display_width, strip_ansi, truncate_to_width};
use crate::{Capabilities, Error, Result};

/// A frame-oriented painter for wizards and status screens.
pub struct Screen {
    caps: Capabilities,
    out: Box<dyn Write>,
    alt_requested: bool,
    alt_active: bool,
}

impl Screen {
    pub fn new(caps: Capabilities) -> Screen {
        Screen::new_with_writer(caps, Box::new(io::stdout()))
    }

    /// Create a screen with an injected writer, for headless tests.
    pub fn new_with_writer(caps: Capabilities, out: Box<dyn Write>) -> Screen {
        Screen {
            caps,
            out,
            alt_requested: false,
            alt_active: false,
        }
    }

    pub fn caps(&self) -> Capabilities {
        self.caps
    }

    pub fn set_writer(&mut self, out: Box<dyn Write>) {
        self.out = out;
    }

    /// Request (or stop requesting) the alternate screen. It is entered by the
    /// next [Screen::begin_frame] and left by [Screen::finish].
    pub fn set_alt_screen(&mut self, on: bool) {
        self.alt_requested = on;
    }

    pub fn width(&self) -> usize {
        let w = self.caps.width as usize;
        if w == 0 {
            80
        } else {
            w
        }
    }

    /// Start a frame: enter the alternate screen once (if requested) and clear
    /// from home. On a dumb terminal this writes nothing.
    pub fn begin_frame(&mut self) -> Result<()> {
        if !self.caps.ansi {
            return Ok(());
        }
        if self.alt_requested && !self.alt_active {
            self.write_raw("\x1b[?1049h")?;
            self.alt_active = true;
        }
        self.write_raw("\x1b[H\x1b[2J")?;
        self.flush()
    }

    /// Print one line. Long lines are truncated to the terminal width and the
    /// text is sanitised to a single line.
    pub fn line(&mut self, text: &str) -> Result<()> {
        let width = self.width();
        let mut text = sanitize_line(text);
        text = truncate_to_width(&text, width);
        if !self.caps.ansi {
            text = strip_ansi(&text);
        }
        let mut out = String::with_capacity(text.len() + 2);
        out.push_str(&text);
        out.push_str("\r\n");
        self.out.write_all(out.as_bytes()).map_err(Error::from)
    }

    /// Finish a frame by flushing buffered output.
    pub fn end_frame(&mut self) -> Result<()> {
        self.flush()
    }

    /// Write a raw string. The string is passed through unchanged only when
    /// ANSI is available; otherwise escape sequences are removed.
    pub fn write_raw(&mut self, s: &str) -> Result<()> {
        let text = if self.caps.ansi {
            s.to_string()
        } else {
            strip_ansi(s)
        };
        self.out.write_all(text.as_bytes()).map_err(Error::from)
    }

    pub fn hide_cursor(&mut self) -> Result<()> {
        if self.caps.ansi {
            self.write_raw("\x1b[?25l")?;
        }
        Ok(())
    }

    pub fn show_cursor(&mut self) -> Result<()> {
        if self.caps.ansi {
            self.write_raw("\x1b[?25h")?;
        }
        Ok(())
    }

    /// Clear the current line. On a dumb terminal this is just a carriage
    /// return (no escape bytes).
    pub fn clear_line(&mut self) -> Result<()> {
        if self.caps.ansi {
            self.write_raw("\r\x1b[K")
        } else {
            self.write_raw("\r")
        }
    }

    /// Horizontal rule using the configured glyph set.
    pub fn rule(&mut self, width: usize) -> Result<()> {
        let width = normalize_width(width, self.width());
        let glyph = self.caps.glyph("hline");
        let text = glyph.repeat(width);
        self.line(&text)
    }

    /// Top border of a box, width columns including corners.
    pub fn box_top(&mut self, width: usize) -> Result<()> {
        let width = normalize_width(width, self.width()).max(2);
        let glyphs = self.caps.glyphs();
        let mut text = String::new();
        text.push_str(glyphs.tl);
        text.push_str(&glyphs.hline.repeat(width - 2));
        text.push_str(glyphs.tr);
        self.line(&text)
    }

    /// Bottom border of a box.
    pub fn box_bottom(&mut self, width: usize) -> Result<()> {
        let width = normalize_width(width, self.width()).max(2);
        let glyphs = self.caps.glyphs();
        let mut text = String::new();
        text.push_str(glyphs.bl);
        text.push_str(&glyphs.hline.repeat(width - 2));
        text.push_str(glyphs.br);
        self.line(&text)
    }

    /// One row inside a box: vertical borders plus padded text.
    pub fn box_row(&mut self, text: &str, width: usize) -> Result<()> {
        let width = normalize_width(width, self.width()).max(2);
        let glyphs = self.caps.glyphs();
        let clean = sanitize_line(text);
        if width < 4 {
            let body = truncate_to_width(&clean, width.saturating_sub(1));
            return self.line(&format!("{}{}", glyphs.vline, body));
        }
        let inner = width - 2;
        let body = truncate_to_width(&clean, inner.saturating_sub(2));
        let padding = inner.saturating_sub(2 + display_width(&body));
        let mut line = String::new();
        line.push_str(glyphs.vline);
        line.push(' ');
        line.push_str(&body);
        for _ in 0..padding {
            line.push(' ');
        }
        line.push(' ');
        line.push_str(glyphs.vline);
        self.line(&line)
    }

    /// Draw a complete box with an optional title row.
    pub fn draw_box(&mut self, title: &str, rows: &[&str], width: usize) -> Result<()> {
        let width = normalize_width(width, self.width());
        self.box_top(width)?;
        if !title.is_empty() {
            self.box_row(title, width)?;
        }
        for row in rows {
            self.box_row(row, width)?;
        }
        self.box_bottom(width)
    }

    /// Leave the alternate screen (if entered) and show the cursor.
    pub fn finish(&mut self) -> Result<()> {
        if self.alt_active {
            self.write_raw("\x1b[?1049l")?;
            self.alt_active = false;
        }
        if self.caps.ansi {
            self.write_raw("\x1b[?25h")?;
        }
        self.flush()
    }

    fn flush(&mut self) -> Result<()> {
        self.out.flush().map_err(Error::from)
    }
}

fn normalize_width(requested: usize, fallback: usize) -> usize {
    if requested == 0 {
        fallback.max(1)
    } else {
        requested
    }
}

fn sanitize_line(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '\r' | '\n' | '\t' => out.push(' '),
            _ => out.push(c),
        }
    }
    out
}

/// Glyph set helper for callers that do not have a Screen instance.
pub fn glyphs_for(caps: Capabilities) -> Glyphs {
    caps.glyphs()
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

    fn caps(ansi: bool, unicode: bool, width: u16) -> Capabilities {
        Capabilities {
            width,
            height: 16,
            ansi,
            color: ansi,
            unicode,
            tty: false,
        }
    }

    fn screen(caps: Capabilities) -> (Screen, Rc<RefCell<Vec<u8>>>) {
        let data = Rc::new(RefCell::new(Vec::new()));
        let out = Box::new(Sink(data.clone()));
        (Screen::new_with_writer(caps, out), data)
    }

    #[test]
    fn non_ansi_mode_emits_zero_escape_bytes() {
        let (mut s, out) = screen(caps(false, false, 40));
        s.set_alt_screen(true);
        s.begin_frame().unwrap();
        s.line("\x1b[31mred\x1b[0m text").unwrap();
        s.write_raw("\x1b[2J\x1b[?25l").unwrap();
        s.hide_cursor().unwrap();
        s.show_cursor().unwrap();
        s.clear_line().unwrap();
        s.rule(40).unwrap();
        s.box_top(20).unwrap();
        s.box_row("item", 20).unwrap();
        s.box_bottom(20).unwrap();
        s.draw_box("Title", &["a", "b"], 30).unwrap();
        s.end_frame().unwrap();
        s.finish().unwrap();
        let bytes = out.borrow().clone();
        assert!(!bytes.contains(&0x1b), "escape emitted: {bytes:?}");
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.contains("red text"));
        assert!(text.contains('+'));
        assert!(!text.contains("?1049"));
    }

    #[test]
    fn ansi_mode_uses_clear_and_alt_screen() {
        let (mut s, out) = screen(caps(true, true, 80));
        s.set_alt_screen(true);
        s.begin_frame().unwrap();
        s.begin_frame().unwrap();
        s.hide_cursor().unwrap();
        s.show_cursor().unwrap();
        s.line("hello").unwrap();
        s.end_frame().unwrap();
        s.finish().unwrap();
        let text = String::from_utf8(out.borrow().clone()).unwrap();
        assert!(text.contains("\x1b[?1049h"));
        assert!(text.contains("\x1b[H\x1b[2J"));
        assert_eq!(
            text.matches("\x1b[?1049h").count(),
            1,
            "alt screen entered twice"
        );
        assert!(text.contains("\x1b[?1049l"));
        assert!(text.contains("\x1b[?25l"));
        assert!(text.contains("\x1b[?25h"));
    }

    #[test]
    fn lines_are_truncated_to_terminal_width() {
        let (mut s, out) = screen(caps(true, false, 40));
        s.line(&"x".repeat(60)).unwrap();
        let text = String::from_utf8(out.borrow().clone()).unwrap();
        let first = text.split("\r\n").next().unwrap();
        assert_eq!(display_width(first), 40);
    }

    #[test]
    fn ascii_box_is_ascii_only() {
        let (mut s, out) = screen(caps(false, false, 40));
        s.draw_box("Title", &["one", "two"], 20).unwrap();
        let text = String::from_utf8(out.borrow().clone()).unwrap();
        assert!(text.is_ascii());
        assert!(text.contains("+------------------+"));
    }

    #[test]
    fn rule_has_requested_width() {
        let (mut s, out) = screen(caps(false, false, 40));
        s.rule(40).unwrap();
        let text = String::from_utf8(out.borrow().clone()).unwrap();
        let first = text.split("\r\n").next().unwrap();
        assert_eq!(first.len(), 40);
        assert!(first.chars().all(|c| c == '-'));

        let (mut s, out) = screen(caps(true, true, 40));
        s.rule(10).unwrap();
        let text = String::from_utf8(out.borrow().clone()).unwrap();
        assert!(text.starts_with("──────────"));
    }
}
