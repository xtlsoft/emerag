//! Wizard input helpers.
//!
//! In raw mode these accept a single key; in cooked mode they print the same
//! choices as a numbered list and read one line. The yes/no parser is public
//! so callers (and tests) can reuse it without touching a terminal.

use std::io::{self, Write};

use crate::keys::{read_key, KeyCode};
use crate::raw::raw_mode;
use crate::width::{strip_ansi, truncate_to_width};
use crate::{detect, Capabilities, Error, ErrorKind, Result};

/// Ask "Continue? [Y/n]" (or [y/N]) and return the answer.
pub fn prompt_yes_no(default: bool) -> Result<bool> {
    prompt_yes_no_caps(detect(), "Continue?", default)
}

/// Ask a custom yes/no question.
pub fn prompt_yes_no_with(prompt: &str, default: bool) -> Result<bool> {
    prompt_yes_no_caps(detect(), prompt, default)
}

/// Yes/no prompt with explicit capabilities (useful after a --plain flag).
pub fn prompt_yes_no_caps(caps: Capabilities, prompt: &str, default: bool) -> Result<bool> {
    let hint = if default { "[Y/n]" } else { "[y/N]" };
    let question = format!("{} {}", clean_line(caps, prompt), hint);
    if caps.tty {
        if let Ok(_guard) = raw_mode() {
            return yes_no_raw(&question, default);
        }
    }
    yes_no_cooked(caps, &question, default)
}

/// Parse a yes/no answer from a cooked line. Empty input yields the default;
/// unrecognised input yields None.
pub fn parse_yes_no(input: &str, default: bool) -> Option<bool> {
    let text = input.trim().to_ascii_lowercase();
    if text.is_empty() {
        return Some(default);
    }
    match text.as_str() {
        "y" | "yes" | "true" | "1" => Some(true),
        "n" | "no" | "false" | "0" => Some(false),
        _ => None,
    }
}

fn yes_no_raw(question: &str, default: bool) -> Result<bool> {
    let mut out = io::stdout();
    write!(out, "{question} ").map_err(Error::from)?;
    out.flush().map_err(Error::from)?;
    loop {
        let key = match read_key() {
            Ok(key) => key,
            Err(e) if e.kind() == ErrorKind::EndOfInput => {
                writeln!(out).map_err(Error::from)?;
                return Ok(default);
            }
            Err(e) => return Err(e),
        };
        match key.code {
            KeyCode::Char('y') | KeyCode::Char('Y') if !key.ctrl => {
                out.write_all(b"y\r\n").map_err(Error::from)?;
                out.flush().map_err(Error::from)?;
                return Ok(true);
            }
            KeyCode::Char('n') | KeyCode::Char('N') if !key.ctrl => {
                out.write_all(b"n\r\n").map_err(Error::from)?;
                out.flush().map_err(Error::from)?;
                return Ok(false);
            }
            KeyCode::Enter => {
                let answer = default;
                let echo = if answer { "y" } else { "n" };
                write!(out, "{echo}\r\n").map_err(Error::from)?;
                out.flush().map_err(Error::from)?;
                return Ok(answer);
            }
            KeyCode::Esc => {
                let answer = default;
                let echo = if answer { "y" } else { "n" };
                write!(out, "{echo}\r\n").map_err(Error::from)?;
                out.flush().map_err(Error::from)?;
                return Ok(answer);
            }
            _ if key.ctrl && key.is_ctrl('c') => {
                out.write_all(b"^C\r\n").map_err(Error::from)?;
                out.flush().map_err(Error::from)?;
                return Err(Error::cancelled());
            }
            _ => {}
        }
    }
}

fn yes_no_cooked(_caps: Capabilities, question: &str, default: bool) -> Result<bool> {
    let mut out = io::stdout();
    loop {
        write!(out, "{question} ").map_err(Error::from)?;
        out.flush().map_err(Error::from)?;
        let mut line = String::new();
        match io::stdin().read_line(&mut line) {
            Ok(0) => return Ok(default),
            Ok(_) => {
                if let Some(answer) = parse_yes_no(&line, default) {
                    return Ok(answer);
                }
                out.write_all(b"\r\nPlease answer y or n.\r\n")
                    .map_err(Error::from)?;
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => return Err(Error::cancelled()),
            Err(e) => return Err(Error::from(e)),
        }
    }
}

/// Show a numbered menu and return the selected zero-based index.
///
/// In raw mode j/k, arrows, digits and Enter work. In cooked mode a line is
/// read and may be a number or the exact option text.
pub fn prompt_choice<S: AsRef<str>>(title: &str, options: &[S], default: usize) -> Result<usize> {
    prompt_choice_caps(detect(), title, options, default)
}

/// [prompt_choice] with explicit capabilities.
pub fn prompt_choice_caps<S: AsRef<str>>(
    caps: Capabilities,
    title: &str,
    options: &[S],
    default: usize,
) -> Result<usize> {
    let labels: Vec<String> = options.iter().map(|s| s.as_ref().to_string()).collect();
    if labels.is_empty() {
        return Err(Error::new("prompt_choice: no options"));
    }
    let default = default.min(labels.len() - 1);
    if caps.tty {
        if let Ok(_guard) = raw_mode() {
            return choice_raw(caps, title, &labels, default);
        }
    }
    choice_cooked(caps, title, &labels, default)
}

fn choice_raw(caps: Capabilities, title: &str, labels: &[String], default: usize) -> Result<usize> {
    let mut out = io::stdout();
    let mut selected = default;
    let mut drawn = 0usize;
    let mut typed = String::new();
    draw_choice(
        &mut out, caps, title, labels, selected, &typed, true, &mut drawn,
    )?;
    loop {
        let key = match read_key() {
            Ok(key) => key,
            Err(e) if e.kind() == ErrorKind::EndOfInput => {
                out.write_all(b"\r\n").map_err(Error::from)?;
                return Ok(selected);
            }
            Err(e) => return Err(e),
        };
        match key.code {
            KeyCode::Char('j') | KeyCode::Down | KeyCode::PageDown if !key.ctrl => {
                typed.clear();
                if selected + 1 < labels.len() {
                    selected += 1;
                }
                if caps.ansi {
                    draw_choice(
                        &mut out, caps, title, labels, selected, &typed, false, &mut drawn,
                    )?;
                }
            }
            KeyCode::Char('k') | KeyCode::Up | KeyCode::PageUp if !key.ctrl => {
                typed.clear();
                selected = selected.saturating_sub(1);
                if caps.ansi {
                    draw_choice(
                        &mut out, caps, title, labels, selected, &typed, false, &mut drawn,
                    )?;
                }
            }
            KeyCode::Home => {
                typed.clear();
                selected = 0;
                if caps.ansi {
                    draw_choice(
                        &mut out, caps, title, labels, selected, &typed, false, &mut drawn,
                    )?;
                }
            }
            KeyCode::End => {
                typed.clear();
                selected = labels.len() - 1;
                if caps.ansi {
                    draw_choice(
                        &mut out, caps, title, labels, selected, &typed, false, &mut drawn,
                    )?;
                }
            }
            KeyCode::Char(c) if c.is_ascii_digit() && !key.ctrl => {
                if labels.len() > 9 {
                    // Eleven providers do not fit in a single digit. Collect
                    // the number and let Enter select it, so 10 and 11 work
                    // even when arrow keys are unavailable.
                    // A digit that cannot extend the number starts a new one,
                    // so "3" then "5" selects 5 instead of nothing.
                    typed.push(c);
                    if !matches!(typed.parse::<usize>(), Ok(n) if n >= 1 && n <= labels.len()) {
                        typed.clear();
                        typed.push(c);
                    }
                    if let Ok(n) = typed.parse::<usize>() {
                        if n >= 1 && n <= labels.len() {
                            selected = n - 1;
                        }
                    }
                    show_typed(&mut out, caps, title, labels, selected, &typed, &mut drawn)?;
                } else {
                    let n = c.to_digit(10).unwrap_or(0) as usize;
                    let index = if n == 0 { 9 } else { n - 1 };
                    if index < labels.len() {
                        selected = index;
                        finish_choice(&mut out, caps, title, labels, selected, &typed, &mut drawn)?;
                        return Ok(selected);
                    }
                }
            }
            KeyCode::Backspace if !typed.is_empty() => {
                typed.pop();
                if let Ok(n) = typed.parse::<usize>() {
                    if n >= 1 && n <= labels.len() {
                        selected = n - 1;
                    }
                }
                show_typed(&mut out, caps, title, labels, selected, &typed, &mut drawn)?;
            }
            KeyCode::Enter => {
                if let Ok(n) = typed.parse::<usize>() {
                    if n >= 1 && n <= labels.len() {
                        selected = n - 1;
                    }
                }
                finish_choice(&mut out, caps, title, labels, selected, &typed, &mut drawn)?;
                return Ok(selected);
            }
            KeyCode::Esc => {
                out.write_all(b"^[\r\n").map_err(Error::from)?;
                out.flush().map_err(Error::from)?;
                return Err(Error::cancelled());
            }
            _ if key.ctrl && key.is_ctrl('c') => {
                out.write_all(b"^C\r\n").map_err(Error::from)?;
                out.flush().map_err(Error::from)?;
                return Err(Error::cancelled());
            }
            _ => {}
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn draw_choice<W: Write>(
    out: &mut W,
    caps: Capabilities,
    title: &str,
    labels: &[String],
    selected: usize,
    typed: &str,
    first: bool,
    drawn: &mut usize,
) -> Result<()> {
    let width = choice_width(caps);
    let mut lines = Vec::with_capacity(labels.len() + 1);
    lines.push(fit(caps, title, width));
    for (i, label) in labels.iter().enumerate() {
        let marker = if i == selected { "> " } else { "  " };
        let line = format!("{marker}{}. {}", i + 1, label);
        lines.push(fit(caps, &line, width));
    }
    if labels.len() > 9 {
        let hint = format!("  type the number and press Enter: {typed}");
        lines.push(fit(caps, &hint, width));
    }
    if !first && caps.ansi && *drawn > 0 {
        write!(out, "\x1b[{}A", *drawn).map_err(Error::from)?;
    }
    for line in &lines {
        if caps.ansi {
            write!(out, "\r\x1b[K{line}\r\n").map_err(Error::from)?;
        } else {
            write!(out, "{line}\r\n").map_err(Error::from)?;
        }
    }
    out.flush().map_err(Error::from)?;
    *drawn = lines.len();
    Ok(())
}

/// Show the number typed so far. With ANSI the whole menu is redrawn with the
/// number on the hint line; without it (legacy Windows consoles, serial
/// terminals) the menu cannot move, so the number is echoed on the line below
/// it. Either way the user can see what Enter will select.
fn show_typed<W: Write>(
    out: &mut W,
    caps: Capabilities,
    title: &str,
    labels: &[String],
    selected: usize,
    typed: &str,
    drawn: &mut usize,
) -> Result<()> {
    if caps.ansi {
        return draw_choice(out, caps, title, labels, selected, typed, false, drawn);
    }
    // Back to column 0, pad over a longer previous number, then print again.
    write!(out, "\r> {typed}   \r> {typed}").map_err(Error::from)?;
    out.flush().map_err(Error::from)
}

fn finish_choice<W: Write>(
    out: &mut W,
    caps: Capabilities,
    title: &str,
    labels: &[String],
    selected: usize,
    typed: &str,
    drawn: &mut usize,
) -> Result<()> {
    if caps.ansi {
        draw_choice(out, caps, title, labels, selected, typed, false, drawn)?;
    }
    out.write_all(b"\r\n").map_err(Error::from)?;
    out.flush().map_err(Error::from)
}

fn choice_cooked(
    caps: Capabilities,
    title: &str,
    labels: &[String],
    default: usize,
) -> Result<usize> {
    let mut out = io::stdout();
    let width = choice_width(caps);
    writeln!(out, "{}", fit(caps, title, width)).map_err(Error::from)?;
    for (i, label) in labels.iter().enumerate() {
        let line = format!("  {}. {}", i + 1, label);
        writeln!(out, "{}", fit(caps, &line, width)).map_err(Error::from)?;
    }
    writeln!(
        out,
        "Choice [1-{}] (default {}):",
        labels.len(),
        default + 1
    )
    .map_err(Error::from)?;
    out.flush().map_err(Error::from)?;

    loop {
        let mut line = String::new();
        match io::stdin().read_line(&mut line) {
            Ok(0) => return Ok(default),
            Ok(_) => {
                let text = line.trim();
                if text.is_empty() {
                    return Ok(default);
                }
                if let Ok(n) = text.parse::<usize>() {
                    if n >= 1 && n <= labels.len() {
                        return Ok(n - 1);
                    }
                }
                if let Some(index) = labels
                    .iter()
                    .position(|label| label.eq_ignore_ascii_case(text))
                {
                    return Ok(index);
                }
                writeln!(out, "Please enter 1-{}.", labels.len()).map_err(Error::from)?;
                out.flush().map_err(Error::from)?;
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => return Err(Error::cancelled()),
            Err(e) => return Err(Error::from(e)),
        }
    }
}

fn choice_width(caps: Capabilities) -> usize {
    let w = caps.width as usize;
    if w == 0 {
        80
    } else {
        w
    }
}

fn fit(caps: Capabilities, text: &str, width: usize) -> String {
    let mut line = clean_line(caps, text);
    line = truncate_to_width(&line, width);
    if !caps.ansi {
        line = strip_ansi(&line);
    }
    line
}

fn clean_line(caps: Capabilities, text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '\r' | '\n' | '\t' => out.push(' '),
            _ => out.push(c),
        }
    }
    if !caps.ansi {
        out = strip_ansi(&out);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::width::display_width;

    #[test]
    fn yes_no_parsing() {
        assert_eq!(parse_yes_no("", true), Some(true));
        assert_eq!(parse_yes_no("", false), Some(false));
        assert_eq!(parse_yes_no("y", false), Some(true));
        assert_eq!(parse_yes_no("YES", false), Some(true));
        assert_eq!(parse_yes_no(" n ", true), Some(false));
        assert_eq!(parse_yes_no("no", true), Some(false));
        assert_eq!(parse_yes_no("1", false), Some(true));
        assert_eq!(parse_yes_no("0", true), Some(false));
        assert_eq!(parse_yes_no("maybe", true), None);
    }

    #[test]
    fn choice_lines_fit_width() {
        let caps = Capabilities {
            width: 20,
            ..Capabilities::default()
        };
        let line = fit(caps, "a very long option that must be truncated", 20);
        assert!(display_width(&line) <= 20);
        assert!(line.is_ascii());
    }

    #[test]
    fn typed_number_is_visible_with_and_without_ansi() {
        let labels: Vec<String> = (1..=11).map(|i| format!("option {i}")).collect();
        let mut drawn = 0;

        let plain = Capabilities {
            ansi: false,
            ..Capabilities::default()
        };
        let mut out = Vec::new();
        show_typed(&mut out, plain, "Pick", &labels, 10, "11", &mut drawn).unwrap();
        assert_eq!(String::from_utf8(out).unwrap(), "\r> 11   \r> 11");

        let vt = Capabilities {
            ansi: true,
            width: 80,
            ..Capabilities::default()
        };
        let mut out = Vec::new();
        draw_choice(&mut out, vt, "Pick", &labels, 0, "", true, &mut drawn).unwrap();
        show_typed(&mut out, vt, "Pick", &labels, 10, "11", &mut drawn).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("type the number and press Enter: 11"));
        assert!(text.contains("> 11. option 11"));
    }

    #[test]
    fn empty_choice_list_is_an_error() {
        let caps = Capabilities::default();
        let options: [&str; 0] = [];
        let err = prompt_choice_caps(caps, "Pick", &options, 0).unwrap_err();
        assert!(err.to_string().contains("no options"));
    }
}
