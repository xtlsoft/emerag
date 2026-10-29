//! The printable key card. Kept short so it fits one serial-console screen.

pub const CARD: &str = r#"emerag key card
==============

Type / then a command (prefix works):
  /help /h     help & this card
  /wizard /w   provider + model setup
  /model /m    switch model
  /p           configured providers
  /auth /k     set API key
  /mode        ask | auto | read-only | yolo
  /new [name]  new session
  /session     list / switch sessions
  /fork [name] fork this session
  /bg PROMPT   run in background
  /wait /kill  wait for / cancel background
  /jobs /j     background commands
  /skills /s   skills
  /mcp         MCP servers/tools
  /config /c   effective config
  /clear       clear conversation
  /compact     shrink context
  /script /x   run a script file
  /doctor /d   diagnostics
  /quit /q     exit

Ctrl+X then one key:
  H help   W wizard   M model    A auth
  P mode   J jobs     G agents   S skills
  T transcript         C compact
  L redraw             Q quit

While typing:
  Enter send      Ctrl+C cancel     Ctrl+D quit
  Up/Down history Tab complete      Ctrl+L redraw
  Ctrl+A/E start/end                  Ctrl+W delete word

Approval prompt:
  y once    a always (session)    n no

No arrow keys? Type the slash commands.
Read-only disk? emerag --no-write
Broken DNS?      emerag --resolve host:443:IP
"#;

pub fn print() {
    println!("{CARD}");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn card_fits_a_narrow_screen() {
        for line in CARD.lines() {
            assert!(line.chars().count() <= 60, "line too wide: {line}");
        }
    }
}
