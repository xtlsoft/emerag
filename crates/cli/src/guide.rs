//! Offline tutorial. No network, no model, no config required.

use std::io::{BufRead, Write};

pub fn run() -> std::io::Result<()> {
    let pages: &[(&str, &str)] = &[
        (
            "What emerag is",
            "emerag is one static binary that talks to an AI model and runs tools\n\
             on this machine: shell commands, file edits, and a small script engine.\n\
             It is built for broken or unusual systems: no Node.js, no Python,\n\
             no package manager, no working DNS required.\n",
        ),
        (
            "Connect a model (one time)",
            "Run:  emerag --wizard\n\
             Pick a provider by number, press Enter for its endpoint, paste the key\n\
             (it is not echoed when typing in a terminal), then pick a model from\n\
             the discovered list. If DNS is broken, answer y and type an IP.\n\
             Nothing is saved unless you say yes at the end.\n",
        ),
        (
            "Ask for help",
            "At the prompt, type what you want in plain language:\n\
             \n    why did nginx fail to start?\n    fix it\n    check disk space\n\
             \nThe agent inspects first, then proposes commands. In ask mode every\n\
             command and file write needs your y/n approval.\n",
        ),
        (
            "Control it",
            "Type /help for commands, /mode auto to stop approvals, /jobs to see\n\
             background commands, /quit to leave. Ctrl+X then H prints the key card.\n\
             Arrow keys are optional: slash commands work everywhere.\n",
        ),
        (
            "When the shell is broken",
            "Use the script tool: the agent can read and write files, list\n\
             directories and run processes without a shell.\n\
             Try:  use the script tool to read /etc/resolv.conf\n",
        ),
        (
            "When the network is broken",
            "Pin the endpoint to an IP:\n\
             \n    emerag --resolve api.deepseek.com:443:203.0.113.10 --wizard\n\
             \nTLS still verifies the hostname, so pinning is safe.\n",
        ),
    ];
    let mut out = std::io::stdout();
    for (i, (title, body)) in pages.iter().enumerate() {
        writeln!(out, "\n=== {} / {} : {} ===\n", i + 1, pages.len(), title)?;
        writeln!(out, "{}", body)?;
        if i + 1 < pages.len() {
            write!(out, "Press Enter to continue (q to quit) ")?;
            out.flush()?;
            let mut line = String::new();
            std::io::stdin().lock().read_line(&mut line)?;
            if line.trim().eq_ignore_ascii_case("q") {
                break;
            }
        }
    }
    writeln!(
        out,
        "\nThat is everything you need for an emergency. Good luck."
    )?;
    Ok(())
}
