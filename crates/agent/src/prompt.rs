//! System prompt construction.
//!
//! Kept deliberately short: small local models have small context windows, and
//! every token here costs money on hosted providers.

use crate::skills::SkillRegistry;
use emerag_util::sys;

pub struct PromptContext<'a> {
    pub cwd: &'a std::path::Path,
    pub shell: &'a str,
    pub mode: &'a str,
    pub skills: &'a SkillRegistry,
    pub mcp_tools: &'a [String],
    pub extra: &'a str,
    pub model: &'a str,
    pub is_subagent: bool,
    pub env: &'a str,
}

pub fn build(ctx: &PromptContext<'_>) -> String {
    let mut s = String::with_capacity(4096);
    s.push_str(
        "You are emerag, a small, precise coding agent that runs on broken or unusual systems.\n         You operate a real machine through tools: commands, file edits and a built-in script engine.\n         Act, do not lecture. Inspect before you change. Prefer the smallest fix that works.\n",
    );
    s.push_str("\nEnvironment probe (measured just now):\n");
    s.push_str(ctx.env);
    s.push_str(&format!(
        "\nHost: {} | mode: {} | model: {}\n",
        sys::hostname(),
        ctx.mode,
        ctx.model
    ));

    s.push_str(
        "\nWorking rules:\n         - Explain only what matters; the user may be on a 40-column serial console. Keep lines short and avoid tables.\n         - Before destructive or privileged actions, say what you are about to do. In ask mode the user sees an approval prompt.\n         - If a command fails, read the error and adapt instead of repeating it.\n         - Prefer read/list/glob/grep before editing. Use edit_file for small changes and write_file for new files.\n         - When shells are missing or broken, use the script tool: it exposes fs/env/proc/time/json/hash without a shell.\n         - Never print or request secrets. API keys are configured outside this conversation.\n         - If the network or DNS is broken, say so and suggest a resolve override instead of retrying blindly.\n         - Use jobs for long-running commands and poll with job_output instead of blocking.\n         - Use the task tool for self-contained side work; keep the main context focused.\n",
    );

    if ctx.is_subagent {
        s.push_str(
            "\nYou are a subagent: finish the assigned task, return a compact result, and do not ask the user questions.\n",
        );
    }

    if !ctx.skills.skills.is_empty() {
        s.push_str("\nSkills you can load with the skill tool (name - description):\n");
        for sk in &ctx.skills.skills {
            s.push_str(&format!(
                "- {} - {}\n",
                sk.name,
                emerag_util::text::single_line(&sk.description)
            ));
        }
    }
    if !ctx.mcp_tools.is_empty() {
        s.push_str("\nMCP tools are available under names starting with mcp__ (server__tool).\n");
        let mut names = ctx.mcp_tools.to_vec();
        names.sort();
        for n in names.iter().take(40) {
            s.push_str(&format!("- {n}\n"));
        }
    }
    if !ctx.extra.trim().is_empty() {
        s.push_str("\nUser instructions:\n");
        s.push_str(ctx.extra.trim());
        s.push('\n');
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn prompt_contains_environment_and_rules() {
        let skills = SkillRegistry::empty();
        let ctx = PromptContext {
            cwd: Path::new("/tmp"),
            shell: "bash",
            mode: "ask",
            skills: &skills,
            mcp_tools: &[],
            extra: "be terse",
            model: "test-model",
            is_subagent: false,
            env: "OS: test\nCwd: /tmp (writable: yes)",
        };
        let p = build(&ctx);
        assert!(p.contains("emerag"));
        assert!(p.contains("/tmp"));
        assert!(p.contains("test-model"));
        assert!(p.contains("be terse"));
        assert!(p.contains("script"));
    }
}
