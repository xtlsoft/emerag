# Skills and MCP

emerag has two extension mechanisms, both cheap enough that a small binary can
carry them: **skills** (instruction documents, loaded on demand) and **MCP**
(tool servers over stdio).

## Skills

A skill is a Markdown file with optional frontmatter:

    ---
    name: nginx-repair
    description: diagnose and repair nginx startup failures
    ---
    # nginx repair

    1. Check configuration syntax: nginx -t
    2. Look for port conflicts: ss -ltnp
    3. ...

Where emerag looks, in order:

1. `./.emerag/skills/<name>/SKILL.md`
2. `./.emerag/skills/<name>.md`
3. `~/.config/emerag/skills/...`
4. any `--skill DIR` or `skill_dirs` entries in the config

The system prompt lists only the name and description (cheap). The model calls
the `skill` tool with a name to load the full body, so a hundred skills cost
almost nothing until used.

`/skills` lists what was found and where; `/skills reload` re-scans.

Writing a good skill:

- Start with when to use it, not background.
- Concrete commands, file paths, and expected output.
- Include the failure modes you have actually seen.
- Keep it under ~200 lines; it competes for context.

## MCP servers

emerag is an MCP *client* over stdio: it starts servers as child processes,
initializes, lists tools, and exposes them to the model as
`mcp__<server>__<tool>`.

Add servers to `config.json`:

    {
      "mcp": {
        "servers": [
          {"name": "fs", "command": "mcp-server-filesystem", "args": ["/srv"]},
          {"name": "git", "command": "uvx", "args": ["mcp-server-git"],
           "env": {"GIT_PAGER": "cat"}, "timeout_secs": 30}
        ]
      }
    }

The object form with names as keys is also accepted:

    {"mcpServers": {"fs": {"command": "mcp-server-filesystem", "args": ["/srv"]}}}

At startup each server is launched; a server that fails to start produces a
warning (`/mcp` shows it) and the rest of the session continues. Tools are
called with a 20-30s timeout, stderr is retained for diagnostics, and the
process is killed when emerag exits.

Notes for air-gapped machines: if `npx`/`uvx` cannot download, vendor the
server binary next to the config and use an absolute path. A server that is a
shell script speaking JSON-RPC on stdin/stdout works too; that is often the
smallest possible MCP server.

## Security

Both mechanisms give the model more power:

- Skills are text, but text that tells the model what to run. Only install
  skills you have read.
- MCP tools run with emerag's permissions and are classified as write-risk, so
  `read-only` mode denies them and `ask` mode prompts. A malicious server can
  still return misleading content; treat MCP output like any other untrusted
  text.
