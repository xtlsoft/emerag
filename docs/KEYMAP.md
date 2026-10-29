# Keys and slash commands

emerag has two control surfaces: short slash commands (always available, typed)
and a Ctrl+X chord (fast, no conflicts with shells or tmux).

## Slash commands

Type at the prompt. Prefix matching is supported: `/m` means `/model`.

    /help  /h       context help and key card
    /wizard /w      provider + model setup wizard
    /model /m       switch model (numbered list)
    /provider /p    configured providers; "configure another" shows the catalog
    /auth  /k       authenticate: API key or DeepSeek account sign-in
    /login          sign in with a DeepSeek account (OAuth, no key)
    /logout         remove the stored DeepSeek account grant
    /new [name]     new conversation (memory with --no-write)
    /session [N]    list or switch conversations
    /fork [name]    copy this conversation into a new one
    /bg PROMPT      run a turn in the background (prompt ending in " &" too)
    /wait [ID]      wait for background output and approvals
    /kill [ID]      cancel a background turn
    /mode  /perm    permission mode: ask | auto | read-only | yolo
    /config /c      show effective configuration (secrets redacted)
    /keys           print the key card
    /skills /s      list and reload skills
    /mcp            list MCP servers and tools
    /jobs  /j       list background jobs; /jobs output ID; /jobs kill ID
    /agents /a      list subagents and their status
    /transcript /t  show or save the session transcript
    /clear /cls     clear the conversation (keeps system prompt)
    /compact        summarize older turns to free context
    /script /x      run an emera script file or snippet
    /local          local model: status | up | stop
    /doctor /d      diagnostics: terminal, shells, TLS, DNS, disk
    /quit /q        exit (Ctrl+D also works)

Commands never require you to memorize options: every command with choices
prints a numbered menu, and every menu accepts a digit or Enter.

## Ctrl+X chord

Ctrl+X is a prefix (like Emacs). Press Ctrl+X, release, then one letter.
This avoids collisions with Ctrl+C/D/L/R/Z that shells and terminals steal.

    Ctrl+X H      help / key card
    Ctrl+X W      wizard
    Ctrl+X M      model picker
    Ctrl+X A      auth (API key or DeepSeek account)
    Ctrl+X P      permission mode
    Ctrl+X J      jobs
    Ctrl+X G      subagents
    Ctrl+X S      skills
    Ctrl+X T      transcript view
    Ctrl+X C      compact context
    Ctrl+X L      redraw screen
    Ctrl+X Q      quit
    Ctrl+X ?      print the chord table

## Line editing

    Ctrl+C        cancel the current turn or input
    Ctrl+D        exit when the input is empty
    Ctrl+L        redraw
    Ctrl+A / E    start / end of line
    Ctrl+B / F    one character left / right
    Alt+B / F     one word left / right
    Ctrl+W        delete previous word
    Ctrl+U / K    delete to start / end
    Ctrl+Y        paste last deleted text
    Up / Down     history
    Tab           complete commands, paths and skill names
    PgUp / PgDn  scroll transcript (fullscreen mode)

Arrow keys are optional. In a serial console use Ctrl+B/F or just retype; the
line editor degrades to cooked mode and everything still works.

## Permission prompts

The approval prompt is always the same four answers:

    y  allow once
    a  allow for this session (this exact pattern)
    n  deny (the model sees the denial and may try another way)
    e  edit the command before running it

In `ask` mode nothing runs without an answer. In `auto` mode all tool calls run
without prompts. `read-only` allows reads and searches but never writes or
executes. `yolo` disables prompts and sandbox hints; use it only in throwaway
containers.
