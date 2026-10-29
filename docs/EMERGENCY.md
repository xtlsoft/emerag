# Emergency playbooks

Each scenario lists the exact commands. Everything below works without a
clipboard, a mouse or a working DNS resolver.

## The machine has no working DNS

Symptoms: `ping api.deepseek.com` says "unknown host"; curl fails to resolve;
the model endpoint cannot be reached.

    ./emerag --doctor
    # find the IP elsewhere (phone, another host, your notes)
    ./emerag --resolve api.deepseek.com:443:203.0.113.10 --wizard
    # or, for one session:
    ./emerag --ip 203.0.113.10 -p "hello"

TLS still verifies the certificate against `api.deepseek.com`, so pinning an IP
does not weaken security. Multiple endpoints can be pinned by repeating
`--resolve`. IPv6 is written `--resolve api.example.com:443:[2001:db8::1]`.

If the *system* resolver is broken but a proxy works:

    export HTTPS_PROXY=http://10.0.0.1:3128
    ./emerag -p "test the endpoint"

## The disk is read-only (rescue shell, squashfs, locked-down box)

    ./emerag --no-write -p "inspect /etc/fstab and tell me what is wrong"

`--no-write` keeps configuration, sessions and transcripts in memory only. No
temp files are created in the working directory. To still keep a transcript,
write it to a writable mount:

    ./emerag --no-write --transcript /mnt/usb/session.jsonl

## The shell itself is broken

If `bash` segfaults or the loader is hosed, use emerag's built-in script
engine, which talks to the kernel directly and does not need a shell:

    ./emerag -p "use the script tool: list /etc, read passwd, and report users with uid 0"

The script tool exposes fs read/write/list/stat, process spawn (when possible),
environment variables, time, hashing and JSON. See docs/SCRIPTING.md.

## No editor, no nano, no vi

    ./emerag -p "read /etc/ssh/sshd_config, fix the PermitRootLogin line, write it back"
    ./emerag --mode ask -p "add ListenAddress 0.0.0.0 to /etc/ssh/sshd_config"

Every write shows a diff and asks for approval in `ask` mode.

## Serial console / 40-column terminal

    ./emerag --ascii --width 40
    # If keys do not arrive: type /help, /mode auto, /quit
    # Ctrl+X chords may not work; slash commands always do.

Raw mode is optional. If emerag cannot put the terminal in raw mode it reads
plain lines, which is exactly what a serial console wants.

## Windows: old console, no PowerShell

    emerag.exe --wizard
    emerag.exe -p "check why the service does not start"
    emerag.exe --mode ask -p "read C:\Windows\System32\drivers\etc\hosts"

cmd.exe and PowerShell are both auto-detected; Python/PHP are used as shells
when present. ANSI output is disabled automatically on legacy consoles.

## Air-gapped network

Two options:

1. Point emerag at a model server that is already on the LAN:

       ./emerag --base-url http://192.168.1.50:8080/v1 --model local-model

2. Use the offline release with embedded weights:

       ./emerag-offline local up
       ./emerag --provider local --model embedded

See docs/LOCAL-MODELS.md for sizes and which models are practical.

## The box is on fire, give me the shortest path

    ./emerag --doctor                     # 10 seconds, tells you what is broken
    ./emerag --wizard                     # one-time model setup
    ./emerag "the system booted to emergency mode; diagnose and fix"

In `ask` mode nothing destructive happens without your y/n.
