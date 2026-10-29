# The emera script engine

When shells are missing, broken, or untrusted, emerag can run a small script
instead. The language is a Lua 5.4 subset (no metatables, single number type)
with host functions for the operations an emergency operator needs.

Ask the model to use it:

    use the script tool: list /etc, read resolv.conf, and print nameservers

or run it yourself:

    /script ./fix.emer

## Host functions

All are available as globals; failures raise a Lua error catchable with pcall.

| function | returns | notes |
| --- | --- | --- |
| `fs.read(path)` | string | up to 2 MiB, lossy UTF-8 |
| `fs.write(path, text)` | bytes | atomic replace; creates parents |
| `fs.append(path, text)` | nil | adds a newline |
| `fs.list(path)` | table | entries `{name, dir, size}` |
| `fs.stat(path)` | table | `{size, dir, file, mtime_ms}` |
| `fs.mkdir(path)` | nil | recursive |
| `fs.remove(path)` | nil | file or directory tree |
| `fs.rename(from, to)` | nil | |
| `fs.exists(path)` | boolean | |
| `env.get(name)` | string or nil | |
| `proc.run(cmd[, timeout_ms])` | table | `{code, stdout, stderr, timed_out}`; needs a shell |
| `time.now_ms()` | number | |
| `sleep.ms(n)` | nil | capped at 60s |
| `json.encode(v)` / `json.decode(s)` | string / table | |
| `hash.sha256(s)` | hex string | |
| `base64.encode(s)` / `base64.decode(s)` | string | |
| `sys.open(path, mode)` | fd | mode r/w/a/r+/w+/a+; direct descriptor |
| `sys.read(fd, max)` | string | up to 1 MiB per call; empty at EOF |
| `sys.write(fd, text)` | bytes | |
| `sys.seek(fd, off[, whence])` | position | whence set/cur/end |
| `sys.close(fd)` / `sys.fsync(fd)` | bool / nil | |
| `sys.read_at(path, off, len)` | string | pread-style whole-file helper |
| `sys.write_at(path, off, text)` | bytes | pwrite-style |
| `sys.truncate(path, size)` | nil | |
| `sys.chmod(path, mode)` | nil | Unix |
| `sys.symlink(target, link)` / `sys.readlink(path)` | nil / string | Unix symlink |
| `sys.link(from, to)` | nil | hard link |
| `sys.pid()`, `sys.ppid()`, `sys.uid()`, `sys.gid()` | number | no fork |
| `sys.pid_limit()` | table | `{soft, hard, raw}` from /proc/self/limits |
| `sys.loadavg()`, `sys.uptime_ms()`, `sys.meminfo()` | table/number/table | /proc readers |
| `sys.kill(pid, sig)` | nil | signal name or number; direct syscall |
| `sys.random_hex(n)` | string | OS randomness |
| `sys.os()`, `sys.arch()`, `sys.cwd()` | string | |
| `print(...)` | nil | captured into the tool result |

## Forkless mode

There is no separate mode flag: `fs.*` and every `sys.*` function except
`sys.kill` use filesystem syscalls through Rust std and never create a child
process. This is the fallback when `RLIMIT_NPROC`/PID limits are exhausted and
`fork` returns EAGAIN.

`proc.run` and the shell tool do need a child process. If they fail, switch to
the script tool:

    -- check the limit and the current pid
    print(sys.pid(), sys.pid_limit().soft)

    -- chunked log read without a shell or fork
    local fd = sys.open("/var/log/messages", "r")
    while true do
      local chunk = sys.read(fd, 65536)
      if chunk == "" then break end
      print(chunk)
    end
    sys.close(fd)

`sys.read_at`/`sys.write_at` are also useful when `fs.read`'s 2 MiB limit is
too small. All descriptor calls are bounded by the script limits (instruction
budget, 1 MiB per read, 20 s wall clock).

## Language subset

Supported: local/global variables, multiple assignment and returns, functions,
closures with shared upvalues, varargs, tables, `if/elseif/else`, `while`,
`repeat`, numeric and generic `for`, `break`, `return`, `do`, method calls,
`#`, `..`, arithmetic (`+ - * / // % ^`), comparisons, `and/or/not`,
`string.*`, `table.*`, `math.*`, `os.time/clock/getenv`, `pcall`, `error`,
`assert`, `select`, `pairs/ipairs/next`, Lua patterns in `string.find/match/
gmatch/gsub`.

Not supported: metatables, `goto`, integer subtype/bitwise operators, `os.date`,
coroutines, `require`/modules, I/O streams other than the host functions.

Safety limits are always on: 2,000,000 instructions, 1 MiB of captured output,
20 seconds of wall clock, 200 call frames, 100k table entries, 8 MiB strings.
Exceeding a limit is a catchable-or-fatal script error, never a hang.

## Examples

List root-owned accounts without a shell:

    local f = fs.read("/etc/passwd")
    for line in string.gmatch(f, "[^\n]+") do
      local uid = string.match(line, "^[^:]+:[^:]*:(%d+):")
      if uid == "0" then print(line) end
    end
    return "done"

Check several paths and report:

    local paths = {"/etc/resolv.conf", "/etc/hosts", "/etc/fstab"}
    local out = {}
    for _, p in ipairs(paths) do
      table.insert(out, p .. (fs.exists(p) and " ok" or " MISSING"))
    end
    return table.concat(out, "\n")

Read a large file in chunks and count matches:

    local text = fs.read("/var/log/syslog")
    local n = 0
    for _ in string.gmatch(text, "error") do n = n + 1 end
    return n

## Why not just shell out?

A shell needs an executable loader, a libc, a PATH, and an environment.
On a rescue image with a broken `bash`, `proc.run` fails but `fs.*` still
works, because emerag itself is a static binary. That is the whole point.
