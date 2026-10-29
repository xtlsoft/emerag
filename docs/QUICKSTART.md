# emerag quick start card

Print this page. It fits in 60 columns on purpose.

    +----------------------------------------------------------+
    |  emerag - emergency agent                                |
    +----------------------------------------------------------+

## 1. Install (no installer)

Copy one file. On a USB stick, over the serial console, whatever works.

    Linux:    chmod +x emerag; ./emerag
    Windows:  emerag.exe
    macOS:    chmod +x emerag; ./emerag

Check it runs:

    ./emerag --version
    ./emerag --doctor

If you have network but no patience:

    wget -qO- http://10.20.2.226:8899/install.sh | sh
    wget -qO- http://10.20.2.226:8899/install.sh | sh -s -- --run
    wget -qO- http://10.20.2.226:8899/install.sh | sh -s -- --run --mini
    wget -qO- http://10.20.2.226:8899/install.sh | sh -s -- --run --lite

--run uses a writable tmpfs and leaves the root filesystem alone. If no
curl/wget exists, busybox wget is used. --mini is the packed 17-CA build.

## 2. Connect a model (one time)

    ./emerag --wizard

Answer with digits and Enter. You need:

    - provider: pick a number (DeepSeek API key is 1,
                DeepSeek account sign-in is 2)
    - endpoint: press Enter for the default
    - API key:  paste or type it (it is not echoed twice;
                Ctrl+C cancels, nothing is saved unless you say so)
                For the account option, a browser sign-in replaces the key.
    - model:    pick from the discovered list, or type a name
    - save:     y = write config, n = memory only

### DeepSeek account instead of an API key

    ./emerag login deepseek

emerag opens a browser (or prints a URL) and listens on 127.0.0.1 for the
callback. On a phone, open the printed URL in the phone's browser; the
loopback callback reaches the terminal directly. The token is stored in the
config file (0600), and model names are fetched from /models.

If DNS is broken, the wizard asks whether to pin an IP:

    endpoint: https://api.deepseek.com/v1
    DNS broken? [y/N]: y
    IP address: 1.2.3.4

On Termux/Android, a static binary often cannot use the system resolver even
when the phone's DNS works. emerag tries the platform nameservers and a public
fallback automatically; to force one:

    ./emerag --dns 1.1.1.1 --doctor

Non-interactive equivalent:

    ./emerag --provider deepseek --api-key sk-... --model deepseek-chat

## 3. Ask for help

    ./emerag "the box has no network, find out why"
    ./emerag -p "read /etc/resolv.conf and explain it"

Inside the interactive session just type, like a shell:

    > why did nginx fail to start
    > fix it
    > /mode auto        (stop asking for each command)
    > /jobs            (see background commands)
    > /quit

## 4. When the terminal is minimal

Everything works at 40x16, with ASCII only:

    ./emerag --ascii --width 40

If arrow keys do not work, type the slash commands instead:

    /help /model /mode /jobs /quit

If the terminal cannot do raw mode at all, emerag falls back to plain
line-by-line input automatically. Press Ctrl+D (or type /quit) to leave.

## 5. Emergency one-liners

    # no shell? run our script engine instead
    ./emerag -p "use the script tool to list /etc and read resolv.conf"

    # no DNS? pin the endpoint
    ./emerag --resolve api.deepseek.com:443:1.2.3.4 -p "hi"

    # read-only filesystem? keep everything in memory
    ./emerag --no-write -p "inspect /etc/fstab"

    # root-ish work with explicit elevation per command
    ./emerag -p "check why systemctl fails; use run_elevated for reads"

    # get the key card even with no network
    ./emerag --keys
