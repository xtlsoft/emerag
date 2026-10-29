//! Tiny, explicit CLI parser. No clap: startup time and binary size matter.
//!
//! The grammar is intentionally conventional so muscle memory works:
//!   emerag [options] [prompt words...]
//!   emerag -p "prompt"
//!   emerag --wizard | --doctor | --keys | --local up

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    Interactive,
    Wizard,
    Doctor,
    Keys,
    Guide,
    Models,
    Local(String),
    McpServer,
    Login(String),
    Version,
    Help,
    Prompt(String),
}

#[derive(Debug, Clone)]
pub struct Cli {
    pub action: Action,
    pub provider: Option<String>,
    pub model: Option<String>,
    pub base_url: Option<String>,
    pub api: Option<String>,
    pub api_key: Option<String>,
    pub config_path: Option<std::path::PathBuf>,
    pub no_write: bool,
    pub mode: Option<String>,
    pub resolve: Vec<String>,
    pub dns: Vec<String>,
    pub ip: Option<String>,
    pub insecure: bool,
    pub cacert: Option<String>,
    pub proxy: Option<String>,
    pub timeout_secs: Option<u64>,
    pub workdir: Option<std::path::PathBuf>,
    pub ascii: bool,
    pub no_color: bool,
    pub width: Option<u16>,
    pub fullscreen: bool,
    pub yes: bool,
    pub max_turns: Option<u32>,
    pub transcript: Option<std::path::PathBuf>,
    pub quiet: bool,
    pub verbose: bool,
    pub read_stdin: bool,
    pub skills: Vec<String>,
    pub mcp_config: Option<std::path::PathBuf>,
    pub session: Option<String>,
    pub json_output: bool,
}

impl Default for Cli {
    fn default() -> Self {
        Cli {
            action: Action::Interactive,
            provider: None,
            model: None,
            base_url: None,
            api: None,
            api_key: None,
            config_path: None,
            no_write: false,
            mode: None,
            resolve: Vec::new(),
            dns: Vec::new(),
            ip: None,
            insecure: false,
            cacert: None,
            proxy: None,
            timeout_secs: None,
            workdir: None,
            ascii: false,
            no_color: false,
            width: None,
            fullscreen: false,
            yes: false,
            max_turns: None,
            transcript: None,
            quiet: false,
            verbose: false,
            read_stdin: false,
            skills: Vec::new(),
            mcp_config: None,
            session: None,
            json_output: false,
        }
    }
}

pub const HELP: &str = r#"emerag - a tiny portable agent for emergencies

USAGE
  emerag [options] [prompt words...]
  emerag -p "prompt"
  emerag --wizard

MODES
  (no args)              interactive session
  "prompt" or -p TEXT    one-shot turn, prints the answer
  --wizard               set up provider, endpoint, key and model
  --doctor               diagnose terminal, shells, TLS, DNS, disk
  --keys                 print the key card
  --guide                offline interactive tutorial
  --models               list models for the current provider
  --login deepseek       sign in with a DeepSeek account (OAuth, no key)
  --version, --help

SUBCOMMANDS
  emerag local ACTION    status | up | stop | models
  emerag login deepseek  sign in with a DeepSeek account

MODEL
  --provider ID          provider profile (deepseek, openai, anthropic, ...)
  --model ID             model name
  --base-url URL         endpoint base URL
  --api KIND             chat | responses | anthropic
  --api-key KEY          API key (prefer EMERAG_API_KEY)
  -k, --key KEY          alias for --api-key

NETWORK (broken DNS friendly)
  --resolve SPEC         host:port:ip (repeatable, curl style)
  --dns IP               nameserver to use before the system resolver (repeatable)
  --ip ADDR              shortcut: pin the endpoint to this IP
  --cacert PATH          extra CA bundle (PEM)
  --insecure             skip TLS verification (dangerous)
  --proxy URL            HTTP proxy (CONNECT)
  --timeout SECS         request timeout

SESSION
  -C, --workdir DIR      working directory for tools
  --mode MODE            ask | auto | read-only | yolo
  -y, --yes              same as --mode auto
  --max-turns N          limit agent turns per request
  --transcript PATH      write a JSONL transcript
  --no-write             keep config and state in memory only
  --config PATH          alternate config file

INTERFACE
  --ascii                ASCII-only UI (no box drawing/unicode)
  --no-color             disable colors
  --width N              force terminal width
  --quiet                suppress the banner and tool chatter
  --verbose              show HTTP and tool details
  --json                 machine-readable one-shot output

INPUT
  --stdin                read the prompt from stdin (also: emerag -)
  --skill PATH           extra skill file or directory (repeatable)
  --mcp-config PATH      JSON file with MCP server definitions

KEYS
  Ctrl+X then H/M/A/P/J/G/S/T/C/Q  (see --keys)
  Slash commands: /help /model /mode /jobs /quit

Examples
  emerag --wizard
  emerag --ip 203.0.113.10 -p "check nginx"
  emerag --mode auto "install curl and test connectivity"
  emerag --resolve api.deepseek.com:443:203.0.113.10 -p "hello"
"#;

pub fn parse<I: IntoIterator<Item = String>>(args: I) -> Result<Cli, String> {
    let mut cli = Cli::default();
    let mut args: Vec<String> = args.into_iter().collect();
    // Subcommand form: "emerag local up" is friendlier to type than --local up.
    if args.first().map(|a| a == "local").unwrap_or(false) {
        let sub = args.get(1).cloned().unwrap_or_else(|| "status".to_string());
        args.drain(0..2.min(args.len()));
        cli.action = Action::Local(sub);
    } else if args.first().map(|a| a == "login").unwrap_or(false) {
        let provider = args
            .get(1)
            .cloned()
            .unwrap_or_else(|| "deepseek".to_string());
        args.drain(0..2.min(args.len()));
        cli.action = Action::Login(provider);
    }
    let mut it = args.into_iter().peekable();
    let mut prompt_words: Vec<String> = Vec::new();
    let mut explicit_prompt: Option<String> = None;
    let mut saw_dashdash = false;

    while let Some(arg) = it.next() {
        if saw_dashdash {
            prompt_words.push(arg);
            continue;
        }
        if arg == "--" {
            saw_dashdash = true;
            continue;
        }
        if !arg.starts_with('-') || arg == "-" {
            if arg == "-" {
                cli.read_stdin = true;
            } else {
                prompt_words.push(arg);
            }
            continue;
        }
        let (flag, inline) = match arg.split_once('=') {
            Some((f, v)) => (f.to_string(), Some(v.to_string())),
            None => (arg.clone(), None),
        };
        let mut value = |name: &str| -> Result<String, String> {
            if let Some(v) = inline.clone() {
                return Ok(v);
            }
            it.next().ok_or_else(|| format!("{name} needs a value"))
        };
        match flag.as_str() {
            "-h" | "--help" => cli.action = Action::Help,
            "-V" | "--version" => cli.action = Action::Version,
            "--wizard" => cli.action = Action::Wizard,
            "--doctor" => cli.action = Action::Doctor,
            "--keys" => cli.action = Action::Keys,
            "--guide" => cli.action = Action::Guide,
            "--models" => cli.action = Action::Models,
            "--mcp-server" => cli.action = Action::McpServer,
            "--login" => {
                let provider = match inline.clone() {
                    Some(v) => v,
                    None => match it.peek() {
                        Some(next) if !next.starts_with('-') => it.next().unwrap(),
                        _ => "deepseek".to_string(),
                    },
                };
                cli.action = Action::Login(provider);
            }
            "--local" => cli.action = Action::Local(value("--local")?),
            "-p" | "--prompt" => explicit_prompt = Some(value("--prompt")?),
            "--provider" => cli.provider = Some(value("--provider")?),
            "--model" => cli.model = Some(value("--model")?),
            "--base-url" => cli.base_url = Some(value("--base-url")?),
            "--api" => cli.api = Some(value("--api")?),
            "--api-key" | "-k" | "--key" => cli.api_key = Some(value("--api-key")?),
            "--config" => cli.config_path = Some(value("--config")?.into()),
            "--no-write" => cli.no_write = true,
            "--mode" => cli.mode = Some(value("--mode")?),
            "--resolve" => cli.resolve.push(value("--resolve")?),
            "--dns" => cli.dns.push(value("--dns")?),
            "--ip" => cli.ip = Some(value("--ip")?),
            "--insecure" => cli.insecure = true,
            "--cacert" => cli.cacert = Some(value("--cacert")?),
            "--proxy" => cli.proxy = Some(value("--proxy")?),
            "--timeout" => {
                let v = value("--timeout")?;
                cli.timeout_secs = Some(
                    v.parse()
                        .map_err(|_| "--timeout needs a number".to_string())?,
                );
            }
            "-C" | "--workdir" | "--cwd" => cli.workdir = Some(value("--workdir")?.into()),
            "--ascii" => cli.ascii = true,
            "--no-color" | "--no-colour" => cli.no_color = true,
            "--width" => {
                let v = value("--width")?;
                cli.width = Some(
                    v.parse()
                        .map_err(|_| "--width needs a number".to_string())?,
                );
            }
            "--fullscreen" => cli.fullscreen = true,
            "-y" | "--yes" => cli.yes = true,
            "--max-turns" => {
                let v = value("--max-turns")?;
                cli.max_turns = Some(
                    v.parse()
                        .map_err(|_| "--max-turns needs a number".to_string())?,
                );
            }
            "--transcript" => cli.transcript = Some(value("--transcript")?.into()),
            "--quiet" => cli.quiet = true,
            "--verbose" | "-v" => cli.verbose = true,
            "--json" => cli.json_output = true,
            "--stdin" => cli.read_stdin = true,
            "--skill" => cli.skills.push(value("--skill")?),
            "--mcp-config" => cli.mcp_config = Some(value("--mcp-config")?.into()),
            "--session" => cli.session = Some(value("--session")?),
            other => return Err(format!("unknown option '{other}' (try --help)")),
        }
    }

    if let Some(p) = explicit_prompt {
        if !prompt_words.is_empty() {
            return Err("both -p and positional prompt given".into());
        }
        cli.action = Action::Prompt(p);
    } else if !prompt_words.is_empty() {
        cli.action = Action::Prompt(prompt_words.join(" "));
    }
    if cli.read_stdin && matches!(cli.action, Action::Prompt(_)) {
        return Err("use either --stdin or a prompt, not both".into());
    }
    if cli.yes && cli.mode.is_none() {
        cli.mode = Some("auto".into());
    }
    Ok(cli)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(args: &[&str]) -> Result<Cli, String> {
        parse(args.iter().map(|s| s.to_string()))
    }

    #[test]
    fn positional_prompt_joins_words() {
        let cli = p(&["fix", "the", "network"]).unwrap();
        assert_eq!(cli.action, Action::Prompt("fix the network".into()));
    }

    #[test]
    fn flags_and_values() {
        let cli = p(&[
            "--provider",
            "deepseek",
            "--resolve",
            "api.deepseek.com:443:1.2.3.4",
            "--resolve=example.com:443:5.6.7.8",
            "--mode=auto",
            "-C",
            "/tmp",
            "--ascii",
        ])
        .unwrap();
        assert_eq!(cli.provider.as_deref(), Some("deepseek"));
        assert_eq!(cli.resolve.len(), 2);
        assert_eq!(cli.mode.as_deref(), Some("auto"));
        assert_eq!(cli.workdir.as_deref(), Some(std::path::Path::new("/tmp")));
        assert!(cli.ascii);
    }

    #[test]
    fn actions_win_over_prompt() {
        let cli = p(&["--doctor"]).unwrap();
        assert_eq!(cli.action, Action::Doctor);
        let cli = p(&["--local", "up"]).unwrap();
        assert_eq!(cli.action, Action::Local("up".into()));
    }

    #[test]
    fn rejects_unknown_and_missing_values() {
        assert!(p(&["--nope"]).is_err());
        assert!(p(&["--provider"]).is_err());
        assert!(p(&["-p", "x", "extra"]).is_err());
    }

    #[test]
    fn yes_implies_auto_mode() {
        let cli = p(&["-y", "-p", "hi"]).unwrap();
        assert_eq!(cli.mode.as_deref(), Some("auto"));
        assert_eq!(cli.action, Action::Prompt("hi".into()));
    }
}
