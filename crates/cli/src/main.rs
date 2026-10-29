//! emerag entry point.

mod app;
mod args;
mod config;
mod doctor;
mod guide;
mod keys_card;
mod local;
mod oauth;
mod providers;
mod signals;
mod ui;
mod wizard;

use args::{Action, Cli};
use config::{Config, PermissionMode};
use emerag_agent::{Agent, AgentConfig};
use emerag_term::Capabilities;
use std::io::Read;
use std::sync::Arc;

fn main() {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let cli = match args::parse(argv) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("emerag: {e}");
            eprintln!("try: emerag --help");
            std::process::exit(2);
        }
    };

    match cli.action {
        Action::Help => {
            print!("{}", args::HELP);
            return;
        }
        Action::Version => {
            println!("emerag {}", env!("CARGO_PKG_VERSION"));
            println!("zero-dependency emergency agent");
            println!(
                "built for {}-{} at {}",
                std::env::consts::OS,
                std::env::consts::ARCH,
                build_time()
            );
            return;
        }
        _ => {}
    }

    let (mut cfg, notes) = Config::load(cli.config_path.as_deref());
    apply_cli(&mut cfg, &cli);
    if cli.verbose {
        for n in &notes {
            eprintln!("[config] {n}");
        }
    }

    if let Some(path) = &cli.mcp_config {
        match std::fs::read_to_string(path) {
            Ok(text) => match emerag_json::parse(&text) {
                Ok(v) => {
                    let servers = v
                        .get("servers")
                        .or_else(|| v.get("mcpServers"))
                        .and_then(|s| s.as_array())
                        .cloned()
                        .unwrap_or_default();
                    cfg.mcp_servers = servers;
                }
                Err(e) => {
                    eprintln!("emerag: cannot parse --mcp-config {}: {e}", path.display());
                    std::process::exit(2);
                }
            },
            Err(e) => {
                eprintln!("emerag: cannot read --mcp-config {}: {e}", path.display());
                std::process::exit(2);
            }
        }
    }

    let caps = terminal_caps(&cfg, &cli);
    let ascii = cli.ascii || cfg.ui.ascii || !caps.unicode || caps.is_dumb();
    let color = !cli.no_color && cfg.ui.color && caps.color && !caps.is_dumb();
    signals::install();

    match cli.action.clone() {
        Action::Keys => {
            keys_card::print();
            return;
        }
        Action::Guide => {
            if let Err(e) = guide::run() {
                eprintln!("guide: {e}");
            }
            return;
        }
        Action::Doctor => {
            let report = doctor::run(&cfg, ascii, color);
            if cli.json_output {
                println!("{}", emerag_json::to_string_pretty(&report.to_json()));
            } else {
                doctor::render(&report, ascii, color);
                println!();
                println!("config: {}", Config::config_path().display());
                println!("shells: use --models to test the endpoint, --wizard to configure");
            }
            if report.failures() > 0 {
                std::process::exit(1);
            }
            return;
        }
        Action::Wizard => {
            let token = emerag_util::sync::CancelToken::new();
            let mut ui = ui::TermUi::new(
                caps,
                color,
                ascii,
                cli.width.or(cfg.ui.width),
                cli.verbose,
                token,
            );
            match wizard::run(&mut cfg, &cli, &mut ui) {
                Ok(()) => {}
                Err(e) => {
                    eprintln!("wizard: {e}");
                    std::process::exit(1);
                }
            }
            return;
        }
        Action::Models => {
            match providers::build(&cfg, &cli) {
                Ok(p) => match p.list_models() {
                    Ok(models) => {
                        if cli.json_output {
                            let arr: Vec<emerag_json::Value> = models
                                .iter()
                                .map(|m| emerag_json::Value::String(m.id.clone()))
                                .collect();
                            println!(
                                "{}",
                                emerag_json::to_string_pretty(&emerag_json::Value::Array(arr))
                            );
                        } else if models.is_empty() {
                            println!("provider returned no models");
                        } else {
                            for m in models {
                                println!("{}", m.id);
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("models: {e}");
                        eprintln!("hint: {}", e.hint());
                        std::process::exit(1);
                    }
                },
                Err(e) => {
                    eprintln!("{e}");
                    std::process::exit(2);
                }
            }
            return;
        }
        Action::Local(sub) => {
            let model = cfg.model.clone();
            let result = match sub.as_str() {
                "" | "status" => {
                    local::status(&cfg);
                    Ok(())
                }
                "up" | "start" => local::up(if model.ends_with(".gguf") {
                    Some(&model)
                } else {
                    None
                }),
                "stop" => local::stop(),
                "models" => local::models(),
                other => Err(format!(
                    "unknown local action '{other}' (status|up|stop|models)"
                )),
            };
            if let Err(e) = result {
                eprintln!("{e}");
                std::process::exit(1);
            }
            return;
        }
        Action::McpServer => {
            eprintln!("MCP server mode is not implemented yet; MCP client mode is available.");
            std::process::exit(1);
        }
        Action::Login(provider) => {
            if provider != "deepseek" {
                eprintln!("emerag: only 'deepseek' account login is supported");
                std::process::exit(2);
            }
            match oauth::login_deepseek(&mut cfg, true) {
                Ok(()) => {
                    println!("next: emerag --models, then emerag --model <id>");
                    return;
                }
                Err(e) => {
                    eprintln!("emerag: {e}");
                    std::process::exit(1);
                }
            }
        }
        Action::Interactive | Action::Prompt(_) | Action::Help | Action::Version => {}
    }

    // Validate and build.
    if cfg.workdir.is_none() {
        cfg.workdir = Some(emerag_util::sys::current_dir());
    }
    if let Some(dir) = &cfg.workdir {
        if !dir.is_dir() {
            eprintln!(
                "emerag: working directory does not exist: {}",
                dir.display()
            );
            std::process::exit(2);
        }
    }
    if cfg.base_url.is_empty() && !matches!(cli.action, Action::Interactive) {
        eprintln!("emerag: no endpoint configured. Run: emerag --wizard");
        std::process::exit(2);
    }

    // First run with no configuration: open the wizard instead of failing.
    if matches!(cli.action, Action::Interactive) && wizard::first_run_needed(&cfg) {
        let token = emerag_util::sync::CancelToken::new();
        let mut ui = ui::TermUi::new(
            caps,
            color,
            ascii,
            cli.width.or(cfg.ui.width),
            cli.verbose,
            token,
        );
        println!("No model is configured yet. Starting the setup wizard (Ctrl+C to skip).");
        match wizard::run(&mut cfg, &cli, &mut ui) {
            Ok(()) => {}
            Err(e) => eprintln!("wizard: {e}"),
        }
        if wizard::first_run_needed(&cfg) {
            eprintln!("emerag: still no endpoint or model configured.");
            eprintln!("Run 'emerag --wizard', or set EMERAG_BASE_URL and EMERAG_MODEL.");
            std::process::exit(2);
        }
    }

    let agent = match build_agent(&cfg, &cli) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("emerag: {e}");
            std::process::exit(2);
        }
    };

    match cli.action.clone() {
        Action::Prompt(text) => {
            let prompt_text = if cli.read_stdin {
                let mut s = String::new();
                if std::io::stdin().read_to_string(&mut s).is_err() {
                    eprintln!("emerag: cannot read stdin");
                    std::process::exit(2);
                }
                s
            } else {
                text
            };
            if prompt_text.trim().is_empty() {
                eprintln!("emerag: empty prompt");
                std::process::exit(2);
            }
            match app::run_one_shot(&mut cfg, &cli, agent, prompt_text.trim()) {
                Ok(code) => std::process::exit(code),
                Err(e) => {
                    eprintln!("emerag: {e}");
                    std::process::exit(1);
                }
            }
        }
        _ => {
            let token = agent.cancel.clone();
            let ui = ui::TermUi::new(
                caps,
                color,
                ascii,
                cli.width.or(cfg.ui.width),
                cli.verbose,
                token,
            );
            let mut application = app::App {
                cfg,
                cli: cli.clone(),
                ui,
                agent,
            };
            if let Err(e) = application.run() {
                eprintln!("emerag: {e}");
                std::process::exit(1);
            }
        }
    }
}

fn terminal_caps(cfg: &Config, cli: &Cli) -> Capabilities {
    let mut caps = emerag_term::detect();
    if let Some(w) = cli.width.or(cfg.ui.width) {
        caps.width = w;
    }
    if cli.no_color {
        caps.color = false;
    }
    caps
}

fn build_agent(cfg: &Config, cli: &Cli) -> Result<Agent, String> {
    let provider = providers::build(cfg, cli)?;
    let mcp_values: Vec<emerag_json::Value> = cfg.mcp_servers.clone();
    let mut mcp_obj = emerag_json::Map::new();
    mcp_obj.insert("servers".into(), emerag_json::Value::Array(mcp_values));
    let configs = emerag_mcp::parse_server_configs(&emerag_json::Value::Object(mcp_obj))
        .map_err(|e| e.message)?;
    let mode = match cfg.mode {
        PermissionMode::Ask => emerag_agent::permissions::Mode::Ask,
        PermissionMode::Auto => emerag_agent::permissions::Mode::Auto,
        PermissionMode::ReadOnly => emerag_agent::permissions::Mode::ReadOnly,
        PermissionMode::Yolo => emerag_agent::permissions::Mode::Yolo,
    };
    let agent_cfg = AgentConfig {
        model: cfg.model.clone(),
        mode,
        max_turns: cfg.max_turns,
        context_limit: cfg.context_limit,
        max_output_tokens: cfg.max_output_tokens,
        temperature: cfg.temperature,
        cwd: cfg
            .workdir
            .clone()
            .unwrap_or_else(emerag_util::sys::current_dir),
        shell: cfg.shell.clone(),
        system_extra: cfg.system_extra.clone(),
        no_write: cfg.no_write,
        transcript_path: cli.transcript.clone(),
        skill_dirs: cfg.skill_dirs.clone(),
        mcp_servers: configs.clone(),
        ..Default::default()
    };
    Agent::new(agent_cfg, Arc::from(provider), &configs).map_err(|e| e.to_string())
}

fn apply_cli(cfg: &mut Config, cli: &Cli) {
    if let Some(v) = &cli.provider {
        cfg.provider = v.clone();
    }
    if let Some(v) = &cli.model {
        cfg.model = v.clone();
    }
    if let Some(v) = &cli.base_url {
        cfg.base_url = v.clone();
    }
    if let Some(v) = &cli.api {
        cfg.api = v.clone();
    }
    if let Some(v) = &cli.api_key {
        cfg.api_key = v.clone();
    }
    if let Some(v) = &cli.mode {
        if let Some(m) = PermissionMode::parse(v) {
            cfg.mode = m;
        } else {
            eprintln!("emerag: unknown mode '{v}' (ask|auto|read-only|yolo)");
        }
    }
    if cli.no_write {
        cfg.no_write = true;
    }
    if !cli.resolve.is_empty() {
        cfg.network.resolve.extend(cli.resolve.clone());
    }
    if !cli.dns.is_empty() {
        cfg.network.dns.extend(cli.dns.clone());
    }
    if let Some(ip) = &cli.ip {
        cfg.network.ip = Some(ip.clone());
    }
    if cli.insecure {
        cfg.network.insecure = true;
        eprintln!("emerag: WARNING: TLS verification disabled (--insecure)");
    }
    if let Some(c) = &cli.cacert {
        cfg.network.cacert = Some(c.clone());
    }
    if let Some(p) = &cli.proxy {
        cfg.network.proxy = Some(p.clone());
    }
    if let Some(t) = cli.timeout_secs {
        cfg.network.timeout_secs = t;
    }
    if let Some(w) = &cli.workdir {
        let p = if w.is_absolute() {
            w.clone()
        } else {
            emerag_util::sys::current_dir().join(w)
        };
        cfg.workdir = Some(p);
    }
    if cli.ascii {
        cfg.ui.ascii = true;
    }
    if cli.no_color {
        cfg.ui.color = false;
    }
    if let Some(w) = cli.width {
        cfg.ui.width = Some(w);
    }
    if cli.fullscreen {
        cfg.ui.fullscreen = true;
    }
    if let Some(n) = cli.max_turns {
        cfg.max_turns = n;
    }
    if !cli.skills.is_empty() {
        for s in &cli.skills {
            cfg.skill_dirs.push(emerag_util::sys::expand_tilde(s));
        }
    }
}

fn build_time() -> &'static str {
    option_env!("EMERAG_BUILD_TIME").unwrap_or("unknown")
}
