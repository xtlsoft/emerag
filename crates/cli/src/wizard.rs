//! Model/provider setup wizard, optimized for keyboards and serial consoles:
//! numbered choices, Enter for defaults, no editor, no mouse, no clipboard.

use crate::args::Cli;
use crate::config::{Config, PermissionMode};
use crate::ui::TermUi;
use emerag_agent::Ui;
use emerag_http::Url;
use emerag_llm::{ChatRequest, Message, StreamEvent};
use emerag_term::prompt;
use std::io::Write;
use std::net::ToSocketAddrs;
use std::time::{Duration, Instant};

pub fn run(cfg: &mut Config, cli: &Cli, ui: &mut TermUi) -> Result<(), String> {
    let caps = ui.caps;
    println!();
    println!("emerag setup wizard");
    println!("===================");
    println!("Nothing is saved unless you confirm at the end. Ctrl+C aborts safely.");
    if !cfg.base_url.is_empty() {
        println!();
        println!("Current: {}", cfg.redacted_summary());
        if !prompt::prompt_yes_no_caps(caps, "Reconfigure?", false).unwrap_or(false) {
            return Ok(());
        }
    }

    let profiles = emerag_llm::catalog::all();
    let labels: Vec<String> = profiles
        .iter()
        .map(|p| format!("{} - {}", p.label, p.note))
        .collect();
    let default_idx = profiles
        .iter()
        .position(|p| p.id == crate::providers::profile_id(cfg))
        .unwrap_or(0);
    println!();
    let choice = prompt::prompt_choice_caps(caps, "Provider", &labels, default_idx)
        .map_err(|e| e.to_string())?;

    let (profile, mut base_url) = if choice < profiles.len() {
        let p = &profiles[choice];
        (Some(p), p.base_url.to_string())
    } else {
        (None, String::new())
    };

    if let Some(p) = profile {
        cfg.provider = p.id.to_string();
        cfg.api = p.api.as_str().to_string();
        cfg.base_url = if p.base_url.is_empty() {
            String::new()
        } else {
            p.base_url.to_string()
        };
    } else {
        cfg.provider = "custom".into();
    }
    if !cfg.base_url.is_empty() {
        base_url = cfg.base_url.clone();
    }
    let account_profile = profile
        .map(|p| p.auth == emerag_llm::catalog::AuthKind::DeepSeekAccount)
        .unwrap_or(false);

    // Endpoint. An account grant is bound to the DeepSeek origin, so do not
    // let the wizard send it somewhere else.
    println!();
    let endpoint = if account_profile {
        println!("Endpoint: {base_url} (fixed for DeepSeek account sign-in)");
        base_url.clone()
    } else {
        ask_text(ui, "Endpoint", &base_url)?
    };
    let endpoint = if endpoint.trim().is_empty() {
        base_url.clone()
    } else {
        endpoint
    };
    let endpoint = normalize_endpoint(&endpoint)?;
    cfg.base_url = endpoint.clone();

    // API kind for custom endpoints
    if profile.map(|p| p.id == "custom").unwrap_or(true) {
        let kinds = [
            "Chat Completions (OpenAI-compatible, most common)",
            "Responses (OpenAI Responses API)",
            "Anthropic Messages",
        ];
        let idx =
            prompt::prompt_choice_caps(caps, "API style", &kinds, 0).map_err(|e| e.to_string())?;
        cfg.api = match idx {
            1 => "responses".into(),
            2 => "anthropic".into(),
            _ => "chat".into(),
        };
    }

    // API key or DeepSeek account sign-in
    let is_account = account_profile;
    let needs_key = profile
        .map(|p| !matches!(p.auth, emerag_llm::catalog::AuthKind::None))
        .unwrap_or(true);
    if is_account {
        crate::oauth::login_deepseek(cfg, false)?;
    } else if needs_key {
        println!();
        if cfg.api_key.is_empty() {
            let key = ask_secret(ui, "API key (input hidden; leave empty to skip)")?;
            if !key.trim().is_empty() {
                cfg.api_key = key.trim().to_string();
            }
        } else {
            println!("Using existing key {}", emerag_llm::redact(&cfg.api_key));
            if prompt::prompt_yes_no_caps(caps, "Replace it?", false).unwrap_or(false) {
                let key = ask_secret(ui, "New API key")?;
                if !key.trim().is_empty() {
                    cfg.api_key = key.trim().to_string();
                }
            }
        }
    }

    // DNS / reachability
    println!();
    if let Ok(url) = Url::parse(&cfg.base_url) {
        print!("Checking DNS for {} ... ", url.host);
        let _ = std::io::stdout().flush();
        let mut fallback: Vec<std::net::IpAddr> = Vec::new();
        for spec in &cfg.network.dns {
            if let Ok(ip) = spec.trim().parse::<std::net::IpAddr>() {
                fallback.push(ip);
            }
        }
        if fallback.is_empty() {
            fallback = emerag_http::dns::discover().servers;
        }
        let resolved = match resolve_with_timeout(&url.host, url.port, Duration::from_secs(6)) {
            Ok(addrs) => Ok(addrs),
            Err(e) => {
                if !fallback.is_empty() {
                    match emerag_http::dns::resolve(
                        &url.host,
                        url.port,
                        &fallback,
                        Duration::from_secs(5),
                    ) {
                        Ok(ips) if !ips.is_empty() => {
                            println!(
                                "system resolver failed ({e}); DNS fallback works: {}",
                                ips.iter()
                                    .map(|i| i.to_string())
                                    .collect::<Vec<_>>()
                                    .join(", ")
                            );
                            Ok(ips.iter().map(|i| i.to_string()).collect())
                        }
                        _ => Err(e),
                    }
                } else {
                    Err(e)
                }
            }
        };
        match resolved {
            Ok(addrs) => println!("ok ({})", addrs.join(", ")),
            Err(e) => {
                println!("failed: {e}");
                println!("If this machine has no working DNS, pin the endpoint to an IP, or restart with --dns <nameserver>.");
                if prompt::prompt_yes_no_caps(caps, "Pin an IP address now?", true).unwrap_or(false)
                {
                    let ip = ask_text(ui, "IP address", "")?;
                    let ip = ip.trim().trim_start_matches('[').trim_end_matches(']');
                    if ip.parse::<std::net::IpAddr>().is_ok() {
                        cfg.network
                            .resolve
                            .push(format!("{}:{}:{}", url.host, url.port, ip));
                        println!("Will connect to {ip} for {}:{}", url.host, url.port);
                    } else {
                        println!("'{ip}' is not a valid IP; skipping");
                    }
                }
            }
        }
    }

    // Discover models
    println!();
    let mut models: Vec<String> = Vec::new();
    print!("Connecting and listing models ... ");
    let _ = std::io::stdout().flush();
    match crate::providers::build(cfg, cli) {
        Ok(provider) => match provider.list_models() {
            Ok(list) => {
                models = list
                    .iter()
                    .map(|m| m.id.clone())
                    .filter(|id| !id.is_empty())
                    .collect();
                println!("{} models", models.len());
            }
            Err(e) => {
                println!("could not list models: {e}");
                println!("-> {}", e.hint());
                if let Some(p) = profile {
                    if !p.default_models.is_empty() {
                        println!(
                            "Known models for this provider: {}",
                            p.default_models.join(", ")
                        );
                    }
                }
            }
        },
        Err(e) => {
            println!("cannot build client: {e}");
            return Err(e);
        }
    }

    let model = if models.is_empty() {
        let fallback = profile
            .and_then(|p| p.default_models.first().copied())
            .unwrap_or("");
        ask_text(ui, "Model name", fallback)?
    } else {
        let mut options: Vec<String> = models.iter().take(60).cloned().collect();
        options.push("(type another model name)".into());
        let idx =
            prompt::prompt_choice_caps(caps, "Model", &options, 0).map_err(|e| e.to_string())?;
        if idx == options.len() - 1 {
            ask_text(ui, "Model name", "")?
        } else {
            models[idx].clone()
        }
    };
    if model.trim().is_empty() {
        return Err("no model selected".into());
    }
    cfg.model = model.trim().to_string();

    // Connectivity test
    println!();
    print!("Testing {} with a tiny request ... ", cfg.model);
    let _ = std::io::stdout().flush();
    match test_completion(cfg, cli) {
        Ok(text) => {
            println!("ok");
            if !text.trim().is_empty() {
                println!(
                    "model replied: {}",
                    emerag_util::text::single_line(text.trim())
                );
            }
        }
        Err(e) => {
            println!("failed: {e}");
            println!("You can still save and fix it later with /auth or /model.");
        }
    }

    // Mode
    println!();
    let modes = [
        "ask - approve every write/command (recommended)",
        "auto - run tools without prompts",
        "read-only - inspect only",
    ];
    let idx = prompt::prompt_choice_caps(caps, "Permission mode", &modes, 0)
        .map_err(|e| e.to_string())?;
    cfg.mode = match idx {
        1 => PermissionMode::Auto,
        2 => PermissionMode::ReadOnly,
        _ => PermissionMode::Ask,
    };

    // Save
    println!();
    println!("Summary: {}", cfg.redacted_summary());
    if cfg.no_write {
        println!("--no-write is active: configuration stays in memory for this run only.");
        return Ok(());
    }
    if prompt::prompt_yes_no_caps(caps, "Save configuration?", true).unwrap_or(true) {
        let path = Config::config_path();
        cfg.save(&path)
            .map_err(|e| format!("cannot save config: {e}"))?;
        println!("saved {}", path.display());
    } else {
        println!("not saved");
    }
    Ok(())
}

fn ask_text(ui: &mut TermUi, prompt_text: &str, default: &str) -> Result<String, String> {
    let label = if default.is_empty() {
        format!("{prompt_text}: ")
    } else {
        format!("{prompt_text} [{default}]: ")
    };
    match ui.read_input(&label) {
        Ok(crate::ui::Input::Line(s)) => {
            if s.trim().is_empty() {
                Ok(default.to_string())
            } else {
                Ok(s.trim().to_string())
            }
        }
        Ok(crate::ui::Input::Eof) | Ok(crate::ui::Input::Cancelled) => Err("cancelled".into()),
        Ok(crate::ui::Input::Command(_)) => Err("chord not allowed here".into()),
        Err(e) => Err(e.to_string()),
    }
}

fn ask_secret(ui: &mut TermUi, prompt_text: &str) -> Result<String, String> {
    let answer = ui.ask(&emerag_agent::Question {
        id: "wizard-key".into(),
        prompt: prompt_text.to_string(),
        kind: emerag_agent::QuestionKind::Text { secret: true },
    });
    match answer {
        emerag_agent::Answer::Text(t) => Ok(t),
        _ => Err("cancelled".into()),
    }
}

pub fn normalize_endpoint(input: &str) -> Result<String, String> {
    let mut s = input.trim().to_string();
    if s.is_empty() {
        return Err("endpoint is required".into());
    }
    if !s.starts_with("http://") && !s.starts_with("https://") {
        // Accept host/path shorthand from a serial console.
        s = if s.contains("localhost") || s.starts_with("127.") || s.starts_with("[::1]") {
            format!("http://{s}")
        } else {
            format!("https://{s}")
        };
    }
    let url = Url::parse(&s).map_err(|e| format!("bad endpoint: {e}"))?;
    if url.host.is_empty() {
        return Err("endpoint has no host".into());
    }
    Ok(s.trim_end_matches('/').to_string())
}

fn resolve_with_timeout(host: &str, port: u16, timeout: Duration) -> Result<Vec<String>, String> {
    let host = host.to_string();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let res = (host.as_str(), port)
            .to_socket_addrs()
            .map(|it| it.map(|a| a.ip().to_string()).collect::<Vec<_>>());
        let _ = tx.send(res);
    });
    match rx.recv_timeout(timeout) {
        Ok(Ok(addrs)) if !addrs.is_empty() => Ok(addrs),
        Ok(Ok(_)) => Err("resolved to no addresses".into()),
        Ok(Err(e)) => Err(e.to_string()),
        Err(_) => Err("resolver timed out".into()),
    }
}

fn test_completion(cfg: &Config, cli: &Cli) -> Result<String, String> {
    let provider = crate::providers::build(cfg, cli)?;
    let mut req = ChatRequest::new(
        cfg.model.clone(),
        "You are a connectivity test. Reply with the single word OK.",
        vec![Message::user("Reply with OK")],
    );
    req.max_output_tokens = Some(16);
    req.stream = true;
    let mut text = String::new();
    let start = Instant::now();
    let mut sink = |ev: StreamEvent| -> bool {
        match ev {
            StreamEvent::Text(t) => text.push_str(&t),
            StreamEvent::Error(e) => text.push_str(&format!("[error {e}]")),
            _ => {}
        }
        start.elapsed() < Duration::from_secs(60)
    };
    provider
        .stream(&req, &mut sink)
        .map_err(|e| format!("{e}"))?;
    Ok(text)
}

pub fn first_run_needed(cfg: &Config) -> bool {
    // A key is not mandatory: local servers have none, and some gateways
    // authenticate by IP. Only an endpoint and a model are truly required.
    cfg.base_url.is_empty() || cfg.model.is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_normalization() {
        assert_eq!(
            normalize_endpoint("api.deepseek.com/v1").unwrap(),
            "https://api.deepseek.com/v1"
        );
        assert_eq!(
            normalize_endpoint("http://127.0.0.1:8080/v1").unwrap(),
            "http://127.0.0.1:8080/v1"
        );
        assert!(normalize_endpoint("").is_err());
        assert!(normalize_endpoint("ftp://x").is_err());
    }
}
