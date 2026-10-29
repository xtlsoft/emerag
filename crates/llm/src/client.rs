//! Wire adapters for Chat Completions, Responses and Anthropic Messages.
//!
//! One canonical ChatRequest goes in; provider-specific JSON comes out. The
//! streaming parsers normalize to StreamEvent so the agent never sees an SSE
//! event name.

use std::time::Duration;

use emerag_http::{Client as HttpClient, Request, Response, SseDecoder};
#[allow(unused_imports)]
use emerag_json::{json, Map, Value};
use emerag_util::sync::CancelToken;

use crate::catalog::{find, Profile, Quirk};
use crate::types::*;
#[allow(unused_imports)]
use crate::{ClientConfig, Credentials, Error, ErrorKind, EventSink, Provider};

pub fn build(cfg: &ClientConfig) -> Result<Box<dyn Provider>, Error> {
    if cfg.base_url.trim().is_empty() {
        return Err(Error::config("no endpoint configured"));
    }
    let http = HttpClient {
        resolve: cfg.resolve.clone(),
        tls: cfg.tls.clone(),
        proxy: cfg.proxy.clone(),
        connect_timeout: Duration::from_secs(20),
        read_timeout: Duration::from_secs(cfg.timeout.as_secs().max(30)),
        max_redirects: 4,
        user_agent: cfg.user_agent.clone(),
        verbose: cfg.verbose,
        cancel: CancelToken::new(),
        no_dns: false,
        dns_servers: cfg.dns_servers.clone(),
        dns_first: cfg.dns_first,
    };
    Ok(Box::new(Adapter {
        cfg: cfg.clone(),
        http,
        kind: cfg.api,
        session_id: format!("ses_{}", emerag_util::rand::id(24)),
    }))
}

struct Adapter {
    cfg: ClientConfig,
    http: HttpClient,
    kind: ApiKind,
    session_id: String,
}

impl Adapter {
    fn profile(&self) -> Option<&Profile> {
        find(&self.cfg.profile_id)
    }

    fn base(&self) -> &str {
        self.cfg.base_url.trim_end_matches('/')
    }

    fn url(&self, path: &str) -> String {
        format!("{}/{}", self.base(), path.trim_start_matches('/'))
    }

    fn chat_url(&self) -> String {
        let path = self
            .profile()
            .map(|p| p.chat_path)
            .unwrap_or(match self.kind {
                ApiKind::ChatCompletions => "chat/completions",
                ApiKind::Responses => "responses",
                ApiKind::AnthropicMessages => "messages",
            });
        // A user-supplied base URL usually already ends in /v1; a profile path
        // may add another prefix. Avoid duplicating /v1/.
        let mut url = self.url(path);
        if url.contains("/v1/v1/") {
            url = url.replace("/v1/v1/", "/v1/");
        }
        url
    }

    fn models_url(&self) -> String {
        if let Some(url) = self.profile().and_then(|p| p.absolute_models_url) {
            return url.to_string();
        }
        let path = self.profile().map(|p| p.models_path).unwrap_or("models");
        self.url(path)
    }

    fn require_credentials(&self) -> Result<(), Error> {
        if let Some(p) = self.profile() {
            if p.auth == crate::catalog::AuthKind::DeepSeekAccount
                && self
                    .cfg
                    .credentials
                    .account_token
                    .as_deref()
                    .unwrap_or("")
                    .is_empty()
            {
                return Err(Error::new(
                    ErrorKind::Auth,
                    "not signed in to a DeepSeek account; run /login deepseek (or use a DeepSeek API key)",
                ));
            }
        }
        Ok(())
    }

    fn auth_headers(&self) -> Vec<(String, String)> {
        let mut headers = Vec::new();
        if let Some(p) = self.profile() {
            for (k, v) in p.headers {
                headers.push((k.to_string(), v.to_string()));
            }
            match p.auth {
                crate::catalog::AuthKind::None => {}
                crate::catalog::AuthKind::Bearer | crate::catalog::AuthKind::BearerWithHeaders => {
                    if !self.cfg.credentials.api_key.is_empty() {
                        headers.push((
                            "authorization".into(),
                            format!("Bearer {}", self.cfg.credentials.api_key),
                        ));
                    }
                }
                crate::catalog::AuthKind::ApiKeyHeader => {
                    if !self.cfg.credentials.api_key.is_empty() {
                        headers.push(("x-api-key".into(), self.cfg.credentials.api_key.clone()));
                    }
                }
                crate::catalog::AuthKind::DeepSeekAccount => {
                    if let Some(token) = &self.cfg.credentials.account_token {
                        headers.push(("x-dsh-auth-token".into(), token.clone()));
                    }
                }
            }
            // Anthropic transition period: send both forms.
            if p.id == "anthropic" && !self.cfg.credentials.api_key.is_empty() {
                headers.push(("x-api-key".into(), self.cfg.credentials.api_key.clone()));
            }
            if p.has(Quirk::RequiresSessionHeader) {
                headers.push(("x-opencode-session".into(), self.session_id.clone()));
            }
        } else if let Some(token) = &self.cfg.credentials.account_token {
            headers.push(("x-dsh-auth-token".into(), token.clone()));
        } else if !self.cfg.credentials.api_key.is_empty() {
            headers.push((
                "authorization".into(),
                format!("Bearer {}", self.cfg.credentials.api_key),
            ));
        }
        for (k, v) in self
            .cfg
            .credentials
            .extra_headers
            .iter()
            .chain(self.cfg.extra_headers.iter())
        {
            set_header(&mut headers, k, v);
        }
        headers
    }

    fn post_json(&self, url: &str, body: &Value, stream: bool) -> Result<Response, Error> {
        let mut headers = self.auth_headers();
        set_header(&mut headers, "content-type", "application/json");
        set_header(
            &mut headers,
            "accept",
            if stream {
                "text/event-stream"
            } else {
                "application/json"
            },
        );
        let mut req = Request::new("POST", emerag_http::Url::parse(url)?);
        req.headers = headers;
        req.body = emerag_json::to_string(body).into_bytes();
        self.http.send(req).map_err(map_http)
    }

    fn get(&self, url: &str) -> Result<Response, Error> {
        let mut headers = self.auth_headers();
        set_header(&mut headers, "accept", "application/json");
        let mut req = Request::new("GET", emerag_http::Url::parse(url)?);
        req.headers = headers;
        self.http.send(req).map_err(map_http)
    }

    fn check_status(&self, resp: &Response) -> Result<(), Error> {
        if resp.status >= 200 && resp.status < 300 {
            return Ok(());
        }
        let body = if !resp.early_body.is_empty() {
            String::from_utf8_lossy(&resp.early_body).to_string()
        } else {
            String::new()
        };
        let detail = extract_error_message(&body);
        let message = if detail.is_empty() {
            format!("HTTP {} {}", resp.status, resp.reason)
        } else {
            format!("HTTP {} {}: {}", resp.status, resp.reason, detail)
        };
        let kind = match resp.status {
            401 | 403 => ErrorKind::Auth,
            429 => ErrorKind::RateLimit,
            400..=499 => ErrorKind::BadRequest,
            500..=599 => ErrorKind::Server,
            _ => ErrorKind::Protocol,
        };
        let mut err = Error::new(kind, message);
        if resp.status == 404 && matches!(self.kind, ApiKind::ChatCompletions) {
            err.message.push_str(" (check the endpoint path and --api)");
        }
        Err(err)
    }

    // ---------- model listing ----------

    fn list_models_impl(&self) -> Result<Vec<ModelInfo>, Error> {
        self.require_credentials()?;
        let mut resp = self.get(&self.models_url())?;
        if resp.status == 404 || resp.status == 405 {
            if let Some(p) = self.profile() {
                if !p.default_models.is_empty() {
                    return Ok(p
                        .default_models
                        .iter()
                        .map(|m| ModelInfo::new(*m))
                        .collect());
                }
            }
            return Err(Error::protocol("provider has no /models endpoint"));
        }
        self.check_status(&resp)?;
        let body = resp
            .read_to_string_limited(4 * 1024 * 1024)
            .map_err(map_http)?;
        parse_model_list(&body)
    }

    // ---------- streaming ----------

    fn stream_impl(
        &self,
        req: &ChatRequest,
        sink: &mut EventSink<'_>,
    ) -> Result<ChatResponse, Error> {
        let body = match self.kind {
            ApiKind::ChatCompletions => build_chat_body(&self.cfg, req),
            ApiKind::Responses => build_responses_body(&self.cfg, req),
            ApiKind::AnthropicMessages => build_anthropic_body(&self.cfg, req),
        };
        let url = self.chat_url();
        let mut resp = self.post_json(&url, &body, req.stream)?;
        self.check_status(&resp)?;
        if !req.stream {
            let text = resp
                .read_to_string_limited(32 * 1024 * 1024)
                .map_err(map_http)?;
            return parse_full_response(self.kind, &text);
        }
        match self.kind {
            ApiKind::ChatCompletions => self.stream_chat(&mut resp, sink),
            ApiKind::Responses => self.stream_responses(&mut resp, sink),
            ApiKind::AnthropicMessages => self.stream_anthropic(&mut resp, sink),
        }
    }

    fn read_sse(
        &self,
        resp: &mut Response,
        mut on_event: impl FnMut(&SseEventData) -> Result<bool, Error>,
    ) -> Result<(), Error> {
        let mut decoder = SseDecoder::new();
        let mut buf = [0u8; 8192];
        let mut idle = 0u32;
        loop {
            match resp.read_some(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    idle = 0;
                    for ev in decoder.feed(&buf[..n]) {
                        let data = SseEventData {
                            event: ev.event.clone(),
                            data: ev.data.clone(),
                        };
                        if data.data == "[DONE]" {
                            return Ok(());
                        }
                        if !on_event(&data)? {
                            return Ok(());
                        }
                    }
                }
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::TimedOut =>
                {
                    idle += 1;
                    if idle > 4 {
                        return Err(Error::network("stream stalled (no data for a long time)"));
                    }
                    continue;
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(Error::network(format!("stream read: {e}"))),
            }
        }
        Ok(())
    }

    fn stream_chat(
        &self,
        resp: &mut Response,
        sink: &mut EventSink<'_>,
    ) -> Result<ChatResponse, Error> {
        let mut out = ChatResponse::default();
        let mut acc: Vec<ChatAcc> = Vec::new();
        let mut saw_done = false;
        self.read_sse(resp, |ev| {
            let Ok(v) = emerag_json::parse(&ev.data) else {
                return Ok(true);
            };
            if let Some(err) = v.get("error") {
                return Err(Error::protocol(format!(
                    "provider error: {}",
                    error_text(err)
                )));
            }
            if let Some(u) = v.get("usage").filter(|u| u.is_object()) {
                out.usage = usage_openai(u);
                sink(StreamEvent::Usage(out.usage));
            }
            let Some(choices) = v.get("choices").and_then(|c| c.as_array()) else {
                return Ok(true);
            };
            for choice in choices {
                if let Some(delta) = choice.get("delta") {
                    if let Some(text) = delta.get("content").and_then(|c| c.as_str()) {
                        if !text.is_empty() {
                            out.content.push_str(text);
                            sink(StreamEvent::Text(text.to_string()));
                        }
                    }
                    if let Some(text) = delta.get("reasoning_content").and_then(|c| c.as_str()) {
                        if !text.is_empty() {
                            out.reasoning.push_str(text);
                            sink(StreamEvent::Reasoning(text.to_string()));
                        }
                    }
                    if let Some(calls) = delta.get("tool_calls").and_then(|c| c.as_array()) {
                        for call in calls {
                            let idx =
                                call.get("index").and_then(|i| i.as_u64()).unwrap_or(0) as usize;
                            while acc.len() <= idx {
                                acc.push(ChatAcc::default());
                            }
                            let a = &mut acc[idx];
                            if let Some(id) = call.get("id").and_then(|i| i.as_str()) {
                                if !id.is_empty() {
                                    a.id = id.to_string();
                                }
                            }
                            if let Some(f) = call.get("function") {
                                if let Some(name) = f.get("name").and_then(|n| n.as_str()) {
                                    if !name.is_empty() {
                                        a.name = name.to_string();
                                    }
                                }
                                if let Some(args) = f.get("arguments").and_then(|n| n.as_str()) {
                                    a.args.push_str(args);
                                }
                            }
                        }
                    }
                }
                if let Some(reason) = choice.get("finish_reason").and_then(|r| r.as_str()) {
                    out.stop = Some(stop_from_chat(reason));
                    saw_done = true;
                }
            }
            Ok(true)
        })?;
        let _ = saw_done;
        for (i, a) in acc.into_iter().enumerate() {
            if a.name.is_empty() {
                continue;
            }
            let id = if a.id.is_empty() {
                format!("call_{i}")
            } else {
                a.id
            };
            let args = if a.args.trim().is_empty() {
                "{}".to_string()
            } else {
                a.args
            };
            let call = ToolCall::new(id, a.name, args);
            out.tool_calls.push(call.clone());
            sink(StreamEvent::ToolCall(call));
        }
        if out.stop.is_none() {
            out.stop = Some(if out.tool_calls.is_empty() {
                StopReason::EndTurn
            } else {
                StopReason::ToolUse
            });
        }
        sink(StreamEvent::Done(
            out.stop.clone().unwrap_or(StopReason::EndTurn),
        ));
        Ok(out)
    }

    fn stream_responses(
        &self,
        resp: &mut Response,
        sink: &mut EventSink<'_>,
    ) -> Result<ChatResponse, Error> {
        let mut out = ChatResponse::default();
        let mut args_by_id: Vec<(String, String)> = Vec::new();
        let mut completed_calls: Vec<ToolCall> = Vec::new();
        self.read_sse(resp, |ev| {
            let Ok(v) = emerag_json::parse(&ev.data) else {
                return Ok(true);
            };
            let ty = v
                .get("type")
                .and_then(|t| t.as_str())
                .or_else(|| {
                    if ev.event.is_empty() {
                        None
                    } else {
                        Some(ev.event.as_str())
                    }
                })
                .unwrap_or("");
            match ty {
                "response.output_text.delta" | "response.text.delta" => {
                    if let Some(d) = v.get("delta").and_then(|d| d.as_str()) {
                        out.content.push_str(d);
                        sink(StreamEvent::Text(d.to_string()));
                    }
                }
                "response.reasoning_summary_text.delta" | "response.reasoning_text.delta" => {
                    if let Some(d) = v.get("delta").and_then(|d| d.as_str()) {
                        out.reasoning.push_str(d);
                        sink(StreamEvent::Reasoning(d.to_string()));
                    }
                }
                "response.function_call_arguments.delta" => {
                    let id = v.get("item_id").and_then(|i| i.as_str()).unwrap_or("");
                    let d = v.get("delta").and_then(|d| d.as_str()).unwrap_or("");
                    match args_by_id.iter_mut().find(|(k, _)| k == id) {
                        Some((_, buf)) => buf.push_str(d),
                        None => args_by_id.push((id.to_string(), d.to_string())),
                    }
                }
                "response.output_item.done" => {
                    if let Some(item) = v.get("item") {
                        if item.get("type").and_then(|t| t.as_str()) == Some("function_call") {
                            let call_id =
                                item.get("call_id").and_then(|c| c.as_str()).unwrap_or("");
                            let name = item.get("name").and_then(|c| c.as_str()).unwrap_or("");
                            let args = item
                                .get("arguments")
                                .and_then(|c| c.as_str())
                                .map(str::to_string)
                                .unwrap_or_else(|| {
                                    args_by_id
                                        .iter()
                                        .find(|(k, _)| k == call_id)
                                        .map(|(_, v)| v.clone())
                                        .unwrap_or_else(|| "{}".into())
                                });
                            if !name.is_empty() {
                                let call = ToolCall::new(
                                    call_id.to_string(),
                                    name.to_string(),
                                    if args.trim().is_empty() {
                                        "{}".into()
                                    } else {
                                        args
                                    },
                                );
                                completed_calls.push(call.clone());
                                sink(StreamEvent::ToolCall(call));
                            }
                        }
                    }
                }
                "response.completed" | "response.done" => {
                    if let Some(r) = v.get("response") {
                        if let Some(u) = r.get("usage") {
                            out.usage = usage_responses(u);
                        }
                        out.stop = Some(StopReason::EndTurn);
                    }
                }
                "response.incomplete" => {
                    out.stop = Some(StopReason::MaxTokens);
                }
                "response.failed" | "error" => {
                    let msg = v
                        .get("response")
                        .and_then(|r| r.get("error"))
                        .map(error_text)
                        .or_else(|| v.get("error").map(error_text))
                        .unwrap_or_else(|| emerag_json::to_string(&v));
                    return Err(Error::protocol(format!("responses error: {msg}")));
                }
                _ => {}
            }
            Ok(true)
        })?;
        out.tool_calls = completed_calls;
        if out.stop.is_none() {
            out.stop = Some(if out.tool_calls.is_empty() {
                StopReason::EndTurn
            } else {
                StopReason::ToolUse
            });
        }
        sink(StreamEvent::Done(
            out.stop.clone().unwrap_or(StopReason::EndTurn),
        ));
        Ok(out)
    }

    fn stream_anthropic(
        &self,
        resp: &mut Response,
        sink: &mut EventSink<'_>,
    ) -> Result<ChatResponse, Error> {
        let mut out = ChatResponse::default();
        let mut blocks: Vec<AnthBlock> = Vec::new();
        self.read_sse(resp, |ev| {
            let Ok(v) = emerag_json::parse(&ev.data) else {
                return Ok(true);
            };
            let ty = v
                .get("type")
                .and_then(|t| t.as_str())
                .or_else(|| {
                    if ev.event.is_empty() {
                        None
                    } else {
                        Some(ev.event.as_str())
                    }
                })
                .unwrap_or("");
            match ty {
                "message_start" => {
                    if let Some(u) = v.get("message").and_then(|m| m.get("usage")) {
                        out.usage = merge_usage(out.usage, usage_anthropic(u));
                        sink(StreamEvent::Usage(out.usage));
                    }
                }
                "content_block_start" => {
                    let idx = v.get("index").and_then(|i| i.as_u64()).unwrap_or(0) as usize;
                    while blocks.len() <= idx {
                        blocks.push(AnthBlock::default());
                    }
                    if let Some(b) = v.get("content_block") {
                        match b.get("type").and_then(|t| t.as_str()) {
                            Some("tool_use") => {
                                blocks[idx].kind = AnthKind::Tool;
                                blocks[idx].id = b
                                    .get("id")
                                    .and_then(|x| x.as_str())
                                    .unwrap_or("")
                                    .to_string();
                                blocks[idx].name = b
                                    .get("name")
                                    .and_then(|x| x.as_str())
                                    .unwrap_or("")
                                    .to_string();
                                if let Some(input) = b.get("input") {
                                    if !input.is_null()
                                        && input.as_object().map(|m| !m.is_empty()).unwrap_or(false)
                                    {
                                        blocks[idx].args = emerag_json::to_string(input);
                                    }
                                }
                            }
                            Some("thinking") => blocks[idx].kind = AnthKind::Thinking,
                            _ => blocks[idx].kind = AnthKind::Text,
                        }
                    }
                }
                "content_block_delta" => {
                    let idx = v.get("index").and_then(|i| i.as_u64()).unwrap_or(0) as usize;
                    while blocks.len() <= idx {
                        blocks.push(AnthBlock::default());
                    }
                    if let Some(d) = v.get("delta") {
                        match d.get("type").and_then(|t| t.as_str()) {
                            Some("text_delta") => {
                                if let Some(t) = d.get("text").and_then(|t| t.as_str()) {
                                    out.content.push_str(t);
                                    sink(StreamEvent::Text(t.to_string()));
                                }
                            }
                            Some("thinking_delta") => {
                                if let Some(t) = d.get("thinking").and_then(|t| t.as_str()) {
                                    out.reasoning.push_str(t);
                                    sink(StreamEvent::Reasoning(t.to_string()));
                                }
                            }
                            Some("input_json_delta") => {
                                if let Some(t) = d.get("partial_json").and_then(|t| t.as_str()) {
                                    blocks[idx].args.push_str(t);
                                }
                            }
                            _ => {}
                        }
                    }
                }
                "content_block_stop" => {
                    let idx = v.get("index").and_then(|i| i.as_u64()).unwrap_or(0) as usize;
                    if let Some(b) = blocks.get(idx) {
                        if b.kind == AnthKind::Tool && !b.name.is_empty() {
                            let args = if b.args.trim().is_empty() {
                                "{}".into()
                            } else {
                                b.args.clone()
                            };
                            let call = ToolCall::new(b.id.clone(), b.name.clone(), args);
                            out.tool_calls.push(call.clone());
                            sink(StreamEvent::ToolCall(call));
                        }
                    }
                }
                "message_delta" => {
                    if let Some(d) = v.get("delta") {
                        if let Some(r) = d.get("stop_reason").and_then(|r| r.as_str()) {
                            out.stop = Some(stop_from_anthropic(r));
                        }
                    }
                    if let Some(u) = v.get("usage") {
                        out.usage = merge_usage(out.usage, usage_anthropic(u));
                        sink(StreamEvent::Usage(out.usage));
                    }
                }
                "message_stop" => {
                    if out.stop.is_none() {
                        out.stop = Some(if out.tool_calls.is_empty() {
                            StopReason::EndTurn
                        } else {
                            StopReason::ToolUse
                        });
                    }
                    sink(StreamEvent::Done(
                        out.stop.clone().unwrap_or(StopReason::EndTurn),
                    ));
                }
                "error" => {
                    let msg = v
                        .get("error")
                        .map(error_text)
                        .unwrap_or_else(|| emerag_json::to_string(&v));
                    return Err(Error::protocol(format!("anthropic error: {msg}")));
                }
                "ping" => {}
                _ => {}
            }
            Ok(true)
        })?;
        if out.stop.is_none() {
            out.stop = Some(if out.tool_calls.is_empty() {
                StopReason::EndTurn
            } else {
                StopReason::ToolUse
            });
            sink(StreamEvent::Done(out.stop.clone().unwrap()));
        }
        Ok(out)
    }
}

impl Provider for Adapter {
    fn list_models(&self) -> Result<Vec<ModelInfo>, Error> {
        self.list_models_impl()
    }

    fn stream(&self, req: &ChatRequest, sink: &mut EventSink<'_>) -> Result<ChatResponse, Error> {
        self.stream_impl(req, sink)
    }

    fn probe(&self) -> Result<(), Error> {
        match self.list_models_impl() {
            Ok(models) if !models.is_empty() => Ok(()),
            Ok(_) => Err(Error::protocol("provider returned no models")),
            Err(list_err) => {
                // Some gateways do not expose /models; fall back to a tiny chat.
                let mut req = ChatRequest::new(
                    self.cfg.model.clone(),
                    "Reply with OK.",
                    vec![Message::user("OK?")],
                );
                req.max_output_tokens = Some(8);
                req.stream = false;
                let mut sink = |_ev: StreamEvent| true;
                match self.stream(&req, &mut sink) {
                    Ok(_) => Ok(()),
                    Err(e) => Err(if e.kind == ErrorKind::Auth {
                        e
                    } else {
                        Error::new(
                            e.kind,
                            format!("{} (model list failed: {})", e.message, list_err.message),
                        )
                    }),
                }
            }
        }
    }
}

#[derive(Default)]
struct ChatAcc {
    id: String,
    name: String,
    args: String,
}

#[derive(Default, PartialEq, Eq, Clone, Copy)]
enum AnthKind {
    #[default]
    Text,
    Tool,
    Thinking,
}

#[derive(Default, Clone)]
struct AnthBlock {
    kind: AnthKind,
    id: String,
    name: String,
    args: String,
}

struct SseEventData {
    event: String,
    data: String,
}

fn set_header(headers: &mut Vec<(String, String)>, key: &str, value: &str) {
    if let Some(existing) = headers
        .iter_mut()
        .find(|(k, _)| k.eq_ignore_ascii_case(key))
    {
        existing.1 = value.to_string();
    } else {
        headers.push((key.to_string(), value.to_string()));
    }
}

fn map_http(e: emerag_http::Error) -> Error {
    let msg = e.to_string();
    let kind = if msg.contains("cancel") {
        ErrorKind::Cancelled
    } else if msg.contains("tls")
        || msg.contains("certificate")
        || msg.contains("dns")
        || msg.contains("resolve")
        || msg.contains("connect")
        || msg.contains("io:")
        || msg.contains("stalled")
    {
        ErrorKind::Network
    } else {
        ErrorKind::Protocol
    };
    Error::new(kind, msg)
}

fn error_text(v: &Value) -> String {
    if let Some(s) = v.as_str() {
        return s.to_string();
    }
    if let Some(m) = v.get("message").and_then(|m| m.as_str()) {
        let ty = v.get("type").and_then(|t| t.as_str()).unwrap_or("");
        return if ty.is_empty() {
            m.to_string()
        } else {
            format!("{ty}: {m}")
        };
    }
    emerag_json::to_string(v)
}

fn extract_error_message(body: &str) -> String {
    if body.trim().is_empty() {
        return String::new();
    }
    if let Ok(v) = emerag_json::parse(body) {
        if let Some(e) = v.get("error") {
            return error_text(e);
        }
        if let Some(s) = v.get("message").and_then(|m| m.as_str()) {
            return s.to_string();
        }
    }
    emerag_util::text::truncate_ellipsis(&emerag_util::text::single_line(body), 400)
}

fn usage_openai(v: &Value) -> Usage {
    Usage {
        input_tokens: v.get("prompt_tokens").and_then(|x| x.as_u64()).unwrap_or(0) as u32,
        output_tokens: v
            .get("completion_tokens")
            .and_then(|x| x.as_u64())
            .unwrap_or(0) as u32,
        cached_input_tokens: v
            .get("prompt_tokens_details")
            .and_then(|d| d.get("cached_tokens"))
            .or_else(|| v.get("prompt_cache_hit_tokens"))
            .and_then(|x| x.as_u64())
            .unwrap_or(0) as u32,
        reasoning_tokens: v
            .get("completion_tokens_details")
            .and_then(|d| d.get("reasoning_tokens"))
            .and_then(|x| x.as_u64())
            .unwrap_or(0) as u32,
    }
}

fn usage_responses(v: &Value) -> Usage {
    Usage {
        input_tokens: v.get("input_tokens").and_then(|x| x.as_u64()).unwrap_or(0) as u32,
        output_tokens: v.get("output_tokens").and_then(|x| x.as_u64()).unwrap_or(0) as u32,
        cached_input_tokens: v
            .get("input_tokens_details")
            .and_then(|d| d.get("cached_tokens"))
            .and_then(|x| x.as_u64())
            .unwrap_or(0) as u32,
        reasoning_tokens: v
            .get("output_tokens_details")
            .and_then(|d| d.get("reasoning_tokens"))
            .and_then(|x| x.as_u64())
            .unwrap_or(0) as u32,
    }
}

fn usage_anthropic(v: &Value) -> Usage {
    let input = v.get("input_tokens").and_then(|x| x.as_u64()).unwrap_or(0);
    let cache_read = v
        .get("cache_read_input_tokens")
        .and_then(|x| x.as_u64())
        .unwrap_or(0);
    let cache_write = v
        .get("cache_creation_input_tokens")
        .and_then(|x| x.as_u64())
        .unwrap_or(0);
    Usage {
        input_tokens: (input + cache_read + cache_write) as u32,
        output_tokens: v.get("output_tokens").and_then(|x| x.as_u64()).unwrap_or(0) as u32,
        cached_input_tokens: cache_read as u32,
        reasoning_tokens: 0,
    }
}

fn merge_usage(a: Usage, b: Usage) -> Usage {
    Usage {
        input_tokens: a.input_tokens.max(b.input_tokens),
        output_tokens: a.output_tokens.max(b.output_tokens),
        cached_input_tokens: a.cached_input_tokens.max(b.cached_input_tokens),
        reasoning_tokens: a.reasoning_tokens.max(b.reasoning_tokens),
    }
}

fn stop_from_chat(reason: &str) -> StopReason {
    match reason {
        "stop" => StopReason::EndTurn,
        "length" => StopReason::MaxTokens,
        "tool_calls" | "function_call" => StopReason::ToolUse,
        "content_filter" => StopReason::ContentFilter,
        other => StopReason::Other(other.to_string()),
    }
}

fn stop_from_anthropic(reason: &str) -> StopReason {
    match reason {
        "end_turn" | "stop_sequence" => StopReason::EndTurn,
        "max_tokens" => StopReason::MaxTokens,
        "tool_use" => StopReason::ToolUse,
        other => StopReason::Other(other.to_string()),
    }
}

// ---------- request bodies ----------

fn obj(pairs: Vec<(&str, Value)>) -> Value {
    let mut m = Map::new();
    for (k, v) in pairs {
        m.insert(k.to_string(), v);
    }
    Value::Object(m)
}

fn vstr(v: impl std::fmt::Display) -> Value {
    Value::String(v.to_string())
}

fn vbool(b: bool) -> Value {
    Value::Bool(b)
}

fn vnum(n: i64) -> Value {
    Value::Number(emerag_json::Number::Int(n))
}

fn vf(n: f64) -> Value {
    Value::Number(emerag_json::Number::Float(n))
}

fn tool_specs_chat(tools: &[ToolSpec]) -> Value {
    Value::Array(
        tools
            .iter()
            .map(|t| {
                obj(vec![
                    ("type", vstr("function")),
                    (
                        "function",
                        obj(vec![
                            ("name", vstr(&t.name)),
                            ("description", vstr(&t.description)),
                            ("parameters", t.parameters.clone()),
                        ]),
                    ),
                ])
            })
            .collect(),
    )
}

fn tool_choice_chat(choice: &ToolChoice) -> Value {
    match choice {
        ToolChoice::Auto => vstr("auto"),
        ToolChoice::None => vstr("none"),
        ToolChoice::Required => vstr("required"),
        ToolChoice::Named(name) => obj(vec![
            ("type", vstr("function")),
            ("function", obj(vec![("name", vstr(name))])),
        ]),
    }
}

fn build_chat_body(cfg: &ClientConfig, req: &ChatRequest) -> Value {
    let mut messages: Vec<Value> = Vec::new();
    let profile = find(&cfg.profile_id);
    let no_system = profile.map(|p| p.has(Quirk::NoSystemRole)).unwrap_or(false);
    let mut system = req.system.clone();
    if !system.is_empty() && !no_system {
        messages.push(obj(vec![
            ("role", vstr("system")),
            ("content", vstr(&system)),
        ]));
        system.clear();
    }
    for m in &req.messages {
        match m.role {
            Role::System => messages.push(obj(vec![
                ("role", vstr("system")),
                ("content", vstr(&m.content)),
            ])),
            Role::User => {
                let content = if messages.is_empty() && !system.is_empty() {
                    format!("{system}\n\n{}", m.content)
                } else {
                    m.content.clone()
                };
                messages.push(obj(vec![
                    ("role", vstr("user")),
                    ("content", vstr(content)),
                ]));
            }
            Role::Assistant => {
                let mut pairs: Vec<(&str, Value)> = vec![("role", vstr("assistant"))];
                if m.tool_calls.is_empty() {
                    pairs.push(("content", vstr(&m.content)));
                } else {
                    pairs.push((
                        "content",
                        if m.content.is_empty() {
                            Value::Null
                        } else {
                            vstr(&m.content)
                        },
                    ));
                    let calls: Vec<Value> = m
                        .tool_calls
                        .iter()
                        .map(|c| {
                            obj(vec![
                                ("id", vstr(&c.id)),
                                ("type", vstr("function")),
                                (
                                    "function",
                                    obj(vec![
                                        ("name", vstr(&c.name)),
                                        ("arguments", vstr(&c.arguments)),
                                    ]),
                                ),
                            ])
                        })
                        .collect();
                    pairs.push(("tool_calls", Value::Array(calls)));
                }
                if let Some(r) = &m.reasoning {
                    if profile
                        .map(|p| matches!(p.id, "deepseek" | "deepseek-account"))
                        .unwrap_or(false)
                    {
                        pairs.push(("reasoning_content", vstr(r)));
                    }
                }
                messages.push(obj(pairs));
            }
            Role::Tool => {
                messages.push(obj(vec![
                    ("role", vstr("tool")),
                    (
                        "tool_call_id",
                        vstr(m.tool_call_id.clone().unwrap_or_default()),
                    ),
                    ("content", vstr(&m.content)),
                ]));
            }
        }
    }
    let mut body: Vec<(&str, Value)> = vec![
        ("model", vstr(&req.model)),
        ("messages", Value::Array(messages)),
    ];
    if !req.tools.is_empty() {
        body.push(("tools", tool_specs_chat(&req.tools)));
        body.push(("tool_choice", tool_choice_chat(&req.tool_choice)));
    }
    body.push(("stream", vbool(req.stream)));
    let local = profile
        .map(|p| {
            p.id.starts_with("ollama") || p.id.starts_with("llama") || p.id.starts_with("lmstudio")
        })
        .unwrap_or(false);
    if req.stream && !local {
        body.push(("stream_options", obj(vec![("include_usage", vbool(true))])));
    }
    if let Some(t) = req.temperature {
        body.push(("temperature", vf(t as f64)));
    }
    if let Some(m) = req.max_output_tokens {
        let key = if profile.map(|p| p.id.starts_with("openai")).unwrap_or(false) {
            "max_completion_tokens"
        } else {
            "max_tokens"
        };
        body.push((key, vnum(m as i64)));
    }
    if !req.stop.is_empty() {
        body.push((
            "stop",
            Value::Array(req.stop.iter().map(|s| vstr(s)).collect()),
        ));
    }
    for (k, v) in req.extra_body.iter() {
        body.push((Box::leak(k.clone().into_boxed_str()), v.clone()));
    }
    for (k, v) in cfg.extra_body.iter() {
        if k != "_temperature" && !body.iter().any(|(bk, _)| *bk == k.as_str()) {
            body.push((Box::leak(k.clone().into_boxed_str()), v.clone()));
        }
    }
    obj(body)
}

fn build_responses_body(cfg: &ClientConfig, req: &ChatRequest) -> Value {
    let mut input: Vec<Value> = Vec::new();
    for m in &req.messages {
        match m.role {
            Role::User => input.push(obj(vec![
                ("role", vstr("user")),
                (
                    "content",
                    Value::Array(vec![obj(vec![
                        ("type", vstr("input_text")),
                        ("text", vstr(&m.content)),
                    ])]),
                ),
            ])),
            Role::Assistant => {
                if !m.content.trim().is_empty() {
                    input.push(obj(vec![
                        ("role", vstr("assistant")),
                        (
                            "content",
                            Value::Array(vec![obj(vec![
                                ("type", vstr("output_text")),
                                ("text", vstr(&m.content)),
                            ])]),
                        ),
                    ]));
                }
                for c in &m.tool_calls {
                    input.push(obj(vec![
                        ("type", vstr("function_call")),
                        ("call_id", vstr(&c.id)),
                        ("name", vstr(&c.name)),
                        ("arguments", vstr(&c.arguments)),
                    ]));
                }
            }
            Role::Tool => input.push(obj(vec![
                ("type", vstr("function_call_output")),
                ("call_id", vstr(m.tool_call_id.clone().unwrap_or_default())),
                ("output", vstr(&m.content)),
            ])),
            Role::System => {}
        }
    }
    let tools: Vec<Value> = req
        .tools
        .iter()
        .map(|t| {
            obj(vec![
                ("type", vstr("function")),
                ("name", vstr(&t.name)),
                ("description", vstr(&t.description)),
                ("parameters", t.parameters.clone()),
                ("strict", vbool(false)),
            ])
        })
        .collect();
    let mut body: Vec<(&str, Value)> =
        vec![("model", vstr(&req.model)), ("input", Value::Array(input))];
    if !req.system.is_empty() {
        body.push(("instructions", vstr(&req.system)));
    }
    if !tools.is_empty() {
        body.push(("tools", Value::Array(tools)));
        body.push((
            "tool_choice",
            match &req.tool_choice {
                ToolChoice::Auto => vstr("auto"),
                ToolChoice::None => vstr("none"),
                ToolChoice::Required => vstr("required"),
                ToolChoice::Named(n) => obj(vec![("type", vstr("function")), ("name", vstr(n))]),
            },
        ));
    }
    body.push(("stream", vbool(req.stream)));
    body.push(("store", vbool(false)));
    if let Some(m) = req.max_output_tokens {
        body.push(("max_output_tokens", vnum(m.max(16) as i64)));
    }
    if let Some(t) = req.temperature {
        body.push(("temperature", vf(t as f64)));
    }
    if !req.stop.is_empty() {
        body.push((
            "stop",
            Value::Array(req.stop.iter().map(|s| vstr(s)).collect()),
        ));
    }
    for (k, v) in req.extra_body.iter() {
        body.push((Box::leak(k.clone().into_boxed_str()), v.clone()));
    }
    for (k, v) in cfg.extra_body.iter() {
        if k != "_temperature" && !body.iter().any(|(bk, _)| *bk == k.as_str()) {
            body.push((Box::leak(k.clone().into_boxed_str()), v.clone()));
        }
    }
    obj(body)
}

fn build_anthropic_body(cfg: &ClientConfig, req: &ChatRequest) -> Value {
    let mut messages: Vec<Value> = Vec::new();
    for m in &req.messages {
        match m.role {
            Role::System => {}
            Role::User => {
                push_anthropic_message(
                    &mut messages,
                    "user",
                    vec![obj(vec![
                        ("type", vstr("text")),
                        ("text", vstr(&m.content)),
                    ])],
                );
            }
            Role::Assistant => {
                let mut blocks: Vec<Value> = Vec::new();
                if !m.content.trim().is_empty() {
                    blocks.push(obj(vec![
                        ("type", vstr("text")),
                        ("text", vstr(&m.content)),
                    ]));
                }
                for c in &m.tool_calls {
                    let input = emerag_json::parse(&c.arguments)
                        .unwrap_or_else(|_| Value::Object(Map::new()));
                    blocks.push(obj(vec![
                        ("type", vstr("tool_use")),
                        ("id", vstr(&c.id)),
                        ("name", vstr(&c.name)),
                        ("input", input),
                    ]));
                }
                if blocks.is_empty() {
                    blocks.push(obj(vec![("type", vstr("text")), ("text", vstr("(empty)"))]));
                }
                push_anthropic_message(&mut messages, "assistant", blocks);
            }
            Role::Tool => {
                let block = obj(vec![
                    ("type", vstr("tool_result")),
                    (
                        "tool_use_id",
                        vstr(m.tool_call_id.clone().unwrap_or_default()),
                    ),
                    ("content", vstr(&m.content)),
                ]);
                push_anthropic_message(&mut messages, "user", vec![block]);
            }
        }
    }
    let tools: Vec<Value> = req
        .tools
        .iter()
        .map(|t| {
            obj(vec![
                ("name", vstr(&t.name)),
                ("description", vstr(&t.description)),
                ("input_schema", t.parameters.clone()),
            ])
        })
        .collect();
    let mut body: Vec<(&str, Value)> = vec![
        ("model", vstr(&req.model)),
        (
            "max_tokens",
            vnum(req.max_output_tokens.unwrap_or(4096) as i64),
        ),
        ("messages", Value::Array(messages)),
    ];
    if !req.system.is_empty() {
        body.push(("system", vstr(&req.system)));
    }
    if !tools.is_empty() {
        body.push(("tools", Value::Array(tools)));
        body.push((
            "tool_choice",
            match &req.tool_choice {
                ToolChoice::Auto => obj(vec![("type", vstr("auto"))]),
                ToolChoice::None => obj(vec![("type", vstr("none"))]),
                ToolChoice::Required => obj(vec![("type", vstr("any"))]),
                ToolChoice::Named(n) => obj(vec![("type", vstr("tool")), ("name", vstr(n))]),
            },
        ));
    }
    body.push(("stream", vbool(req.stream)));
    if let Some(t) = req.temperature {
        body.push(("temperature", vf(t as f64)));
    }
    if !req.stop.is_empty() {
        body.push((
            "stop_sequences",
            Value::Array(req.stop.iter().map(|s| vstr(s)).collect()),
        ));
    }
    for (k, v) in req.extra_body.iter() {
        body.push((Box::leak(k.clone().into_boxed_str()), v.clone()));
    }
    for (k, v) in cfg.extra_body.iter() {
        if k != "_temperature" && !body.iter().any(|(bk, _)| *bk == k.as_str()) {
            body.push((Box::leak(k.clone().into_boxed_str()), v.clone()));
        }
    }
    obj(body)
}

fn push_anthropic_message(messages: &mut Vec<Value>, role: &str, blocks: Vec<Value>) {
    if let Some(last) = messages.last_mut() {
        if last.get("role").and_then(|r| r.as_str()) == Some(role) {
            if let Some(arr) = last.get_mut("content").and_then(|c| c.as_array_mut()) {
                arr.extend(blocks);
                return;
            }
        }
    }
    messages.push(obj(vec![
        ("role", vstr(role)),
        ("content", Value::Array(blocks)),
    ]));
}

fn parse_full_response(kind: ApiKind, text: &str) -> Result<ChatResponse, Error> {
    let v = emerag_json::parse(text)
        .map_err(|e| Error::protocol(format!("invalid response JSON: {e}")))?;
    if let Some(err) = v.get("error") {
        return Err(Error::protocol(format!(
            "provider error: {}",
            error_text(err)
        )));
    }
    let mut out = ChatResponse::default();
    match kind {
        ApiKind::ChatCompletions => {
            if let Some(choice) = v
                .get("choices")
                .and_then(|c| c.as_array())
                .and_then(|a| a.first())
            {
                if let Some(msg) = choice.get("message") {
                    out.content = msg
                        .get("content")
                        .and_then(|c| c.as_str())
                        .unwrap_or("")
                        .to_string();
                    out.reasoning = msg
                        .get("reasoning_content")
                        .and_then(|c| c.as_str())
                        .unwrap_or("")
                        .to_string();
                    if let Some(calls) = msg.get("tool_calls").and_then(|c| c.as_array()) {
                        for c in calls {
                            let id = c.get("id").and_then(|x| x.as_str()).unwrap_or("call_0");
                            let f = c.get("function");
                            let name = f
                                .and_then(|f| f.get("name"))
                                .and_then(|x| x.as_str())
                                .unwrap_or("");
                            let args = f
                                .and_then(|f| f.get("arguments"))
                                .and_then(|x| x.as_str())
                                .unwrap_or("{}");
                            if !name.is_empty() {
                                out.tool_calls.push(ToolCall::new(id, name, args));
                            }
                        }
                    }
                }
                if let Some(r) = choice.get("finish_reason").and_then(|r| r.as_str()) {
                    out.stop = Some(stop_from_chat(r));
                }
            }
            if let Some(u) = v.get("usage") {
                out.usage = usage_openai(u);
            }
        }
        ApiKind::Responses => {
            if let Some(output) = v.get("output").and_then(|o| o.as_array()) {
                for item in output {
                    match item.get("type").and_then(|t| t.as_str()) {
                        Some("message") => {
                            if let Some(content) = item.get("content").and_then(|c| c.as_array()) {
                                for part in content {
                                    if let Some(t) = part.get("text").and_then(|t| t.as_str()) {
                                        out.content.push_str(t);
                                    }
                                }
                            }
                        }
                        Some("function_call") => {
                            let id = item
                                .get("call_id")
                                .and_then(|x| x.as_str())
                                .unwrap_or("call_0");
                            let name = item.get("name").and_then(|x| x.as_str()).unwrap_or("");
                            let args = item
                                .get("arguments")
                                .and_then(|x| x.as_str())
                                .unwrap_or("{}");
                            if !name.is_empty() {
                                out.tool_calls.push(ToolCall::new(id, name, args));
                            }
                        }
                        Some("reasoning") => {
                            if let Some(summary) = item.get("summary").and_then(|s| s.as_array()) {
                                for part in summary {
                                    if let Some(t) = part.get("text").and_then(|t| t.as_str()) {
                                        out.reasoning.push_str(t);
                                    }
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
            if let Some(u) = v.get("usage") {
                out.usage = usage_responses(u);
            }
        }
        ApiKind::AnthropicMessages => {
            if let Some(content) = v.get("content").and_then(|c| c.as_array()) {
                for block in content {
                    match block.get("type").and_then(|t| t.as_str()) {
                        Some("text") => {
                            if let Some(t) = block.get("text").and_then(|t| t.as_str()) {
                                out.content.push_str(t);
                            }
                        }
                        Some("thinking") => {
                            if let Some(t) = block.get("thinking").and_then(|t| t.as_str()) {
                                out.reasoning.push_str(t);
                            }
                        }
                        Some("tool_use") => {
                            let id = block.get("id").and_then(|x| x.as_str()).unwrap_or("call_0");
                            let name = block.get("name").and_then(|x| x.as_str()).unwrap_or("");
                            let args = block
                                .get("input")
                                .map(|i| emerag_json::to_string(i))
                                .unwrap_or_else(|| "{}".into());
                            if !name.is_empty() {
                                out.tool_calls.push(ToolCall::new(id, name, args));
                            }
                        }
                        _ => {}
                    }
                }
            }
            if let Some(r) = v.get("stop_reason").and_then(|r| r.as_str()) {
                out.stop = Some(stop_from_anthropic(r));
            }
            if let Some(u) = v.get("usage") {
                out.usage = usage_anthropic(u);
            }
        }
    }
    if out.stop.is_none() {
        out.stop = Some(if out.tool_calls.is_empty() {
            StopReason::EndTurn
        } else {
            StopReason::ToolUse
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalog::find;

    fn cfg(profile: &str, model: &str) -> ClientConfig {
        let p = find(profile).unwrap();
        ClientConfig::new(p, model)
    }

    #[test]
    fn chat_body_has_tools_and_messages() {
        let mut c = cfg("deepseek", "deepseek-flash");
        c.credentials = Credentials::key("sk-test");
        let mut req = ChatRequest::new("deepseek-flash", "be brief", vec![Message::user("hi")]);
        req.tools = vec![ToolSpec::new("shell", "run", json!({"type": "object"}))];
        req.max_output_tokens = Some(64);
        let body = build_chat_body(&c, &req);
        assert_eq!(body["model"].as_str(), Some("deepseek-flash"));
        assert_eq!(body["messages"][0]["role"].as_str(), Some("system"));
        assert_eq!(body["tools"][0]["function"]["name"].as_str(), Some("shell"));
        assert_eq!(body["max_tokens"].as_i64(), Some(64));
    }

    #[test]
    fn anthropic_body_moves_tool_results() {
        let c = cfg("anthropic", "claude-sonnet-4-5");
        let mut req = ChatRequest::new(
            "claude-sonnet-4-5",
            "sys",
            vec![
                Message::user("read it"),
                Message::assistant("").with_tool_calls(vec![ToolCall::new(
                    "toolu_1",
                    "read_file",
                    "{\"path\":\"/x\"}",
                )]),
                Message::tool("toolu_1", "contents"),
            ],
        );
        req.max_output_tokens = Some(128);
        let body = build_anthropic_body(&c, &req);
        assert_eq!(body["max_tokens"].as_i64(), Some(128));
        let msgs = body["messages"].as_array().unwrap();
        assert_eq!(msgs[1]["content"][0]["type"].as_str(), Some("tool_use"));
        assert_eq!(msgs[2]["role"].as_str(), Some("user"));
        assert_eq!(msgs[2]["content"][0]["type"].as_str(), Some("tool_result"));
    }

    #[test]
    fn responses_body_is_stateless_and_flat() {
        let c = cfg("openai-responses", "gpt-4o-mini");
        let mut req = ChatRequest::new("gpt-4o-mini", "sys", vec![Message::user("hi")]);
        req.tools = vec![ToolSpec::new("shell", "run", json!({"type": "object"}))];
        let body = build_responses_body(&c, &req);
        assert_eq!(body["store"].as_bool(), Some(false));
        assert_eq!(body["tools"][0]["name"].as_str(), Some("shell"));
        assert!(body["input"].is_array());
    }
}
