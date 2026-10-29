//! Canonical request/response model shared by all adapters.

use emerag_json::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApiKind {
    ChatCompletions,
    Responses,
    AnthropicMessages,
}

impl ApiKind {
    pub fn as_str(self) -> &'static str {
        match self {
            ApiKind::ChatCompletions => "chat",
            ApiKind::Responses => "responses",
            ApiKind::AnthropicMessages => "anthropic",
        }
    }

    pub fn parse(s: &str) -> Option<ApiKind> {
        match s.to_ascii_lowercase().as_str() {
            "chat" | "chat-completions" | "chat_completions" | "openai" | "completions" => {
                Some(ApiKind::ChatCompletions)
            }
            "responses" | "response" | "openai-responses" => Some(ApiKind::Responses),
            "anthropic" | "messages" | "anthropic-messages" | "claude" => {
                Some(ApiKind::AnthropicMessages)
            }
            _ => None,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            ApiKind::ChatCompletions => "Chat Completions",
            ApiKind::Responses => "Responses",
            ApiKind::AnthropicMessages => "Anthropic Messages",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    System,
    User,
    Assistant,
    Tool,
}

impl Role {
    pub fn as_str(self) -> &'static str {
        match self {
            Role::System => "system",
            Role::User => "user",
            Role::Assistant => "assistant",
            Role::Tool => "tool",
        }
    }
}

/// One tool invocation requested by the model.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolCall {
    pub id: String,
    pub name: String,
    /// Raw JSON string as produced by the model (may be empty or invalid).
    pub arguments: String,
}

impl ToolCall {
    pub fn new(
        id: impl Into<String>,
        name: impl Into<String>,
        arguments: impl Into<String>,
    ) -> Self {
        ToolCall {
            id: id.into(),
            name: name.into(),
            arguments: arguments.into(),
        }
    }

    /// Parse arguments, returning an empty object for empty/invalid input.
    pub fn args(&self) -> Value {
        if self.arguments.trim().is_empty() {
            return Value::Object(emerag_json::Map::new());
        }
        emerag_json::parse(&self.arguments).unwrap_or_else(|_| {
            // Some models emit trailing text after JSON; try a prefix parse.
            emerag_json::parse_prefix(&self.arguments)
                .map(|(v, _)| v)
                .unwrap_or(Value::Null)
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Message {
    pub role: Role,
    pub content: String,
    /// Reasoning/thinking text (deepseek-reasoner, o-series, Claude thinking).
    pub reasoning: Option<String>,
    pub tool_calls: Vec<ToolCall>,
    /// Set for Role::Tool: which call this result answers.
    pub tool_call_id: Option<String>,
    pub name: Option<String>,
}

impl Message {
    pub fn system(content: impl Into<String>) -> Self {
        Message {
            role: Role::System,
            content: content.into(),
            reasoning: None,
            tool_calls: Vec::new(),
            tool_call_id: None,
            name: None,
        }
    }
    pub fn user(content: impl Into<String>) -> Self {
        Message {
            role: Role::User,
            content: content.into(),
            reasoning: None,
            tool_calls: Vec::new(),
            tool_call_id: None,
            name: None,
        }
    }
    pub fn assistant(content: impl Into<String>) -> Self {
        Message {
            role: Role::Assistant,
            content: content.into(),
            reasoning: None,
            tool_calls: Vec::new(),
            tool_call_id: None,
            name: None,
        }
    }
    pub fn tool(call_id: impl Into<String>, content: impl Into<String>) -> Self {
        Message {
            role: Role::Tool,
            content: content.into(),
            reasoning: None,
            tool_calls: Vec::new(),
            tool_call_id: Some(call_id.into()),
            name: None,
        }
    }

    pub fn with_tool_calls(mut self, calls: Vec<ToolCall>) -> Self {
        self.tool_calls = calls;
        self
    }

    pub fn with_reasoning(mut self, reasoning: impl Into<String>) -> Self {
        let r = reasoning.into();
        if !r.trim().is_empty() {
            self.reasoning = Some(r);
        }
        self
    }

    /// Rough token estimate: about 4 ASCII chars per token, CJK ~1.5 chars.
    pub fn estimated_tokens(&self) -> usize {
        let mut n = self.content.chars().count() / 3;
        if let Some(r) = &self.reasoning {
            n += r.chars().count() / 4;
        }
        for c in &self.tool_calls {
            n += (c.name.len() + c.arguments.len()) / 3 + 8;
        }
        n + 4
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ToolSpec {
    pub name: String,
    pub description: String,
    pub parameters: Value,
}

impl ToolSpec {
    pub fn new(name: impl Into<String>, description: impl Into<String>, parameters: Value) -> Self {
        ToolSpec {
            name: name.into(),
            description: description.into(),
            parameters,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum ToolChoice {
    Auto,
    None,
    Required,
    Named(String),
}

#[derive(Debug, Clone)]
pub struct ChatRequest {
    pub model: String,
    pub system: String,
    pub messages: Vec<Message>,
    pub tools: Vec<ToolSpec>,
    pub tool_choice: ToolChoice,
    pub temperature: Option<f32>,
    pub max_output_tokens: Option<u32>,
    pub stop: Vec<String>,
    pub stream: bool,
    /// Provider-specific extras (e.g. reasoning effort).
    pub extra_body: emerag_json::Map,
}

impl ChatRequest {
    pub fn new(
        model: impl Into<String>,
        system: impl Into<String>,
        messages: Vec<Message>,
    ) -> Self {
        ChatRequest {
            model: model.into(),
            system: system.into(),
            messages,
            tools: Vec::new(),
            tool_choice: ToolChoice::Auto,
            temperature: None,
            max_output_tokens: None,
            stop: Vec::new(),
            stream: true,
            extra_body: emerag_json::Map::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Usage {
    pub input_tokens: u32,
    pub output_tokens: u32,
    pub cached_input_tokens: u32,
    pub reasoning_tokens: u32,
}

impl Usage {
    pub fn total(&self) -> u32 {
        self.input_tokens + self.output_tokens
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StopReason {
    EndTurn,
    MaxTokens,
    ToolUse,
    StopSequence,
    ContentFilter,
    Other(String),
}

#[derive(Debug, Clone, PartialEq)]
pub enum StreamEvent {
    /// Visible answer text delta.
    Text(String),
    /// Reasoning/thinking delta.
    Reasoning(String),
    /// A complete tool call (arguments fully received).
    ToolCall(ToolCall),
    Usage(Usage),
    Done(StopReason),
    /// Provider error surfaced mid-stream.
    Error(String),
}

#[derive(Debug, Clone, Default)]
pub struct ChatResponse {
    pub content: String,
    pub reasoning: String,
    pub tool_calls: Vec<ToolCall>,
    pub usage: Usage,
    pub stop: Option<StopReason>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelInfo {
    pub id: String,
    pub context_window: Option<u32>,
    pub max_output: Option<u32>,
    /// Free-form note shown in the wizard (e.g. "free", "reasoning").
    pub tag: Option<String>,
}

impl ModelInfo {
    pub fn new(id: impl Into<String>) -> Self {
        ModelInfo {
            id: id.into(),
            context_window: None,
            max_output: None,
            tag: None,
        }
    }
    pub fn with_context(mut self, n: u32) -> Self {
        self.context_window = Some(n);
        self
    }
    pub fn with_tag(mut self, t: impl Into<String>) -> Self {
        self.tag = Some(t.into());
        self
    }
}

/// Parse an OpenAI-style /models response: {"data":[{"id":...},...]}.
/// Also accepts Anthropic's {"data":[{"id":...}]} and bare arrays.
pub fn parse_model_list(body: &str) -> Result<Vec<ModelInfo>, crate::Error> {
    let value = emerag_json::parse(body)
        .map_err(|e| crate::Error::protocol(format!("invalid model list: {e}")))?;
    let items: &Vec<Value> = if let Some(arr) = value.as_array() {
        arr
    } else if let Some(arr) = value.get("data").and_then(|v| v.as_array()) {
        arr
    } else if let Some(arr) = value.get("models").and_then(|v| v.as_array()) {
        arr
    } else {
        return Err(crate::Error::protocol("model list has no data array"));
    };
    let mut out = Vec::new();
    for item in items {
        let id = match item {
            Value::String(s) => s.clone(),
            Value::Object(_) => match item
                .get("id")
                .or_else(|| item.get("name"))
                .and_then(|v| v.as_str())
            {
                Some(s) => s.to_string(),
                None => continue,
            },
            _ => continue,
        };
        let mut info = ModelInfo::new(id);
        info.context_window = item
            .get("context_window")
            .or_else(|| item.get("context_length"))
            .or_else(|| item.get("max_context_length"))
            .and_then(|v| v.as_u64())
            .map(|v| v as u32);
        info.max_output = item
            .get("max_output_tokens")
            .or_else(|| item.get("max_completion_tokens"))
            .and_then(|v| v.as_u64())
            .map(|v| v as u32);
        out.push(info);
    }
    out.sort_by(|a, b| a.id.cmp(&b.id));
    out.dedup_by(|a, b| a.id == b.id);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tool_call_arguments_tolerate_noise() {
        let c = ToolCall::new("1", "shell", "{\"command\":\"ls\"} trailing");
        assert_eq!(c.args()["command"].as_str(), Some("ls"));
        assert!(ToolCall::new("1", "x", "").args().is_object());
        assert_eq!(ToolCall::new("1", "x", "not json").args(), Value::Null);
    }

    #[test]
    fn parses_openai_model_list() {
        let models =
            parse_model_list(r#"{"object":"list","data":[{"id":"b"},{"id":"a"}]}"#).unwrap();
        assert_eq!(
            models.iter().map(|m| m.id.as_str()).collect::<Vec<_>>(),
            vec!["a", "b"]
        );
        let models = parse_model_list(r#"[{"id":"x","context_length":8192}]"#).unwrap();
        assert_eq!(models[0].context_window, Some(8192));
        assert!(parse_model_list("{}").is_err());
    }

    #[test]
    fn token_estimate_grows_with_content() {
        assert!(Message::user("hello world").estimated_tokens() >= 4);
        assert!(Message::user("a".repeat(400)).estimated_tokens() > 50);
    }

    #[test]
    fn redaction_hides_secrets() {
        assert_eq!(crate::redact("sk-1234567890abcdef"), "sk-1...cdef");
        assert_eq!(crate::redact("short"), "****");
    }
}
