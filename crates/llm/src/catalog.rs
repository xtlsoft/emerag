//! Embedded provider catalog.
//!
//! Adding a provider should never require touching agent logic: append a
//! Profile here (or load a JSON override at runtime). Base URLs and API kinds
//! are data; auth construction is driven by AuthKind.

use crate::{ApiKind, Error, ErrorKind};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthKind {
    /// No credential (local servers).
    None,
    /// Authorization: Bearer <key>
    Bearer,
    /// x-api-key: <key> (Anthropic style)
    ApiKeyHeader,
    /// Authorization: Bearer + anthropic-version style headers are in Profile.headers.
    BearerWithHeaders,
    /// DeepSeek account grant, sent as x-dsh-auth-token.
    DeepSeekAccount,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Quirk {
    /// The API rejects a system role; fold it into the first user message.
    NoSystemRole,
    /// max_tokens is required (Anthropic Messages).
    RequiresMaxTokens,
    /// Supports a reasoning/thinking field in responses.
    Reasoning,
    /// Model list endpoint may require a beta header or may 404.
    OptionalModelList,
    /// Only a fixed set of models exists; discovery is meaningless.
    FixedModels,
    /// Supports prompt caching headers.
    PromptCaching,
    /// Requires a stable x-opencode-session header (OpenCode Go).
    RequiresSessionHeader,
}

#[derive(Debug, Clone, Copy)]
pub struct Profile {
    pub id: &'static str,
    pub label: &'static str,
    pub base_url: &'static str,
    pub api: ApiKind,
    pub auth: AuthKind,
    /// Path appended to base_url for chat (no leading slash).
    pub chat_path: &'static str,
    pub models_path: &'static str,
    /// Absolute models listing URL when it is not under base_url.
    pub absolute_models_url: Option<&'static str>,
    pub default_models: &'static [&'static str],
    pub env_key: &'static str,
    pub env_base: &'static str,
    pub docs_url: &'static str,
    pub headers: &'static [(&'static str, &'static str)],
    pub quirks: &'static [Quirk],
    /// Shown in the wizard under the provider name.
    pub note: &'static str,
}

impl Profile {
    pub fn has(&self, q: Quirk) -> bool {
        self.quirks.contains(&q)
    }

    pub fn default_model(&self) -> &'static str {
        self.default_models.first().copied().unwrap_or("")
    }
}

pub const PROFILES: &[Profile] = &[
    Profile {
        id: "deepseek",
        label: "DeepSeek",
        base_url: "https://api.deepseek.com",
        api: ApiKind::ChatCompletions,
        auth: AuthKind::Bearer,
        chat_path: "chat/completions",
        models_path: "models",
        absolute_models_url: None,
        default_models: &["deepseek-flash", "deepseek-v4-pro"],
        env_key: "DEEPSEEK_API_KEY",
        env_base: "DEEPSEEK_BASE_URL",
        docs_url: "https://api-docs.deepseek.com/",
        headers: &[],
        quirks: &[Quirk::Reasoning, Quirk::OptionalModelList],
        note: "DeepSeek V4 models; also serves Anthropic/Responses formats",
    },
    Profile {
        id: "deepseek-account",
        label: "DeepSeek account (OAuth)",
        base_url: "https://api.deepseek.com",
        api: ApiKind::ChatCompletions,
        auth: AuthKind::DeepSeekAccount,
        chat_path: "chat/completions",
        models_path: "models",
        absolute_models_url: Some("https://api.deepseek.com/models"),
        default_models: &[],
        env_key: "",
        env_base: "DEEPSEEK_ACCOUNT_BASE_URL",
        docs_url: "https://platform.deepseek.com",
        headers: &[],
        quirks: &[
            Quirk::RequiresMaxTokens,
            Quirk::Reasoning,
            Quirk::OptionalModelList,
        ],
        note: "sign in with a DeepSeek account; no API key, models from /models",
    },
    Profile {
        id: "openai",
        label: "OpenAI",
        base_url: "https://api.openai.com/v1",
        api: ApiKind::ChatCompletions,
        auth: AuthKind::Bearer,
        chat_path: "chat/completions",
        models_path: "models",
        absolute_models_url: None,
        default_models: &["gpt-4o-mini"],
        env_key: "OPENAI_API_KEY",
        env_base: "OPENAI_BASE_URL",
        docs_url: "https://platform.openai.com/docs/api-reference/chat",
        headers: &[],
        quirks: &[],
        note: "Chat Completions; use openai-responses for the Responses API",
    },
    Profile {
        id: "openai-responses",
        label: "OpenAI Responses",
        base_url: "https://api.openai.com/v1",
        api: ApiKind::Responses,
        auth: AuthKind::Bearer,
        chat_path: "responses",
        models_path: "models",
        absolute_models_url: None,
        default_models: &["gpt-4o-mini"],
        env_key: "OPENAI_API_KEY",
        env_base: "OPENAI_BASE_URL",
        docs_url: "https://platform.openai.com/docs/api-reference/responses",
        headers: &[],
        quirks: &[Quirk::Reasoning],
        note: "Responses API; better tool-call fidelity on newer models",
    },
    Profile {
        id: "anthropic",
        label: "Anthropic",
        base_url: "https://api.anthropic.com",
        api: ApiKind::AnthropicMessages,
        auth: AuthKind::Bearer,
        chat_path: "v1/messages",
        models_path: "v1/models",
        absolute_models_url: None,
        default_models: &["claude-sonnet-4-5"],
        env_key: "ANTHROPIC_API_KEY",
        env_base: "ANTHROPIC_BASE_URL",
        docs_url: "https://docs.anthropic.com/en/api/messages",
        headers: &[("anthropic-version", "2026-10-21")],
        quirks: &[
            Quirk::RequiresMaxTokens,
            Quirk::Reasoning,
            Quirk::OptionalModelList,
        ],
        note: "Messages API; requires anthropic-version header and max_tokens",
    },
    Profile {
        id: "opencode-zen",
        label: "OpenCode Console",
        base_url: "https://opencode.ai/inference",
        api: ApiKind::ChatCompletions,
        auth: AuthKind::Bearer,
        chat_path: "openai/v1/chat/completions",
        models_path: "v1/models",
        absolute_models_url: None,
        default_models: &["kimi-k3", "grok-code"],
        env_key: "OPENCODE_API_KEY",
        env_base: "OPENCODE_BASE_URL",
        docs_url: "https://opencode.ai/v2/docs/console/models/",
        headers: &[],
        quirks: &[Quirk::OptionalModelList],
        note: "curated gateway; free-tier models refuse non-OpenCode clients",
    },
    Profile {
        id: "opencode-go",
        label: "OpenCode Go",
        base_url: "https://opencode.ai/inference/go",
        api: ApiKind::ChatCompletions,
        auth: AuthKind::Bearer,
        chat_path: "openai/v1/chat/completions",
        models_path: "v1/models",
        absolute_models_url: None,
        default_models: &["kimi-k3", "grok-code"],
        env_key: "OPENCODE_GO_API_KEY",
        env_base: "OPENCODE_GO_BASE_URL",
        docs_url: "https://opencode.ai/v2/docs/console/go/",
        headers: &[],
        quirks: &[Quirk::OptionalModelList, Quirk::RequiresSessionHeader],
        note: "Go subscription gateway; needs a stable session id",
    },
    Profile {
        id: "ollama",
        label: "Ollama (local)",
        base_url: "http://127.0.0.1:11434/v1",
        api: ApiKind::ChatCompletions,
        auth: AuthKind::None,
        chat_path: "chat/completions",
        models_path: "models",
        absolute_models_url: None,
        default_models: &[],
        env_key: "OLLAMA_API_KEY",
        env_base: "OLLAMA_BASE_URL",
        docs_url: "https://ollama.com",
        headers: &[],
        quirks: &[Quirk::OptionalModelList],
        note: "local models; no key needed",
    },
    Profile {
        id: "llamacpp",
        label: "llama.cpp server (local)",
        base_url: "http://127.0.0.1:9931/v1",
        api: ApiKind::ChatCompletions,
        auth: AuthKind::None,
        chat_path: "chat/completions",
        models_path: "models",
        absolute_models_url: None,
        default_models: &[],
        env_key: "",
        env_base: "LLAMACPP_BASE_URL",
        docs_url: "https://github.com/ggml-org/llama.cpp",
        headers: &[],
        quirks: &[Quirk::OptionalModelList],
        note: "uses the model name reported by the server",
    },
    Profile {
        id: "lmstudio",
        label: "LM Studio (local)",
        base_url: "http://127.0.0.1:1234/v1",
        api: ApiKind::ChatCompletions,
        auth: AuthKind::None,
        chat_path: "chat/completions",
        models_path: "models",
        absolute_models_url: None,
        default_models: &[],
        env_key: "",
        env_base: "LMSTUDIO_BASE_URL",
        docs_url: "https://lmstudio.ai",
        headers: &[],
        quirks: &[Quirk::OptionalModelList],
        note: "local OpenAI-compatible server",
    },
    Profile {
        id: "custom",
        label: "Custom / other",
        base_url: "",
        api: ApiKind::ChatCompletions,
        auth: AuthKind::Bearer,
        chat_path: "chat/completions",
        models_path: "models",
        absolute_models_url: None,
        default_models: &[],
        env_key: "EMERAG_API_KEY",
        env_base: "EMERAG_BASE_URL",
        docs_url: "",
        headers: &[],
        quirks: &[Quirk::OptionalModelList],
        note: "any OpenAI-compatible endpoint (vLLM, OpenRouter, LiteLLM, ...)",
    },
];

pub fn all() -> &'static [Profile] {
    PROFILES
}

pub fn find(id: &str) -> Option<&'static Profile> {
    let id = id.trim().to_ascii_lowercase();
    PROFILES
        .iter()
        .find(|p| p.id == id || p.label.eq_ignore_ascii_case(&id))
}

/// Guess a profile from a base URL, used when the user pastes an endpoint.
pub fn detect_from_url(url: &str) -> Option<&'static Profile> {
    let u = url.to_ascii_lowercase();
    if u.contains("api.deepseek.com") {
        return find("deepseek");
    }
    if u.contains("api.anthropic.com") {
        return find("anthropic");
    }
    if u.contains("opencode.ai/inference/go") {
        return find("opencode-go");
    }
    if u.contains("opencode.ai/inference") || u.contains("opencode.ai/zen") {
        return find("opencode-zen");
    }
    if u.contains("api.openai.com") {
        return find("openai");
    }
    if u.contains("11434") {
        return find("ollama");
    }
    if u.contains(":9931") || u.contains(":8080") || u.contains("llama") {
        return find("llamacpp");
    }
    if u.contains("1234") {
        return find("lmstudio");
    }
    if u.starts_with("http://127.0.0.1") || u.starts_with("http://localhost") {
        return find("custom");
    }
    None
}

/// Heuristic API detection from URL path, for pasted endpoints.
pub fn detect_api(url: &str) -> Option<ApiKind> {
    if url.contains("/messages") {
        Some(ApiKind::AnthropicMessages)
    } else if url.contains("/responses") {
        Some(ApiKind::Responses)
    } else if url.contains("/chat/completions") {
        Some(ApiKind::ChatCompletions)
    } else {
        None
    }
}

pub fn require_known(id: &str) -> Result<&'static Profile, Error> {
    find(id).ok_or_else(|| {
        Error::new(
            ErrorKind::Config,
            format!("unknown provider '{}'; run /provider to list them", id),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_ids_are_unique_and_well_formed() {
        let mut seen = Vec::new();
        for p in all() {
            assert!(!seen.contains(&p.id), "duplicate profile {}", p.id);
            seen.push(p.id);
            assert!(!p.label.is_empty());
            if !p.base_url.is_empty() {
                assert!(p.base_url.starts_with("http"), "{}", p.id);
            }
            assert!(!p.chat_path.starts_with('/'));
        }
    }

    #[test]
    fn detection_works() {
        assert_eq!(
            detect_from_url("https://api.deepseek.com/v1").unwrap().id,
            "deepseek"
        );
        assert_eq!(
            detect_from_url("https://api.anthropic.com/v1").unwrap().id,
            "anthropic"
        );
        assert_eq!(
            detect_api("https://x/v1/messages"),
            Some(ApiKind::AnthropicMessages)
        );
        assert_eq!(
            detect_api("https://x/v1/responses"),
            Some(ApiKind::Responses)
        );
        assert!(find("nope").is_none());
    }
}
