# emerag PROVIDERS.md — LLM provider implementation spec

Research snapshot 2026-10-29 for the `emerag-llm` adapters in DESIGN.md (HTTP/1.1 only, no gzip,
hand-written `SseDecoder`, no crates). "Verified" = live curl from this host on 2026-10-29. Where a
vendor docs site was unreachable (OpenAI platform/developers answer 403 here; Anthropic docs
geo-redirect to `claude.com/app-unavailable-in-region`), shapes come from the vendor OpenAPI spec or
official SDK types — both cited in §9.

## 0. Rules common to every adapter

- `Accept-Encoding: identity` or nothing; never advertise gzip. A 200 with `Content-Encoding: gzip` is a
  hard error, do not inflate. POST with `Content-Type: application/json`; send `Accept: text/event-stream`.
- SSE framing: split on a blank line (LF or CRLF), strip one space after `data:`, drop `:` comment lines
  (keep-alives), join multiple `data:` lines with LF, ignore `event:` / `id:` / `retry:` unless the adapter
  needs them. `[DONE]` terminates OpenAI Chat Completions and DeepSeek only; Responses/Anthropic never send it.
- Per-read timeout >=120s reset on every byte, never a whole-request deadline: prompt processing can
  be silent for a minute. Error bodies are not uniformly JSON (DeepSeek 401 is `text/plain`): keep the
  raw prefix, then try `error.message`. Redact `Authorization`/`x-api-key` in verbose logs.
- Never replay `reasoning_content` or thinking blocks unless the provider demands it (§4 does, when
  tools are present). Strip provider-specific fields when switching `ApiKind`.

## 1. OpenAI Chat Completions

- base_url `https://api.openai.com/v1`, endpoint `POST {base}/chat/completions`.
- auth `Authorization: Bearer <OPENAI_API_KEY>`. Org/project headers are optional extras.
- models `GET {base}/models` →
  `{"object":"list","data":[{"id","object":"model","created","owned_by","shutdown_date"?}]}`
  (`shutdown_date` is new in 2026; ignore unknown keys).
- Stream: `data:` chunks, `[DONE]` terminator.
```
data: {"id":"chatcmpl-1","object":"chat.completion.chunk","created":1,"model":"m",
       "choices":[{"index":0,"delta":{"role":"assistant","content":"He"},"finish_reason":null}]}
data: {"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"call_1","type":"function",
       "function":{"name":"read","arguments":"{\"pa"}}]},"finish_reason":null}]}
data: {"choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}
data: {"choices":[],"usage":{"prompt_tokens":10,"completion_tokens":5,"total_tokens":15}}
data: [DONE]
```
- `delta.content` may be null; `delta.refusal` may carry a refusal string; `delta.obfuscation` may appear
  (random padding) — ignore unknown delta keys. Tool calls are deltas keyed by `index`: the first carries
  `id` and `function.name`, later ones append `function.arguments`; concatenate per index, parse JSON
  only after `finish_reason`.
- Usage is null unless `stream_options.include_usage:true`; with it OpenAI sends a final chunk with an
  **empty** `choices` array plus `usage`, so tolerate `choices.len()==0` and never index `choices[0]`.
- `max_tokens` is deprecated for `max_completion_tokens` and incompatible with o-series. Rule: OpenAI
  profile → `max_completion_tokens`; every other OpenAI-compatible server → `max_tokens` (§6).
  Reasoning: Chat Completions returns no reasoning text, only
  `usage.completion_tokens_details.reasoning_tokens`; reasoning text needs Responses (§2).
  `reasoning_effort` is accepted on both.
```json
{"model":"gpt-6-sol","messages":[{"role":"system","content":"You are emerag."},
 {"role":"user","content":"list /tmp"}],
 "tools":[{"type":"function","function":{"name":"list","description":"List a directory",
   "parameters":{"type":"object","properties":{"path":{"type":"string"}},"required":["path"]}}}],
 "tool_choice":"auto","parallel_tool_calls":true,
 "max_completion_tokens":2048,"stream":true,"stream_options":{"include_usage":true}}
```
Quirks: `n>1` multiplies choices (send `n:1` or omit); `store` defaults false for chat, leave it; the
system role may also be `developer`; `finish_reason:"content_filter"` must map to a filtered stop, not
success; tool-call `arguments` is a JSON string, never an object.

## 2. OpenAI Responses API

- base_url `https://api.openai.com/v1`, endpoint `POST {base}/responses`; auth and model listing as §1.
- Fields that matter: `model`, `input` (string or item array), `instructions`, `tools`, `tool_choice`,
  `max_output_tokens` (min 16), `stream`, `store` (default **true**), `previous_response_id`,
  `include`, `reasoning:{"effort","summary"}`, `text:{"format"}`.
- Tools are flat, no `function` wrapper:
  `{"type":"function","name":"list","description":"...","parameters":{...},"strict":false}`
  (`strict` is schema-required, `parameters` may be null).
- Items: `{"id":"fc_...","type":"function_call","call_id":"call_...","name":"list",
  "arguments":"{\"path\":\"/tmp\"}","status":"completed"}` and
  `{"type":"message","role":"assistant","content":[{"type":"output_text","text":"..."}]}`.
- Stream: SSE where the type is the JSON `type` field (OpenAI also sets `event:`). No `[DONE]`; the
  stream ends at a terminal event.

| event | payload |
|---|---|
| `response.created` / `.in_progress` | `response.id` (keep for `previous_response_id`) |
| `response.output_item.*`, `response.content_part.*` | `item`, `part` |
| `response.output_text.delta` / `.done` | `delta` then full `text`; `item_id`, `output_index` |
| `response.reasoning_summary_text.*` / `reasoning_text.*` | o-series summary / raw CoT |
| `response.function_call_arguments.delta` / `.done` | `delta` fragments, then `arguments` |
| `response.completed` / `.incomplete` / `.failed` | full `response` (usage; truncation; error) |
| `error` | `{"type":"error","code","message","param","sequence_number"}` |

  Every event has `sequence_number`; gaps are not errors. Unknown `type` must be ignored — the union
  keeps growing (`response.mcp_call.*`, `response.shell_call.*`, `response.compaction.*`, ...).
- Continuing a conversation, two ways: (a) `previous_response_id` plus only the new input, requires
  `store:true`, and `instructions` is *not* inherited so resend it; (b) stateless replay of the whole `input`
  array, appending previous output items and tool results as
  `{"type":"function_call_output","call_id":"call_...","output":"..."}` — for reasoning models also request
  `include:["reasoning.encrypted_content"]` and replay the `reasoning` items. emerag should default to (b)
  with `store:false`: no vendor retention, and it works on gateways without `previous_response_id`.
```json
{"model":"gpt-6-sol","instructions":"You are emerag.","input":"list /tmp","store":false,
 "tools":[{"type":"function","name":"list","description":"List a directory","strict":false,
   "parameters":{"type":"object","properties":{"path":{"type":"string"}},"required":["path"]}}],
 "max_output_tokens":2048,"stream":true}
```
Quirks: set `store` explicitly; `max_output_tokens` min 16 (a 1-token key check is rejected); `input`
items may use `role:"system"` but `instructions` is portable; text and function-call deltas
interleave, dispatch by `item_id` not arrival order; pre-flight counting at
`POST {base}/responses/input_tokens`.

## 3. Anthropic Messages API

- base_url `https://api.anthropic.com`, endpoint `POST {base}/v1/messages`.
- Headers, current per both official SDKs: `authorization: Bearer <ANTHROPIC_API_KEY>` (the SDK
  documents the key as "sent as `Authorization: Bearer <key>`"); `anthropic-version: 2026-10-21` (both
  SDKs pin it — the historical `2023-06-01` is no longer sent); `x-api-key` is the legacy form, still
  accepted by the SDKs as an alternative header, but server-side acceptance of `x-api-key` alone is
  unverified here (api.anthropic.com answers 403 "Request not allowed" for region reasons) — send
  Bearer, optionally plus `x-api-key`; `anthropic-beta` only for beta features, not for these paths.
- Request: `model`, `max_tokens` (**required**), `messages` (roles `user`/`assistant` only), `system`
  (top-level string or text blocks), `tools`, `tool_choice`, `stream`, `thinking`, `stop_sequences`,
  `metadata`.
- Tools: `{"name","description","input_schema":{...},"strict"?}` — no `type` wrapper;
  `input_schema.type` must be `"object"`.
- Tool round trip: assistant content has `{"type":"tool_use","id":"toolu_...","name":"list",
  "input":{...}}`; the next user message has
  `{"type":"tool_result","tool_use_id":"toolu_...","content":"...","is_error":false}`. No `tool` role.
- Thinking: `{"type":"enabled","budget_tokens":N,"display":"summarized"|"omitted"}`,
  `{"type":"adaptive"}`, `{"type":"disabled"}`, `{"type":"between_tools"}`. History may contain
  `{"type":"thinking","thinking":"...","signature":"..."}` and `{"type":"redacted_thinking",
  "data":"..."}`; replay both verbatim.
```
event: message_start       data: {"type":"message_start","message":{"id":"msg_1","role":"assistant",
                           "content":[],"usage":{"input_tokens":12,"output_tokens":1,
                           "cache_read_input_tokens":0,"cache_creation_input_tokens":0}}}
event: content_block_start data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}
event: content_block_delta data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Hi"}}
event: content_block_delta data: {"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"{\"pa"}}
event: content_block_delta data: {"type":"content_block_delta","index":2,"delta":{"type":"thinking_delta","thinking":"..."}}
event: content_block_delta data: {"type":"content_block_delta","index":2,"delta":{"type":"signature_delta","signature":"EqQ..."}}
event: content_block_stop  data: {"type":"content_block_stop","index":0}
event: message_delta      data: {"type":"message_delta","delta":{"stop_reason":"tool_use","stop_sequence":null},"usage":{"output_tokens":42}}
event: message_stop       data: {"type":"message_stop"}
event: ping               data: {"type":"ping"}
event: error              data: {"type":"error","error":{"type":"overloaded_error","message":"..."}}
```
- `content_block_start` carries the block type; `input_json_delta.partial_json` fragments concatenate
  per `index` and parse at `content_block_stop`. `message_delta.usage` is cumulative
  (`output_tokens` final; `input_tokens` may be null there, take input counts from `message_start`).
  `ping` is normal; `error` can arrive mid-stream and the socket then closes.
- `stop_reason` ∈ `end_turn`, `max_tokens`, `stop_sequence`, `tool_use`, `pause_turn`, `refusal`,
  `model_context_window_exceeded`; `pause_turn` means "resend to continue a server-tool loop" (retry once).
- Models: `GET {base}/v1/models?limit=100&after_id=&before_id=` (no beta header) → `{"data":[{"id":
  "claude-opus-5-5","type":"model","display_name":"...","created_at":"...","max_input_tokens":N,
  "max_tokens":N,"capabilities":{...},"lifecycle":"active"}],"has_more":false,"first_id":"...",
  "last_id":"..."}`. Current ids: `claude-opus-5-5`, `claude-sonnet-5-5`, `claude-haiku-5-5`,
  `claude-fable-5-1`, `claude-opus-5`, `claude-sonnet-4-5`, `claude-haiku-4-5`. Counting:
  `POST {base}/v1/messages/count_tokens` → `{"input_tokens":N}` (free).
```json
{"model":"claude-sonnet-5-5","max_tokens":2048,"system":"You are emerag.",
 "messages":[{"role":"user","content":"list /tmp"}],
 "tools":[{"name":"list","description":"List a directory",
   "input_schema":{"type":"object","properties":{"path":{"type":"string"}},"required":["path"]}}],
 "stream":true}
```
Quirks: missing `max_tokens` is a 400; `system` is not a message role (a `system` message in
`messages` is a 400); empty content arrays and empty text blocks are rejected; roles must alternate
after normalization (merge consecutive same-role turns); `temperature` and `top_p` cannot both be set;
large tool output belongs in blocks, not stringified JSON.

## 4. DeepSeek

- base_url OpenAI format `https://api.deepseek.com` — both `/chat/completions` and
  `/v1/chat/completions` answer (`/v1` is an alias; verified: `/models` and `/v1/models` both return
  401 unauthenticated, so both routes exist). Anthropic format `https://api.deepseek.com/anthropic`;
  Responses `https://api.deepseek.com/responses`; beta/FIM `https://api.deepseek.com/beta`.
- auth `Authorization: Bearer <DEEPSEEK_API_KEY>`. The shape is OpenAI-compatible, so
  `ApiKind::ChatCompletions` plus a base_url override is enough.
- models: `deepseek-flash` (served by DeepSeek-V4.1-Flash-1017) and `deepseek-v4-pro`. Legacy ids
  `deepseek-v4-flash` and `deepseek-v4-flash-vision-exp` are still accepted and billed as Flash. The
  2025 names `deepseek-chat` / `deepseek-reasoner` (used in DESIGN.md) are no longer documented —
  treat them as stale, not supported.
- models list `GET {base}/models` → OpenAI list shape plus `name`, `context_window`,
  `max_output_tokens`, `input_modalities`, `output_modalities`, `effort.supported_levels`,
  `api_capabilities.anthropic_messages.system_prompt_update`. Verified: `context_window 1048576`,
  `max_output_tokens 393216`.
- Thinking: on by default at effort `high`. Toggle `{"thinking":{"type":"enabled"|"disabled"}}`; effort
  `reasoning_effort` ∈ `none|low|high|max` (`minimal`→`low`, `medium`/`xhigh`→`high`). In thinking mode
  `temperature`, `top_p` and the penalties are ignored without error.
- Reasoning output: `message.reasoning_content` and, streaming, `choices[0].delta.reasoning_content`
  (sibling of `content`). If the request carries `tools`, every previous assistant turn
  `reasoning_content` must be sent back or the API returns 400; without `tools` it is ignored.
- Stream: `data:` only (no `event:` lines), terminated by `data: [DONE]`. Unlike OpenAI there is **no
  separate usage-only chunk**: the last chunk before `[DONE]` carries `usage` and one choice with no
  new content and a non-null `finish_reason`; `include_usage` only nulls the earlier chunks.
- usage: `prompt_tokens`, `completion_tokens`, `total_tokens`, `prompt_cache_hit_tokens`,
  `prompt_cache_miss_tokens`, `prompt_tokens_details.cached_tokens`,
  `completion_tokens_details.reasoning_tokens`.
- FIM (beta): `POST https://api.deepseek.com/beta/completions` with `{"model":"deepseek-flash",
  "prompt":"def fib(a):","suffix":"...","max_tokens":128}`, `max_tokens` capped at 4096, result at
  `choices[0].text`. Chat prefix completion is `POST /beta/chat/completions` with
  `messages[last].prefix:true`.
- Responses API is stateless: `store` always false, `previous_response_id` always null; multi-turn
  needs the full `input` array.
- Errors: 401 is `text/plain` `Authentication Fails (governor)` (verified, not JSON); others are
  `{"error":{"message","type","code"}}`.
```sh
curl -N https://api.deepseek.com/chat/completions \
  -H "Authorization: Bearer $DEEPSEEK_API_KEY" -H "Content-Type: application/json" \
  -d '{"model":"deepseek-flash","stream":true,"max_tokens":256,
       "thinking":{"type":"enabled"},"reasoning_effort":"high",
       "messages":[{"role":"user","content":"Say hi"}]}'
```
Quirks: `tool_choice:"required"` and named tool choice return 400 in thinking mode (disable thinking
or use `auto`); `max_tokens` defaults to 8K non-thinking, 64K thinking, 128K at `max`;
`frequency_penalty`/`presence_penalty` are accepted and silently ignored; `finish_reason` may be
`insufficient_system_resource` or `aborted` (retryable); the isolation field is `user_id`, not `user`.

### 4.1 DeepSeek account (OAuth, no API key)

Profile id `deepseek-account`. Use this when the user has a DeepSeek account
rather than a platform API key.

- Login is the Desktop Harness browser flow, verified live:
  `POST https://platform.deepseek.com/auth-api/v0/dsh/auth_init` with
  `{code_challenge, code_challenge_method:"S256", state, redirect_uri,
  locale, login_source}` returns
  `{code:0,data:{biz_code:0,biz_data:{authorize_url,authorize_id,expires_in}}}`.
  The browser approves at `/dsh/authorize`, redirects to the loopback
  `redirect_uri` with `code` and `state`, and
  `POST .../dsh/auth_exchange` (with `code_verifier`, `device_id`,
  `device_model`, `os_version`) returns `biz_data.token` plus an optional user.
- Auth header is `x-dsh-auth-token: <token>`. There is no `Authorization`
  header. The grant has no expiry or refresh flow; `/logout` removes it locally
  and best-effort calls `/auth-api/v0/users/logout`.
- Models: `GET https://api.deepseek.com/models` with the same header. Model ids
  come from `data[].id`; do not hardcode them. A wrong grant returns HTTP 401
  JSON `{"error":{"message":"Authentication Fails (invalid dsh token)",
  "type":"authentication_error"}}` (verified).
- Inference: `POST https://api.deepseek.com/chat/completions` with
  `x-dsh-auth-token`. The OpenAI-compatible route is used because
  `reasoning_content` is then replayed on assistant turns; DeepSeek requires
  that replay when tools are present. The account grant is accepted on this
  route (the invalid-token error proves the header is read there).
- Client headers used for login: `x-client-platform: web`, `x-client-version`,
  `x-client-locale: en_US`, `x-client-timezone-offset`, empty
  `x-client-bundle-id`.
- On Termux/Android, the browser can be on the same phone: open the printed
  URL and the callback reaches `127.0.0.1` inside Termux.

## 5. OpenCode Console (formerly "Zen") and OpenCode Go

Console is a paid pay-as-you-go model gateway run by the OpenCode project (curated GPT, Claude,
Gemini, Kimi, GLM, DeepSeek, Qwen, Grok, MiniMax, Mistral models behind one API key). OpenCode Go /
Go Plus / Go Teams is a subscription (Go from $5/member/month, Go Teams $20/member) with monthly
per-model allowances. Both are the same gateway at different base URLs, and both are
OpenAI/Anthropic/Gemini-compatible front doors that translate to the model native API. The old
`https://opencode.ai/zen/v1` in DESIGN.md is gone; `/docs/zen/` redirects to `/v2/docs/console/models/`.

- base_url pay-as-you-go `https://opencode.ai/inference` (verified); Go
  `https://opencode.ai/inference/go` (verified; the Go model list answers at
  `/inference/go/v1/models`, while `/inference/go/openai/v1/models` is 404).
- Paths: `/openai/v1/chat/completions`, `/openai/v1/responses`, `/anthropic/v1/messages`,
  `/google/v1beta/models/<model>:generateContent`, `/systemone/v1/systemone` (Jev).
- auth `Authorization: Bearer <token>`. Tokens are Console API keys shaped `oc_sk_1a2b3c4d5e6f_...`, created
  in the Console UI (personal key, or service-account key for shared machines/CI). **No OAuth device flow
  for inference** — the key is pasted; OAuth with dynamic client registration exists only for the Console
  MCP server (`https://opencode.ai/console/mcp`), which manages a workspace, not inference. A key is
  required for paid models; free-tier chat models reject non-OpenCode clients with 403 even with a key.
- Go requires a stable per-conversation `x-opencode-session: ses_...` (verified: omitting it returns
  `400 {"type":"error","error":{"type":"MissingSessionID",...}}` **before** the auth check) and a
  non-generic `User-Agent` naming the client (e.g. `emerag/0.1`), not an SDK or HTTP-library name.
- Models: `GET https://opencode.ai/inference/v1/models` (unauthenticated, verified 200) and
  `GET https://opencode.ai/inference/go/v1/models`. Plain OpenAI shape, no metadata: `{"object":"list",
  "data":[{"id":"kimi-k3","object":"model","created":1793287781,"owned_by":"opencode"}]}`. The
  model→API-family mapping exists only in the docs table, so use the profile family and on 404 fall back
  to `/openai/v1/chat/completions` (the gateway translates every text model onto every family).
- Streaming uses the §1/§2/§3 formats for the matching family. Every response also carries cost telemetry
  on the final usage object: `"usage":{"prompt_tokens":1200,"completion_tokens":300,"cost":0.00412,
  "opencode":{"billing_source":"balance","list_cost":0.00412,"tokens":{"input":1200,"output":300,
  "reasoning":120,"cache_read":8000,"cache_write_5m":0,"cache_write_1h":0}}}`. `billing_source` ∈
  `free|balance|go|go-plus|byok`; `opencode.allowance` (Go) is the dollars of plan allowance consumed.
- Errors: `{"type":"error","error":{"type":"AuthError","message":"Missing API key."}}` with 401
  (verified) — note the outer `type` wrapper, unlike OpenAI `{"error":{...}}`.
- CLI login: `/connect` in the TUI or `opencode auth login [integration]`; pick "OpenCode Console" or
  "OpenCode Go", choose the `key` method, paste the key. Stored in the CLI credential store (`opencode auth
  list`); the provider also reads `OPENCODE_API_KEY`. The picker ranks `opencode-go` above `opencode`.
```
POST https://opencode.ai/inference/openai/v1/chat/completions
Authorization: Bearer oc_sk_...
{"model":"kimi-k3","messages":[{"role":"user","content":"Say hi"}],
 "max_tokens":256,"stream":true,"stream_options":{"include_usage":true}}
POST https://opencode.ai/inference/go/anthropic/v1/messages
Authorization: Bearer oc_sk_...
x-opencode-session: ses_7f3c...
User-Agent: emerag/0.1
{"model":"claude-sonnet-5-5","max_tokens":1024,"stream":true,
 "messages":[{"role":"user","content":"Say hi"}]}
```
Quirks: free models are unusable outside OpenCode (403) so never make one a catalog default; Go
meters allowance dollars, not tokens, so display both; the session header must be stable per
conversation or routing/caching degrade (and Go 400s); a wrong-family path is a 404, not a redirect;
some models are region/privacy gated so a 403 can be policy rather than auth; `created` in
`/v1/models` is a constant, do not sort by it.

## 6. Generic OpenAI-compatible local servers

| server | base_url | auth | models list |
|---|---|---|---|
| ollama | `http://127.0.0.1:11434/v1` | none (key accepted, ignored) | `GET /v1/models`, native `GET /api/tags` |
| llama.cpp | `http://127.0.0.1:9931/v1` | none unless `--api-key` (then Bearer) | `GET /v1/models` (one entry) |
| LM Studio | `http://127.0.0.1:1234/v1` | none by default | `GET /v1/models` |

- ollama: `POST /v1/chat/completions` (OpenAI subset); native `POST /api/chat` streams **NDJSON** (one
  object per line, no `data:` prefix) and needs a separate decoder. Also serves `/v1/responses` and an
  Anthropic-compatible `/v1/messages`. Cloud `https://ollama.com/v1` with
  `Authorization: Bearer $OLLAMA_API_KEY`; the local server ignores the key value but many clients
  insist on one (`api_key="sk-no-key"`).
- llama.cpp: default port is **9931**, not 8080 (8080 appears only in Docker examples such as
  `-p 8080:8080`). `/v1/models` returns one object whose `id` is the model path unless `--alias` was given,
  plus non-standard `architecture` (`input_modalities`, `output_modalities`) and `meta` (`n_ctx_train`,
  `n_params`, ...); `meta` may be null while loading. `GET /health` is public. Extra body params:
  `chat_template_kwargs`, `reasoning_format`, `reasoning_effort` (`none` disables thinking).
- Shared quirks: `max_tokens` (never `max_completion_tokens`) is the portable field; `usage` is often absent
  or zero, so never fail a turn for missing usage; `tools` support depends on the model chat template, so a
  400 on `tools` must degrade to a prompt-based tool protocol rather than abort; ids can contain `/`, `:`,
  `.gguf` and must be JSON-escaped, not URL-quoted into the path; there is no auth failure to detect, so
  "is it up" is a 2s TCP connect test.

## 7. Embedded provider catalog — data model

Static data compiled in as a const table: `&'static str` throughout, slices for model defaults and
pricing.
```rust
pub enum AuthKind { Bearer, XApiKey, OAuthDevice, None, CustomHeader }

pub struct AuthSpec {
    pub kind: AuthKind,
    pub env: &'static str,        // "OPENAI_API_KEY"
    pub header: &'static str,     // "authorization" | "x-api-key" | custom
    pub scheme: &'static str,     // "Bearer " or "" for a raw key
    pub extra_headers: &'static [(&'static str, &'static str)], // anthropic-version, ...
    pub beta_header: Option<&'static str>,   // anthropic-beta value, if any
    pub device_flow: Option<DeviceFlowSpec>, // RFC 8628; reserved, unused today
}
pub struct DeviceFlowSpec { // RFC 8628 fields: device_code_url, token_url, client_id, scope,
    pub device_code_url: &'static str, pub token_url: &'static str, pub client_id: &'static str,
    pub scope: &'static str, pub grant_type: &'static str, // grant_type
}
pub struct ProviderProfile {
    pub id: &'static str, pub label: &'static str, pub base_url: &'static str,
    pub api: ApiKind, pub auth: AuthSpec,
    pub models_path: &'static str, // "/models" | "/v1/models"
    pub chat_path: &'static str,   // "/chat/completions" | "/responses" | "/v1/messages"
    pub token_field: TokenField,   // MaxTokens | MaxCompletionTokens | MaxOutputTokens |
                                   // MaxTokensRequired
    pub usage_style: UsageStyle,   // None | IncludeUsage | LastChunk | FinalEvent
    pub reasoning: ReasoningStyle, // None | DeltaField("reasoning_content") |
                                   // AnthropicThinking | ResponsesSummary | UsageOnly
    pub default_models: &'static [&'static str],
    pub context_default: Option<u32>, pub max_out_default: Option<u32>,
    pub requires_session_header: bool, pub free_models_restricted: bool,
    pub pricing: &'static [PriceRow], pub quirks: &'static [&'static str],
}
pub struct PriceRow { // per 1M tokens, USD
    pub model: &'static str, pub input: f32, pub output: f32,
    pub cache_read: Option<f32>, pub cache_write: Option<f32>,
    pub long_context_over: Option<u32>, pub long_context_multiplier: Option<f32>,
}
```
Rows: openai (ChatCompletions, `max_completion_tokens`, `include_usage`), openai-responses (Responses,
`store:false`), anthropic (AnthropicMessages, `max_tokens` required, `anthropic-version: 2026-10-21`),
deepseek (`https://api.deepseek.com`, `max_tokens`, usage on the last chunk, `reasoning_content`),
opencode (`https://opencode.ai/inference`), opencode-go (`https://opencode.ai/inference/go`, session
header on), ollama, llamacpp, lmstudio, custom (user base_url + ApiKind + AuthKind).

One normalized usage struct, filled by every adapter, drives cost display:
```rust
pub struct Usage { pub input: u32, pub output: u32, pub reasoning: Option<u32>,
                   pub cache_read: Option<u32>, pub cache_write: Option<u32>,
                   pub total: Option<u32>, pub cost_usd: Option<f64>,
                   pub billing_source: Option<&'static str> }
```
Mapping: OpenAI chat `prompt_tokens`/`completion_tokens`/`completion_tokens_details.reasoning_tokens`/
`prompt_tokens_details.cached_tokens`; Responses `input_tokens`/`output_tokens`/
`output_tokens_details.reasoning_tokens`/`input_tokens_details.cached_tokens`/`cache_write_tokens`;
Anthropic `input_tokens` + `cache_read_input_tokens` + `cache_creation_input_tokens` (total input is
the sum of all three) and `output_tokens`; DeepSeek `prompt_tokens`/`completion_tokens`/
`prompt_cache_hit_tokens`/`completion_tokens_details.reasoning_tokens`; OpenCode adds `usage.cost` and
`usage.opencode.*` (use `cost` verbatim when present, else compute from `PriceRow`).

Reasoning fields feeding `StreamEvent::Reasoning`: DeepSeek → `delta.reasoning_content`; OpenAI o-series
on Responses → `response.reasoning_summary_text.delta` (and `reasoning_text.delta` where exposed); OpenAI
on Chat Completions → nothing, only `reasoning_tokens`; Anthropic → `thinking_delta.thinking` plus a
`signature_delta` to preserve and replay; local servers → `delta.reasoning_content` when the template
emits it, else server-side extraction (llama.cpp `reasoning_format`).

## 8. Corrections to DESIGN.md

1. `opencode-zen` `https://opencode.ai/zen/v1` → `https://opencode.ai/inference` (+ `/inference/go`); Zen is
   now called Console.
2. DeepSeek `deepseek-chat`/`deepseek-reasoner` → `deepseek-flash`/`deepseek-v4-pro`; the same host
   also serves Anthropic format at `/anthropic` and Responses at `/responses`.
3. llama.cpp default port 8080 → 9931.
4. Anthropic `x-api-key` → `Authorization: Bearer` plus `anthropic-version: 2026-10-21`.
5. `ProviderProfile` needs `token_field`, `usage_style`, `reasoning`, `requires_session_header`: the three
   APIs disagree on all four.

## 9. Sources

OpenAI — OpenAPI spec v2.3.0 (chunk, delta, Responses event and model shapes):
https://raw.githubusercontent.com/openai/openai-openapi/master/openapi.yaml . Docs (403 here, cited
for readers): https://platform.openai.com/docs/api-reference/chat ,
https://platform.openai.com/docs/api-reference/responses ,
https://developers.openai.com/api/docs/guides/streaming-responses

Anthropic — event shapes, `anthropic-version`, auth header, thinking config, model ids, ModelInfo from
https://github.com/anthropics/anthropic-sdk-typescript (`src/resources/messages/messages.ts`,
`src/resources/models.ts`, `src/client.ts`), cross-checked with
https://github.com/anthropics/anthropic-sdk-python (`src/anthropic/_constants.py`). Docs:
https://platform.claude.com/docs/en/api/messages , https://platform.claude.com/docs/en/api/messages-streaming

DeepSeek — https://api-docs.deepseek.com/ , https://api-docs.deepseek.com/api/create-chat-completion ,
https://api-docs.deepseek.com/api/list-models , https://api-docs.deepseek.com/guides/thinking_mode ,
https://api-docs.deepseek.com/guides/fim_completion , https://api-docs.deepseek.com/guides/responses_api

OpenCode — https://opencode.ai/v2/docs/console/models/ , https://opencode.ai/v2/docs/console/api/inference/ ,
https://opencode.ai/v2/docs/console/harnesses/ (base URLs, session header, key format),
https://opencode.ai/v2/docs/console/go/ (plans, limits, validated clients),
https://github.com/anomalyco/opencode (`packages/ai/src/providers/opencode.ts`,
`packages/cli/src/commands/handlers/auth/`). Live: `GET https://opencode.ai/inference/v1/models`,
`GET https://opencode.ai/inference/go/v1/models`.

Local servers — https://docs.ollama.com/api/openai-compatibility , https://docs.ollama.com/api/authentication ,
https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md ,
https://lmstudio.ai/docs/app/api/endpoints/openai
