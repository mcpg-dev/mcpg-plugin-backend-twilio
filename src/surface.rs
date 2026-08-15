//! MCP surface shaping for the backend binding.
//!
//! A binding is a tool by default; the operator may instead place it under
//! `mcp.capabilities.resources[]` / `resource_templates[]` / `prompts[]`. The
//! gateway routes those reads through the same `execute()` path but applies a
//! strict decoder: `{contents:[…]}` for `resources/read` and `{messages:[…]}`
//! for `prompts/get`. The tool surface keeps the raw op result body.

use mcpg_plugin_protocol::{ListedResource, ResourcePage};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

/// Which MCP surface a binding serves.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Surface {
    /// Tool surface — unchanged op result body.
    #[default]
    Tool,
    /// `resources/read` surface — `{contents:[{uri,text,mimeType}]}`.
    Resource,
    /// `prompts/get` surface — `{messages:[{role,content}]}`.
    Prompt,
}

impl Surface {
    #[allow(dead_code)]
    pub fn as_str(self) -> &'static str {
        match self {
            Surface::Tool => "tool",
            Surface::Resource => "resource",
            Surface::Prompt => "prompt",
        }
    }
}

/// Whether a serialized body should carry the transport `truncated` flag. Only
/// the tool surface may — the resource/prompt bodies are complete JSON the
/// gateway decodes strictly, so a truncation suffix would corrupt them.
pub fn surface_truncated(surface: Surface, payload_len: usize, cap: usize) -> bool {
    matches!(surface, Surface::Tool) && payload_len > cap
}

/// Resolve the resource URI for a `resources/read`: a static binding `uri`
/// wins, otherwise the gateway-supplied `uri` argument.
pub fn resolve_resource_uri<'a>(
    static_uri: Option<&'a str>,
    arguments: &'a Value,
) -> Option<&'a str> {
    if let Some(u) = static_uri
        && !u.trim().is_empty()
    {
        return Some(u);
    }
    arguments
        .get("uri")
        .and_then(Value::as_str)
        .filter(|u| !u.trim().is_empty())
}

/// Wrap the op result body into the `resources/read` contract body.
pub fn resource_contents_body(uri: &str, body: &Value) -> Value {
    let text = serde_json::to_string(body).unwrap_or_else(|_| "null".to_owned());
    json!({
        "contents": [
            { "uri": uri, "text": text, "mimeType": "application/json" }
        ]
    })
}

/// Wrap the op result body into the `prompts/get` contract body.
pub fn prompt_messages_body(body: &Value) -> Value {
    let text = serde_json::to_string(body).unwrap_or_else(|_| "null".to_owned());
    json!({
        "messages": [
            { "role": "user", "content": { "type": "text", "text": text } }
        ]
    })
}

/// Map a page of Twilio `Messages.json` records into a [`ResourcePage`] of
/// `twilio://message/{sid}` resources. `next_cursor` is the encoded
/// `next_page_uri`, or `None` when paging is exhausted.
pub fn messages_to_resource_page(messages: &[Value], next_cursor: Option<String>) -> ResourcePage {
    let mut resources = Vec::with_capacity(messages.len());
    for m in messages {
        let Some(sid) = m.get("sid").and_then(Value::as_str) else {
            continue;
        };
        let from = m.get("from").and_then(Value::as_str).unwrap_or("unknown");
        let preview = m
            .get("body")
            .and_then(Value::as_str)
            .map(|b| truncate_preview(b, 80));
        resources.push(ListedResource {
            uri: format!("twilio://message/{sid}"),
            name: Some(format!("SMS from {from}")),
            description: preview,
            mime_type: Some("text/plain".into()),
        });
    }
    ResourcePage {
        resources,
        next_cursor,
    }
}

/// Extract recent message SIDs (prefix-filtered) for `complete_template_variable`.
pub fn messages_to_sids(messages: &[Value], prefix: &str, max: usize) -> Vec<String> {
    messages
        .iter()
        .filter_map(|m| m.get("sid").and_then(Value::as_str))
        .filter(|sid| sid.starts_with(prefix))
        .take(max)
        .map(str::to_owned)
        .collect()
}

fn truncate_preview(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_owned()
    } else {
        let truncated: String = s.chars().take(max).collect();
        format!("{truncated}…")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn messages_map_to_resource_page() {
        let msgs = vec![
            json!({ "sid": "SM1", "from": "+1555", "body": "hello there" }),
            json!({ "sid": "SM2", "from": "+1666", "body": "second" }),
            json!({ "from": "+1777", "body": "no sid" }),
        ];
        let page = messages_to_resource_page(&msgs, Some("cursor2".into()));
        assert_eq!(page.resources.len(), 2);
        assert_eq!(page.resources[0].uri, "twilio://message/SM1");
        assert_eq!(page.resources[0].name.as_deref(), Some("SMS from +1555"));
        assert_eq!(
            page.resources[0].description.as_deref(),
            Some("hello there")
        );
        assert_eq!(page.next_cursor.as_deref(), Some("cursor2"));
    }

    #[test]
    fn sid_completion_prefix_filters() {
        let msgs = vec![
            json!({ "sid": "SMaaa" }),
            json!({ "sid": "SMabb" }),
            json!({ "sid": "CAxyz" }),
        ];
        let got = messages_to_sids(&msgs, "SMa", 10);
        assert_eq!(got, vec!["SMaaa".to_owned(), "SMabb".to_owned()]);
    }

    #[test]
    fn preview_truncates_long_bodies() {
        let long = "x".repeat(200);
        let page =
            messages_to_resource_page(&[json!({ "sid": "SM1", "from": "+1", "body": long })], None);
        let desc = page.resources[0].description.as_deref().unwrap();
        assert!(desc.ends_with('…'));
        assert!(desc.chars().count() <= 81);
    }

    #[test]
    fn resource_body_satisfies_decoder_shape() {
        let body = resource_contents_body("twilio://message/SM1", &json!({ "sid": "SM1" }));
        let contents = body["contents"].as_array().unwrap();
        assert_eq!(contents.len(), 1);
        assert_eq!(contents[0]["uri"], json!("twilio://message/SM1"));
        assert!(contents[0]["text"].is_string());
        assert_eq!(contents[0]["mimeType"], json!("application/json"));
    }

    #[test]
    fn prompt_body_satisfies_decoder_shape() {
        let body = prompt_messages_body(&json!({ "messages": [] }));
        let messages = body["messages"].as_array().unwrap();
        assert_eq!(messages[0]["role"], json!("user"));
        assert_eq!(messages[0]["content"]["type"], json!("text"));
    }

    #[test]
    fn surfaces_truncate_only_tool() {
        assert!(surface_truncated(Surface::Tool, 100, 10));
        assert!(!surface_truncated(Surface::Resource, 100, 10));
        assert!(!surface_truncated(Surface::Prompt, 100, 10));
    }

    #[test]
    fn resolve_uri_static_wins() {
        let args = json!({ "uri": "twilio://message/from-arg" });
        assert_eq!(
            resolve_resource_uri(Some("twilio://message/static"), &args),
            Some("twilio://message/static")
        );
        assert_eq!(
            resolve_resource_uri(None, &args),
            Some("twilio://message/from-arg")
        );
        assert_eq!(resolve_resource_uri(None, &json!({})), None);
    }
}
