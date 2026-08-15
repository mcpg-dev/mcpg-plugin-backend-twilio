//! Configuration for the backend + webhook entities.
//!
//! - [`TwilioConfig`] is the per-binding backend spec (the `backend:` block on
//!   a tool binding). It carries the `operation` discriminator plus REST auth.
//! - [`TwilioWebhookConfig`] is the `http_route` entity's plugin-level config
//!   (the webhook receiver: signing token, public base URL, inbound control).
//!
//! The `watch_strategy` entity (kind `twilio_inbound`) takes no plugin-level
//! config; its only knob is an optional per-watch `kinds` filter parsed in
//! `watch.rs` from the resource's `strategy` spec.
//!
//! Secrets (`auth_token`, `api_key_secret`) arrive already resolved — the
//! gateway substitutes `${cred://…}` at config load. A bare `cred://` left in
//! an operator-fixed or request-supplied string is rejected (it would be sent
//! upstream verbatim, leaking nothing but signalling a misconfiguration).

use serde::Deserialize;

use crate::surface::Surface;
use crate::twiml::TwimlVerb;

/// The Twilio REST operation a binding performs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Operation {
    SendSms,
    ListMessages,
    GetMessage,
    RedactMessage,
    DeleteMessage,
    MakeCall,
    ListCalls,
    GetCall,
    ModifyCall,
    GetRecording,
    /// Phone-number validation / carrier / caller-name via the Lookups v2 API.
    Lookup,
    /// Start an OTP verification via the Verify v2 API.
    VerifyStart,
    /// Check an OTP verification via the Verify v2 API.
    VerifyCheck,
    /// Local — render TwiML from verbs (no REST call).
    BuildTwiml,
    /// Local → state — stage a TwiML reply the inbound-voice webhook serves.
    StageCallResponse,
    /// Mutates Twilio account state — opt-in, capability-gated.
    ConfigureNumberWebhooks,
}

impl Operation {
    pub fn as_str(self) -> &'static str {
        match self {
            Operation::SendSms => "send_sms",
            Operation::ListMessages => "list_messages",
            Operation::GetMessage => "get_message",
            Operation::RedactMessage => "redact_message",
            Operation::DeleteMessage => "delete_message",
            Operation::MakeCall => "make_call",
            Operation::ListCalls => "list_calls",
            Operation::GetCall => "get_call",
            Operation::ModifyCall => "modify_call",
            Operation::GetRecording => "get_recording",
            Operation::Lookup => "lookup",
            Operation::VerifyStart => "verify_start",
            Operation::VerifyCheck => "verify_check",
            Operation::BuildTwiml => "build_twiml",
            Operation::StageCallResponse => "stage_call_response",
            Operation::ConfigureNumberWebhooks => "configure_number_webhooks",
        }
    }

    /// Whether the op talks to the Twilio REST API (vs purely local/state).
    pub fn needs_rest(self) -> bool {
        !matches!(self, Operation::BuildTwiml | Operation::StageCallResponse)
    }
}

/// REST auth shape: either an API Key (sid + secret) or the Account Auth Token
/// used directly as the HTTP Basic password.
#[derive(Debug, Clone)]
pub enum RestAuth {
    /// `Authorization: Basic base64(api_key_sid:api_key_secret)`.
    ApiKey { sid: String, secret: String },
    /// `Authorization: Basic base64(account_sid:auth_token)`.
    AuthToken { token: String },
}

/// Per-binding backend config.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename = "twilio", deny_unknown_fields)]
pub struct TwilioConfig {
    /// Twilio Account SID (`AC…`). Embedded in the REST URL.
    pub account_sid: String,

    /// API Key SID (`SK…`) — recommended REST credential. Pair with
    /// `api_key_secret`.
    #[serde(default)]
    pub api_key_sid: Option<String>,
    /// API Key secret (resolved from `${cred://…}`).
    #[serde(default)]
    pub api_key_secret: Option<String>,
    /// Account Auth Token (resolved from `${cred://…}`). Used as the REST
    /// password when no API Key is configured.
    #[serde(default)]
    pub auth_token: Option<String>,

    /// The operation this binding performs.
    pub operation: Operation,

    /// Default `From` number / messaging service for send_sms / make_call.
    #[serde(default)]
    pub from: Option<String>,
    #[serde(default)]
    pub messaging_service_sid: Option<String>,

    /// Which MCP surface the binding serves (tool / resource / prompt).
    #[serde(default)]
    pub surface: Surface,
    /// Static resource URI for the resource surface (optional).
    #[serde(default)]
    pub uri: Option<String>,

    /// Twilio REST base. Overridden only for testing (wiremock); production
    /// leaves the default.
    #[serde(default = "default_api_base")]
    pub api_base: String,

    /// Verify v2 Service SID (`VA…`) for `verify_start` / `verify_check`. It is
    /// a public service identifier, not a secret, but is rejected if it carries
    /// a bare `cred://` (config-convention consistency).
    #[serde(default)]
    pub verify_service_sid: Option<String>,

    /// Lookups v2 API base. Overridden only for testing; production leaves the
    /// default (`https://lookups.twilio.com`).
    #[serde(default = "default_lookups_base")]
    pub lookups_base: String,

    /// Verify v2 API base. Overridden only for testing; production leaves the
    /// default (`https://verify.twilio.com`).
    #[serde(default = "default_verify_base")]
    pub verify_base: String,

    /// Per-call timeout in milliseconds.
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,

    /// Max bytes of a REST response retained (cap for tool output).
    #[serde(default = "default_max_response_bytes")]
    pub max_response_bytes: usize,

    /// Default page size for list_* operations.
    #[serde(default = "default_page_size")]
    pub page_size: u32,
}

fn default_api_base() -> String {
    "https://api.twilio.com".to_owned()
}
fn default_lookups_base() -> String {
    "https://lookups.twilio.com".to_owned()
}
fn default_verify_base() -> String {
    "https://verify.twilio.com".to_owned()
}
fn default_timeout_ms() -> u64 {
    15_000
}
fn default_max_response_bytes() -> usize {
    256 * 1024
}
fn default_page_size() -> u32 {
    50
}

impl TwilioConfig {
    /// Parse + validate a binding spec.
    pub fn parse(spec: &serde_json::Value) -> Result<Self, String> {
        let cfg: TwilioConfig = serde_json::from_value(spec.clone())
            .map_err(|e| format!("invalid twilio spec: {e}"))?;
        cfg.validate()?;
        Ok(cfg)
    }

    fn validate(&self) -> Result<(), String> {
        if self.account_sid.trim().is_empty() {
            return Err("account_sid is required".into());
        }
        reject_bare_cred("account_sid", &self.account_sid)?;
        if let Some(f) = &self.from {
            reject_bare_cred("from", f)?;
        }
        // REST ops need credentials; local ops do not.
        if self.operation.needs_rest() && self.rest_auth().is_none() {
            return Err(
                "REST operations require either api_key_sid+api_key_secret or auth_token".into(),
            );
        }
        if matches!(self.operation, Operation::SendSms)
            && self.from.is_none()
            && self.messaging_service_sid.is_none()
        {
            return Err("send_sms requires a `from` number or `messaging_service_sid`".into());
        }
        if let Some(sid) = &self.verify_service_sid {
            reject_bare_cred("verify_service_sid", sid)?;
        }
        if matches!(
            self.operation,
            Operation::VerifyStart | Operation::VerifyCheck
        ) && self
            .verify_service_sid
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .is_none()
        {
            return Err(format!(
                "{} requires a `verify_service_sid` (VA…)",
                self.operation.as_str()
            ));
        }
        if self.timeout_ms == 0 {
            return Err("timeout_ms must be > 0".into());
        }
        Ok(())
    }

    /// Resolve the REST auth shape: API Key wins; else the Auth Token.
    pub fn rest_auth(&self) -> Option<RestAuth> {
        match (&self.api_key_sid, &self.api_key_secret) {
            (Some(sid), Some(secret)) if !sid.is_empty() && !secret.is_empty() => {
                Some(RestAuth::ApiKey {
                    sid: sid.clone(),
                    secret: secret.clone(),
                })
            }
            _ => self
                .auth_token
                .as_ref()
                .filter(|t| !t.is_empty())
                .map(|t| RestAuth::AuthToken { token: t.clone() }),
        }
    }
}

/// Reject a bare `cred://` URI in an operator-fixed or request-supplied string.
/// Secrets reach the plugin through `${cred://…}` resolved at config load; a
/// bare `cred://` would be forwarded to Twilio verbatim, which is always a
/// misconfiguration.
pub fn reject_bare_cred(field: &str, value: &str) -> Result<(), String> {
    if value.contains("cred://") {
        return Err(format!(
            "{field} must not contain a bare cred:// URI — use ${{cred://…}} (resolved at config load)"
        ));
    }
    Ok(())
}

/// The `http_route` webhook entity's plugin-level config.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TwilioWebhookConfig {
    /// Twilio Account SID — the webhook-signing identity.
    pub account_sid: String,

    /// The Account Auth Token — ALWAYS the webhook-signing key (API Key
    /// secrets do not sign webhooks). Resolved from `${cred://…}`.
    pub auth_token: String,

    /// The externally-reachable base URL the gateway is served at, e.g.
    /// `https://gw.example.com`. Used to reconstruct the exact URL Twilio
    /// signed. No trailing slash.
    pub public_base_url: String,

    /// Entity mount name under `/plugins/{plugin_id}/{entity_name}`. Defaults
    /// to `hooks` (matches the `inner_name` in `declare_plugin!`).
    #[serde(default = "default_mount_name")]
    pub mount_name: String,

    /// When true (default), every webhook validates `X-Twilio-Signature`
    /// before any side effect. Set false ONLY for local dev — the handler
    /// warns loudly.
    #[serde(default = "default_true")]
    pub validate_signature: bool,

    /// Max inbound webhook body size.
    #[serde(default = "default_webhook_body_cap")]
    pub max_body_bytes: u64,

    /// Inbound-SMS control.
    #[serde(default)]
    pub inbound_sms: InboundSms,
    /// Inbound-voice control.
    #[serde(default)]
    pub inbound_voice: InboundVoice,

    /// Optional built-in `/webhooks/resource-updated/{token}` URL the handler
    /// POSTs after recording an inbound event (PUSH). MUST be on the gateway's
    /// own `public_base_url` origin.
    #[serde(default)]
    pub notify_webhook_url: Option<String>,

    /// Bound on the handler-tool invocation per webhook turn (ms). Twilio's
    /// webhook deadline is ~15s; keep margin for the TwiML response.
    #[serde(default = "default_handler_timeout_ms")]
    pub handler_timeout_ms: u64,
}

fn default_mount_name() -> String {
    "hooks".to_owned()
}
fn default_true() -> bool {
    true
}
fn default_webhook_body_cap() -> u64 {
    64 * 1024
}
fn default_handler_timeout_ms() -> u64 {
    8_000
}

/// Inbound-SMS handling: an optional handler tool and/or a static auto-reply.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct InboundSms {
    /// Tool the handler `invoke_tool`s per inbound SMS. Its structured result
    /// (`{twiml_verbs:[…]}` or `{text:"…"}`) becomes the reply.
    pub handler_tool: Option<String>,
    /// Static auto-reply text (templated with `${From}`/`${To}`/`${Body}`)
    /// used when no handler tool is configured (or it errs/times out).
    pub auto_reply: Option<String>,
}

/// Inbound-voice handling: handler tool + static templated default verbs.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct InboundVoice {
    /// Tool the handler `invoke_tool`s per inbound call / gather turn.
    pub handler_tool: Option<String>,
    /// Static TwiML verbs (templated with `${From}`/`${To}`) served when no
    /// staged script and no handler tool apply.
    pub default_twiml_verbs: Vec<TwimlVerb>,
}

impl TwilioWebhookConfig {
    pub fn parse(cfg_json: &str) -> Result<Self, String> {
        if cfg_json.trim().is_empty() {
            return Err(
                "missing twilio webhook config (account_sid, auth_token, public_base_url required)"
                    .into(),
            );
        }
        let cfg: TwilioWebhookConfig = serde_json::from_str(cfg_json)
            .map_err(|e| format!("invalid twilio webhook config: {e}"))?;
        cfg.validate()?;
        Ok(cfg)
    }

    fn validate(&self) -> Result<(), String> {
        if self.account_sid.trim().is_empty() {
            return Err("account_sid is required".into());
        }
        if self.auth_token.trim().is_empty() {
            return Err("auth_token is required (it signs the webhooks)".into());
        }
        if self.public_base_url.trim().is_empty() {
            return Err("public_base_url is required (used to reconstruct the signed URL)".into());
        }
        if !self.public_base_url.starts_with("https://")
            && !self.public_base_url.starts_with("http://")
        {
            return Err("public_base_url must be an absolute http(s) URL".into());
        }
        // PUSH target, when set, must be on the gateway's own origin (SSRF pin).
        if let Some(url) = &self.notify_webhook_url
            && !url.starts_with(&self.public_base_url)
        {
            return Err(
                "notify_webhook_url must be on the configured public_base_url origin".into(),
            );
        }
        Ok(())
    }

    /// The route's mount path prefix: `/plugins/{plugin_id}/{mount_name}`.
    pub fn mount_prefix(&self, plugin_id: &str) -> String {
        format!("/plugins/{plugin_id}/{}", self.mount_name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn send_spec() -> serde_json::Value {
        json!({
            "account_sid": "AC123",
            "auth_token": "tok",
            "operation": "send_sms",
            "from": "+15550001111"
        })
    }

    #[test]
    fn parses_send_sms_with_auth_token() {
        let cfg = TwilioConfig::parse(&send_spec()).unwrap();
        assert_eq!(cfg.operation, Operation::SendSms);
        assert!(matches!(cfg.rest_auth(), Some(RestAuth::AuthToken { .. })));
    }

    #[test]
    fn api_key_auth_wins_over_token() {
        let mut spec = send_spec();
        spec["api_key_sid"] = json!("SK1");
        spec["api_key_secret"] = json!("secret");
        let cfg = TwilioConfig::parse(&spec).unwrap();
        assert!(matches!(cfg.rest_auth(), Some(RestAuth::ApiKey { .. })));
    }

    #[test]
    fn send_sms_requires_from_or_service() {
        let mut spec = send_spec();
        spec.as_object_mut().unwrap().remove("from");
        let err = TwilioConfig::parse(&spec).unwrap_err();
        assert!(err.contains("from"));
    }

    #[test]
    fn rest_op_requires_credentials() {
        let spec = json!({
            "account_sid": "AC1",
            "operation": "list_messages"
        });
        let err = TwilioConfig::parse(&spec).unwrap_err();
        assert!(err.contains("credentials") || err.contains("auth"));
    }

    #[test]
    fn local_op_needs_no_credentials() {
        let spec = json!({ "account_sid": "AC1", "operation": "build_twiml" });
        assert!(TwilioConfig::parse(&spec).is_ok());
    }

    #[test]
    fn unknown_field_is_rejected() {
        let mut spec = send_spec();
        spec["frmo"] = json!("typo");
        assert!(TwilioConfig::parse(&spec).is_err());
    }

    #[test]
    fn bare_cred_in_from_rejected() {
        let mut spec = send_spec();
        spec["from"] = json!("cred://dev.mcpg.backend.twilio/from");
        let err = TwilioConfig::parse(&spec).unwrap_err();
        assert!(err.contains("cred://"));
    }

    #[test]
    fn lookup_op_needs_credentials_not_service_sid() {
        let spec = json!({
            "account_sid": "AC1",
            "auth_token": "tok",
            "operation": "lookup"
        });
        let cfg = TwilioConfig::parse(&spec).unwrap();
        assert_eq!(cfg.operation, Operation::Lookup);
        assert_eq!(cfg.lookups_base, "https://lookups.twilio.com");
    }

    #[test]
    fn verify_start_requires_service_sid() {
        let spec = json!({
            "account_sid": "AC1",
            "auth_token": "tok",
            "operation": "verify_start"
        });
        let err = TwilioConfig::parse(&spec).unwrap_err();
        assert!(err.contains("verify_service_sid"));
    }

    #[test]
    fn verify_check_with_service_sid_parses() {
        let spec = json!({
            "account_sid": "AC1",
            "auth_token": "tok",
            "operation": "verify_check",
            "verify_service_sid": "VA123"
        });
        let cfg = TwilioConfig::parse(&spec).unwrap();
        assert_eq!(cfg.verify_service_sid.as_deref(), Some("VA123"));
        assert_eq!(cfg.verify_base, "https://verify.twilio.com");
    }

    #[test]
    fn bare_cred_in_verify_service_sid_rejected() {
        let spec = json!({
            "account_sid": "AC1",
            "auth_token": "tok",
            "operation": "verify_start",
            "verify_service_sid": "cred://dev.mcpg.backend.twilio/va"
        });
        let err = TwilioConfig::parse(&spec).unwrap_err();
        assert!(err.contains("cred://"));
    }

    #[test]
    fn webhook_config_parses_and_validates() {
        let cfg = TwilioWebhookConfig::parse(
            &json!({
                "account_sid": "AC1",
                "auth_token": "tok",
                "public_base_url": "https://gw.example.com"
            })
            .to_string(),
        )
        .unwrap();
        assert!(cfg.validate_signature);
        assert_eq!(cfg.mount_name, "hooks");
        assert_eq!(
            cfg.mount_prefix("dev.mcpg.backend.twilio"),
            "/plugins/dev.mcpg.backend.twilio/hooks"
        );
    }

    #[test]
    fn webhook_requires_auth_token() {
        let err = TwilioWebhookConfig::parse(
            &json!({
                "account_sid": "AC1",
                "auth_token": "",
                "public_base_url": "https://gw.example.com"
            })
            .to_string(),
        )
        .unwrap_err();
        assert!(err.contains("auth_token"));
    }

    #[test]
    fn notify_url_must_be_on_public_origin() {
        let err = TwilioWebhookConfig::parse(
            &json!({
                "account_sid": "AC1",
                "auth_token": "tok",
                "public_base_url": "https://gw.example.com",
                "notify_webhook_url": "https://evil.example.com/webhooks/resource-updated/t"
            })
            .to_string(),
        )
        .unwrap_err();
        assert!(err.contains("public_base_url"));
    }
}
