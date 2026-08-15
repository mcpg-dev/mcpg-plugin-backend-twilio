//! Inbound webhook handler (`http_route` entity).
//!
//! Twilio POSTs inbound SMS / voice / gather / status callbacks to routes under
//! `/plugins/dev.mcpg.backend.twilio/hooks/*`. The handler:
//!
//! 1. Validates `X-Twilio-Signature` over the reconstructed public URL + sorted
//!    POST params (HMAC-SHA1, constant-time) BEFORE any side effect. A mismatch
//!    returns `403` with no TwiML and no state mutation.
//! 2. Records the event into the shared [`TwilioState`] ring.
//! 3. Publishes an [`InboundNotice`] onto the shared in-process channel so the
//!    `watch_strategy` entity can push `resources/updated` natively. This is a
//!    non-blocking `send` — the dispatcher (on the watch entity's runtime)
//!    calls the host's `emit_event` OUTSIDE this handler's `block_on`.
//! 4. Runs the inbound-control logic (staged script → handler tool → templated
//!    default → safe fallback) and returns TwiML.
//! 5. Optionally POSTs `notify_webhook_url` (PUSH) after recording — the
//!    cross-replica alternative to the in-process watch path.
//!
//! The handler does NOT receive a `HostHandle` per call (the trait's `handle`
//! takes only the request), so it captures the handle + shared state at entity
//! construction.

use std::sync::Arc;
use std::time::{Duration, Instant};

use mcpg_plugin_protocol::PluginManifest;
use mcpg_plugin_protocol::backend::BackendInvocationContext;
use mcpg_plugin_protocol::firstparty_manifest;
use mcpg_plugin_protocol::http_route::{HttpRouteRequest, HttpRouteResponse, RouteSpec};
use mcpg_plugin_sdk::HostHandle;
use serde_json::{Value, json};
use tracing::warn;

use crate::config::{InboundSms, InboundVoice, TwilioWebhookConfig};
use crate::signature;
use crate::state::{InboundEvent, InboundNotice, ScriptKey, TwilioState};
use crate::twiml::{self, TwimlVerb};

pub const PLUGIN_ID: &str = "dev.mcpg.backend.twilio";

/// The webhook receiver. Holds the captured host handle, shared state, and
/// config so the per-request `handle` can validate signatures, run handler
/// tools, and push.
pub struct TwilioWebhook {
    manifest: PluginManifest,
    cfg: TwilioWebhookConfig,
    state: Arc<TwilioState>,
    host: HostHandle,
    /// Private runtime to drive the async host calls (invoke_tool / push)
    /// from the sync FFI `handle`.
    rt: tokio::runtime::Runtime,
    http: reqwest::Client,
}

impl TwilioWebhook {
    pub fn new(cfg: TwilioWebhookConfig, state: Arc<TwilioState>, host: HostHandle) -> Self {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name("mcpg-twilio-webhook")
            .enable_all()
            .build()
            .unwrap_or_else(|e| panic!("twilio webhook: tokio runtime init failed: {e}"));
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap_or_else(|e| panic!("twilio webhook: reqwest build failed: {e}"));
        Self {
            manifest: firstparty_manifest! {
                id: "dev.mcpg.backend.twilio",
                name: "Twilio SMS + Voice Binding",
                class: Backend,
            },
            cfg,
            state,
            host,
            rt,
            http,
        }
    }

    pub fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    pub fn routes(&self) -> Vec<RouteSpec> {
        let body_cap = Some(self.cfg.max_body_bytes);
        [
            "/hooks/sms",
            "/hooks/voice",
            "/hooks/status",
            "/hooks/gather/:id",
        ]
        .into_iter()
        .map(|path| RouteSpec {
            method: "POST".into(),
            path: path.into(),
            requires_identity: false,
            streaming: false,
            max_body_bytes: body_cap,
        })
        .collect()
    }

    /// Reconstruct the exact URL Twilio signed: `public_base_url` + the request
    /// full path + the raw query string (as received).
    fn reconstruct_url(&self, req: &HttpRouteRequest) -> String {
        let base = self.cfg.public_base_url.trim_end_matches('/');
        let mut url = format!("{base}{}", req.full_path);
        if !req.query.is_empty() {
            let qs = serde_urlencoded::to_string(&req.query).unwrap_or_default();
            if !qs.is_empty() {
                url.push('?');
                url.push_str(&qs);
            }
        }
        url
    }

    /// Validate the signature for a form-body webhook. Returns Ok on a match or
    /// when validation is disabled (dev only). Logs + Err on mismatch.
    fn check_signature(
        &self,
        req: &HttpRouteRequest,
        params: &[(String, String)],
    ) -> Result<(), HttpRouteResponse> {
        if !self.cfg.validate_signature {
            warn!(
                plugin_id = PLUGIN_ID,
                "twilio: signature validation DISABLED (validate_signature=false) — dev only"
            );
            return Ok(());
        }
        let provided = find_header(&req.headers, "x-twilio-signature").unwrap_or("");
        if provided.is_empty() {
            return Err(HttpRouteResponse::error_json(
                403,
                "missing X-Twilio-Signature",
            ));
        }
        let url = self.reconstruct_url(req);
        // Twilio signs form webhooks over the URL + sorted params, and JSON
        // webhooks over the URL alone (which already carries `bodySHA256`).
        // Pick the variant by whether the request carries a `bodySHA256` query
        // param (set by Twilio for non-form bodies). For the JSON variant the
        // `bodySHA256` value must also match the actual body.
        let valid = if let Some(body_sha) = query_value(&req.query, "bodySHA256") {
            body_sha == signature::body_sha256_hex(&req.body)
                && signature::verify(
                    &signature::expected_signature_json(&self.cfg.auth_token, &url),
                    provided,
                )
        } else {
            signature::validate_form(&self.cfg.auth_token, &url, params, provided).is_ok()
        };
        if valid {
            Ok(())
        } else {
            warn!(plugin_id = PLUGIN_ID, "twilio: webhook signature rejected");
            metrics::counter!("mcpg_twilio_webhook_total", "outcome" => "sig_rejected")
                .increment(1);
            Err(HttpRouteResponse::error_json(403, "invalid signature"))
        }
    }

    /// Parse the form body into key/value pairs.
    fn parse_form(req: &HttpRouteRequest) -> Vec<(String, String)> {
        serde_urlencoded::from_bytes(&req.body).unwrap_or_default()
    }

    /// Dispatch a validated request to the matching route handler.
    pub fn handle(&self, req: HttpRouteRequest) -> HttpRouteResponse {
        let params = Self::parse_form(&req);
        // Signature FIRST — no side effects until it validates.
        if let Err(resp) = self.check_signature(&req, &params) {
            return resp;
        }
        let path = req.full_path.as_str();
        if path.ends_with("/hooks/sms") {
            self.handle_sms(&req, &params)
        } else if path.ends_with("/hooks/voice") {
            self.handle_voice(&req, &params)
        } else if path.ends_with("/hooks/status") {
            self.handle_status(&params)
        } else if path.contains("/hooks/gather/") {
            self.handle_gather(&req, &params)
        } else {
            HttpRouteResponse::error_json(404, "unknown twilio webhook route")
        }
    }

    fn handle_sms(
        &self,
        _req: &HttpRouteRequest,
        params: &[(String, String)],
    ) -> HttpRouteResponse {
        let from = param(params, "From");
        let to = param(params, "To");
        let sid = param(params, "MessageSid").or_else(|| param(params, "SmsSid"));
        self.state.record_event(InboundEvent {
            kind: "sms".into(),
            sid: sid.map(str::to_owned),
            from: from.map(str::to_owned),
            to: to.map(str::to_owned),
            received_at: Instant::now(),
        });
        self.state.notify_inbound(InboundNotice {
            kind: "sms".into(),
            sid: sid.map(str::to_owned),
            from: from.map(str::to_owned),
            to: to.map(str::to_owned),
        });
        self.maybe_push("sms");
        metrics::counter!("mcpg_twilio_webhook_total", "outcome" => "sms").increment(1);

        let inbound = &self.cfg.inbound_sms;
        let body = sms_reply_verbs(inbound, params, || {
            self.run_handler_tool(inbound.handler_tool.as_deref(), params, None)
        });
        match body {
            Some(verbs) => HttpRouteResponse::ok_bytes("text/xml", twiml::render(&verbs)),
            None => HttpRouteResponse::ok_bytes("text/xml", twiml::empty_response()),
        }
    }

    fn handle_voice(
        &self,
        _req: &HttpRouteRequest,
        params: &[(String, String)],
    ) -> HttpRouteResponse {
        let from = param(params, "From");
        let to = param(params, "To");
        let call_sid = param(params, "CallSid");
        self.state.record_event(InboundEvent {
            kind: "voice".into(),
            sid: call_sid.map(str::to_owned),
            from: from.map(str::to_owned),
            to: to.map(str::to_owned),
            received_at: Instant::now(),
        });
        self.state.notify_inbound(InboundNotice {
            kind: "voice".into(),
            sid: call_sid.map(str::to_owned),
            from: from.map(str::to_owned),
            to: to.map(str::to_owned),
        });
        self.maybe_push("voice");
        metrics::counter!("mcpg_twilio_webhook_total", "outcome" => "voice").increment(1);

        // Control level 2: a staged script for this CallSid or To wins.
        if let Some(sid) = call_sid
            && let Some(verbs) = self.state.take_script(&ScriptKey::CallSid(sid.to_owned()))
        {
            return HttpRouteResponse::ok_bytes("text/xml", twiml::render(&verbs));
        }
        if let Some(to) = to
            && let Some(verbs) = self.state.take_script(&ScriptKey::To(to.to_owned()))
        {
            return HttpRouteResponse::ok_bytes("text/xml", twiml::render(&verbs));
        }

        // Control level 3: a live handler tool.
        if let Some(verbs) =
            self.run_handler_tool(self.cfg.inbound_voice.handler_tool.as_deref(), params, None)
        {
            return HttpRouteResponse::ok_bytes("text/xml", twiml::render(&verbs));
        }

        // Control level 1: templated default verbs, else a safe <Reject/>.
        let default = templated_voice_default(&self.cfg.inbound_voice, params);
        match default {
            Some(verbs) => HttpRouteResponse::ok_bytes("text/xml", twiml::render(&verbs)),
            None => HttpRouteResponse::ok_bytes("text/xml", twiml::reject_response()),
        }
    }

    fn handle_gather(
        &self,
        req: &HttpRouteRequest,
        params: &[(String, String)],
    ) -> HttpRouteResponse {
        let captured = param(params, "Digits")
            .or_else(|| param(params, "SpeechResult"))
            .map(str::to_owned);
        let call_sid = req.path_params.get("id").cloned();
        self.state.record_event(InboundEvent {
            kind: "gather".into(),
            sid: call_sid.clone(),
            from: param(params, "From").map(str::to_owned),
            to: param(params, "To").map(str::to_owned),
            received_at: Instant::now(),
        });
        metrics::counter!("mcpg_twilio_webhook_total", "outcome" => "gather").increment(1);

        // The handler tool drives the next IVR turn given the captured input.
        if let Some(verbs) = self.run_handler_tool(
            self.cfg.inbound_voice.handler_tool.as_deref(),
            params,
            captured.as_deref(),
        ) {
            return HttpRouteResponse::ok_bytes("text/xml", twiml::render(&verbs));
        }
        HttpRouteResponse::ok_bytes("text/xml", twiml::reject_response())
    }

    fn handle_status(&self, params: &[(String, String)]) -> HttpRouteResponse {
        let sid = param(params, "CallSid").or_else(|| param(params, "MessageSid"));
        let status = param(params, "CallStatus").or_else(|| param(params, "MessageStatus"));
        if let (Some(sid), Some(status)) = (sid, status) {
            self.state.record_status(sid.to_owned(), status.to_owned());
        }
        self.state.record_event(InboundEvent {
            kind: "status".into(),
            sid: sid.map(str::to_owned),
            from: None,
            to: None,
            received_at: Instant::now(),
        });
        self.state.notify_inbound(InboundNotice {
            kind: "status".into(),
            sid: sid.map(str::to_owned),
            from: None,
            to: None,
        });
        metrics::counter!("mcpg_twilio_webhook_total", "outcome" => "status").increment(1);
        // Status callbacks expect a 204 (no TwiML).
        HttpRouteResponse::status(204)
    }

    /// Invoke a configured handler tool with the inbound params + optional
    /// captured input, under a tight timeout. Returns the verbs the tool
    /// produced, or `None` (no tool configured, error, timeout, or non-verb
    /// result → caller falls back to a safe default).
    fn run_handler_tool(
        &self,
        handler_tool: Option<&str>,
        params: &[(String, String)],
        captured: Option<&str>,
    ) -> Option<Vec<TwimlVerb>> {
        let tool_name = handler_tool?;
        let mut payload = serde_json::Map::new();
        for (k, v) in params {
            payload.insert(k.clone(), Value::String(v.clone()));
        }
        if let Some(c) = captured {
            payload.insert("captured_input".into(), Value::String(c.to_owned()));
        }
        let args = Value::Object(payload);
        let ctx = BackendInvocationContext::root(
            format!("twilio-webhook-{}", uuid_like()),
            None,
            PLUGIN_ID,
        );
        let timeout = Duration::from_millis(self.cfg.handler_timeout_ms);
        let host = self.host.clone();
        let tool = tool_name.to_owned();
        let result = self.rt.block_on(async move {
            tokio::time::timeout(timeout, async move {
                tokio::task::spawn_blocking(move || host.invoke_tool(&ctx, &tool, &args))
                    .await
                    .map_err(|e| format!("join error: {e}"))?
                    .map_err(|e| format!("{e:?}"))
            })
            .await
        });
        match result {
            Ok(Ok(value)) => verbs_from_tool_result(&value),
            Ok(Err(reason)) => {
                warn!(plugin_id = PLUGIN_ID, tool = %tool_name, reason = %reason, "twilio: handler tool failed");
                None
            }
            Err(_) => {
                warn!(plugin_id = PLUGIN_ID, tool = %tool_name, "twilio: handler tool timed out");
                None
            }
        }
    }

    /// POST the configured `notify_webhook_url` to signal a fresh inbound event.
    /// Best-effort; failures are logged, never block the TwiML reply.
    fn maybe_push(&self, kind: &str) {
        let Some(url) = self.cfg.notify_webhook_url.clone() else {
            return;
        };
        let http = self.http.clone();
        let kind = kind.to_owned();
        // Fire-and-forget on the private runtime.
        self.rt.spawn(async move {
            let _ = http
                .post(&url)
                .json(&json!({ "reason": format!("twilio-inbound-{kind}") }))
                .send()
                .await;
        });
    }
}

/// Decide the SMS reply verbs: a handler tool wins; else a static templated
/// auto-reply; else `None` (empty `<Response/>`).
fn sms_reply_verbs(
    inbound: &InboundSms,
    params: &[(String, String)],
    run_handler: impl FnOnce() -> Option<Vec<TwimlVerb>>,
) -> Option<Vec<TwimlVerb>> {
    if inbound.handler_tool.is_some()
        && let Some(verbs) = run_handler()
    {
        return Some(verbs);
    }
    inbound.auto_reply.as_ref().map(|tmpl| {
        vec![TwimlVerb::Message {
            body: substitute(tmpl, params),
            media_url: vec![],
        }]
    })
}

/// Templated default voice verbs (level 1), with `${From}`/`${To}` substitution.
fn templated_voice_default(
    inbound: &InboundVoice,
    params: &[(String, String)],
) -> Option<Vec<TwimlVerb>> {
    if inbound.default_twiml_verbs.is_empty() {
        return None;
    }
    Some(
        inbound
            .default_twiml_verbs
            .iter()
            .map(|v| substitute_verb(v, params))
            .collect(),
    )
}

/// Extract TwiML verbs from a handler tool's structured result.
/// Accepts `{twiml_verbs:[…]}` or a plain `{text:"…"}` (rendered as a `<Say>`).
fn verbs_from_tool_result(value: &Value) -> Option<Vec<TwimlVerb>> {
    if let Some(verbs) = value.get("twiml_verbs")
        && let Ok(parsed) = serde_json::from_value::<Vec<TwimlVerb>>(verbs.clone())
    {
        return Some(parsed);
    }
    if let Some(text) = value.get("text").and_then(Value::as_str) {
        return Some(vec![TwimlVerb::Say {
            text: text.to_owned(),
            voice: None,
            language: None,
        }]);
    }
    None
}

/// Apply `${From}`/`${To}`/`${Body}` substitution to a template string.
fn substitute(template: &str, params: &[(String, String)]) -> String {
    let mut out = template.to_owned();
    for key in ["From", "To", "Body"] {
        if let Some(v) = param(params, key) {
            out = out.replace(&format!("${{{key}}}"), v);
        }
    }
    out
}

/// Substitute template placeholders inside a verb's text/url fields.
fn substitute_verb(verb: &TwimlVerb, params: &[(String, String)]) -> TwimlVerb {
    match verb {
        TwimlVerb::Say {
            text,
            voice,
            language,
        } => TwimlVerb::Say {
            text: substitute(text, params),
            voice: voice.clone(),
            language: language.clone(),
        },
        TwimlVerb::Message { body, media_url } => TwimlVerb::Message {
            body: substitute(body, params),
            media_url: media_url.clone(),
        },
        other => other.clone(),
    }
}

fn param<'a>(params: &'a [(String, String)], key: &str) -> Option<&'a str> {
    params
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.as_str())
        .filter(|s| !s.is_empty())
}

fn query_value<'a>(query: &'a [(String, String)], key: &str) -> Option<&'a str> {
    query
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.as_str())
}

fn find_header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

/// Cheap unique-ish suffix for the synthetic invocation request_id (no uuid
/// dependency needed — monotonic nanos suffice for correlation).
fn uuid_like() -> u128 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(json_str: &str) -> TwilioWebhookConfig {
        TwilioWebhookConfig::parse(json_str).unwrap()
    }

    fn base_cfg() -> TwilioWebhookConfig {
        cfg(
            r#"{"account_sid":"AC1","auth_token":"12345","public_base_url":"https://gw.example.com"}"#,
        )
    }

    fn webhook(cfg: TwilioWebhookConfig) -> TwilioWebhook {
        let host = unsafe { HostHandle::from_ffi(mcpg_plugin_sdk::testing::stub_host_ref()) };
        TwilioWebhook::new(cfg, Arc::new(TwilioState::default()), host)
    }

    fn req(
        path: &str,
        query: Vec<(String, String)>,
        body: &str,
        sig: Option<&str>,
    ) -> HttpRouteRequest {
        let mut headers = vec![];
        if let Some(s) = sig {
            headers.push(("X-Twilio-Signature".into(), s.to_owned()));
        }
        HttpRouteRequest {
            method: "POST".into(),
            full_path: format!("/plugins/dev.mcpg.backend.twilio/hooks{path}"),
            path_params: Default::default(),
            query,
            headers,
            body: bytes::Bytes::from(body.as_bytes().to_vec()),
            identity: None,
            request_id: "r".into(),
            remote_addr: None,
        }
    }

    /// Compute the valid signature for a request the test will send.
    fn sign(cfg: &TwilioWebhookConfig, path: &str, params: &[(String, String)]) -> String {
        let url = format!(
            "{}/plugins/dev.mcpg.backend.twilio/hooks{path}",
            cfg.public_base_url
        );
        signature::expected_signature_form(&cfg.auth_token, &url, params)
    }

    #[test]
    fn routes_cover_the_four_hooks() {
        let wh = webhook(base_cfg());
        let paths: Vec<String> = wh.routes().into_iter().map(|r| r.path).collect();
        assert!(paths.contains(&"/hooks/sms".to_string()));
        assert!(paths.contains(&"/hooks/voice".to_string()));
        assert!(paths.contains(&"/hooks/status".to_string()));
        assert!(paths.iter().any(|p| p.contains("/hooks/gather/")));
    }

    #[test]
    fn missing_signature_is_403() {
        let wh = webhook(base_cfg());
        let r = wh.handle(req("/sms", vec![], "From=%2B1555&To=%2B1666&Body=hi", None));
        assert_eq!(r.status, 403);
        // No event recorded (signature rejected before side effects).
        assert_eq!(wh.state.event_count(), 0);
    }

    #[test]
    fn bad_signature_is_403_no_side_effects() {
        let wh = webhook(base_cfg());
        let r = wh.handle(req(
            "/sms",
            vec![],
            "From=%2B1555&To=%2B1666&Body=hi",
            Some("deadbeef"),
        ));
        assert_eq!(r.status, 403);
        assert_eq!(wh.state.event_count(), 0);
    }

    #[test]
    fn valid_sms_signature_records_and_replies_empty() {
        let c = base_cfg();
        let params = vec![
            ("From".to_string(), "+1555".to_string()),
            ("To".to_string(), "+1666".to_string()),
            ("Body".to_string(), "hi".to_string()),
            ("MessageSid".to_string(), "SM1".to_string()),
        ];
        let sig = sign(&c, "/sms", &params);
        let wh = webhook(c);
        let body = serde_urlencoded::to_string(&params).unwrap();
        let r = wh.handle(req("/sms", vec![], &body, Some(&sig)));
        assert_eq!(r.status, 200);
        assert_eq!(wh.state.event_count(), 1);
    }

    #[test]
    fn sms_auto_reply_templated() {
        let c = cfg(
            r#"{"account_sid":"AC1","auth_token":"12345","public_base_url":"https://gw.example.com","inbound_sms":{"auto_reply":"Hi ${From}"}}"#,
        );
        let params = vec![
            ("From".to_string(), "+1555".to_string()),
            ("Body".to_string(), "yo".to_string()),
        ];
        let sig = sign(&c, "/sms", &params);
        let wh = webhook(c);
        let body = serde_urlencoded::to_string(&params).unwrap();
        let resp = wh.handle(req("/sms", vec![], &body, Some(&sig)));
        let xml = match resp.body {
            mcpg_plugin_protocol::http_route::HttpBody::Bytes(b) => {
                String::from_utf8(b.to_vec()).unwrap()
            }
            _ => panic!("bytes"),
        };
        assert!(xml.contains("Hi +1555"));
    }

    #[test]
    fn voice_falls_back_to_reject() {
        let c = base_cfg();
        let params = vec![
            ("From".to_string(), "+1555".to_string()),
            ("To".to_string(), "+1666".to_string()),
            ("CallSid".to_string(), "CA1".to_string()),
        ];
        let sig = sign(&c, "/voice", &params);
        let wh = webhook(c);
        let body = serde_urlencoded::to_string(&params).unwrap();
        let resp = wh.handle(req("/voice", vec![], &body, Some(&sig)));
        let xml = match resp.body {
            mcpg_plugin_protocol::http_route::HttpBody::Bytes(b) => {
                String::from_utf8(b.to_vec()).unwrap()
            }
            _ => panic!("bytes"),
        };
        assert!(xml.contains("<Reject/>"));
    }

    #[test]
    fn voice_serves_staged_script() {
        let c = base_cfg();
        let params = vec![
            ("From".to_string(), "+1555".to_string()),
            ("To".to_string(), "+1666".to_string()),
            ("CallSid".to_string(), "CA42".to_string()),
        ];
        let sig = sign(&c, "/voice", &params);
        let wh = webhook(c);
        // Pre-stage a script for this CallSid.
        wh.state.stage_script(
            ScriptKey::CallSid("CA42".into()),
            vec![TwimlVerb::Say {
                text: "scripted".into(),
                voice: None,
                language: None,
            }],
            Duration::from_secs(60),
        );
        let body = serde_urlencoded::to_string(&params).unwrap();
        let resp = wh.handle(req("/voice", vec![], &body, Some(&sig)));
        let xml = match resp.body {
            mcpg_plugin_protocol::http_route::HttpBody::Bytes(b) => {
                String::from_utf8(b.to_vec()).unwrap()
            }
            _ => panic!("bytes"),
        };
        assert!(xml.contains("scripted"));
        // Consumed.
        assert_eq!(wh.state.staged_count(), 0);
    }

    #[test]
    fn status_callback_is_204_and_records_status() {
        let c = base_cfg();
        let params = vec![
            ("CallSid".to_string(), "CA7".to_string()),
            ("CallStatus".to_string(), "completed".to_string()),
        ];
        let sig = sign(&c, "/status", &params);
        let wh = webhook(c);
        let body = serde_urlencoded::to_string(&params).unwrap();
        let resp = wh.handle(req("/status", vec![], &body, Some(&sig)));
        assert_eq!(resp.status, 204);
        assert_eq!(wh.state.last_status("CA7").as_deref(), Some("completed"));
    }

    #[test]
    fn validate_disabled_skips_signature() {
        let c = cfg(
            r#"{"account_sid":"AC1","auth_token":"12345","public_base_url":"https://gw.example.com","validate_signature":false}"#,
        );
        let wh = webhook(c);
        let r = wh.handle(req("/sms", vec![], "From=%2B1555&Body=hi", None));
        assert_eq!(r.status, 200);
    }

    #[test]
    fn verbs_from_tool_result_text_and_verbs() {
        let v = verbs_from_tool_result(&json!({ "text": "spoken" })).unwrap();
        assert_eq!(v.len(), 1);
        let v2 = verbs_from_tool_result(&json!({ "twiml_verbs": [{ "verb": "hangup" }] })).unwrap();
        assert_eq!(v2, vec![TwimlVerb::Hangup]);
        assert!(verbs_from_tool_result(&json!({ "other": 1 })).is_none());
    }
}
