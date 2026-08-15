//! Operation dispatch + per-operation input/output schema.
//!
//! Each binding fixes one [`Operation`]; `execute` marshals the call arguments
//! into the Twilio request, runs it via [`TwilioRest`], and shapes the result.
//! Repeated-key parameters (`MediaUrl`, `StatusCallbackEvent`) are emitted as
//! repeated form pairs.

use std::sync::Arc;
use std::time::Duration;

use mcpg_plugin_protocol::BackendError;
use serde_json::{Value, json};

use crate::config::{Operation, TwilioConfig};
use crate::rest::{RestOutcome, TwilioRest};
use crate::state::{ScriptKey, TwilioState};
use crate::twiml::{self, TwimlVerb};

/// The result of running an operation: either a JSON success body or a logical
/// tool-level error string.
pub enum OpResult {
    Ok(Value),
    ToolError(String),
}

/// Internal dispatch error. A `Tool` failure is a logical/business error the
/// agent should see as a tool result; a `Backend` failure is a real transport
/// fault that propagates as a [`BackendError`].
enum DispatchError {
    Tool(String),
    Backend(BackendError),
}

impl From<String> for DispatchError {
    fn from(s: String) -> Self {
        DispatchError::Tool(s)
    }
}

impl From<&str> for DispatchError {
    fn from(s: &str) -> Self {
        DispatchError::Tool(s.to_owned())
    }
}

impl From<BackendError> for DispatchError {
    fn from(e: BackendError) -> Self {
        DispatchError::Backend(e)
    }
}

/// Pull a required string argument, or return a tool error.
fn req_str<'a>(args: &'a Value, key: &str) -> Result<&'a str, String> {
    args.get(key)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| format!("missing required argument `{key}`"))
}

/// Pull a required Twilio resource SID.
///
/// A SID is always two uppercase letters followed by 32 hex digits, so the
/// grammar is checked rather than escaped: the accepted alphabet contains
/// no path separator and no dot, which is what makes the value safe to
/// interpolate into a REST path. A free-form `sid` reaching the path would
/// otherwise walk out of the collection the operator scoped the tool to,
/// carrying the account's `Authorization: Basic` header with it.
fn req_sid<'a>(args: &'a Value, key: &str) -> Result<&'a str, String> {
    let raw = req_str(args, key)?;
    let bytes = raw.as_bytes();
    let well_formed = bytes.len() == 34
        && bytes[..2].iter().all(u8::is_ascii_uppercase)
        && bytes[2..].iter().all(u8::is_ascii_hexdigit);
    if !well_formed {
        return Err(format!(
            "argument `{key}` is not a Twilio SID (expected two uppercase letters \
             followed by 32 hex digits)"
        ));
    }
    Ok(raw)
}

fn opt_str<'a>(args: &'a Value, key: &str) -> Option<&'a str> {
    args.get(key)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
}

/// Append repeated form pairs for a JSON array of strings (e.g. MediaUrl).
fn push_repeated(form: &mut Vec<(String, String)>, key: &str, args: &Value, arg_key: &str) {
    if let Some(arr) = args.get(arg_key).and_then(Value::as_array) {
        for v in arr {
            if let Some(s) = v.as_str() {
                form.push((key.to_owned(), s.to_owned()));
            }
        }
    }
}

/// Parse a `twiml_verbs` argument into structured verbs.
fn parse_verbs(args: &Value) -> Result<Vec<TwimlVerb>, String> {
    match args.get("twiml_verbs") {
        Some(v) => {
            serde_json::from_value(v.clone()).map_err(|e| format!("invalid twiml_verbs: {e}"))
        }
        None => Ok(vec![]),
    }
}

/// Percent-encode one URL path segment (e.g. a phone number going into the
/// Lookups path). Encodes everything outside the unreserved set so a `+` in an
/// E.164 number becomes `%2B` and the number can't break out of its segment.
fn encode_path_segment(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(b as char);
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Validate that an agent-supplied URL is https (SSRF guard for callbacks /
/// media / TwiML URLs).
fn require_https(field: &str, url: &str) -> Result<(), String> {
    if url.starts_with("https://") {
        Ok(())
    } else {
        Err(format!("{field} must be an https:// URL"))
    }
}

/// Run one operation. `rest` is `None` only for the purely-local ops. A logical
/// failure surfaces as `Ok(OpResult::ToolError)`; a real transport fault
/// surfaces as `Err(BackendError)`.
pub async fn execute_op(
    cfg: &TwilioConfig,
    rest: Option<&TwilioRest>,
    state: &Arc<TwilioState>,
    args: &Value,
) -> Result<OpResult, BackendError> {
    match dispatch(cfg, rest, state, args).await {
        Ok(r) => Ok(r),
        Err(DispatchError::Tool(msg)) => Ok(OpResult::ToolError(msg)),
        Err(DispatchError::Backend(e)) => Err(e),
    }
}

async fn dispatch(
    cfg: &TwilioConfig,
    rest: Option<&TwilioRest>,
    state: &Arc<TwilioState>,
    args: &Value,
) -> Result<OpResult, DispatchError> {
    match cfg.operation {
        Operation::BuildTwiml => {
            let verbs = parse_verbs(args)?;
            Ok(OpResult::Ok(json!({ "twiml": twiml::render(&verbs) })))
        }
        Operation::StageCallResponse => {
            let verbs = parse_verbs(args)?;
            if verbs.is_empty() {
                return Err("stage_call_response requires non-empty twiml_verbs".into());
            }
            let key = match (opt_str(args, "call_sid"), opt_str(args, "to")) {
                (Some(sid), _) => ScriptKey::CallSid(sid.to_owned()),
                (None, Some(to)) => ScriptKey::To(to.to_owned()),
                (None, None) => {
                    return Err("stage_call_response requires `call_sid` or `to`".into());
                }
            };
            let ttl_secs = args.get("ttl_secs").and_then(Value::as_u64).unwrap_or(900);
            state.stage_script(key, verbs, Duration::from_secs(ttl_secs));
            Ok(OpResult::Ok(json!({ "staged": true })))
        }
        Operation::SendSms => {
            let rest = rest.ok_or("send_sms requires a REST client")?;
            let mut form: Vec<(String, String)> = Vec::new();
            form.push(("To".into(), req_str(args, "to")?.to_owned()));
            form.push(("Body".into(), req_str(args, "body")?.to_owned()));
            // From / MessagingServiceSid: arg overrides config default.
            if let Some(svc) =
                opt_str(args, "messaging_service_sid").or(cfg.messaging_service_sid.as_deref())
            {
                form.push(("MessagingServiceSid".into(), svc.to_owned()));
            } else if let Some(from) = opt_str(args, "from").or(cfg.from.as_deref()) {
                form.push(("From".into(), from.to_owned()));
            } else {
                return Err("send_sms needs `from` or `messaging_service_sid`".into());
            }
            if let Some(cb) = opt_str(args, "status_callback") {
                require_https("status_callback", cb)?;
                form.push(("StatusCallback".into(), cb.to_owned()));
            }
            // Repeated MediaUrl pairs (each must be https).
            if let Some(arr) = args.get("media_url").and_then(Value::as_array) {
                for v in arr {
                    if let Some(s) = v.as_str() {
                        require_https("media_url", s)?;
                        form.push(("MediaUrl".into(), s.to_owned()));
                    }
                }
            }
            map_rest(rest.post_form("Messages.json", &form).await?)
        }
        Operation::ListMessages => {
            let rest = rest.ok_or("list_messages requires a REST client")?;
            let mut q: Vec<(String, String)> = Vec::new();
            for (arg, param) in [("to", "To"), ("from", "From"), ("date_sent", "DateSent")] {
                if let Some(v) = opt_str(args, arg) {
                    q.push((param.into(), v.to_owned()));
                }
            }
            let (items, next) = rest.list("Messages.json", &q, "messages").await?;
            Ok(OpResult::Ok(
                json!({ "messages": items, "next_page_uri": next }),
            ))
        }
        Operation::GetMessage => {
            let rest = rest.ok_or("get_message requires a REST client")?;
            let sid = req_sid(args, "sid")?;
            map_rest(rest.get(&format!("Messages/{sid}.json")).await?)
        }
        Operation::RedactMessage => {
            let rest = rest.ok_or("redact_message requires a REST client")?;
            let sid = req_sid(args, "sid")?;
            // Redaction = POST the message with an empty Body.
            let form = vec![("Body".to_owned(), String::new())];
            map_rest(
                rest.post_form(&format!("Messages/{sid}.json"), &form)
                    .await?,
            )
        }
        Operation::DeleteMessage => {
            let rest = rest.ok_or("delete_message requires a REST client")?;
            let sid = req_sid(args, "sid")?;
            map_rest(rest.delete(&format!("Messages/{sid}.json")).await?)
        }
        Operation::MakeCall => {
            let rest = rest.ok_or("make_call requires a REST client")?;
            let mut form: Vec<(String, String)> = Vec::new();
            form.push(("To".into(), req_str(args, "to")?.to_owned()));
            let from = opt_str(args, "from")
                .or(cfg.from.as_deref())
                .ok_or("make_call needs a `from` number")?;
            form.push(("From".into(), from.to_owned()));
            // Exactly one call-flow source: twiml_verbs (built locally) > twiml > url.
            let verbs = parse_verbs(args)?;
            if !verbs.is_empty() {
                form.push(("Twiml".into(), twiml::render(&verbs)));
            } else if let Some(t) = opt_str(args, "twiml") {
                form.push(("Twiml".into(), t.to_owned()));
            } else if let Some(u) = opt_str(args, "url") {
                require_https("url", u)?;
                form.push(("Url".into(), u.to_owned()));
            } else {
                return Err("make_call requires one of `twiml_verbs`, `twiml`, or `url`".into());
            }
            if let Some(cb) = opt_str(args, "status_callback") {
                require_https("status_callback", cb)?;
                form.push(("StatusCallback".into(), cb.to_owned()));
            }
            push_repeated(
                &mut form,
                "StatusCallbackEvent",
                args,
                "status_callback_event",
            );
            if let Some(md) = opt_str(args, "machine_detection") {
                form.push(("MachineDetection".into(), md.to_owned()));
            }
            if args.get("record").and_then(Value::as_bool) == Some(true) {
                form.push(("Record".into(), "true".into()));
            }
            map_rest(rest.post_form("Calls.json", &form).await?)
        }
        Operation::ListCalls => {
            let rest = rest.ok_or("list_calls requires a REST client")?;
            let mut q: Vec<(String, String)> = Vec::new();
            for (arg, param) in [("to", "To"), ("from", "From"), ("status", "Status")] {
                if let Some(v) = opt_str(args, arg) {
                    q.push((param.into(), v.to_owned()));
                }
            }
            let (items, next) = rest.list("Calls.json", &q, "calls").await?;
            Ok(OpResult::Ok(
                json!({ "calls": items, "next_page_uri": next }),
            ))
        }
        Operation::GetCall => {
            let rest = rest.ok_or("get_call requires a REST client")?;
            let sid = req_sid(args, "sid")?;
            map_rest(rest.get(&format!("Calls/{sid}.json")).await?)
        }
        Operation::ModifyCall => {
            let rest = rest.ok_or("modify_call requires a REST client")?;
            let sid = req_sid(args, "sid")?;
            let action = req_str(args, "action")?;
            let mut form: Vec<(String, String)> = Vec::new();
            match action {
                "hangup" => {
                    form.push(("Status".into(), "completed".into()));
                }
                "redirect" => {
                    let verbs = parse_verbs(args)?;
                    if !verbs.is_empty() {
                        form.push(("Twiml".into(), twiml::render(&verbs)));
                    } else if let Some(u) = opt_str(args, "url") {
                        require_https("url", u)?;
                        form.push(("Url".into(), u.to_owned()));
                    } else {
                        return Err("modify_call redirect requires `twiml_verbs` or `url`".into());
                    }
                }
                other => {
                    return Err(DispatchError::Tool(format!(
                        "unknown modify_call action `{other}` (hangup|redirect)"
                    )));
                }
            }
            map_rest(rest.post_form(&format!("Calls/{sid}.json"), &form).await?)
        }
        Operation::GetRecording => {
            let rest = rest.ok_or("get_recording requires a REST client")?;
            let sid = req_sid(args, "sid")?;
            map_rest(rest.get(&format!("Recordings/{sid}.json")).await?)
        }
        Operation::Lookup => {
            let rest = rest.ok_or("lookup requires a REST client")?;
            let phone = req_str(args, "phone")?;
            let mut suffix = format!("PhoneNumbers/{}", encode_path_segment(phone));
            // Optional data packages: a CSV of `Fields` (line_type_intelligence,
            // caller_name). Twilio expects a comma-joined `Fields` query param.
            let fields: Vec<String> = match args.get("fields").and_then(Value::as_array) {
                Some(arr) => arr
                    .iter()
                    .filter_map(Value::as_str)
                    .filter(|s| !s.is_empty())
                    .map(str::to_owned)
                    .collect(),
                None => Vec::new(),
            };
            if !fields.is_empty() {
                let q =
                    serde_urlencoded::to_string([("Fields", fields.join(","))]).unwrap_or_default();
                suffix.push('?');
                suffix.push_str(&q);
            }
            map_rest(rest.get_url(&rest.lookups_url(&suffix)).await?)
        }
        Operation::VerifyStart => {
            let rest = rest.ok_or("verify_start requires a REST client")?;
            let svc = cfg
                .verify_service_sid
                .as_deref()
                .ok_or("verify_start requires a configured `verify_service_sid`")?;
            // Channel defaults to sms; Twilio accepts sms|call|email (and more).
            let channel = opt_str(args, "channel").unwrap_or("sms");
            let form: Vec<(String, String)> = vec![
                ("To".into(), req_str(args, "to")?.to_owned()),
                ("Channel".into(), channel.to_owned()),
            ];
            let suffix = format!("Services/{}/Verifications", encode_path_segment(svc));
            map_rest(rest.post_form_url(&rest.verify_url(&suffix), &form).await?)
        }
        Operation::VerifyCheck => {
            let rest = rest.ok_or("verify_check requires a REST client")?;
            let svc = cfg
                .verify_service_sid
                .as_deref()
                .ok_or("verify_check requires a configured `verify_service_sid`")?;
            let form: Vec<(String, String)> = vec![
                ("To".into(), req_str(args, "to")?.to_owned()),
                ("Code".into(), req_str(args, "code")?.to_owned()),
            ];
            let suffix = format!("Services/{}/VerificationCheck", encode_path_segment(svc));
            map_rest(rest.post_form_url(&rest.verify_url(&suffix), &form).await?)
        }
        Operation::ConfigureNumberWebhooks => {
            let rest = rest.ok_or("configure_number_webhooks requires a REST client")?;
            let sid = req_sid(args, "sid")?;
            let mut form: Vec<(String, String)> = Vec::new();
            for (arg, param) in [
                ("sms_url", "SmsUrl"),
                ("voice_url", "VoiceUrl"),
                ("status_callback", "StatusCallback"),
            ] {
                if let Some(v) = opt_str(args, arg) {
                    require_https(arg, v)?;
                    form.push((param.into(), v.to_owned()));
                }
            }
            if form.is_empty() {
                return Err("configure_number_webhooks needs at least one of sms_url/voice_url/status_callback".into());
            }
            map_rest(
                rest.post_form(&format!("IncomingPhoneNumbers/{sid}.json"), &form)
                    .await?,
            )
        }
    }
}

fn map_rest(outcome: RestOutcome) -> Result<OpResult, DispatchError> {
    Ok(match outcome {
        RestOutcome::Ok(v) => OpResult::Ok(v),
        RestOutcome::ToolError(msg) => OpResult::ToolError(msg),
    })
}

/// JSON Schema for a binding's tool input, derived from its operation.
pub fn op_input_schema(op: Operation) -> Value {
    let verbs = twiml::verbs_schema();
    match op {
        Operation::SendSms => json!({
            "type": "object",
            "properties": {
                "to": { "type": "string", "description": "Destination E.164 number" },
                "body": { "type": "string", "description": "Message text" },
                "from": { "type": "string", "description": "Sender number (overrides the binding default)" },
                "messaging_service_sid": { "type": "string" },
                "media_url": { "type": "array", "items": { "type": "string" }, "description": "MMS media URLs (https)" },
                "status_callback": { "type": "string", "description": "https status-callback URL" }
            },
            "required": ["to", "body"]
        }),
        Operation::ListMessages => json!({
            "type": "object",
            "properties": {
                "to": { "type": "string" },
                "from": { "type": "string" },
                "date_sent": { "type": "string", "description": "YYYY-MM-DD filter" }
            }
        }),
        Operation::GetMessage | Operation::RedactMessage | Operation::DeleteMessage => json!({
            "type": "object",
            "properties": { "sid": { "type": "string", "pattern": "^[A-Z]{2}[0-9a-fA-F]{32}$", "description": "Message SID (SM…)" } },
            "required": ["sid"]
        }),
        Operation::MakeCall => json!({
            "type": "object",
            "properties": {
                "to": { "type": "string" },
                "from": { "type": "string" },
                "twiml_verbs": verbs,
                "twiml": { "type": "string", "description": "Raw TwiML (alternative to twiml_verbs)" },
                "url": { "type": "string", "description": "https TwiML URL (alternative)" },
                "status_callback": { "type": "string" },
                "status_callback_event": { "type": "array", "items": { "type": "string" } },
                "machine_detection": { "type": "string" },
                "record": { "type": "boolean" }
            },
            "required": ["to"]
        }),
        Operation::ListCalls => json!({
            "type": "object",
            "properties": {
                "to": { "type": "string" },
                "from": { "type": "string" },
                "status": { "type": "string" }
            }
        }),
        Operation::GetCall => json!({
            "type": "object",
            "properties": { "sid": { "type": "string", "pattern": "^[A-Z]{2}[0-9a-fA-F]{32}$", "description": "Call SID (CA…)" } },
            "required": ["sid"]
        }),
        Operation::ModifyCall => json!({
            "type": "object",
            "properties": {
                "sid": { "type": "string", "pattern": "^[A-Z]{2}[0-9a-fA-F]{32}$" },
                "action": { "type": "string", "enum": ["hangup", "redirect"] },
                "url": { "type": "string", "description": "https TwiML URL (redirect)" },
                "twiml_verbs": verbs
            },
            "required": ["sid", "action"]
        }),
        Operation::GetRecording => json!({
            "type": "object",
            "properties": { "sid": { "type": "string", "pattern": "^[A-Z]{2}[0-9a-fA-F]{32}$", "description": "Recording SID (RE…)" } },
            "required": ["sid"]
        }),
        Operation::BuildTwiml => json!({
            "type": "object",
            "properties": { "twiml_verbs": verbs },
            "required": ["twiml_verbs"]
        }),
        Operation::StageCallResponse => json!({
            "type": "object",
            "properties": {
                "call_sid": { "type": "string", "description": "Stage for an active call" },
                "to": { "type": "string", "description": "Stage for an expected inbound (by destination)" },
                "twiml_verbs": verbs,
                "ttl_secs": { "type": "integer", "description": "How long the staged script stays valid (default 900)" }
            },
            "required": ["twiml_verbs"]
        }),
        Operation::Lookup => json!({
            "type": "object",
            "properties": {
                "phone": { "type": "string", "description": "Phone number to validate, ideally E.164 (e.g. +15551234567)" },
                "fields": {
                    "type": "array",
                    "items": { "type": "string", "enum": ["line_type_intelligence", "caller_name"] },
                    "description": "Optional Lookups data packages (joined into the `Fields` query param)"
                }
            },
            "required": ["phone"]
        }),
        Operation::VerifyStart => json!({
            "type": "object",
            "properties": {
                "to": { "type": "string", "description": "Recipient (E.164 number for sms/call, email address for email)" },
                "channel": { "type": "string", "enum": ["sms", "call", "email"], "description": "Delivery channel (default sms)" }
            },
            "required": ["to"]
        }),
        Operation::VerifyCheck => json!({
            "type": "object",
            "properties": {
                "to": { "type": "string", "description": "The same recipient passed to verify_start" },
                "code": { "type": "string", "description": "The OTP the user entered" }
            },
            "required": ["to", "code"]
        }),
        Operation::ConfigureNumberWebhooks => json!({
            "type": "object",
            "properties": {
                "sid": { "type": "string", "pattern": "^[A-Z]{2}[0-9a-fA-F]{32}$", "description": "IncomingPhoneNumber SID (PN…)" },
                "sms_url": { "type": "string" },
                "voice_url": { "type": "string" },
                "status_callback": { "type": "string" }
            },
            "required": ["sid"]
        }),
    }
}

/// JSON Schema for the op result envelope.
pub fn op_output_schema(op: Operation) -> Value {
    match op {
        Operation::BuildTwiml => json!({
            "type": "object",
            "properties": { "twiml": { "type": "string" } }
        }),
        Operation::ListMessages => json!({
            "type": "object",
            "properties": {
                "messages": { "type": "array", "items": { "type": "object" } },
                "next_page_uri": { "type": ["string", "null"] }
            }
        }),
        Operation::ListCalls => json!({
            "type": "object",
            "properties": {
                "calls": { "type": "array", "items": { "type": "object" } },
                "next_page_uri": { "type": ["string", "null"] }
            }
        }),
        _ => json!({ "type": "object", "description": "Twilio REST resource JSON" }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A SID reaching the REST path unchecked walks out of its collection:
    /// `Messages/../../../Accounts.json` normalizes to `/Accounts.json`,
    /// which is served with the account's Basic credentials and returns
    /// every account's `auth_token`.
    #[test]
    fn rejects_sid_that_is_not_a_twilio_sid() {
        for bad in [
            "../../../Accounts.json?",
            "../Calls/CA_TARGET.json?",
            "SM1",
            "sm00000000000000000000000000000000",
            "SM0000000000000000000000000000000g",
            "SM/0000000000000000000000000000000",
        ] {
            let args = json!({ "sid": bad });
            assert!(
                req_sid(&args, "sid").is_err(),
                "expected `{bad}` to be refused"
            );
        }
    }

    #[test]
    fn accepts_a_well_formed_sid() {
        let args = json!({ "sid": "SM0123456789abcdef0123456789abcdef" });
        assert_eq!(
            req_sid(&args, "sid").unwrap(),
            "SM0123456789abcdef0123456789abcdef"
        );
    }

    #[tokio::test]
    async fn build_twiml_renders_locally() {
        let cfg = TwilioConfig::parse(&json!({
            "account_sid": "AC1", "operation": "build_twiml"
        }))
        .unwrap();
        let state = Arc::new(TwilioState::default());
        let args = json!({ "twiml_verbs": [{ "verb": "say", "text": "hi" }] });
        match execute_op(&cfg, None, &state, &args).await.unwrap() {
            OpResult::Ok(v) => {
                assert!(v["twiml"].as_str().unwrap().contains("<Say>hi</Say>"));
            }
            OpResult::ToolError(e) => panic!("unexpected tool error: {e}"),
        }
    }

    #[tokio::test]
    async fn stage_call_response_records_to_state() {
        let cfg = TwilioConfig::parse(&json!({
            "account_sid": "AC1", "operation": "stage_call_response"
        }))
        .unwrap();
        let state = Arc::new(TwilioState::default());
        let args = json!({
            "to": "+15551112222",
            "twiml_verbs": [{ "verb": "say", "text": "scripted" }]
        });
        match execute_op(&cfg, None, &state, &args).await.unwrap() {
            OpResult::Ok(v) => assert_eq!(v["staged"], json!(true)),
            OpResult::ToolError(e) => panic!("unexpected: {e}"),
        }
        assert_eq!(state.staged_count(), 1);
    }

    #[tokio::test]
    async fn stage_requires_key() {
        let cfg = TwilioConfig::parse(&json!({
            "account_sid": "AC1", "operation": "stage_call_response"
        }))
        .unwrap();
        let state = Arc::new(TwilioState::default());
        let args = json!({ "twiml_verbs": [{ "verb": "hangup" }] });
        match execute_op(&cfg, None, &state, &args).await.unwrap() {
            OpResult::ToolError(e) => assert!(e.contains("call_sid") || e.contains("to")),
            OpResult::Ok(_) => panic!("expected tool error"),
        }
    }

    #[tokio::test]
    async fn send_sms_missing_to_is_tool_error() {
        let cfg = TwilioConfig::parse(&json!({
            "account_sid": "AC1", "auth_token": "t", "operation": "send_sms", "from": "+1555"
        }))
        .unwrap();
        let state = Arc::new(TwilioState::default());
        // A rest client is present, so dispatch reaches the required-arg check.
        let rest = TwilioRest::new(&cfg, cfg.rest_auth().unwrap()).unwrap();
        let args = json!({ "body": "hi" });
        match execute_op(&cfg, Some(&rest), &state, &args).await.unwrap() {
            OpResult::ToolError(e) => assert!(e.contains("to")),
            OpResult::Ok(_) => panic!("expected tool error"),
        }
    }

    #[tokio::test]
    async fn media_url_must_be_https() {
        let cfg = TwilioConfig::parse(&json!({
            "account_sid": "AC1", "auth_token": "t", "operation": "send_sms", "from": "+1555"
        }))
        .unwrap();
        let state = Arc::new(TwilioState::default());
        // Build a rest client so the op reaches the media_url check.
        let rest = TwilioRest::new(&cfg, cfg.rest_auth().unwrap()).unwrap();
        let args = json!({ "to": "+1666", "body": "hi", "media_url": ["http://insecure/x.png"] });
        match execute_op(&cfg, Some(&rest), &state, &args).await.unwrap() {
            OpResult::ToolError(e) => assert!(e.contains("https")),
            OpResult::Ok(_) => panic!("expected tool error"),
        }
    }

    #[tokio::test]
    async fn lookup_missing_phone_is_tool_error() {
        let cfg = TwilioConfig::parse(&json!({
            "account_sid": "AC1", "auth_token": "t", "operation": "lookup"
        }))
        .unwrap();
        let state = Arc::new(TwilioState::default());
        let rest = TwilioRest::new(&cfg, cfg.rest_auth().unwrap()).unwrap();
        match execute_op(&cfg, Some(&rest), &state, &json!({}))
            .await
            .unwrap()
        {
            OpResult::ToolError(e) => assert!(e.contains("phone")),
            OpResult::Ok(_) => panic!("expected tool error"),
        }
    }

    #[tokio::test]
    async fn verify_check_missing_code_is_tool_error() {
        let cfg = TwilioConfig::parse(&json!({
            "account_sid": "AC1", "auth_token": "t", "operation": "verify_check",
            "verify_service_sid": "VA1"
        }))
        .unwrap();
        let state = Arc::new(TwilioState::default());
        let rest = TwilioRest::new(&cfg, cfg.rest_auth().unwrap()).unwrap();
        let args = json!({ "to": "+1555" });
        match execute_op(&cfg, Some(&rest), &state, &args).await.unwrap() {
            OpResult::ToolError(e) => assert!(e.contains("code")),
            OpResult::Ok(_) => panic!("expected tool error"),
        }
    }

    #[test]
    fn encode_path_segment_encodes_plus() {
        assert_eq!(encode_path_segment("+15551234567"), "%2B15551234567");
        assert_eq!(encode_path_segment("abc-1.2_3~"), "abc-1.2_3~");
    }

    #[test]
    fn input_schema_lookup_requires_phone() {
        let s = op_input_schema(Operation::Lookup);
        assert!(s["required"].as_array().unwrap().contains(&json!("phone")));
    }

    #[test]
    fn input_schema_verify_check_requires_to_code() {
        let s = op_input_schema(Operation::VerifyCheck);
        let req = s["required"].as_array().unwrap();
        assert!(req.contains(&json!("to")));
        assert!(req.contains(&json!("code")));
    }

    #[test]
    fn input_schema_send_sms_requires_to_body() {
        let s = op_input_schema(Operation::SendSms);
        let req = s["required"].as_array().unwrap();
        assert!(req.contains(&json!("to")));
        assert!(req.contains(&json!("body")));
    }

    #[test]
    fn input_schema_make_call_has_verbs() {
        let s = op_input_schema(Operation::MakeCall);
        assert!(s["properties"]["twiml_verbs"].is_object());
    }
}
