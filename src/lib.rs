//! `dev.mcpg.backend.twilio` — Twilio SMS + Voice plugin.
//!
//! One cdylib carrying THREE entities (see [`cdylib`]):
//!
//! - a `backend` binding whose operations proxy the Twilio REST API — send /
//!   list / get / redact / delete SMS, make / list / get / modify calls, fetch
//!   recordings, author TwiML locally, and stage call responses, plus an opt-in
//!   `configure_number_webhooks`. One binding == one [`config::Operation`]
//!   (the `soap` / `dynamodb` op model). A binding may serve the tool surface
//!   (default), or the resource surface (`twilio://message/{sid}` reads + list).
//!
//! - an `http_route` entity that receives Twilio's inbound SMS / voice / gather
//!   / status webhooks, validates `X-Twilio-Signature` (HMAC-SHA1, constant
//!   time) BEFORE any side effect, records the event into a shared in-process
//!   ring, runs three complementary inbound-control levels (staged script →
//!   handler tool → templated default → safe `<Reject/>`), returns TwiML, and
//!   publishes an in-process notice for the watch entity.
//!
//! - a `watch_strategy` entity (kind `twilio_inbound`) that pushes
//!   `notifications/resources/updated` to subscribed MCP clients natively when
//!   the webhook receives an inbound event — no `notify_webhook_url` HTTP
//!   round-trip. The webhook is the source; this entity's dispatcher fans the
//!   in-process notice out to registered watchers (filtered by an optional
//!   `kinds` spec).
//!
//! REST auth is HTTP Basic with an API Key (recommended) or the Account Auth
//! Token; the webhook signature is ALWAYS keyed by the Account Auth Token (API
//! Key secrets do not sign webhooks). Secrets arrive resolved from `${cred://…}`
//! at config load; a bare `cred://` left in a request argument is rejected.
//! Transport is pure-Rust reqwest + rustls (no native-tls / OpenSSL).

mod backend_plugin;
mod config;
mod rest;
mod signature;
mod state;
mod surface;
mod tools;
mod twiml;
mod watch;
mod webhook;

#[cfg(any(feature = "cdylib-export", feature = "static-firstparty"))]
mod cdylib;

pub use backend_plugin::TwilioBackendPlugin;
pub use config::{Operation, TwilioConfig, TwilioWebhookConfig};
pub use state::TwilioState;
pub use watch::TwilioWatchCdylib;
pub use webhook::TwilioWebhook;

/// Compute the expected `X-Twilio-Signature` for a form webhook. Exposed only
/// for the integration suite (which signs the requests it simulates).
#[cfg(feature = "integration-tests")]
pub fn signature_for_test(auth_token: &str, url: &str, params: &[(String, String)]) -> String {
    signature::expected_signature_form(auth_token, url, params)
}
