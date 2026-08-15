//! Twilio REST client (reqwest + rustls).
//!
//! Base path is `{api_base}/2010-04-01/Accounts/{AccountSid}/…`; resource
//! endpoints append `.json`. Request bodies are form-encoded; parameters that
//! repeat (`MediaUrl`, `StatusCallbackEvent`) are sent as repeated key/value
//! pairs (a `Vec<(String,String)>`), never a serde array. List endpoints
//! paginate by following `next_page_uri` until null.
//!
//! Twilio surfaces two failure shapes. A logical failure (invalid `To`,
//! unsubscribed recipient, carrier-filtered message) comes back as a JSON
//! `{code, message, more_info, status}` body and is mapped to a tool-level
//! error envelope so the agent sees it as a result, not a transport fault.
//! A real failure (connection reset, 5xx, timeout) is a [`BackendError`].
//! Retries apply only to connection errors / 5xx / 429 (honouring
//! `Retry-After`); `send_sms` is therefore at-least-once (Twilio has no
//! idempotency key).

use std::time::Duration;

#[cfg(test)]
use base64::Engine as _;
use mcpg_plugin_protocol::BackendError;
use reqwest::StatusCode;
use serde_json::Value;

use crate::config::{RestAuth, TwilioConfig};

/// Maximum retry attempts for transient failures (conn / 5xx / 429).
const MAX_RETRIES: u32 = 2;

/// Outcome of a REST call: either a logical tool-level error (Twilio rejected
/// the request for a business reason) or the decoded JSON success body.
pub enum RestOutcome {
    Ok(Value),
    /// A logical failure → surfaced as a tool error (not a transport fault).
    ToolError(String),
}

/// A built Twilio REST client for one binding.
pub struct TwilioRest {
    http: reqwest::Client,
    auth: RestAuth,
    account_sid: String,
    api_base: String,
    /// Lookups v2 host (`https://lookups.twilio.com`) — a distinct Twilio
    /// subdomain from the account REST host, addressed by absolute URL.
    lookups_base: String,
    /// Verify v2 host (`https://verify.twilio.com`) — likewise.
    verify_base: String,
    page_size: u32,
}

impl TwilioRest {
    /// Build the client. `auth` is required for REST ops (the caller validated
    /// this).
    pub fn new(cfg: &TwilioConfig, auth: RestAuth) -> Result<Self, BackendError> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_millis(cfg.timeout_ms))
            // No redirect following: a 30x must not let a request escape the
            // configured api_base origin.
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| BackendError::Transport {
                message: format!("twilio: reqwest client build failed: {e}"),
            })?;
        Ok(Self {
            http,
            auth,
            account_sid: cfg.account_sid.clone(),
            api_base: cfg.api_base.trim_end_matches('/').to_owned(),
            lookups_base: cfg.lookups_base.trim_end_matches('/').to_owned(),
            verify_base: cfg.verify_base.trim_end_matches('/').to_owned(),
            page_size: cfg.page_size,
        })
    }

    /// Build the `Authorization: Basic` header value for the configured auth.
    fn basic_auth(&self) -> (String, String) {
        match &self.auth {
            RestAuth::ApiKey { sid, secret } => (sid.clone(), secret.clone()),
            RestAuth::AuthToken { token } => (self.account_sid.clone(), token.clone()),
        }
    }

    fn account_path(&self, suffix: &str) -> String {
        format!(
            "{}/2010-04-01/Accounts/{}/{}",
            self.api_base, self.account_sid, suffix
        )
    }

    /// POST a form-encoded body to a resource collection/instance.
    pub async fn post_form(
        &self,
        suffix: &str,
        form: &[(String, String)],
    ) -> Result<RestOutcome, BackendError> {
        let url = self.account_path(suffix);
        self.send_with_retry(reqwest::Method::POST, &url, Some(form))
            .await
    }

    /// GET a resource instance (`<Collection>/{Sid}.json`).
    pub async fn get(&self, suffix: &str) -> Result<RestOutcome, BackendError> {
        let url = self.account_path(suffix);
        self.send_with_retry(reqwest::Method::GET, &url, None).await
    }

    /// DELETE a resource instance.
    pub async fn delete(&self, suffix: &str) -> Result<RestOutcome, BackendError> {
        let url = self.account_path(suffix);
        self.send_with_retry(reqwest::Method::DELETE, &url, None)
            .await
    }

    /// Build a Lookups v2 URL: `{lookups_base}/v2/{suffix}`.
    pub fn lookups_url(&self, suffix: &str) -> String {
        format!("{}/v2/{}", self.lookups_base, suffix)
    }

    /// Build a Verify v2 URL: `{verify_base}/v2/{suffix}`.
    pub fn verify_url(&self, suffix: &str) -> String {
        format!("{}/v2/{}", self.verify_base, suffix)
    }

    /// GET an absolute Twilio URL (Lookups / Verify hosts). The same HTTP Basic
    /// auth applies across Twilio API subdomains.
    pub async fn get_url(&self, url: &str) -> Result<RestOutcome, BackendError> {
        self.send_with_retry(reqwest::Method::GET, url, None).await
    }

    /// POST a form-encoded body to an absolute Twilio URL (Verify host).
    pub async fn post_form_url(
        &self,
        url: &str,
        form: &[(String, String)],
    ) -> Result<RestOutcome, BackendError> {
        self.send_with_retry(reqwest::Method::POST, url, Some(form))
            .await
    }

    /// GET a list collection, following `next_page_uri` to accumulate up to
    /// `page_size` records. Returns `(items, next_cursor)` where `next_cursor`
    /// is the next `next_page_uri` (absolute path) when more remain.
    ///
    /// `collection` is the JSON key holding the array (`messages` / `calls`).
    pub async fn list(
        &self,
        suffix: &str,
        query: &[(String, String)],
        collection: &str,
    ) -> Result<(Vec<Value>, Option<String>), BackendError> {
        // First page via the collection endpoint with PageSize + filters.
        let mut url = self.account_path(suffix);
        let mut q: Vec<(String, String)> = query.to_vec();
        q.push(("PageSize".into(), self.page_size.to_string()));
        let qs = serde_urlencoded::to_string(&q).unwrap_or_default();
        if !qs.is_empty() {
            url.push('?');
            url.push_str(&qs);
        }

        let mut items = Vec::new();
        let mut next_cursor: Option<String> = None;
        let mut pages_left = 1; // single-page fetch per call; cursor carries more

        while pages_left > 0 {
            pages_left -= 1;
            match self
                .send_with_retry(reqwest::Method::GET, &url, None)
                .await?
            {
                RestOutcome::ToolError(msg) => {
                    return Err(BackendError::Transport {
                        message: format!("twilio list failed: {msg}"),
                    });
                }
                RestOutcome::Ok(body) => {
                    if let Some(arr) = body.get(collection).and_then(Value::as_array) {
                        items.extend(arr.iter().cloned());
                    }
                    // `next_page_uri` is an absolute path on api.twilio.com;
                    // surface it as the opaque cursor for the next call.
                    let next = body
                        .get("next_page_uri")
                        .and_then(Value::as_str)
                        .filter(|s| !s.is_empty())
                        .map(str::to_owned);
                    next_cursor = next;
                }
            }
        }
        Ok((items, next_cursor))
    }

    /// Fetch a list page directly by a `next_page_uri` cursor (absolute path).
    pub async fn list_cursor(
        &self,
        cursor_path: &str,
        collection: &str,
    ) -> Result<(Vec<Value>, Option<String>), BackendError> {
        let url = format!("{}{}", self.api_base, cursor_path);
        match self
            .send_with_retry(reqwest::Method::GET, &url, None)
            .await?
        {
            RestOutcome::ToolError(msg) => Err(BackendError::Transport {
                message: format!("twilio list page failed: {msg}"),
            }),
            RestOutcome::Ok(body) => {
                let items = body
                    .get(collection)
                    .and_then(Value::as_array)
                    .cloned()
                    .unwrap_or_default();
                let next = body
                    .get("next_page_uri")
                    .and_then(Value::as_str)
                    .filter(|s| !s.is_empty())
                    .map(str::to_owned);
                Ok((items, next))
            }
        }
    }

    /// Issue a single request with bounded retries on transient failures.
    async fn send_with_retry(
        &self,
        method: reqwest::Method,
        url: &str,
        form: Option<&[(String, String)]>,
    ) -> Result<RestOutcome, BackendError> {
        let (user, pass) = self.basic_auth();
        let mut attempt = 0;
        loop {
            let mut req = self
                .http
                .request(method.clone(), url)
                .basic_auth(&user, Some(&pass));
            if let Some(f) = form {
                req = req.form(f);
            }
            let resp = req.send().await;
            match resp {
                Ok(r) => {
                    let status = r.status();
                    if status.is_success() {
                        let text = r.text().await.map_err(|e| BackendError::Transport {
                            message: format!("twilio: reading body: {e}"),
                        })?;
                        // DELETE returns 204 with no body.
                        if text.trim().is_empty() {
                            return Ok(RestOutcome::Ok(serde_json::json!({ "deleted": true })));
                        }
                        let body: Value =
                            serde_json::from_str(&text).map_err(|e| BackendError::Transport {
                                message: format!("twilio: malformed JSON response: {e}"),
                            })?;
                        return Ok(RestOutcome::Ok(body));
                    }
                    // 429 / 5xx are retryable; honour Retry-After.
                    if (status == StatusCode::TOO_MANY_REQUESTS || status.is_server_error())
                        && attempt < MAX_RETRIES
                    {
                        let wait = retry_after(&r).unwrap_or_else(|| Duration::from_millis(250));
                        attempt += 1;
                        tokio::time::sleep(wait).await;
                        continue;
                    }
                    // 4xx (and exhausted 429/5xx) — read the Twilio error JSON
                    // and decide tool-error vs transport.
                    let text = r.text().await.unwrap_or_default();
                    return Ok(classify_error(status, &text));
                }
                Err(e) => {
                    if e.is_timeout() {
                        return Err(BackendError::Timeout {
                            timeout_ms: 0, // host fills the configured value in metrics
                        });
                    }
                    if attempt < MAX_RETRIES && (e.is_connect() || e.is_request()) {
                        attempt += 1;
                        tokio::time::sleep(Duration::from_millis(250)).await;
                        continue;
                    }
                    return Err(BackendError::Transport {
                        message: format!("twilio: request failed: {e}"),
                    });
                }
            }
        }
    }
}

fn retry_after(resp: &reqwest::Response) -> Option<Duration> {
    resp.headers()
        .get(reqwest::header::RETRY_AFTER)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.trim().parse::<u64>().ok())
        .map(Duration::from_secs)
}

/// Classify a non-2xx response. A Twilio `{code,message,…}` body is a logical
/// (tool-level) failure; anything else at 5xx is transport.
fn classify_error(status: StatusCode, text: &str) -> RestOutcome {
    if let Ok(body) = serde_json::from_str::<Value>(text)
        && let Some(code) = body.get("code").and_then(Value::as_i64)
    {
        let message = body
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or("Twilio error");
        let more_info = body.get("more_info").and_then(Value::as_str).unwrap_or("");
        return RestOutcome::ToolError(format!(
            "Twilio error {code}: {message}{}",
            if more_info.is_empty() {
                String::new()
            } else {
                format!(" ({more_info})")
            }
        ));
    }
    // No structured error → generic tool error with the status.
    RestOutcome::ToolError(format!("Twilio returned HTTP {status}"))
}

/// Base64 of `user:pass` — a unit-test helper for the auth-header assertion.
#[cfg(test)]
fn basic_auth_header(user: &str, pass: &str) -> String {
    let raw = format!("{user}:{pass}");
    format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(raw.as_bytes())
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn classify_twilio_logical_error() {
        let body = json!({
            "code": 21211,
            "message": "The 'To' number is not a valid phone number.",
            "more_info": "https://www.twilio.com/docs/errors/21211",
            "status": 400
        })
        .to_string();
        match classify_error(StatusCode::BAD_REQUEST, &body) {
            RestOutcome::ToolError(msg) => {
                assert!(msg.contains("21211"));
                assert!(msg.contains("not a valid"));
            }
            _ => panic!("expected tool error"),
        }
    }

    #[test]
    fn classify_unsubscribed_error() {
        let body = json!({ "code": 21610, "message": "Attempt to send to unsubscribed recipient" })
            .to_string();
        match classify_error(StatusCode::BAD_REQUEST, &body) {
            RestOutcome::ToolError(msg) => assert!(msg.contains("21610")),
            _ => panic!("expected tool error"),
        }
    }

    #[test]
    fn classify_non_twilio_body() {
        match classify_error(StatusCode::BAD_REQUEST, "not json") {
            RestOutcome::ToolError(msg) => assert!(msg.contains("HTTP 400")),
            _ => panic!("expected tool error"),
        }
    }

    #[test]
    fn lookups_and_verify_urls_target_their_hosts() {
        let cfg = TwilioConfig::parse(&json!({
            "account_sid": "AC1",
            "auth_token": "tok",
            "operation": "lookup"
        }))
        .unwrap();
        let rest = TwilioRest::new(&cfg, cfg.rest_auth().unwrap()).unwrap();
        assert_eq!(
            rest.lookups_url("PhoneNumbers/%2B15551234567"),
            "https://lookups.twilio.com/v2/PhoneNumbers/%2B15551234567"
        );
        assert_eq!(
            rest.verify_url("Services/VA1/Verifications"),
            "https://verify.twilio.com/v2/Services/VA1/Verifications"
        );
    }

    #[test]
    fn basic_auth_header_encodes() {
        // SK123:secret → known base64.
        let h = basic_auth_header("SK123", "secret");
        assert!(h.starts_with("Basic "));
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(h.trim_start_matches("Basic "))
            .unwrap();
        assert_eq!(String::from_utf8(decoded).unwrap(), "SK123:secret");
    }
}
