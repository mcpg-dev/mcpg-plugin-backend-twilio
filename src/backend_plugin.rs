//! [`BackendPlugin`] implementation for the Twilio backend entity.
//!
//! One binding == one [`Operation`]. `register_profile` parses + validates the
//! spec and (for REST ops) builds the reqwest client up front. `execute`
//! dispatches on the operation; logical Twilio failures become tool-level error
//! envelopes, real failures become [`BackendError`]s. The plugin shares an
//! `Arc<TwilioState>` with the webhook entity so `stage_call_response` stages
//! scripts the inbound-voice webhook later serves.

use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};

use async_trait::async_trait;
use mcpg_plugin_protocol::{
    BackendError, BackendHost, BackendPlugin, BackendRequest, BackendResponse, PluginManifest,
    ResourcePage, firstparty_manifest,
};
use serde_json::{Value, json};

use crate::config::{Operation, TwilioConfig};
use crate::rest::TwilioRest;
use crate::state::TwilioState;
use crate::surface::{self, Surface};
use crate::tools::{self, OpResult};

/// Sentinel the gateway projects verbatim as a `CallToolResult` (so logical
/// failures surface as `isError: true` tool results).
const VERBATIM_RESULT_KEY: &str = "__mcpg_verbatim_result";

/// One registered binding profile.
struct Profile {
    cfg: TwilioConfig,
    rest: Option<TwilioRest>,
}

pub struct TwilioBackendPlugin {
    manifest: PluginManifest,
    state: Arc<TwilioState>,
    profiles: RwLock<BTreeMap<String, Arc<Profile>>>,
}

impl TwilioBackendPlugin {
    pub fn new(state: Arc<TwilioState>) -> Self {
        Self {
            manifest: firstparty_manifest! {
                id: "dev.mcpg.backend.twilio",
                name: "Twilio SMS + Voice Binding",
                class: Backend,
            },
            state,
            profiles: RwLock::new(BTreeMap::new()),
        }
    }

    fn profile(&self, name: &str) -> Option<Arc<Profile>> {
        self.profiles
            .read()
            .expect("twilio profiles poisoned")
            .get(name)
            .cloned()
    }
}

fn verbatim_error(msg: &str) -> Vec<u8> {
    let envelope = json!({
        VERBATIM_RESULT_KEY: {
            "content": [ { "type": "text", "text": msg } ],
            "isError": true,
        }
    });
    serde_json::to_vec(&envelope).unwrap_or_else(|_| b"{}".to_vec())
}

#[async_trait]
impl BackendPlugin for TwilioBackendPlugin {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    fn kind(&self) -> &str {
        "twilio"
    }

    async fn register_profile(
        &self,
        profile_name: &str,
        spec: &Value,
        _host: Arc<dyn BackendHost>,
    ) -> Result<(), BackendError> {
        let cfg =
            TwilioConfig::parse(spec).map_err(|e| BackendError::InvalidSpec { message: e })?;
        let rest = if cfg.operation.needs_rest() {
            let auth = cfg.rest_auth().ok_or_else(|| BackendError::InvalidSpec {
                message: "REST operation requires credentials".into(),
            })?;
            Some(TwilioRest::new(&cfg, auth)?)
        } else {
            None
        };
        self.profiles
            .write()
            .expect("twilio profiles poisoned")
            .insert(profile_name.to_owned(), Arc::new(Profile { cfg, rest }));
        Ok(())
    }

    async fn execute(
        &self,
        profile_name: &str,
        request: BackendRequest,
    ) -> Result<BackendResponse, BackendError> {
        let profile = self
            .profile(profile_name)
            .ok_or_else(|| BackendError::ProfileNotFound {
                backend_name: profile_name.to_owned(),
            })?;

        let args: Value = if request.payload.is_empty() {
            json!({})
        } else {
            match serde_json::from_slice(&request.payload) {
                Ok(v) => v,
                Err(e) => {
                    return Ok(BackendResponse {
                        payload: verbatim_error(&format!("invalid tool arguments JSON: {e}")),
                        truncated: false,
                    });
                }
            }
        };

        let result =
            tools::execute_op(&profile.cfg, profile.rest.as_ref(), &self.state, &args).await?;

        match result {
            OpResult::ToolError(msg) => Ok(BackendResponse {
                payload: verbatim_error(&msg),
                truncated: false,
            }),
            OpResult::Ok(value) => {
                let body = match profile.cfg.surface {
                    Surface::Tool => value,
                    Surface::Resource => {
                        match surface::resolve_resource_uri(profile.cfg.uri.as_deref(), &args) {
                            Some(uri) => surface::resource_contents_body(uri, &value),
                            None => {
                                return Ok(BackendResponse {
                                    payload: verbatim_error(
                                        "resource surface requires a `uri` (set a static `uri` on the binding or invoke via resources/read)",
                                    ),
                                    truncated: false,
                                });
                            }
                        }
                    }
                    Surface::Prompt => surface::prompt_messages_body(&value),
                };
                let payload = serde_json::to_vec(&body).unwrap_or_else(|_| b"{}".to_vec());
                let truncated = surface::surface_truncated(
                    profile.cfg.surface,
                    payload.len(),
                    profile.cfg.max_response_bytes,
                );
                Ok(BackendResponse { payload, truncated })
            }
        }
    }

    fn input_schema(&self, profile_name: &str) -> Option<Value> {
        self.profile(profile_name)
            .map(|p| tools::op_input_schema(p.cfg.operation))
    }

    fn output_schema(&self, profile_name: &str) -> Option<Value> {
        self.profile(profile_name)
            .map(|p| tools::op_output_schema(p.cfg.operation))
    }

    fn audit_metadata(&self, profile_name: &str) -> serde_json::Map<String, Value> {
        let mut m = serde_json::Map::new();
        if let Some(p) = self.profile(profile_name) {
            m.insert(
                "twilio.operation".into(),
                Value::String(p.cfg.operation.as_str().to_owned()),
            );
            m.insert(
                "twilio.account_sid".into(),
                Value::String(p.cfg.account_sid.clone()),
            );
        }
        m
    }

    /// `resources/list` for a resource-surface message binding: pull a page of
    /// `Messages.json` and map to `twilio://message/{sid}` entries. The cursor
    /// is an opaque Twilio `next_page_uri` path. Non-message / non-resource
    /// bindings inherit the empty page.
    async fn list_resources(
        &self,
        profile_name: &str,
        cursor: Option<&str>,
    ) -> Result<ResourcePage, BackendError> {
        let profile = self
            .profile(profile_name)
            .ok_or_else(|| BackendError::ProfileNotFound {
                backend_name: profile_name.to_owned(),
            })?;
        let (Some(rest), Operation::ListMessages | Operation::GetMessage) =
            (profile.rest.as_ref(), profile.cfg.operation)
        else {
            return Ok(ResourcePage::empty());
        };
        let (items, next) = match cursor {
            Some(c) => rest.list_cursor(c, "messages").await?,
            None => rest.list("Messages.json", &[], "messages").await?,
        };
        Ok(surface::messages_to_resource_page(&items, next))
    }

    /// Completion for a `{sid}` template variable — recent message SIDs,
    /// prefix-filtered. Only message bindings with a REST client complete.
    async fn complete_template_variable(
        &self,
        profile_name: &str,
        _variable_name: &str,
        prefix: &str,
        _config: &Value,
        _context: &BTreeMap<String, String>,
    ) -> Result<Vec<String>, BackendError> {
        let profile = self
            .profile(profile_name)
            .ok_or_else(|| BackendError::ProfileNotFound {
                backend_name: profile_name.to_owned(),
            })?;
        let Some(rest) = profile.rest.as_ref() else {
            return Ok(vec![]);
        };
        let (items, _next) = rest.list("Messages.json", &[], "messages").await?;
        Ok(surface::messages_to_sids(&items, prefix, 50))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plugin() -> TwilioBackendPlugin {
        TwilioBackendPlugin::new(Arc::new(TwilioState::default()))
    }

    async fn register(
        p: &TwilioBackendPlugin,
        name: &str,
        spec: Value,
    ) -> Result<(), BackendError> {
        let host = mcpg_plugin_protocol::noop_backend_host();
        BackendPlugin::register_profile(p, name, &spec, host).await
    }

    #[tokio::test]
    async fn kind_and_manifest() {
        let p = plugin();
        assert_eq!(BackendPlugin::kind(&p), "twilio");
        assert_eq!(p.manifest.id, "dev.mcpg.backend.twilio");
    }

    #[tokio::test]
    async fn register_rejects_bad_spec() {
        let p = plugin();
        let err = register(&p, "t", json!({ "operation": "send_sms" })).await;
        assert!(matches!(err, Err(BackendError::InvalidSpec { .. })));
    }

    #[tokio::test]
    async fn local_op_registers_without_credentials() {
        let p = plugin();
        register(
            &p,
            "t",
            json!({ "account_sid": "AC1", "operation": "build_twiml" }),
        )
        .await
        .unwrap();
        assert!(p.profile("t").unwrap().rest.is_none());
    }

    #[tokio::test]
    async fn build_twiml_execute_round_trip() {
        let p = plugin();
        register(
            &p,
            "t",
            json!({ "account_sid": "AC1", "operation": "build_twiml" }),
        )
        .await
        .unwrap();
        let resp = BackendPlugin::execute(
            &p,
            "t",
            BackendRequest {
                payload: serde_json::to_vec(&json!({
                    "twiml_verbs": [{ "verb": "say", "text": "hi" }]
                }))
                .unwrap(),
                headers: vec![],
                request_id: "r".into(),
                session_id: None,
                identity: None,
                idempotency: None,
            },
        )
        .await
        .unwrap();
        let v: Value = serde_json::from_slice(&resp.payload).unwrap();
        assert!(v["twiml"].as_str().unwrap().contains("<Say>hi</Say>"));
    }

    #[tokio::test]
    async fn execute_unknown_profile_is_profile_not_found() {
        let p = plugin();
        let err = BackendPlugin::execute(
            &p,
            "missing",
            BackendRequest {
                payload: b"{}".to_vec(),
                headers: vec![],
                request_id: "r".into(),
                session_id: None,
                identity: None,
                idempotency: None,
            },
        )
        .await;
        assert!(matches!(err, Err(BackendError::ProfileNotFound { .. })));
    }

    #[tokio::test]
    async fn input_schema_tracks_operation() {
        let p = plugin();
        register(
            &p,
            "t",
            json!({ "account_sid": "AC1", "operation": "get_message", "auth_token": "x" }),
        )
        .await
        .unwrap();
        let s = BackendPlugin::input_schema(&p, "t").unwrap();
        assert_eq!(s["required"][0], "sid");
    }

    #[tokio::test]
    async fn audit_metadata_carries_op_and_account() {
        let p = plugin();
        register(
            &p,
            "t",
            json!({ "account_sid": "AC9", "operation": "build_twiml" }),
        )
        .await
        .unwrap();
        let m = BackendPlugin::audit_metadata(&p, "t");
        assert_eq!(m["twilio.operation"], "build_twiml");
        assert_eq!(m["twilio.account_sid"], "AC9");
    }

    #[tokio::test]
    async fn list_resources_empty_for_non_message_binding() {
        let p = plugin();
        register(
            &p,
            "t",
            json!({ "account_sid": "AC1", "operation": "build_twiml" }),
        )
        .await
        .unwrap();
        let page = BackendPlugin::list_resources(&p, "t", None).await.unwrap();
        assert!(page.resources.is_empty());
    }

    #[tokio::test]
    async fn stage_then_visible_in_shared_state() {
        let state = Arc::new(TwilioState::default());
        let p = TwilioBackendPlugin::new(state.clone());
        register(
            &p,
            "t",
            json!({ "account_sid": "AC1", "operation": "stage_call_response" }),
        )
        .await
        .unwrap();
        let _ = BackendPlugin::execute(
            &p,
            "t",
            BackendRequest {
                payload: serde_json::to_vec(&json!({
                    "to": "+1555",
                    "twiml_verbs": [{ "verb": "hangup" }]
                }))
                .unwrap(),
                headers: vec![],
                request_id: "r".into(),
                session_id: None,
                identity: None,
                idempotency: None,
            },
        )
        .await
        .unwrap();
        // The webhook entity (sharing `state`) would see this staged script.
        assert_eq!(state.staged_count(), 1);
    }
}
