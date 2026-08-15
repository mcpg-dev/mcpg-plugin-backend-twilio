//! cdylib bridges + multi-entity `declare_plugin!`.
//!
//! ONE cdylib carrying THREE entities:
//! - `backend` (`SyncBackendPlugin`) — operation-dispatched Twilio REST tools.
//! - `http_route` (`SyncHttpRoute`) — the inbound webhook receiver.
//! - `watch_strategy` (`SyncWatchStrategyPlugin`, kind `twilio_inbound`) — the
//!   native `resources/updated` push path, driven by the webhook.
//!
//! All three entities share one [`TwilioState`]: the backend's
//! `stage_call_response` stages scripts the webhook later serves, and the
//! webhook publishes in-process notices the watch entity's dispatcher fans out.
//! Each entity factory is invoked independently by the host with its own
//! config, so the shared state is held in a process-global [`OnceLock`] (the
//! cdylib is one `.so` instance per gateway process, so a single shared `Arc`
//! is correct + minimal).
//!
//! The backend / http_route bridges own a private multi-thread runtime and
//! `block_on` the async inner logic, mirroring the clickhouse / dynamodb
//! backend bridges. The watch entity ([`TwilioWatchCdylib`]) implements
//! `SyncWatchStrategyPlugin` directly (its dispatcher is the only async work,
//! on its own runtime), so it needs no bridge wrapper.

use std::sync::{Arc, OnceLock};

use mcpg_plugin_protocol::http_route::{HttpRouteRequest, HttpRouteResponse, RouteSpec};
use mcpg_plugin_protocol::{
    BackendError, BackendPlugin, BackendRequest, BackendResponse, PluginManifest, ResourcePage,
};
use mcpg_plugin_sdk::ffi::{SyncBackendPlugin, SyncHttpRoute};
use mcpg_plugin_sdk::{HostHandle, HostHandleBackendHost};
use serde_json::Value;

use crate::backend_plugin::TwilioBackendPlugin;
use crate::config::TwilioWebhookConfig;
use crate::state::TwilioState;
use crate::watch::TwilioWatchCdylib;
use crate::webhook::TwilioWebhook;

/// Process-global shared state, lazily built and handed to both entities.
fn shared_state() -> Arc<TwilioState> {
    static STATE: OnceLock<Arc<TwilioState>> = OnceLock::new();
    STATE
        .get_or_init(|| Arc::new(TwilioState::default()))
        .clone()
}

fn build_runtime(name: &str) -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .thread_name(name.to_owned())
        .enable_all()
        .build()
        .unwrap_or_else(|e| panic!("twilio cdylib: tokio runtime init failed: {e}"))
}

// ---------------------------------------------------------------------------
// backend entity bridge
// ---------------------------------------------------------------------------

pub struct TwilioBackendCdylib {
    inner: TwilioBackendPlugin,
    host: Arc<dyn mcpg_plugin_protocol::BackendHost>,
    rt: tokio::runtime::Runtime,
}

impl TwilioBackendCdylib {
    pub fn from_host_config(_config_json: &str, host: HostHandle) -> Self {
        Self {
            inner: TwilioBackendPlugin::new(shared_state()),
            host: Arc::new(HostHandleBackendHost::new(host)),
            rt: build_runtime("mcpg-backend-twilio"),
        }
    }
}

impl SyncBackendPlugin for TwilioBackendCdylib {
    fn manifest(&self) -> &PluginManifest {
        BackendPlugin::manifest(&self.inner)
    }

    fn kind(&self) -> &str {
        BackendPlugin::kind(&self.inner)
    }

    fn register_profile(&self, profile_name: &str, spec: &Value) -> Result<(), BackendError> {
        self.rt.block_on(BackendPlugin::register_profile(
            &self.inner,
            profile_name,
            spec,
            Arc::clone(&self.host),
        ))
    }

    fn execute(
        &self,
        profile_name: &str,
        request: BackendRequest,
    ) -> Result<BackendResponse, BackendError> {
        self.rt
            .block_on(BackendPlugin::execute(&self.inner, profile_name, request))
    }

    fn input_schema(&self, profile_name: &str) -> Option<Value> {
        BackendPlugin::input_schema(&self.inner, profile_name)
    }

    fn output_schema(&self, profile_name: &str) -> Option<Value> {
        BackendPlugin::output_schema(&self.inner, profile_name)
    }

    fn audit_metadata(&self, profile_name: &str) -> serde_json::Map<String, Value> {
        BackendPlugin::audit_metadata(&self.inner, profile_name)
    }

    fn list_resources(
        &self,
        profile_name: &str,
        cursor: Option<&str>,
    ) -> Result<ResourcePage, BackendError> {
        self.rt.block_on(BackendPlugin::list_resources(
            &self.inner,
            profile_name,
            cursor,
        ))
    }

    fn complete_template_variable(
        &self,
        profile_name: &str,
        variable_name: &str,
        prefix: &str,
        config: &Value,
        context: &std::collections::BTreeMap<String, String>,
    ) -> Result<Vec<String>, BackendError> {
        self.rt.block_on(BackendPlugin::complete_template_variable(
            &self.inner,
            profile_name,
            variable_name,
            prefix,
            config,
            context,
        ))
    }
}

// ---------------------------------------------------------------------------
// http_route entity bridge
// ---------------------------------------------------------------------------

pub struct TwilioWebhookCdylib {
    inner: TwilioWebhook,
}

impl TwilioWebhookCdylib {
    /// Build from the webhook config + captured host handle. A malformed config
    /// panics (the FFI `make` slot turns that into a boot rejection — fail
    /// CLOSED on a misconfigured signing token / base URL).
    pub fn from_host_config(config_json: &str, host: HostHandle) -> Self {
        let cfg = TwilioWebhookConfig::parse(config_json)
            .unwrap_or_else(|e| panic!("twilio webhook config invalid: {e}"));
        Self {
            inner: TwilioWebhook::new(cfg, shared_state(), host),
        }
    }
}

impl SyncHttpRoute for TwilioWebhookCdylib {
    fn manifest(&self) -> &PluginManifest {
        self.inner.manifest()
    }

    fn routes(&self) -> Vec<RouteSpec> {
        self.inner.routes()
    }

    fn handle(&self, req: HttpRouteRequest) -> HttpRouteResponse {
        self.inner.handle(req)
    }
}

// ---------------------------------------------------------------------------
// watch_strategy entity factory
// ---------------------------------------------------------------------------

impl TwilioWatchCdylib {
    /// Infallible cdylib factory. `config_json` + host are ignored — the watch
    /// carries no plugin-level config (the per-watch `kinds` filter arrives via
    /// the `watch` spec) and its source is the shared in-process notice
    /// channel, not the host. Shares the SAME process-global [`TwilioState`] as
    /// the backend + webhook entities so webhook notices reach the dispatcher.
    pub fn from_host_config(_config_json: &str, _host: HostHandle) -> Self {
        Self::new(shared_state())
    }
}

// cdylib export — three entities under `dev.mcpg.backend.twilio`. The backend +
// http_route entities need `NetworkOutbound` (REST calls + the webhook's
// handler-tool / push); the http_route entity additionally gets `HttpRouteServe`
// implicitly from its kind. The watch entity is purely in-process (no I/O) but
// shares the one declared capability set. NetworkOutbound is a unit capability
// variant. The watch entity self-describes via its `manifest()` slot and is
// distinguished by its `inner_name` slug.
mcpg_plugin_sdk::declare_plugin! {
    plugin_id: "dev.mcpg.backend.twilio",
    plugin_version: env!("CARGO_PKG_VERSION"),
    descriptor_yaml: include_str!("../plugin.yaml"),
    capabilities: &[::mcpg_plugin_protocol::capability::Capability::NetworkOutbound],
    // This kind may appear as a backend pipeline step, so it must declare
    // `pipeline_capable`. Every other fact is the behaviour-neutral default
    // (health Skip — HTTP-client-tracked; label = kind; no dynamic list).
    backend_profile: ::mcpg_plugin_protocol::manifest::BackendProfile {
        pipeline_capable: true,
        ..::core::default::Default::default()
    },
    entities: [
        backend as binding {
            inner_name: "",
            plugin_type: TwilioBackendCdylib,
            factory: |cfg, host: ::mcpg_plugin_sdk::HostHandle|
                TwilioBackendCdylib::from_host_config(cfg, host),
        },
        http_route as hooks {
            inner_name: "hooks",
            plugin_type: TwilioWebhookCdylib,
            factory: |cfg, host: ::mcpg_plugin_sdk::HostHandle|
                TwilioWebhookCdylib::from_host_config(cfg, host),
        },
        watch_strategy as watch {
            inner_name: "watch",
            plugin_type: TwilioWatchCdylib,
            factory: |cfg, host: ::mcpg_plugin_sdk::HostHandle|
                TwilioWatchCdylib::from_host_config(cfg, host),
        },
    ],
}
