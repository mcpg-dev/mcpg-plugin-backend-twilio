//! `watch_strategy` entity (`twilio_inbound`) — the NATIVE push path.
//!
//! Unlike a polling or topic-subscribing watch strategy, Twilio has no external
//! source to poll: the plugin's own `http_route` webhook IS the source. When an
//! inbound SMS / voice / status webhook lands, the handler publishes an
//! [`InboundNotice`] onto the shared in-process channel (a non-blocking `send`).
//! This entity runs ONE dispatcher task on a private runtime that drains that
//! channel and, for each notice, calls the host `emit_event` of every watcher
//! whose `kinds` filter matches — making the host emit
//! `notifications/resources/updated` for the watched collection URI.
//!
//! The dispatcher runs on this entity's runtime, NOT the webhook's, so
//! `emit_event` is always invoked OUTSIDE the webhook's `block_on` — there is
//! no nested `block_on` and no deadlock. The webhook never touches `emit_event`
//! directly; it only `try`-sends a notice.
//!
//! `notify_webhook_url` remains documented as the cross-replica push path; this
//! in-process strategy is single-replica (the notice channel lives in one
//! gateway process), matching the existing single-gateway-affinity caveat.

use std::collections::BTreeSet;
use std::sync::Arc;

use mcpg_plugin_protocol::backend::{WatchError, WatchEvent};
use mcpg_plugin_protocol::{PluginManifest, firstparty_manifest};
use mcpg_plugin_sdk::ffi::{SyncWatchStrategyPlugin, WatchHandleBox};
use serde::Deserialize;
use serde_json::Value;
use tokio::sync::oneshot;
use tracing::warn;

use crate::state::{InboundNotice, TwilioState};

pub const PLUGIN_ID: &str = "dev.mcpg.backend.twilio";

/// The strategy discriminator this entity handles.
pub const WATCH_KIND: &str = "twilio_inbound";

/// The inbound kinds a watcher can filter on. A watcher with an empty/absent
/// `kinds` spec fires on all of them.
const ALL_KINDS: [&str; 3] = ["sms", "voice", "status"];

/// Per-watch spec: an optional `kinds` filter selecting which inbound notice
/// kinds fire this watcher. Absent → all kinds.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WatchSpec {
    /// Which inbound kinds emit a tick (`sms` / `voice` / `status`). Default:
    /// all three.
    #[serde(default)]
    kinds: Option<Vec<String>>,
}

/// Parse + validate the per-watch `kinds` filter. Unknown kinds or a malformed
/// spec are `InvalidSpec`.
fn parse_kinds(spec: &Value) -> Result<BTreeSet<String>, WatchError> {
    let parsed: WatchSpec =
        serde_json::from_value(spec.clone()).map_err(|e| WatchError::InvalidSpec {
            message: format!("invalid twilio_inbound watch spec: {e}"),
        })?;
    let kinds: BTreeSet<String> = match parsed.kinds {
        None => ALL_KINDS.iter().map(|s| (*s).to_owned()).collect(),
        Some(list) => {
            if list.is_empty() {
                return Err(WatchError::InvalidSpec {
                    message: "kinds must not be empty (omit it to watch all)".to_owned(),
                });
            }
            for k in &list {
                if !ALL_KINDS.contains(&k.as_str()) {
                    return Err(WatchError::InvalidSpec {
                        message: format!(
                            "unknown inbound kind `{k}`; expected one of sms/voice/status"
                        ),
                    });
                }
            }
            list.into_iter().collect()
        }
    };
    Ok(kinds)
}

/// Cancel payload boxed behind the opaque [`WatchHandleBox`]: just the
/// registration id (cancel deregisters it from the shared state).
struct WatchCancelState {
    id: u64,
}

/// `watch_strategy` entity. Owns the shared [`TwilioState`] + a private runtime
/// running the single notice-fan-out dispatcher.
pub struct TwilioWatchCdylib {
    manifest: PluginManifest,
    state: Arc<TwilioState>,
    /// Private runtime hosting the dispatcher. Held for its lifetime: dropping
    /// the entity drops the runtime, which stops the dispatcher task.
    #[allow(dead_code)]
    rt: tokio::runtime::Runtime,
    /// Signals the dispatcher to stop ahead of the runtime drop.
    stop_tx: Option<oneshot::Sender<()>>,
}

impl TwilioWatchCdylib {
    /// Build the entity over the shared state, spawning the dispatcher task.
    /// `config_json` + host are ignored — the watch carries no plugin-level
    /// config (the per-watch `kinds` filter arrives via the `watch` spec) and
    /// the source is the in-process notice channel, not the host.
    pub fn new(state: Arc<TwilioState>) -> Self {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .thread_name("mcpg-watch-twilio")
            .enable_all()
            .build()
            .unwrap_or_else(|e| panic!("twilio watch: tokio runtime init failed: {e}"));

        let (stop_tx, mut stop_rx) = oneshot::channel::<()>();
        let dispatch_state = Arc::clone(&state);
        rt.spawn(async move {
            let mut rx = dispatch_state.subscribe_notices();
            loop {
                tokio::select! {
                    _ = &mut stop_rx => break,
                    recv = rx.recv() => match recv {
                        Ok(notice) => dispatch(&dispatch_state, &notice),
                        // Lagged: the dispatcher fell behind and the channel
                        // dropped notices. Keep going — Twilio REST stays the
                        // source of truth; the client re-reads on the next tick.
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                            warn!(plugin_id = PLUGIN_ID, dropped = n, "twilio watch: dispatcher lagged; notices dropped");
                        }
                        // Sender gone (state dropped) — nothing more will arrive.
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                    },
                }
            }
        });

        Self {
            manifest: firstparty_manifest! {
                id: "dev.mcpg.backend.twilio",
                name: "Twilio Inbound Watch Strategy",
                class: WatchStrategy,
            },
            state,
            rt,
            stop_tx: Some(stop_tx),
        }
    }
}

/// Fan one notice out to every matching registered watcher. Snapshots the
/// matching emitters under the state lock, then calls them after releasing it
/// (the host's emit may take time and must not hold the state mutex). The
/// `WatchEvent` payload is the default — Twilio inbound is not tied to an MCP
/// session, so `user_id` / `session_id` are both `None`.
fn dispatch(state: &TwilioState, notice: &InboundNotice) {
    let emitters = state.matching_emitters(&notice.kind);
    if emitters.is_empty() {
        return;
    }
    let event_json =
        serde_json::to_string(&WatchEvent::default()).unwrap_or_else(|_| "{}".to_owned());
    for (_uri, emit) in emitters {
        emit(&event_json);
    }
}

impl SyncWatchStrategyPlugin for TwilioWatchCdylib {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    fn kind(&self) -> &str {
        WATCH_KIND
    }

    fn watch(
        &self,
        resource_uri: &str,
        spec: &Value,
        emit_event: Box<dyn Fn(&str) + Send + Sync + 'static>,
    ) -> Result<WatchHandleBox, WatchError> {
        let kinds = parse_kinds(spec)?;
        let id = self
            .state
            .register_watch(resource_uri, kinds, Arc::from(emit_event));
        let state = Box::new(WatchCancelState { id });
        Ok(WatchHandleBox(Box::into_raw(state) as *mut ()))
    }

    fn cancel(&self, watch_handle: WatchHandleBox) {
        if watch_handle.0.is_null() {
            return;
        }
        // SAFETY: pointer produced by `Box::into_raw` in `watch`, round-tripped
        // by the host exactly once.
        #[allow(unsafe_code)]
        let state = unsafe { Box::from_raw(watch_handle.0 as *mut WatchCancelState) };
        self.state.unregister_watch(state.id);
    }

    fn shutdown(&self) {
        // Global teardown happens in `Drop`: signalling `stop_tx` and dropping
        // the runtime stops the dispatcher. `shutdown` takes `&self` and the
        // host drops the entity right after, so there is nothing to do here.
    }
}

impl Drop for TwilioWatchCdylib {
    fn drop(&mut self) {
        if let Some(tx) = self.stop_tx.take() {
            let _ = tx.send(());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use std::time::{Duration, Instant};

    use serde_json::json;

    type Sink = Arc<Mutex<Vec<String>>>;

    fn sink() -> Sink {
        Arc::new(Mutex::new(Vec::new()))
    }

    fn emit_for(s: &Sink) -> Box<dyn Fn(&str) + Send + Sync + 'static> {
        let s = Arc::clone(s);
        Box::new(move |ev: &str| s.lock().unwrap().push(ev.to_owned()))
    }

    fn count(s: &Sink) -> usize {
        s.lock().unwrap().len()
    }

    fn notice(kind: &str) -> InboundNotice {
        InboundNotice {
            kind: kind.into(),
            sid: Some("SM1".into()),
            from: Some("+1555".into()),
            to: Some("+1666".into()),
        }
    }

    /// Poll a condition until true or timeout.
    fn wait_until(mut cond: impl FnMut() -> bool, timeout: Duration) -> bool {
        let start = Instant::now();
        while start.elapsed() < timeout {
            if cond() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        cond()
    }

    fn plugin() -> (Arc<TwilioState>, TwilioWatchCdylib) {
        let state = Arc::new(TwilioState::default());
        let p = TwilioWatchCdylib::new(Arc::clone(&state));
        (state, p)
    }

    #[test]
    fn manifest_and_kind_are_correct() {
        use mcpg_plugin_protocol::PluginClass;
        let (_s, p) = plugin();
        let m = SyncWatchStrategyPlugin::manifest(&p);
        assert_eq!(m.id, PLUGIN_ID);
        assert_eq!(m.plugin_class, PluginClass::WatchStrategy);
        assert_eq!(p.kind(), WATCH_KIND);
    }

    #[test]
    fn watch_registers_and_returns_handle() {
        let (state, p) = plugin();
        let s = sink();
        let handle = p
            .watch("twilio://messages", &json!({}), emit_for(&s))
            .unwrap();
        assert_eq!(state.watch_count(), 1);
        p.cancel(handle);
        assert_eq!(state.watch_count(), 0);
    }

    #[test]
    fn matching_notice_drives_emit() {
        let (state, p) = plugin();
        let s = sink();
        let _handle = p
            .watch(
                "twilio://messages",
                &json!({ "kinds": ["sms"] }),
                emit_for(&s),
            )
            .unwrap();
        // Give the dispatcher a moment to subscribe its receiver.
        std::thread::sleep(Duration::from_millis(50));

        state.notify_inbound(notice("sms"));
        assert!(
            wait_until(|| count(&s) >= 1, Duration::from_secs(2)),
            "a matching sms notice should drive one emit"
        );
        let body = s.lock().unwrap()[0].clone();
        // Default WatchEvent serializes empty (user_id/session_id both None).
        assert_eq!(body, "{}");
    }

    #[test]
    fn kinds_filter_excludes_non_matching() {
        let (state, p) = plugin();
        let s = sink();
        let _handle = p
            .watch(
                "twilio://messages",
                &json!({ "kinds": ["sms"] }),
                emit_for(&s),
            )
            .unwrap();
        std::thread::sleep(Duration::from_millis(50));

        // A voice notice must NOT fire an sms-only watcher.
        state.notify_inbound(notice("voice"));
        std::thread::sleep(Duration::from_millis(200));
        assert_eq!(
            count(&s),
            0,
            "a voice notice must not fire an sms-only watch"
        );

        // A matching sms notice does.
        state.notify_inbound(notice("sms"));
        assert!(wait_until(|| count(&s) >= 1, Duration::from_secs(2)));
    }

    #[test]
    fn default_spec_watches_all_kinds() {
        let (state, p) = plugin();
        let s = sink();
        let _handle = p
            .watch("twilio://inbound", &json!({}), emit_for(&s))
            .unwrap();
        std::thread::sleep(Duration::from_millis(50));

        state.notify_inbound(notice("sms"));
        state.notify_inbound(notice("voice"));
        state.notify_inbound(notice("status"));
        assert!(
            wait_until(|| count(&s) >= 3, Duration::from_secs(2)),
            "an unfiltered watch should fire on all three kinds"
        );
    }

    #[test]
    fn cancel_deregisters_no_further_emits() {
        let (state, p) = plugin();
        let s = sink();
        let handle = p
            .watch("twilio://messages", &json!({}), emit_for(&s))
            .unwrap();
        std::thread::sleep(Duration::from_millis(50));

        state.notify_inbound(notice("sms"));
        assert!(wait_until(|| count(&s) >= 1, Duration::from_secs(2)));
        let after = count(&s);

        p.cancel(handle);
        assert_eq!(state.watch_count(), 0);

        // Notices after cancel must not reach the (deregistered) emitter.
        state.notify_inbound(notice("sms"));
        state.notify_inbound(notice("voice"));
        std::thread::sleep(Duration::from_millis(200));
        assert_eq!(count(&s), after, "no emits after cancel");
    }

    #[test]
    fn bad_spec_is_invalid_spec() {
        let (_s, p) = plugin();
        let snk = sink();
        // Unknown field.
        assert!(matches!(
            p.watch("twilio://x", &json!({ "bogus": 1 }), emit_for(&snk)),
            Err(WatchError::InvalidSpec { .. })
        ));
        // Unknown kind.
        assert!(matches!(
            p.watch("twilio://x", &json!({ "kinds": ["fax"] }), emit_for(&snk)),
            Err(WatchError::InvalidSpec { .. })
        ));
        // Empty kinds list.
        assert!(matches!(
            p.watch("twilio://x", &json!({ "kinds": [] }), emit_for(&snk)),
            Err(WatchError::InvalidSpec { .. })
        ));
    }

    #[test]
    fn cancel_null_handle_is_safe() {
        let (_s, p) = plugin();
        p.cancel(WatchHandleBox(std::ptr::null_mut()));
    }

    #[test]
    fn two_watches_independent_filters() {
        let (state, p) = plugin();
        let sms_sink = sink();
        let voice_sink = sink();
        let _h1 = p
            .watch(
                "twilio://messages",
                &json!({ "kinds": ["sms"] }),
                emit_for(&sms_sink),
            )
            .unwrap();
        let _h2 = p
            .watch(
                "twilio://calls",
                &json!({ "kinds": ["voice"] }),
                emit_for(&voice_sink),
            )
            .unwrap();
        std::thread::sleep(Duration::from_millis(50));

        state.notify_inbound(notice("sms"));
        assert!(wait_until(|| count(&sms_sink) >= 1, Duration::from_secs(2)));
        std::thread::sleep(Duration::from_millis(100));
        assert_eq!(
            count(&voice_sink),
            0,
            "voice watcher must not see an sms notice"
        );

        state.notify_inbound(notice("voice"));
        assert!(wait_until(
            || count(&voice_sink) >= 1,
            Duration::from_secs(2)
        ));
        assert_eq!(
            count(&sms_sink),
            1,
            "sms watcher must not see a voice notice"
        );
    }
}
