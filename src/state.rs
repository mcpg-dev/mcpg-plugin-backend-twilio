//! In-process state shared by all three entities (the `backend` binding, the
//! `http_route` webhook handler, and the `watch_strategy` push path).
//!
//! Holds:
//! - a bounded ring of recently-received inbound events (for a live `list` of
//!   just-arrived items + status correlation),
//! - a staged-script map keyed by CallSid or destination number — TwiML the
//!   inbound-voice webhook will serve once and then consume (TTL'd),
//! - the last-seen status per CallSid/MessageSid (from status callbacks),
//! - an in-process notice channel + watch registry: the webhook publishes an
//!   [`InboundNotice`] when it receives an inbound event; the `watch_strategy`
//!   entity's dispatcher fans each notice out to the registered watchers so
//!   `resources/updated` reaches subscribed MCP clients natively (no
//!   `notify_webhook_url` round-trip).
//!
//! NOT durable and NOT cluster-shared: an inbound webhook lands on whichever
//! replica Twilio happened to reach, so live call scripting AND the native
//! watch push are tied to that replica. Twilio's REST API remains the source
//! of truth for message/call history (the `list_*` / `get_*` operations read
//! it directly). `notify_webhook_url` remains the cross-replica push path.
//! This is a documented single-gateway-affinity caveat for v1.

use std::collections::{BTreeSet, HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::broadcast;

use crate::twiml::TwimlVerb;

/// Default ring capacity for recent inbound events.
const DEFAULT_RING_CAP: usize = 256;

/// Bound on the in-process inbound-notice broadcast channel. Notices are tiny
/// and the dispatcher drains them promptly; a backlog past this means the
/// dispatcher is wedged, so dropping (with a warn) is preferable to growth.
const NOTICE_CHANNEL_CAP: usize = 1024;

/// One recorded inbound event (SMS or voice or status callback).
#[derive(Debug, Clone)]
pub struct InboundEvent {
    /// `"sms"` / `"voice"` / `"status"` / `"gather"`.
    pub kind: String,
    /// `MessageSid` / `CallSid` if present.
    pub sid: Option<String>,
    /// `From` number if present.
    pub from: Option<String>,
    /// `To` number if present.
    pub to: Option<String>,
    /// Monotonic arrival instant (used for ordering / age).
    pub received_at: Instant,
}

/// A lightweight notice the webhook publishes onto the in-process channel when
/// an inbound event arrives. The watch dispatcher fans it out to registered
/// watchers; it is deliberately small (cheap to clone across broadcast).
#[derive(Debug, Clone)]
pub struct InboundNotice {
    /// `"sms"` / `"voice"` / `"status"`. Used by the per-watch `kinds` filter.
    pub kind: String,
    /// `MessageSid` / `CallSid` if present (diagnostics only).
    pub sid: Option<String>,
    /// `From` number if present (diagnostics only).
    pub from: Option<String>,
    /// `To` number if present (diagnostics only).
    pub to: Option<String>,
}

/// The closure the host hands a watcher to emit `resources/updated`. Pre-bound
/// by the SDK macro to the watcher's `resource_uri`; called with a serialized
/// [`mcpg_plugin_protocol::backend::WatchEvent`] JSON.
pub type EmitFn = Arc<dyn Fn(&str) + Send + Sync>;

/// One registered watcher. The dispatcher calls `emit` for every notice whose
/// `kind` is in `kinds`.
struct WatchReg {
    id: u64,
    resource_uri: String,
    kinds: BTreeSet<String>,
    emit: EmitFn,
}

/// A staged TwiML script the inbound-voice webhook will serve once.
#[derive(Debug, Clone)]
struct StagedScript {
    verbs: Vec<TwimlVerb>,
    expires_at: Instant,
}

/// The key a staged script is filed under.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ScriptKey {
    /// Keyed by an active call's `CallSid`.
    CallSid(String),
    /// Keyed by an expected inbound's destination number (`To`).
    To(String),
}

struct Inner {
    ring: VecDeque<InboundEvent>,
    ring_cap: usize,
    staged: HashMap<ScriptKey, StagedScript>,
    last_status: HashMap<String, String>,
    /// Registered native watchers, drained by the watch entity's dispatcher.
    watches: Vec<WatchReg>,
}

/// Process-shared Twilio plugin state.
pub struct TwilioState {
    inner: Mutex<Inner>,
    /// Sender half of the in-process inbound-notice channel. The webhook
    /// `notify_inbound`s onto it (non-blocking); the watch dispatcher
    /// subscribes a receiver. Retained here so a receiver can be created
    /// lazily when the watch entity starts.
    notice_tx: broadcast::Sender<InboundNotice>,
    /// Monotonic source of watch-registration ids.
    next_watch_id: AtomicU64,
}

impl Default for TwilioState {
    fn default() -> Self {
        Self::with_capacity(DEFAULT_RING_CAP)
    }
}

impl TwilioState {
    pub fn with_capacity(ring_cap: usize) -> Self {
        let cap = ring_cap.max(1);
        let (notice_tx, _) = broadcast::channel(NOTICE_CHANNEL_CAP);
        Self {
            inner: Mutex::new(Inner {
                ring: VecDeque::with_capacity(cap),
                ring_cap: cap,
                staged: HashMap::new(),
                last_status: HashMap::new(),
                watches: Vec::new(),
            }),
            notice_tx,
            next_watch_id: AtomicU64::new(1),
        }
    }

    /// Record an inbound event, evicting the oldest when the ring is full.
    pub fn record_event(&self, event: InboundEvent) {
        let mut g = self.inner.lock().expect("twilio state poisoned");
        if g.ring.len() == g.ring_cap {
            g.ring.pop_front();
        }
        g.ring.push_back(event);
    }

    /// Number of events currently retained (test/diagnostic helper).
    pub fn event_count(&self) -> usize {
        self.inner.lock().expect("twilio state poisoned").ring.len()
    }

    /// Snapshot the most recent `max` events, newest last.
    pub fn recent_events(&self, max: usize) -> Vec<InboundEvent> {
        let g = self.inner.lock().expect("twilio state poisoned");
        let n = g.ring.len();
        let start = n.saturating_sub(max);
        g.ring.iter().skip(start).cloned().collect()
    }

    /// Stage a TwiML script for a key, with a time-to-live.
    pub fn stage_script(&self, key: ScriptKey, verbs: Vec<TwimlVerb>, ttl: Duration) {
        let mut g = self.inner.lock().expect("twilio state poisoned");
        g.staged.insert(
            key,
            StagedScript {
                verbs,
                expires_at: Instant::now() + ttl,
            },
        );
    }

    /// Take (consume) a staged script for a key if present and unexpired.
    /// Expired entries are evicted on access.
    pub fn take_script(&self, key: &ScriptKey) -> Option<Vec<TwimlVerb>> {
        let mut g = self.inner.lock().expect("twilio state poisoned");
        match g.staged.remove(key) {
            Some(s) if s.expires_at > Instant::now() => Some(s.verbs),
            // Expired (already removed) → treat as absent.
            _ => None,
        }
    }

    /// Number of staged scripts (test/diagnostic helper).
    pub fn staged_count(&self) -> usize {
        self.inner
            .lock()
            .expect("twilio state poisoned")
            .staged
            .len()
    }

    /// Drop expired staged scripts (callable opportunistically).
    pub fn sweep_expired(&self) {
        let now = Instant::now();
        let mut g = self.inner.lock().expect("twilio state poisoned");
        g.staged.retain(|_, s| s.expires_at > now);
    }

    /// Record the latest status for a SID (from a status callback).
    pub fn record_status(&self, sid: String, status: String) {
        let mut g = self.inner.lock().expect("twilio state poisoned");
        g.last_status.insert(sid, status);
    }

    /// Read the last-seen status for a SID.
    pub fn last_status(&self, sid: &str) -> Option<String> {
        self.inner
            .lock()
            .expect("twilio state poisoned")
            .last_status
            .get(sid)
            .cloned()
    }

    // --- native watch push: notice channel + registry ----------------------

    /// Publish an inbound notice onto the in-process channel. NON-BLOCKING:
    /// the webhook calls this from inside its `block_on`, so it must never
    /// wait. `broadcast::Sender::send` is synchronous and returns immediately;
    /// a missing dispatcher (no subscriber) or a lagging one is a dropped
    /// notice, logged at warn — the watch push is best-effort (Twilio's REST
    /// API stays the source of truth).
    pub fn notify_inbound(&self, notice: InboundNotice) {
        match self.notice_tx.send(notice) {
            Ok(_) => {}
            // No active receiver — the watch entity isn't running (or no client
            // subscribed). Expected when only `notify_webhook_url` is used.
            Err(_) => {
                tracing::debug!("twilio: inbound notice dropped (no active watch dispatcher)");
            }
        }
    }

    /// Subscribe a receiver for the watch dispatcher. Created once when the
    /// watch entity's dispatcher task starts.
    pub fn subscribe_notices(&self) -> broadcast::Receiver<InboundNotice> {
        self.notice_tx.subscribe()
    }

    /// Register a native watcher. Returns its id (the cancel handle payload).
    pub fn register_watch(&self, resource_uri: &str, kinds: BTreeSet<String>, emit: EmitFn) -> u64 {
        let id = self.next_watch_id.fetch_add(1, Ordering::Relaxed);
        let mut g = self.inner.lock().expect("twilio state poisoned");
        g.watches.push(WatchReg {
            id,
            resource_uri: resource_uri.to_owned(),
            kinds,
            emit,
        });
        id
    }

    /// Deregister a watcher by id. Idempotent (unknown id is a no-op).
    pub fn unregister_watch(&self, id: u64) {
        let mut g = self.inner.lock().expect("twilio state poisoned");
        g.watches.retain(|w| w.id != id);
    }

    /// Number of registered watchers (test/diagnostic helper).
    pub fn watch_count(&self) -> usize {
        self.inner
            .lock()
            .expect("twilio state poisoned")
            .watches
            .len()
    }

    /// Snapshot the `(resource_uri, emit)` pairs whose `kinds` filter matches
    /// `notice_kind`. Cloning the small `Arc<Fn>` handles lets the dispatcher
    /// call them after releasing the lock (the host's emit may take time and
    /// must not hold the state mutex).
    pub fn matching_emitters(&self, notice_kind: &str) -> Vec<(String, EmitFn)> {
        let g = self.inner.lock().expect("twilio state poisoned");
        g.watches
            .iter()
            .filter(|w| w.kinds.contains(notice_kind))
            .map(|w| (w.resource_uri.clone(), Arc::clone(&w.emit)))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(kind: &str, sid: &str) -> InboundEvent {
        InboundEvent {
            kind: kind.into(),
            sid: Some(sid.into()),
            from: Some("+1555".into()),
            to: Some("+1666".into()),
            received_at: Instant::now(),
        }
    }

    #[test]
    fn ring_evicts_oldest_past_capacity() {
        let st = TwilioState::with_capacity(3);
        for i in 0..5 {
            st.record_event(ev("sms", &format!("SM{i}")));
        }
        assert_eq!(st.event_count(), 3);
        let recent = st.recent_events(10);
        // Oldest two (SM0, SM1) evicted; SM2..SM4 remain in order.
        assert_eq!(recent.len(), 3);
        assert_eq!(recent[0].sid.as_deref(), Some("SM2"));
        assert_eq!(recent[2].sid.as_deref(), Some("SM4"));
    }

    #[test]
    fn recent_events_caps_to_requested() {
        let st = TwilioState::with_capacity(10);
        for i in 0..6 {
            st.record_event(ev("voice", &format!("CA{i}")));
        }
        let recent = st.recent_events(2);
        assert_eq!(recent.len(), 2);
        assert_eq!(recent[1].sid.as_deref(), Some("CA5"));
    }

    #[test]
    fn staged_script_is_consumed_once() {
        let st = TwilioState::default();
        let key = ScriptKey::To("+1666".into());
        st.stage_script(
            key.clone(),
            vec![TwimlVerb::Hangup],
            Duration::from_secs(60),
        );
        assert_eq!(st.staged_count(), 1);
        assert!(st.take_script(&key).is_some());
        // Second take returns nothing (consumed).
        assert!(st.take_script(&key).is_none());
        assert_eq!(st.staged_count(), 0);
    }

    #[test]
    fn staged_script_expires_by_ttl() {
        let st = TwilioState::default();
        let key = ScriptKey::CallSid("CA1".into());
        st.stage_script(key.clone(), vec![TwimlVerb::Hangup], Duration::ZERO);
        // TTL of zero → already expired on access.
        assert!(st.take_script(&key).is_none());
    }

    #[test]
    fn sweep_drops_expired_entries() {
        let st = TwilioState::default();
        st.stage_script(
            ScriptKey::To("+1".into()),
            vec![TwimlVerb::Hangup],
            Duration::ZERO,
        );
        st.stage_script(
            ScriptKey::To("+2".into()),
            vec![TwimlVerb::Hangup],
            Duration::from_secs(60),
        );
        st.sweep_expired();
        assert_eq!(st.staged_count(), 1);
    }

    #[test]
    fn status_round_trips() {
        let st = TwilioState::default();
        st.record_status("CA9".into(), "completed".into());
        assert_eq!(st.last_status("CA9").as_deref(), Some("completed"));
        assert!(st.last_status("unknown").is_none());
    }
}
