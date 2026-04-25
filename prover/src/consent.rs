//! User-consent gate for incoming challenges.
//!
//! When `require_consent = true`, the `/challenge` handler registers a
//! pending request here and blocks until the browser extension fetches it
//! via `GET /pending-consent`, prompts the user, and reports the decision
//! via `POST /consent`. After a configurable timeout the request is denied
//! by default ("fail closed").

use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tokio::sync::oneshot;

/// Default time to wait for a user decision before denying.
pub const CONSENT_TIMEOUT: Duration = Duration::from_secs(30);

/// One pending consent request waiting for a browser-extension decision.
pub struct PendingEntry {
    pub request_id: String,
    pub site_id: String,
    pub created_at: Instant,
    pub responder: Option<oneshot::Sender<bool>>,
}

/// Lightweight serializable view of a pending entry, used by the
/// `/pending-consent` endpoint that the extension polls.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingEntryView {
    pub request_id: String,
    pub site_id: String,
    pub age_ms: u64,
}

/// Decision payload posted by the extension to `/consent`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsentDecision {
    pub request_id: String,
    pub allow: bool,
}

/// Process-wide registry of pending consent requests.
/// FIFO so users see them in the order they arrived.
pub struct ConsentRegistry {
    pending: Mutex<VecDeque<PendingEntry>>,
}

impl ConsentRegistry {
    pub fn new() -> Self {
        Self {
            pending: Mutex::new(VecDeque::new()),
        }
    }

    /// Register a new pending consent and return its receiver half.
    /// Caller awaits the receiver (with a timeout) for the user's decision.
    pub fn register(&self, request_id: String, site_id: String) -> oneshot::Receiver<bool> {
        let (tx, rx) = oneshot::channel::<bool>();
        let entry = PendingEntry {
            request_id,
            site_id,
            created_at: Instant::now(),
            responder: Some(tx),
        };
        self.pending.lock().unwrap().push_back(entry);
        rx
    }

    /// Snapshot of all currently-pending requests for the extension UI.
    pub fn list(&self) -> Vec<PendingEntryView> {
        let now = Instant::now();
        self.pending
            .lock()
            .unwrap()
            .iter()
            .map(|e| PendingEntryView {
                request_id: e.request_id.clone(),
                site_id: e.site_id.clone(),
                age_ms: now.duration_since(e.created_at).as_millis() as u64,
            })
            .collect()
    }

    /// Resolve a pending request with the user's decision.
    /// Returns true if a matching request was found and notified.
    pub fn resolve(&self, request_id: &str, allow: bool) -> bool {
        let mut q = self.pending.lock().unwrap();
        if let Some(pos) = q.iter().position(|e| e.request_id == request_id) {
            let mut entry = q.remove(pos).unwrap();
            if let Some(tx) = entry.responder.take() {
                let _ = tx.send(allow);
            }
            true
        } else {
            false
        }
    }

    /// Drop a pending request after a timeout (the receiver was already
    /// taken by the awaiting handler, so the responder is consumed here
    /// only to remove the visible queue entry).
    pub fn drop_request(&self, request_id: &str) {
        let mut q = self.pending.lock().unwrap();
        if let Some(pos) = q.iter().position(|e| e.request_id == request_id) {
            q.remove(pos);
        }
    }
}
