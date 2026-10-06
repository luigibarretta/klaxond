//! Deferred delivery that a later event can cancel.
//!
//! A payload carrying `"defer": {"seconds": N, "key": "..."}` is held for N
//! seconds (capped at `MAX_DEFER_SECONDS`). A later payload from the same
//! authenticated source carrying `"cancel_defer": "<key>"` drops the held
//! item; otherwise it is delivered normally when the delay expires. A newer
//! deferral with the same key supersedes the older one. Pending items live in
//! memory only, so a restart inside the window drops them.

use super::{DeliveryCandidate, deliver_candidate};
use crate::state::AppState;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::time::Duration;

pub(super) const MAX_DEFER_SECONDS: u64 = 600;

static NEXT_GENERATION: AtomicU64 = AtomicU64::new(1);

fn pending() -> MutexGuard<'static, HashMap<String, u64>> {
    static PENDING: OnceLock<Mutex<HashMap<String, u64>>> = OnceLock::new();
    PENDING
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[derive(Debug, PartialEq, Eq)]
pub(super) struct DeferRequest {
    pub(super) seconds: u64,
    pub(super) key: String,
}

pub(super) fn defer_request(payload: &Value) -> Option<DeferRequest> {
    let defer = payload.get("defer")?;
    let seconds = defer.get("seconds")?.as_u64()?;
    let key = defer.get("key")?.as_str()?.trim();
    if seconds == 0 || key.is_empty() {
        return None;
    }
    Some(DeferRequest {
        seconds: seconds.min(MAX_DEFER_SECONDS),
        key: key.to_string(),
    })
}

pub(super) fn cancel_key(payload: &Value) -> Option<&str> {
    payload
        .get("cancel_defer")?
        .as_str()
        .map(str::trim)
        .filter(|key| !key.is_empty())
}

/// Keys are namespaced per source so one source cannot cancel another's items.
fn scoped(source: &str, key: &str) -> String {
    format!("{source}\u{0}{key}")
}

fn register(key: &str) -> u64 {
    let generation = NEXT_GENERATION.fetch_add(1, Ordering::Relaxed);
    pending().insert(key.to_string(), generation);
    generation
}

/// Removes the item and returns true only if it is still the current,
/// uncancelled deferral for `key`.
fn take_if_current(key: &str, generation: u64) -> bool {
    let mut map = pending();
    if map.get(key) == Some(&generation) {
        map.remove(key);
        true
    } else {
        false
    }
}

/// Drops a pending deferral; returns true when one was cancelled.
pub(super) fn cancel(source: &str, key: &str) -> bool {
    pending().remove(&scoped(source, key)).is_some()
}

pub(super) fn schedule(
    state: &AppState,
    source: String,
    delivery: DeliveryCandidate,
    request: DeferRequest,
) {
    let scoped_key = scoped(&source, &request.key);
    let generation = register(&scoped_key);
    let state = state.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(request.seconds)).await;
        if take_if_current(&scoped_key, generation) {
            tracing::info!(source = %source, key = %request.key, "delivering deferred notification");
            let _ = deliver_candidate(&state, &source, delivery).await;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parses_and_caps_defer_requests() {
        let req = defer_request(&json!({"defer": {"seconds": 60, "key": " k "}})).unwrap();
        assert_eq!(
            req,
            DeferRequest {
                seconds: 60,
                key: "k".into()
            }
        );
        let capped = defer_request(&json!({"defer": {"seconds": 99999, "key": "k"}})).unwrap();
        assert_eq!(capped.seconds, MAX_DEFER_SECONDS);
        assert!(defer_request(&json!({"defer": {"seconds": 0, "key": "k"}})).is_none());
        assert!(defer_request(&json!({"defer": {"seconds": 60, "key": ""}})).is_none());
        assert!(defer_request(&json!({"title": "x"})).is_none());
    }

    #[test]
    fn parses_cancel_keys() {
        assert_eq!(cancel_key(&json!({"cancel_defer": " k "})), Some("k"));
        assert_eq!(cancel_key(&json!({"cancel_defer": ""})), None);
        assert_eq!(cancel_key(&json!({})), None);
    }

    #[test]
    fn cancelled_item_is_not_delivered() {
        let key = scoped("authentik", "test-cancelled");
        let generation = register(&key);
        assert!(!cancel("other-source", "test-cancelled"));
        assert!(cancel("authentik", "test-cancelled"));
        assert!(!take_if_current(&key, generation));
        assert!(!cancel("authentik", "test-cancelled"));
    }

    #[test]
    fn uncancelled_item_is_delivered_once() {
        let generation = register("test-delivered");
        assert!(take_if_current("test-delivered", generation));
        assert!(!take_if_current("test-delivered", generation));
    }

    #[test]
    fn newer_deferral_supersedes_older() {
        let older = register("test-superseded");
        let newer = register("test-superseded");
        assert!(!take_if_current("test-superseded", older));
        assert!(take_if_current("test-superseded", newer));
    }
}
