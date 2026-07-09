use crate::state::{AppState, lock_mutex};
use crate::util::{b64url_decode_padded, b64url_no_pad, hmac_hex, now_epoch};
use constant_time_eq::constant_time_eq;
use serde_json::json;
use std::collections::HashMap;

pub fn ack_sign(state: &AppState, alertname: &str, ttl_sec: u64) -> String {
    let exp = now_epoch() as i64 + ttl_sec as i64;
    let payload = json!({"a": alertname, "t": ttl_sec, "e": exp}).to_string();
    let b = b64url_no_pad(payload.as_bytes());
    let sig = hmac_hex(state.session_key.as_slice(), b.as_bytes());
    format!("{b}.{sig}")
}

pub fn ack_verify(state: &AppState, token: &str) -> (Option<String>, String) {
    let Some((body_b64, sig)) = token.split_once('.') else {
        return (None, "malformed".into());
    };
    let expected = hmac_hex(state.session_key.as_slice(), body_b64.as_bytes());
    if !constant_time_eq(sig.as_bytes(), expected.as_bytes()) {
        return (None, "bad-signature".into());
    }
    let Ok(bytes) = b64url_decode_padded(body_b64) else {
        return (None, "bad-payload".into());
    };
    let Ok(payload) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
        return (None, "bad-payload".into());
    };
    if payload.get("e").and_then(|v| v.as_i64()).unwrap_or(0) < now_epoch() as i64 {
        return (None, "expired".into());
    }
    let alertname = payload
        .get("a")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_string();
    if alertname.is_empty() {
        return (None, "no-alertname".into());
    }
    (Some(alertname), "ok".into())
}

pub fn register_ack_suppression(state: &AppState, alertname: &str, ttl_sec: u64) {
    lock_mutex(&state.ack_suppressions, "ack suppressions")
        .insert(alertname.to_string(), now_epoch() + ttl_sec as f64);
}

pub fn ack_match(state: &AppState, labels: &HashMap<String, String>) -> Option<String> {
    let name = labels.get("alertname")?;
    if name.is_empty() {
        return None;
    }
    let now = now_epoch();
    let mut acks = lock_mutex(&state.ack_suppressions, "ack suppressions");
    if let Some(exp) = acks.get(name).copied() {
        if exp > now {
            return Some(name.clone());
        }
        acks.remove(name);
    }
    None
}

pub fn ack_status_snapshot(state: &AppState) -> Vec<serde_json::Value> {
    let now = now_epoch();
    let mut rows = lock_mutex(&state.ack_suppressions, "ack suppressions")
        .iter()
        .filter(|(_, exp)| **exp > now)
        .map(|(name, exp)| json!({"alertname": name, "expires_in_seconds": (*exp - now) as i64}))
        .collect::<Vec<_>>();
    rows.sort_by_key(|r| {
        r.get("expires_in_seconds")
            .and_then(|v| v.as_i64())
            .unwrap_or(0)
    });
    rows
}
