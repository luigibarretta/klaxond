use crate::state::keys::INHIBITION_ACK;
use crate::state::{AppState, lock_mutex};
use crate::util::{b64url_decode_padded, b64url_no_pad, now_epoch};
use serde_json::json;
use std::collections::HashMap;

pub fn ack_sign(state: &AppState, alertname: &str, ttl_sec: u64) -> String {
    let exp = now_epoch() as i64 + ttl_sec as i64;
    let payload = json!({"a": alertname, "t": ttl_sec, "e": exp}).to_string();
    let b = b64url_no_pad(payload.as_bytes());
    let sig = state.keys.sign_hex(INHIBITION_ACK, b.as_bytes());
    format!("{b}.{sig}")
}

pub fn ack_verify(state: &AppState, token: &str) -> (Option<String>, String) {
    let Some((body_b64, sig)) = token.split_once('.') else {
        return (None, "malformed".into());
    };
    if state
        .keys
        .verify_hex(INHIBITION_ACK, body_b64.as_bytes(), sig)
        .is_none()
    {
        return (None, "bad-signature".into());
    }
    let Ok(bytes) = b64url_decode_padded(body_b64) else {
        return (None, "bad-payload".into());
    };
    let Ok(payload) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
        return (None, "bad-payload".into());
    };
    if !is_inhibition_ack_payload(&payload) {
        return (None, "bad-payload".into());
    }
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

/// Inhibition tokens always carry the TTL (`t`) and never a receipt (`r`).
/// Emergency acknowledgement tokens (`{"r","e","a":"ack"}`) were signed with
/// the same raw key before 0.23; this shape check keeps such a legacy token
/// from verifying here as an acknowledgement of the alert name `"ack"`.
fn is_inhibition_ack_payload(payload: &serde_json::Value) -> bool {
    payload.get("t").is_some_and(serde_json::Value::is_u64) && payload.get("r").is_none()
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

#[cfg(test)]
mod tests;
