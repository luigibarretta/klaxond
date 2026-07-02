use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::VecDeque;
use std::sync::{Mutex, OnceLock};

const AUDIT_CAPACITY: usize = 1_000;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuditEntry {
    pub ts: f64,
    pub actor: String,
    pub action: String,
    pub outcome: String,
    pub detail: String,
}

static AUDIT_LOG: OnceLock<Mutex<VecDeque<AuditEntry>>> = OnceLock::new();

fn log() -> &'static Mutex<VecDeque<AuditEntry>> {
    AUDIT_LOG.get_or_init(|| Mutex::new(VecDeque::with_capacity(AUDIT_CAPACITY)))
}

pub fn record(actor: impl Into<String>, action: &str, outcome: &str, detail: impl Into<String>) {
    let mut entries = log()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if entries.len() >= AUDIT_CAPACITY {
        entries.pop_front();
    }
    entries.push_back(AuditEntry {
        ts: crate::util::now_epoch(),
        actor: actor.into(),
        action: action.to_string(),
        outcome: outcome.to_string(),
        detail: detail.into(),
    });
}

pub fn query(q: &str, limit: usize, offset: usize) -> Value {
    let needle = q.trim().to_ascii_lowercase();
    let mut entries = log()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .iter()
        .rev()
        .filter(|entry| {
            if needle.is_empty() {
                return true;
            }
            [
                entry.actor.as_str(),
                entry.action.as_str(),
                entry.outcome.as_str(),
                entry.detail.as_str(),
            ]
            .join(" ")
            .to_ascii_lowercase()
            .contains(&needle)
        })
        .cloned()
        .collect::<Vec<_>>();
    let total = entries.len();
    let limit = limit.clamp(1, 500);
    let last_offset = if total == 0 {
        0
    } else {
        ((total - 1) / limit) * limit
    };
    let offset = offset.min(last_offset);
    entries = entries.into_iter().skip(offset).take(limit).collect();
    json!({
        "entries": entries,
        "total": total,
        "limit": limit,
        "offset": offset,
        "capacity": AUDIT_CAPACITY,
    })
}
