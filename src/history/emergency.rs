use crate::parsers::Parts;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub const EMERGENCY_ACTIVE: &str = "active";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmergencyChannelSnapshot {
    pub enabled: bool,
    pub after_attempts: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmergencyPolicySnapshot {
    pub schema_version: u32,
    pub profile_id: String,
    pub profile_name: String,
    pub retry_seconds: u64,
    pub expire_seconds: u64,
    pub max_attempts: u32,
    pub lease_seconds: u64,
    pub telegram: EmergencyChannelSnapshot,
    pub smtp: EmergencyChannelSnapshot,
    pub notify_on_expiry: bool,
    pub auto_resolve: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EmergencyPayload {
    pub parts: Parts,
    /// Normalized producer labels captured when the receipt was created.
    ///
    /// Older durable payloads contain only `parts`, so this must remain
    /// backward-compatible. The labels let a later inhibition source close
    /// dependent receipts even when Alertmanager suppresses their resolved
    /// webhook.
    #[serde(default)]
    pub labels: HashMap<String, String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EmergencyIncident {
    pub receipt_id: String,
    pub fingerprint: String,
    pub source: String,
    pub severity: String,
    pub title: String,
    pub payload_json: String,
    pub policy_id: String,
    pub policy_name: String,
    pub policy_snapshot_json: String,
    pub state: String,
    pub created_at: f64,
    pub updated_at: f64,
    pub next_retry_at: f64,
    pub expires_at: f64,
    pub last_sent_at: Option<f64>,
    pub terminal_at: Option<f64>,
    pub terminal_by: String,
    pub attempts: u32,
    pub max_attempts: u32,
    pub telegram_escalated_at: Option<f64>,
    pub smtp_escalated_at: Option<f64>,
    pub last_error: String,
    pub reserved_until: f64,
    pub reservation_token: String,
}

impl EmergencyIncident {
    pub fn payload(&self) -> serde_json::Result<EmergencyPayload> {
        serde_json::from_str(&self.payload_json)
    }

    pub fn policy_snapshot(&self) -> serde_json::Result<EmergencyPolicySnapshot> {
        serde_json::from_str(&self.policy_snapshot_json)
    }
}

#[derive(Clone, Debug)]
pub struct EmergencyCandidate {
    pub receipt_id: String,
    pub fingerprint: String,
    pub source: String,
    pub severity: String,
    pub title: String,
    pub payload_json: String,
    pub policy_id: String,
    pub policy_name: String,
    pub policy_snapshot_json: String,
    pub now: f64,
    pub next_retry_at: f64,
    pub expires_at: f64,
    pub max_attempts: u32,
}

#[derive(Clone, Debug)]
pub struct EmergencyRegistration {
    pub incident: EmergencyIncident,
    pub created: bool,
}

#[derive(Clone, Debug)]
pub struct EmergencyAttempt {
    pub receipt_id: String,
    pub reservation_token: String,
    pub now: f64,
    pub next_retry_at: f64,
    pub ntfy_ok: bool,
    pub telegram_ok: Option<bool>,
    pub smtp_ok: Option<bool>,
    pub last_error: String,
}

pub(crate) fn sqlite_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<EmergencyIncident> {
    Ok(EmergencyIncident {
        receipt_id: row.get(0)?,
        fingerprint: row.get(1)?,
        source: row.get(2)?,
        severity: row.get(3)?,
        title: row.get(4)?,
        payload_json: row.get(5)?,
        policy_id: row.get(6)?,
        policy_name: row.get(7)?,
        policy_snapshot_json: row.get(8)?,
        state: row.get(9)?,
        created_at: row.get(10)?,
        updated_at: row.get(11)?,
        next_retry_at: row.get(12)?,
        expires_at: row.get(13)?,
        last_sent_at: row.get(14)?,
        terminal_at: row.get(15)?,
        terminal_by: row.get(16)?,
        attempts: row.get::<_, i64>(17)? as u32,
        max_attempts: row.get::<_, i64>(18)? as u32,
        telegram_escalated_at: row.get(19)?,
        smtp_escalated_at: row.get(20)?,
        last_error: row.get(21)?,
        reserved_until: row.get(22)?,
        reservation_token: row.get(23)?,
    })
}

pub(crate) const SELECT_COLUMNS: &str = "receipt_id, fingerprint, source, severity, title, payload_json, policy_id, policy_name, policy_snapshot_json, state, created_at, updated_at, next_retry_at, expires_at, last_sent_at, terminal_at, terminal_by, attempts, max_attempts, telegram_escalated_at, smtp_escalated_at, last_error, reserved_until, reservation_token";
