//! Emergency incidents.

pub(super) const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS klaxond_emergencies (
  receipt_id TEXT PRIMARY KEY,
  fingerprint TEXT NOT NULL,
  source TEXT NOT NULL,
  severity TEXT NOT NULL,
  title TEXT NOT NULL,
  payload_json TEXT NOT NULL,
  policy_id TEXT NOT NULL DEFAULT '',
  policy_name TEXT NOT NULL DEFAULT '',
  policy_snapshot_json TEXT NOT NULL DEFAULT '',
  state TEXT NOT NULL,
  created_at REAL NOT NULL,
  updated_at REAL NOT NULL,
  next_retry_at REAL NOT NULL,
  expires_at REAL NOT NULL,
  last_sent_at REAL,
  terminal_at REAL,
  terminal_by TEXT NOT NULL DEFAULT '',
  attempts INTEGER NOT NULL DEFAULT 0,
  max_attempts INTEGER NOT NULL,
  telegram_escalated_at REAL,
  smtp_escalated_at REAL,
  last_error TEXT NOT NULL DEFAULT '',
  reserved_until REAL NOT NULL DEFAULT 0,
  reservation_token TEXT NOT NULL DEFAULT ''
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_klaxond_emergencies_active_fingerprint
  ON klaxond_emergencies(fingerprint) WHERE state='active';
CREATE INDEX IF NOT EXISTS idx_klaxond_emergencies_due
  ON klaxond_emergencies(state,next_retry_at,reserved_until);
CREATE INDEX IF NOT EXISTS idx_klaxond_emergencies_created
  ON klaxond_emergencies(created_at DESC);
"#;

/// Policy columns added after the table first shipped.
pub(super) const ADDED_COLUMNS: &[(&str, &str, &str)] = &[
    (
        "klaxond_emergencies",
        "policy_id",
        "TEXT NOT NULL DEFAULT ''",
    ),
    (
        "klaxond_emergencies",
        "policy_name",
        "TEXT NOT NULL DEFAULT ''",
    ),
    (
        "klaxond_emergencies",
        "policy_snapshot_json",
        "TEXT NOT NULL DEFAULT ''",
    ),
];
