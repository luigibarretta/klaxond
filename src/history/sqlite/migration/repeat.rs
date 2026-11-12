//! Repeat-suppression state.

pub(super) const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS klaxond_repeat_state (
  fingerprint TEXT PRIMARY KEY,
  source TEXT NOT NULL,
  severity TEXT NOT NULL,
  title TEXT NOT NULL,
  last_delivered_at REAL,
  last_suppressed_at REAL,
  suppressed_count INTEGER NOT NULL DEFAULT 0,
  reserved_until REAL NOT NULL DEFAULT 0,
  reservation_token TEXT NOT NULL DEFAULT '',
  cooldown_s INTEGER NOT NULL DEFAULT 0,
  matched_rule TEXT
);

CREATE INDEX IF NOT EXISTS idx_klaxond_repeat_suppressed_desc
  ON klaxond_repeat_state(last_suppressed_at DESC)
  WHERE last_suppressed_at IS NOT NULL;
"#;

/// Rule columns added after the table first shipped.
pub(super) const ADDED_COLUMNS: &[(&str, &str, &str)] = &[
    (
        "klaxond_repeat_state",
        "cooldown_s",
        "INTEGER NOT NULL DEFAULT 0",
    ),
    ("klaxond_repeat_state", "matched_rule", "TEXT"),
];
