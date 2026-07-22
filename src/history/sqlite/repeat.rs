use crate::history::repeat::REPEAT_STATE_RETENTION_SECONDS;
use crate::history::{RepeatCandidate, RepeatDecision, RepeatState, RepeatSuppressionReason};
use anyhow::Result;
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};

struct ExistingRepeat {
    last_delivered_at: Option<f64>,
    reserved_until: f64,
    suppressed_count: u64,
    reservation_token: String,
}

pub(in crate::history) fn reserve(
    conn: &mut Connection,
    candidate: &RepeatCandidate,
) -> Result<RepeatDecision> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    prune_expired(&tx, candidate.now)?;
    let existing = repeat_row(&tx, &candidate.fingerprint)?;
    let decision = match existing {
        Some(existing) if existing.reservation_token == candidate.reservation_token => {
            RepeatDecision::Deliver {
                reservation_token: candidate.reservation_token.clone(),
            }
        }
        Some(existing)
            if existing
                .last_delivered_at
                .is_some_and(|ts| ts >= candidate.cutoff()) =>
        {
            let suppressed_count = existing.suppressed_count.saturating_add(1);
            record_suppression(&tx, candidate, suppressed_count)?;
            RepeatDecision::Suppress {
                reason: RepeatSuppressionReason::RecentDelivery,
                last_delivered_at: existing.last_delivered_at,
                suppressed_count,
            }
        }
        Some(existing) if existing.reserved_until > candidate.now => {
            RepeatDecision::WaitForDelivery
        }
        _ => {
            reserve_delivery(&tx, candidate)?;
            RepeatDecision::Deliver {
                reservation_token: candidate.reservation_token.clone(),
            }
        }
    };
    tx.commit()?;
    Ok(decision)
}

fn repeat_row(tx: &Transaction<'_>, fingerprint: &str) -> Result<Option<ExistingRepeat>> {
    tx.query_row(
        r#"
SELECT last_delivered_at, reserved_until, suppressed_count, reservation_token
FROM klaxond_repeat_state
WHERE fingerprint = ?1
"#,
        params![fingerprint],
        |row| {
            Ok(ExistingRepeat {
                last_delivered_at: row.get(0)?,
                reserved_until: row.get(1)?,
                suppressed_count: row.get::<_, i64>(2)?.max(0) as u64,
                reservation_token: row.get(3)?,
            })
        },
    )
    .optional()
    .map_err(Into::into)
}

fn prune_expired(tx: &Transaction<'_>, now: f64) -> Result<()> {
    let cutoff = now - REPEAT_STATE_RETENTION_SECONDS;
    tx.execute(
        r#"
DELETE FROM klaxond_repeat_state
WHERE reserved_until < ?1
  AND COALESCE(last_delivered_at, 0) < ?1
  AND COALESCE(last_suppressed_at, 0) < ?1
"#,
        params![cutoff],
    )?;
    Ok(())
}

fn record_suppression(
    tx: &Transaction<'_>,
    candidate: &RepeatCandidate,
    suppressed_count: u64,
) -> Result<()> {
    tx.execute(
        r#"
UPDATE klaxond_repeat_state
SET source = ?2,
    severity = ?3,
    title = ?4,
    last_suppressed_at = ?5,
    suppressed_count = ?6,
    cooldown_s = ?7,
    matched_rule = ?8
WHERE fingerprint = ?1
"#,
        params![
            &candidate.fingerprint,
            &candidate.source,
            &candidate.severity,
            &candidate.title,
            candidate.now,
            suppressed_count as i64,
            candidate.window_s as i64,
            &candidate.matched_rule,
        ],
    )?;
    Ok(())
}

fn reserve_delivery(tx: &Transaction<'_>, candidate: &RepeatCandidate) -> Result<()> {
    tx.execute(
        r#"
INSERT INTO klaxond_repeat_state (
  fingerprint, source, severity, title, last_delivered_at,
  last_suppressed_at, suppressed_count, reserved_until, reservation_token,
  cooldown_s, matched_rule
)
VALUES (?1, ?2, ?3, ?4, NULL, NULL, 0, ?5, ?6, ?7, ?8)
ON CONFLICT(fingerprint) DO UPDATE SET
  source = excluded.source,
  severity = excluded.severity,
  title = excluded.title,
  reserved_until = excluded.reserved_until,
  reservation_token = excluded.reservation_token,
  cooldown_s = excluded.cooldown_s,
  matched_rule = excluded.matched_rule
"#,
        params![
            &candidate.fingerprint,
            &candidate.source,
            &candidate.severity,
            &candidate.title,
            candidate.reservation_until(),
            &candidate.reservation_token,
            candidate.window_s as i64,
            &candidate.matched_rule,
        ],
    )?;
    Ok(())
}

pub(in crate::history) fn complete(
    conn: &Connection,
    fingerprint: &str,
    reservation_token: &str,
    delivered_at: Option<f64>,
) -> Result<()> {
    if let Some(delivered_at) = delivered_at {
        conn.execute(
            r#"
UPDATE klaxond_repeat_state
SET last_delivered_at = ?3, reserved_until = 0, reservation_token = ''
WHERE fingerprint = ?1 AND reservation_token = ?2
"#,
            params![fingerprint, reservation_token, delivered_at],
        )?;
    } else {
        conn.execute(
            r#"
UPDATE klaxond_repeat_state
SET reserved_until = 0, reservation_token = ''
WHERE fingerprint = ?1 AND reservation_token = ?2
"#,
            params![fingerprint, reservation_token],
        )?;
    }
    Ok(())
}

pub(in crate::history) fn recent_suppressions(
    conn: &Connection,
    limit: usize,
) -> Result<Vec<RepeatState>> {
    let mut stmt = conn.prepare(
        r#"
SELECT fingerprint, source, severity, title, last_delivered_at,
       last_suppressed_at, suppressed_count, cooldown_s, matched_rule
FROM klaxond_repeat_state
WHERE last_suppressed_at IS NOT NULL
ORDER BY last_suppressed_at DESC
LIMIT ?1
"#,
    )?;
    let rows = stmt.query_map(params![limit as i64], row_to_state)?;
    rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
}

pub(in crate::history) fn export_all(conn: &Connection) -> Result<Vec<RepeatState>> {
    if !table_exists(conn)? {
        return Ok(Vec::new());
    }
    let mut stmt = conn.prepare(
        r#"
SELECT fingerprint, source, severity, title, last_delivered_at,
       last_suppressed_at, suppressed_count, cooldown_s, matched_rule
FROM klaxond_repeat_state
ORDER BY fingerprint
"#,
    )?;
    let rows = stmt.query_map([], row_to_state)?;
    rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
}

pub(in crate::history) fn import(conn: &Connection, state: &RepeatState) -> Result<()> {
    conn.execute(
        r#"
INSERT INTO klaxond_repeat_state (
  fingerprint, source, severity, title, last_delivered_at,
  last_suppressed_at, suppressed_count, cooldown_s, matched_rule,
  reserved_until, reservation_token
)
VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 0, '')
ON CONFLICT(fingerprint) DO UPDATE SET
  source = excluded.source,
  severity = excluded.severity,
  title = excluded.title,
  last_delivered_at = CASE
    WHEN klaxond_repeat_state.last_delivered_at IS NULL THEN excluded.last_delivered_at
    WHEN excluded.last_delivered_at IS NULL THEN klaxond_repeat_state.last_delivered_at
    ELSE MAX(klaxond_repeat_state.last_delivered_at, excluded.last_delivered_at)
  END,
  last_suppressed_at = CASE
    WHEN klaxond_repeat_state.last_suppressed_at IS NULL THEN excluded.last_suppressed_at
    WHEN excluded.last_suppressed_at IS NULL THEN klaxond_repeat_state.last_suppressed_at
    ELSE MAX(klaxond_repeat_state.last_suppressed_at, excluded.last_suppressed_at)
  END,
  suppressed_count = MAX(
    klaxond_repeat_state.suppressed_count,
    excluded.suppressed_count
  ),
  cooldown_s = excluded.cooldown_s,
  matched_rule = excluded.matched_rule
"#,
        params![
            &state.fingerprint,
            &state.source,
            &state.severity,
            &state.title,
            state.last_delivered_at,
            state.last_suppressed_at,
            state.suppressed_count as i64,
            state.cooldown_s as i64,
            &state.matched_rule,
        ],
    )?;
    Ok(())
}

fn row_to_state(row: &rusqlite::Row<'_>) -> rusqlite::Result<RepeatState> {
    Ok(RepeatState {
        fingerprint: row.get(0)?,
        source: row.get(1)?,
        severity: row.get(2)?,
        title: row.get(3)?,
        last_delivered_at: row.get(4)?,
        last_suppressed_at: row.get(5)?,
        suppressed_count: row.get::<_, i64>(6)?.max(0) as u64,
        cooldown_s: row.get::<_, i64>(7)?.max(0) as u64,
        matched_rule: row.get(8)?,
    })
}

fn table_exists(conn: &Connection) -> Result<bool> {
    Ok(conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'klaxond_repeat_state')",
        [],
        |row| row.get(0),
    )?)
}
