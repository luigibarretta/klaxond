use crate::history::repeat::REPEAT_STATE_RETENTION_SECONDS;
use crate::history::{RepeatCandidate, RepeatDecision, RepeatState, RepeatSuppressionReason};
use anyhow::Result;
use postgres::{Client, Transaction};
use sha2::{Digest, Sha256};

pub(super) fn reserve(client: &mut Client, candidate: &RepeatCandidate) -> Result<RepeatDecision> {
    let mut tx = client.transaction()?;
    let lock_key = advisory_lock_key(&candidate.fingerprint);
    tx.query_one("SELECT pg_advisory_xact_lock($1)", &[&lock_key])?;
    let mut candidate = candidate.clone();
    candidate.now = tx
        .query_one(
            "SELECT EXTRACT(EPOCH FROM clock_timestamp())::double precision",
            &[],
        )?
        .get(0);
    prune_expired(&mut tx, candidate.now)?;
    let existing = tx.query_opt(
        r#"
SELECT last_delivered_at, reserved_until, suppressed_count, reservation_token
FROM klaxond_repeat_state
WHERE fingerprint = $1
FOR UPDATE
"#,
        &[&candidate.fingerprint],
    )?;
    let decision = match existing {
        Some(row) if row.get::<_, String>(3) == candidate.reservation_token => {
            renew_reservation(&mut tx, &candidate)?;
            RepeatDecision::Deliver {
                reservation_token: candidate.reservation_token.clone(),
            }
        }
        Some(row)
            if row
                .get::<_, Option<f64>>(0)
                .is_some_and(|ts| ts >= candidate.cutoff()) =>
        {
            suppress(
                &mut tx,
                &candidate,
                RepeatSuppressionReason::RecentDelivery,
                row.get(0),
                row.get::<_, i64>(2).max(0) as u64,
            )?
        }
        Some(row) if row.get::<_, f64>(1) > candidate.now => RepeatDecision::WaitForDelivery,
        _ => {
            reserve_delivery(&mut tx, &candidate)?;
            RepeatDecision::Deliver {
                reservation_token: candidate.reservation_token.clone(),
            }
        }
    };
    tx.commit()?;
    Ok(decision)
}

fn renew_reservation(tx: &mut Transaction<'_>, candidate: &RepeatCandidate) -> Result<()> {
    tx.execute(
        r#"
UPDATE klaxond_repeat_state
SET reserved_until = $2
WHERE fingerprint = $1 AND reservation_token = $3
"#,
        &[
            &candidate.fingerprint,
            &candidate.reservation_until(),
            &candidate.reservation_token,
        ],
    )?;
    Ok(())
}

fn advisory_lock_key(fingerprint: &str) -> i64 {
    let digest = Sha256::digest(fingerprint.as_bytes());
    let mut prefix = [0_u8; 8];
    prefix.copy_from_slice(&digest[..8]);
    i64::from_be_bytes(prefix)
}

fn prune_expired(tx: &mut Transaction<'_>, now: f64) -> Result<()> {
    let cutoff = now - REPEAT_STATE_RETENTION_SECONDS;
    tx.execute(
        r#"
DELETE FROM klaxond_repeat_state
WHERE reserved_until < $1
  AND COALESCE(last_delivered_at, 0) < $1
  AND COALESCE(last_suppressed_at, 0) < $1
"#,
        &[&cutoff],
    )?;
    Ok(())
}

fn suppress(
    tx: &mut Transaction<'_>,
    candidate: &RepeatCandidate,
    reason: RepeatSuppressionReason,
    last_delivered_at: Option<f64>,
    suppressed_count: u64,
) -> Result<RepeatDecision> {
    let suppressed_count = suppressed_count.saturating_add(1);
    tx.execute(
        r#"
UPDATE klaxond_repeat_state
SET source = $2,
    severity = $3,
    title = $4,
    last_suppressed_at = $5,
    suppressed_count = $6,
    cooldown_s = $7,
    matched_rule = $8
WHERE fingerprint = $1
"#,
        &[
            &candidate.fingerprint,
            &candidate.source,
            &candidate.severity,
            &candidate.title,
            &candidate.now,
            &(suppressed_count as i64),
            &(candidate.window_s as i64),
            &candidate.matched_rule,
        ],
    )?;
    Ok(RepeatDecision::Suppress {
        reason,
        last_delivered_at,
        suppressed_count,
    })
}

fn reserve_delivery(tx: &mut Transaction<'_>, candidate: &RepeatCandidate) -> Result<()> {
    tx.execute(
        r#"
INSERT INTO klaxond_repeat_state (
  fingerprint, source, severity, title, last_delivered_at,
  last_suppressed_at, suppressed_count, reserved_until, reservation_token,
  cooldown_s, matched_rule
)
VALUES ($1, $2, $3, $4, NULL, NULL, 0, $5, $6, $7, $8)
ON CONFLICT(fingerprint) DO UPDATE SET
  source = excluded.source,
  severity = excluded.severity,
  title = excluded.title,
  reserved_until = excluded.reserved_until,
  reservation_token = excluded.reservation_token,
  cooldown_s = excluded.cooldown_s,
  matched_rule = excluded.matched_rule
"#,
        &[
            &candidate.fingerprint,
            &candidate.source,
            &candidate.severity,
            &candidate.title,
            &candidate.reservation_until(),
            &candidate.reservation_token,
            &(candidate.window_s as i64),
            &candidate.matched_rule,
        ],
    )?;
    Ok(())
}

pub(super) fn complete(
    client: &mut Client,
    fingerprint: &str,
    reservation_token: &str,
    delivered_at: Option<f64>,
) -> Result<()> {
    if delivered_at.is_some() {
        client.execute(
            r#"
UPDATE klaxond_repeat_state
SET last_delivered_at = EXTRACT(EPOCH FROM clock_timestamp())::double precision,
    reserved_until = 0,
    reservation_token = ''
WHERE fingerprint = $1 AND reservation_token = $2
"#,
            &[&fingerprint, &reservation_token],
        )?;
    } else {
        client.execute(
            r#"
UPDATE klaxond_repeat_state
SET reserved_until = 0, reservation_token = ''
WHERE fingerprint = $1 AND reservation_token = $2
"#,
            &[&fingerprint, &reservation_token],
        )?;
    }
    Ok(())
}

pub(super) fn recent_suppressions(client: &mut Client, limit: usize) -> Result<Vec<RepeatState>> {
    let rows = client.query(
        r#"
SELECT fingerprint, source, severity, title, last_delivered_at,
       last_suppressed_at, suppressed_count, cooldown_s, matched_rule
FROM klaxond_repeat_state
WHERE last_suppressed_at IS NOT NULL
ORDER BY last_suppressed_at DESC
LIMIT $1
"#,
        &[&(limit as i64)],
    )?;
    Ok(rows.into_iter().map(row_to_state).collect())
}

pub(super) fn export_all(client: &mut Client) -> Result<Vec<RepeatState>> {
    let exists = client
        .query_one("SELECT to_regclass('klaxond_repeat_state')::text", &[])?
        .get::<_, Option<String>>(0)
        .is_some();
    if !exists {
        return Ok(Vec::new());
    }
    let rows = client.query(
        r#"
SELECT fingerprint, source, severity, title, last_delivered_at,
       last_suppressed_at, suppressed_count, cooldown_s, matched_rule
FROM klaxond_repeat_state
ORDER BY fingerprint
"#,
        &[],
    )?;
    Ok(rows.into_iter().map(row_to_state).collect())
}

pub(super) fn import(client: &mut Client, state: &RepeatState) -> Result<()> {
    client.execute(
        r#"
INSERT INTO klaxond_repeat_state (
  fingerprint, source, severity, title, last_delivered_at,
  last_suppressed_at, suppressed_count, cooldown_s, matched_rule,
  reserved_until, reservation_token
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 0, '')
ON CONFLICT(fingerprint) DO UPDATE SET
  source = excluded.source,
  severity = excluded.severity,
  title = excluded.title,
  last_delivered_at = GREATEST(
    klaxond_repeat_state.last_delivered_at,
    excluded.last_delivered_at
  ),
  last_suppressed_at = GREATEST(
    klaxond_repeat_state.last_suppressed_at,
    excluded.last_suppressed_at
  ),
  suppressed_count = GREATEST(
    klaxond_repeat_state.suppressed_count,
    excluded.suppressed_count
  ),
  cooldown_s = excluded.cooldown_s,
  matched_rule = excluded.matched_rule
"#,
        &[
            &state.fingerprint,
            &state.source,
            &state.severity,
            &state.title,
            &state.last_delivered_at,
            &state.last_suppressed_at,
            &(state.suppressed_count as i64),
            &(state.cooldown_s as i64),
            &state.matched_rule,
        ],
    )?;
    Ok(())
}

fn row_to_state(row: postgres::Row) -> RepeatState {
    RepeatState {
        fingerprint: row.get(0),
        source: row.get(1),
        severity: row.get(2),
        title: row.get(3),
        last_delivered_at: row.get(4),
        last_suppressed_at: row.get(5),
        suppressed_count: row.get::<_, i64>(6).max(0) as u64,
        cooldown_s: row.get::<_, i64>(7).max(0) as u64,
        matched_rule: row.get(8),
    }
}
