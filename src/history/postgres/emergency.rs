use crate::history::emergency::{
    EmergencyAttempt, EmergencyCandidate, EmergencyIncident, EmergencyRegistration,
};
use anyhow::{Result, anyhow};
use postgres::{Client, Row};

const COLUMNS: &str = "receipt_id,fingerprint,source,severity,title,payload_json,policy_id,policy_name,policy_snapshot_json,state,created_at,updated_at,next_retry_at,expires_at,last_sent_at,terminal_at,terminal_by,attempts,max_attempts,telegram_escalated_at,smtp_escalated_at,last_error,reserved_until,reservation_token";
const E_COLUMNS: &str = "e.receipt_id,e.fingerprint,e.source,e.severity,e.title,e.payload_json,e.policy_id,e.policy_name,e.policy_snapshot_json,e.state,e.created_at,e.updated_at,e.next_retry_at,e.expires_at,e.last_sent_at,e.terminal_at,e.terminal_by,e.attempts,e.max_attempts,e.telegram_escalated_at,e.smtp_escalated_at,e.last_error,e.reserved_until,e.reservation_token";

fn row(row: Row) -> EmergencyIncident {
    EmergencyIncident {
        receipt_id: row.get(0),
        fingerprint: row.get(1),
        source: row.get(2),
        severity: row.get(3),
        title: row.get(4),
        payload_json: row.get(5),
        policy_id: row.get(6),
        policy_name: row.get(7),
        policy_snapshot_json: row.get(8),
        state: row.get(9),
        created_at: row.get(10),
        updated_at: row.get(11),
        next_retry_at: row.get(12),
        expires_at: row.get(13),
        last_sent_at: row.get(14),
        terminal_at: row.get(15),
        terminal_by: row.get(16),
        attempts: row.get::<_, i64>(17) as u32,
        max_attempts: row.get::<_, i64>(18) as u32,
        telegram_escalated_at: row.get(19),
        smtp_escalated_at: row.get(20),
        last_error: row.get(21),
        reserved_until: row.get(22),
        reservation_token: row.get(23),
    }
}

pub(super) fn materialize_policy_snapshot(
    client: &mut Client,
    policy_id: &str,
    policy_name: &str,
    snapshot_json: &str,
) -> Result<usize> {
    let mut tx = client.transaction()?;
    let changed = tx.execute(
        r#"UPDATE klaxond_emergencies
        SET policy_id=$1,policy_name=$2,policy_snapshot_json=$3
        WHERE state='active' AND policy_snapshot_json=''"#,
        &[&policy_id, &policy_name, &snapshot_json],
    )?;
    tx.commit()?;
    Ok(changed as usize)
}

pub(super) fn register(
    client: &mut Client,
    c: &EmergencyCandidate,
) -> Result<EmergencyRegistration> {
    let mut tx = client.transaction()?;
    if let Some(existing) = tx.query_opt(
        &format!("SELECT {COLUMNS} FROM klaxond_emergencies WHERE fingerprint=$1 AND state='active' FOR UPDATE"),
        &[&c.fingerprint],
    )? {
        tx.execute("UPDATE klaxond_emergencies SET payload_json=$2,title=$3,updated_at=$4 WHERE receipt_id=$1 AND state='active'",
            &[&existing.get::<_,String>(0), &c.payload_json, &c.title, &c.now])?;
        let mut incident = row(existing);
        incident.payload_json.clone_from(&c.payload_json);
        incident.title.clone_from(&c.title);
        incident.updated_at = c.now;
        tx.commit()?;
        return Ok(EmergencyRegistration { incident, created: false });
    }
    let inserted = tx.execute(
        r#"INSERT INTO klaxond_emergencies
        (receipt_id,fingerprint,source,severity,title,payload_json,policy_id,policy_name,policy_snapshot_json,state,created_at,updated_at,next_retry_at,expires_at,max_attempts)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,'active',$10,$10,$11,$12,$13) ON CONFLICT DO NOTHING"#,
        &[&c.receipt_id,&c.fingerprint,&c.source,&c.severity,&c.title,&c.payload_json,
            &c.policy_id,&c.policy_name,&c.policy_snapshot_json,&c.now,
            &c.next_retry_at,&c.expires_at,&(c.max_attempts as i64)],
    )?;
    let incident = tx
        .query_opt(
            &format!(
                "SELECT {COLUMNS} FROM klaxond_emergencies WHERE fingerprint=$1 AND state='active'"
            ),
            &[&c.fingerprint],
        )?
        .map(row)
        .ok_or_else(|| anyhow!("emergency insert conflict without active fingerprint"))?;
    tx.commit()?;
    Ok(EmergencyRegistration {
        incident,
        created: inserted == 1,
    })
}

pub(super) fn record_initial_attempt(
    client: &mut Client,
    attempt: &EmergencyAttempt,
) -> Result<()> {
    client.execute(
        r#"UPDATE klaxond_emergencies SET attempts=attempts+1,last_sent_at=$2,
        updated_at=$2,next_retry_at=$3,last_error=$4,
        telegram_escalated_at=CASE WHEN $5::boolean IS NULL THEN telegram_escalated_at ELSE COALESCE(telegram_escalated_at,$2) END,
        smtp_escalated_at=CASE WHEN $6::boolean IS NULL THEN smtp_escalated_at ELSE COALESCE(smtp_escalated_at,$2) END
        WHERE receipt_id=$1 AND state='active'"#,
        &[
            &attempt.receipt_id,
            &attempt.now,
            &attempt.next_retry_at,
            &if attempt.ntfy_ok {
                ""
            } else {
                &attempt.last_error
            },
            &attempt.telegram_ok,
            &attempt.smtp_ok,
        ],
    )?;
    Ok(())
}

pub(super) fn reserve_due(
    client: &mut Client,
    now: f64,
    lease_until: f64,
    token: &str,
) -> Result<Option<EmergencyIncident>> {
    let sql = format!(
        r#"WITH candidate AS (
      SELECT receipt_id FROM klaxond_emergencies WHERE state='active' AND next_retry_at<=$1
        AND expires_at>$1 AND attempts<max_attempts AND reserved_until<=$1
      ORDER BY next_retry_at,created_at FOR UPDATE SKIP LOCKED LIMIT 1)
      UPDATE klaxond_emergencies e SET reserved_until=$2,reservation_token=$3,updated_at=$1
      FROM candidate c WHERE e.receipt_id=c.receipt_id RETURNING {E_COLUMNS}"#
    );
    Ok(client
        .query_opt(&sql, &[&now, &lease_until, &token])?
        .map(row))
}

pub(super) fn adjust_lease(
    client: &mut Client,
    receipt: &str,
    token: &str,
    lease_until: f64,
) -> Result<bool> {
    Ok(client.execute(
        "UPDATE klaxond_emergencies SET reserved_until=$3 WHERE receipt_id=$1 AND state='active' AND reservation_token=$2",
        &[&receipt, &token, &lease_until],
    )? == 1)
}

pub(super) fn complete_attempt(client: &mut Client, a: &EmergencyAttempt) -> Result<bool> {
    let changed = client.execute(r#"UPDATE klaxond_emergencies SET attempts=attempts+1,last_sent_at=$3,
      updated_at=$3,next_retry_at=$4,last_error=$5,reserved_until=0,reservation_token='',
      telegram_escalated_at=CASE WHEN $6::boolean IS NULL THEN telegram_escalated_at ELSE COALESCE(telegram_escalated_at,$3) END,
      smtp_escalated_at=CASE WHEN $7::boolean IS NULL THEN smtp_escalated_at ELSE COALESCE(smtp_escalated_at,$3) END
      WHERE receipt_id=$1 AND state='active' AND reservation_token=$2"#,
      &[&a.receipt_id,&a.reservation_token,&a.now,&a.next_retry_at,
        &if a.ntfy_ok { "" } else { a.last_error.as_str() },&a.telegram_ok,&a.smtp_ok])?;
    Ok(changed == 1)
}

pub(super) fn terminalize(
    client: &mut Client,
    receipt: &str,
    state: &str,
    actor: &str,
    now: f64,
) -> Result<Option<EmergencyIncident>> {
    let sql = format!(
        r#"UPDATE klaxond_emergencies SET state=$2,terminal_at=$3,terminal_by=$4,
      updated_at=$3,reserved_until=0,reservation_token='' WHERE receipt_id=$1 AND state='active'
      RETURNING {COLUMNS}"#
    );
    if let Some(result_row) = client.query_opt(&sql, &[&receipt, &state, &now, &actor])? {
        return Ok(Some(row(result_row)));
    }
    Ok(None)
}

pub(super) fn terminalize_fingerprint(
    client: &mut Client,
    fingerprint: &str,
    state: &str,
    actor: &str,
    now: f64,
) -> Result<Option<EmergencyIncident>> {
    let sql = format!(
        r#"UPDATE klaxond_emergencies SET state=$2,terminal_at=$3,terminal_by=$4,
      updated_at=$3,reserved_until=0,reservation_token='' WHERE fingerprint=$1 AND state='active'
      RETURNING {COLUMNS}"#
    );
    Ok(client
        .query_opt(&sql, &[&fingerprint, &state, &now, &actor])?
        .map(row))
}

pub(super) fn expire_due(
    client: &mut Client,
    now: f64,
    limit: usize,
) -> Result<Vec<EmergencyIncident>> {
    let sql = format!(
        r#"WITH due AS (SELECT receipt_id FROM klaxond_emergencies WHERE state='active'
      AND (expires_at<=$1 OR attempts>=max_attempts) ORDER BY expires_at FOR UPDATE SKIP LOCKED LIMIT $2)
      UPDATE klaxond_emergencies e SET state='expired',terminal_at=$1,terminal_by='scheduler',
      updated_at=$1,reserved_until=0,reservation_token='' FROM due WHERE e.receipt_id=due.receipt_id RETURNING {E_COLUMNS}"#
    );
    Ok(client
        .query(&sql, &[&now, &(limit as i64)])?
        .into_iter()
        .map(row)
        .collect())
}

pub(super) fn retry_now(client: &mut Client, receipt: &str, now: f64) -> Result<bool> {
    Ok(client.execute("UPDATE klaxond_emergencies SET next_retry_at=$2,reserved_until=0,reservation_token='',updated_at=$2 WHERE receipt_id=$1 AND state='active'", &[&receipt,&now])? == 1)
}

pub(super) fn get(client: &mut Client, receipt: &str) -> Result<Option<EmergencyIncident>> {
    Ok(client
        .query_opt(
            &format!("SELECT {COLUMNS} FROM klaxond_emergencies WHERE receipt_id=$1"),
            &[&receipt],
        )?
        .map(row))
}

pub(super) fn page(
    client: &mut Client,
    state: Option<&str>,
    limit: usize,
) -> Result<Vec<EmergencyIncident>> {
    let rows = match state {
        Some(state) => client.query(&format!("SELECT {COLUMNS} FROM klaxond_emergencies WHERE state=$1 ORDER BY created_at DESC LIMIT $2"), &[&state,&(limit as i64)])?,
        None => client.query(&format!("SELECT {COLUMNS} FROM klaxond_emergencies ORDER BY created_at DESC LIMIT $1"), &[&(limit as i64)])?,
    };
    Ok(rows.into_iter().map(row).collect())
}

pub(super) fn export_all(client: &mut Client) -> Result<Vec<EmergencyIncident>> {
    let exists: Option<String> = client
        .query_one("SELECT to_regclass('klaxond_emergencies')::text", &[])?
        .get(0);
    if exists.is_none() {
        return Ok(Vec::new());
    }
    page(client, None, 1_000_000)
}

pub(super) fn import(client: &mut Client, i: &EmergencyIncident) -> Result<()> {
    client.execute(r#"INSERT INTO klaxond_emergencies
      (receipt_id,fingerprint,source,severity,title,payload_json,policy_id,policy_name,policy_snapshot_json,state,created_at,updated_at,next_retry_at,expires_at,last_sent_at,terminal_at,terminal_by,attempts,max_attempts,telegram_escalated_at,smtp_escalated_at,last_error,reserved_until,reservation_token)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24)
      ON CONFLICT (receipt_id) DO UPDATE SET fingerprint=EXCLUDED.fingerprint,source=EXCLUDED.source,severity=EXCLUDED.severity,
      title=EXCLUDED.title,payload_json=EXCLUDED.payload_json,policy_id=EXCLUDED.policy_id,
      policy_name=EXCLUDED.policy_name,policy_snapshot_json=EXCLUDED.policy_snapshot_json,
      state=EXCLUDED.state,created_at=EXCLUDED.created_at,
      updated_at=EXCLUDED.updated_at,next_retry_at=EXCLUDED.next_retry_at,expires_at=EXCLUDED.expires_at,
      last_sent_at=EXCLUDED.last_sent_at,terminal_at=EXCLUDED.terminal_at,terminal_by=EXCLUDED.terminal_by,
      attempts=EXCLUDED.attempts,max_attempts=EXCLUDED.max_attempts,telegram_escalated_at=EXCLUDED.telegram_escalated_at,
      smtp_escalated_at=EXCLUDED.smtp_escalated_at,last_error=EXCLUDED.last_error,reserved_until=EXCLUDED.reserved_until,
      reservation_token=EXCLUDED.reservation_token"#,
      &[&i.receipt_id,&i.fingerprint,&i.source,&i.severity,&i.title,&i.payload_json,
        &i.policy_id,&i.policy_name,&i.policy_snapshot_json,&i.state,
        &i.created_at,&i.updated_at,&i.next_retry_at,&i.expires_at,&i.last_sent_at,&i.terminal_at,
        &i.terminal_by,&(i.attempts as i64),&(i.max_attempts as i64),&i.telegram_escalated_at,
        &i.smtp_escalated_at,&i.last_error,&i.reserved_until,&i.reservation_token])?;
    Ok(())
}

pub(super) fn active_stats(client: &mut Client, now: f64) -> Result<(usize, f64)> {
    let r = client.query_one(
        "SELECT COUNT(*),MIN(created_at) FROM klaxond_emergencies WHERE state='active'",
        &[],
    )?;
    let count = r.get::<_, i64>(0) as usize;
    let oldest = r
        .get::<_, Option<f64>>(1)
        .map(|v| (now - v).max(0.0))
        .unwrap_or(0.0);
    Ok((count, oldest))
}
