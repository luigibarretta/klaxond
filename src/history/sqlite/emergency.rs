use crate::history::emergency::{
    EMERGENCY_ACTIVE, EmergencyAttempt, EmergencyCandidate, EmergencyIncident,
    EmergencyRegistration, SELECT_COLUMNS, sqlite_row,
};
use anyhow::Result;
use rusqlite::{Connection, OptionalExtension, params};

pub(in crate::history) fn register(
    conn: &mut Connection,
    candidate: &EmergencyCandidate,
) -> Result<EmergencyRegistration> {
    let tx = conn.transaction()?;
    let existing = tx
        .query_row(
            &format!("SELECT {SELECT_COLUMNS} FROM klaxond_emergencies WHERE fingerprint=?1 AND state='active'"),
            params![&candidate.fingerprint],
            sqlite_row,
        )
        .optional()?;
    if let Some(mut incident) = existing {
        tx.execute(
            "UPDATE klaxond_emergencies SET payload_json=?2, title=?3, updated_at=?4 WHERE receipt_id=?1 AND state='active'",
            params![&incident.receipt_id, &candidate.payload_json, &candidate.title, candidate.now],
        )?;
        incident.payload_json.clone_from(&candidate.payload_json);
        incident.title.clone_from(&candidate.title);
        incident.updated_at = candidate.now;
        tx.commit()?;
        return Ok(EmergencyRegistration {
            incident,
            created: false,
        });
    }
    tx.execute(
        r#"INSERT INTO klaxond_emergencies
        (receipt_id,fingerprint,source,severity,title,payload_json,state,created_at,updated_at,next_retry_at,expires_at,max_attempts)
        VALUES (?1,?2,?3,?4,?5,?6,'active',?7,?7,?8,?9,?10)"#,
        params![candidate.receipt_id, candidate.fingerprint, candidate.source, candidate.severity,
            candidate.title, candidate.payload_json, candidate.now, candidate.next_retry_at,
            candidate.expires_at, candidate.max_attempts as i64],
    )?;
    let incident = tx.query_row(
        &format!("SELECT {SELECT_COLUMNS} FROM klaxond_emergencies WHERE receipt_id=?1"),
        params![candidate.receipt_id],
        sqlite_row,
    )?;
    tx.commit()?;
    Ok(EmergencyRegistration {
        incident,
        created: true,
    })
}

pub(in crate::history) fn record_initial_attempt(
    conn: &Connection,
    attempt: &EmergencyAttempt,
) -> Result<()> {
    conn.execute(
        r#"UPDATE klaxond_emergencies SET attempts=attempts+1,last_sent_at=?2,
        updated_at=?2,next_retry_at=?3,last_error=?4,
        telegram_escalated_at=CASE WHEN ?5 IS NULL THEN telegram_escalated_at ELSE COALESCE(telegram_escalated_at,?2) END,
        smtp_escalated_at=CASE WHEN ?6 IS NULL THEN smtp_escalated_at ELSE COALESCE(smtp_escalated_at,?2) END
        WHERE receipt_id=?1 AND state='active'"#,
        params![
            attempt.receipt_id,
            attempt.now,
            attempt.next_retry_at,
            if attempt.ntfy_ok {
                ""
            } else {
                &attempt.last_error
            },
            attempt.telegram_ok,
            attempt.smtp_ok,
        ],
    )?;
    Ok(())
}

pub(in crate::history) fn reserve_due(
    conn: &mut Connection,
    now: f64,
    lease_until: f64,
    token: &str,
) -> Result<Option<EmergencyIncident>> {
    let tx = conn.transaction()?;
    let receipt = tx
        .query_row(
            r#"SELECT receipt_id FROM klaxond_emergencies
            WHERE state='active' AND next_retry_at<=?1 AND expires_at>?1
              AND attempts<max_attempts AND reserved_until<=?1
            ORDER BY next_retry_at,created_at LIMIT 1"#,
            params![now],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    let Some(receipt) = receipt else {
        tx.commit()?;
        return Ok(None);
    };
    let changed = tx.execute(
        r#"UPDATE klaxond_emergencies SET reserved_until=?2,reservation_token=?3,updated_at=?1
        WHERE receipt_id=?4 AND state='active' AND reserved_until<=?1"#,
        params![now, lease_until, token, receipt],
    )?;
    let incident = if changed == 1 {
        tx.query_row(
            &format!("SELECT {SELECT_COLUMNS} FROM klaxond_emergencies WHERE receipt_id=?1"),
            params![receipt],
            sqlite_row,
        )
        .optional()?
    } else {
        None
    };
    tx.commit()?;
    Ok(incident)
}

pub(in crate::history) fn complete_attempt(
    conn: &Connection,
    attempt: &EmergencyAttempt,
) -> Result<bool> {
    let changed = conn.execute(
        r#"UPDATE klaxond_emergencies SET attempts=attempts+1,last_sent_at=?3,updated_at=?3,
        next_retry_at=?4,last_error=?5,reserved_until=0,reservation_token='',
        telegram_escalated_at=CASE WHEN ?6 IS NULL THEN telegram_escalated_at ELSE COALESCE(telegram_escalated_at,?3) END,
        smtp_escalated_at=CASE WHEN ?7 IS NULL THEN smtp_escalated_at ELSE COALESCE(smtp_escalated_at,?3) END
        WHERE receipt_id=?1 AND state='active' AND reservation_token=?2"#,
        params![attempt.receipt_id, attempt.reservation_token, attempt.now, attempt.next_retry_at,
            if attempt.ntfy_ok { "" } else { &attempt.last_error }, attempt.telegram_ok, attempt.smtp_ok],
    )?;
    Ok(changed == 1)
}

pub(in crate::history) fn terminalize(
    conn: &Connection,
    receipt_id: &str,
    state: &str,
    actor: &str,
    now: f64,
) -> Result<Option<EmergencyIncident>> {
    let changed = conn.execute(
        r#"UPDATE klaxond_emergencies SET state=?2,terminal_at=?3,terminal_by=?4,
        updated_at=?3,reserved_until=0,reservation_token='' WHERE receipt_id=?1 AND state='active'"#,
        params![receipt_id, state, now, actor],
    )?;
    if changed == 1 {
        get(conn, receipt_id)
    } else {
        Ok(None)
    }
}

pub(in crate::history) fn terminalize_fingerprint(
    conn: &Connection,
    fingerprint: &str,
    state: &str,
    actor: &str,
    now: f64,
) -> Result<Option<EmergencyIncident>> {
    let receipt = conn
        .query_row(
            "SELECT receipt_id FROM klaxond_emergencies WHERE fingerprint=?1 AND state='active'",
            params![fingerprint],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    match receipt {
        Some(receipt) => terminalize(conn, &receipt, state, actor, now),
        None => Ok(None),
    }
}

pub(in crate::history) fn expire_due(
    conn: &mut Connection,
    now: f64,
    limit: usize,
) -> Result<Vec<EmergencyIncident>> {
    let tx = conn.transaction()?;
    let receipts = {
        let mut stmt = tx.prepare(
            r#"SELECT receipt_id FROM klaxond_emergencies WHERE state='active'
            AND (expires_at<=?1 OR attempts>=max_attempts) ORDER BY expires_at LIMIT ?2"#,
        )?;
        stmt.query_map(params![now, limit as i64], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?
    };
    let mut incidents = Vec::new();
    for receipt in receipts {
        tx.execute(
            "UPDATE klaxond_emergencies SET state='expired',terminal_at=?2,terminal_by='scheduler',updated_at=?2,reserved_until=0,reservation_token='' WHERE receipt_id=?1 AND state='active'",
            params![receipt, now],
        )?;
        if let Some(incident) = tx
            .query_row(
                &format!("SELECT {SELECT_COLUMNS} FROM klaxond_emergencies WHERE receipt_id=?1"),
                params![receipt],
                sqlite_row,
            )
            .optional()?
        {
            incidents.push(incident);
        }
    }
    tx.commit()?;
    Ok(incidents)
}

pub(in crate::history) fn retry_now(conn: &Connection, receipt_id: &str, now: f64) -> Result<bool> {
    Ok(conn.execute(
        "UPDATE klaxond_emergencies SET next_retry_at=?2,reserved_until=0,reservation_token='',updated_at=?2 WHERE receipt_id=?1 AND state='active'",
        params![receipt_id, now],
    )? == 1)
}

pub(in crate::history) fn get(
    conn: &Connection,
    receipt_id: &str,
) -> Result<Option<EmergencyIncident>> {
    Ok(conn
        .query_row(
            &format!("SELECT {SELECT_COLUMNS} FROM klaxond_emergencies WHERE receipt_id=?1"),
            params![receipt_id],
            sqlite_row,
        )
        .optional()?)
}

pub(in crate::history) fn page(
    conn: &Connection,
    state: Option<&str>,
    limit: usize,
) -> Result<Vec<EmergencyIncident>> {
    let mut out = Vec::new();
    if let Some(state) = state {
        let mut stmt = conn.prepare(&format!("SELECT {SELECT_COLUMNS} FROM klaxond_emergencies WHERE state=?1 ORDER BY created_at DESC LIMIT ?2"))?;
        for row in stmt.query_map(params![state, limit as i64], sqlite_row)? {
            out.push(row?);
        }
    } else {
        let mut stmt = conn.prepare(&format!(
            "SELECT {SELECT_COLUMNS} FROM klaxond_emergencies ORDER BY created_at DESC LIMIT ?1"
        ))?;
        for row in stmt.query_map(params![limit as i64], sqlite_row)? {
            out.push(row?);
        }
    }
    Ok(out)
}

pub(in crate::history) fn export_all(conn: &Connection) -> Result<Vec<EmergencyIncident>> {
    let exists: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='klaxond_emergencies')",
        [],
        |row| row.get(0),
    )?;
    if !exists {
        return Ok(Vec::new());
    }
    page(conn, None, 1_000_000)
}

pub(in crate::history) fn import(conn: &Connection, incident: &EmergencyIncident) -> Result<()> {
    conn.execute(
        r#"INSERT OR REPLACE INTO klaxond_emergencies
        (receipt_id,fingerprint,source,severity,title,payload_json,state,created_at,updated_at,next_retry_at,expires_at,last_sent_at,terminal_at,terminal_by,attempts,max_attempts,telegram_escalated_at,smtp_escalated_at,last_error,reserved_until,reservation_token)
        VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21)"#,
        params![incident.receipt_id,incident.fingerprint,incident.source,incident.severity,incident.title,
            incident.payload_json,incident.state,incident.created_at,incident.updated_at,incident.next_retry_at,
            incident.expires_at,incident.last_sent_at,incident.terminal_at,incident.terminal_by,
            incident.attempts as i64,incident.max_attempts as i64,incident.telegram_escalated_at,
            incident.smtp_escalated_at,incident.last_error,incident.reserved_until,incident.reservation_token],
    )?;
    Ok(())
}

pub(in crate::history) fn active_stats(conn: &Connection, now: f64) -> Result<(usize, f64)> {
    let (count, oldest): (i64, Option<f64>) = conn.query_row(
        "SELECT COUNT(*),MIN(created_at) FROM klaxond_emergencies WHERE state=?1",
        params![EMERGENCY_ACTIVE],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    Ok((
        count as usize,
        oldest.map(|v| (now - v).max(0.0)).unwrap_or(0.0),
    ))
}
