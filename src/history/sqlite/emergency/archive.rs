use crate::history::emergency::{EMERGENCY_ACTIVE, EmergencyIncident, SELECT_COLUMNS, sqlite_row};
use anyhow::Result;
use rusqlite::{Connection, OptionalExtension, params};

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
    match state {
        Some(state) => page_by_state(conn, state, limit),
        None => page_all(conn, limit),
    }
}

fn page_by_state(conn: &Connection, state: &str, limit: usize) -> Result<Vec<EmergencyIncident>> {
    let mut stmt = conn.prepare(&format!(
        "SELECT {SELECT_COLUMNS} FROM klaxond_emergencies \
         WHERE state=?1 ORDER BY created_at DESC LIMIT ?2"
    ))?;
    let rows = stmt.query_map(params![state, limit as i64], sqlite_row)?;
    rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
}

fn page_all(conn: &Connection, limit: usize) -> Result<Vec<EmergencyIncident>> {
    let mut stmt = conn.prepare(&format!(
        "SELECT {SELECT_COLUMNS} FROM klaxond_emergencies ORDER BY created_at DESC LIMIT ?1"
    ))?;
    let rows = stmt.query_map(params![limit as i64], sqlite_row)?;
    rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
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
        (receipt_id,fingerprint,source,severity,title,payload_json,policy_id,policy_name,policy_snapshot_json,state,created_at,updated_at,next_retry_at,expires_at,last_sent_at,terminal_at,terminal_by,attempts,max_attempts,telegram_escalated_at,smtp_escalated_at,last_error,reserved_until,reservation_token)
        VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21,?22,?23,?24)"#,
        params![incident.receipt_id,incident.fingerprint,incident.source,incident.severity,incident.title,
            incident.payload_json,incident.policy_id,incident.policy_name,incident.policy_snapshot_json,
            incident.state,incident.created_at,incident.updated_at,incident.next_retry_at,
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
