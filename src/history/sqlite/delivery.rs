use super::sqlite_column_exists;
use crate::history::{DeliveryEntry, DeliveryQuery, dedupe_hash, delivery_search_values};
use anyhow::Result;
use rusqlite::{Connection, params};

mod activity;

pub(in crate::history) use activity::load as activity;

pub(in crate::history) fn insert(conn: &Connection, entry: &DeliveryEntry) -> Result<()> {
    let hash = dedupe_hash(entry);
    let search = delivery_search_values(
        &entry.source,
        &entry.severity,
        &entry.title,
        &entry.channel,
        &entry.suppressed_by,
    );
    conn.execute(
        r#"
INSERT OR IGNORE INTO klaxond_deliveries
  (ts, source, severity, title, channel, suppressed_by, emergency_receipt_id,
   search_source, search_severity, search_title, search_channel, search_suppressed_by,
   search_version, dedupe_hash)
VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, 1, ?13)
"#,
        params![
            entry.ts,
            &entry.source,
            &entry.severity,
            &entry.title,
            &entry.channel,
            &entry.suppressed_by,
            &entry.emergency_receipt_id,
            &search[0],
            &search[1],
            &search[2],
            &search[3],
            &search[4],
            hash,
        ],
    )?;
    Ok(())
}

const FILTER_SQL: &str = r#"
WHERE
  (?1 IS NULL OR
    instr(search_source, ?1) > 0 OR
    instr(search_severity, ?1) > 0 OR
    instr(search_title, ?1) > 0 OR
    instr(search_channel, ?1) > 0 OR
    instr(search_suppressed_by, ?1) > 0)
  AND (?2 IS NULL OR source = ?2)
  AND (?3 IS NULL OR severity = ?3)
  AND (?4 IS NULL OR channel = ?4)
  AND (?5 IS NULL OR ts >= ?5)
  AND (?6 IS NULL OR ts <= ?6)
  AND (
    ?7 = 'include' OR
    (?7 = 'exclude' AND suppressed_by = '') OR
    (?7 = 'only' AND suppressed_by <> '')
  )
"#;

pub(in crate::history) fn count(conn: &Connection, query: &DeliveryQuery) -> Result<usize> {
    let sql = format!("SELECT COUNT(*) FROM klaxond_deliveries {FILTER_SQL}");
    Ok(conn.query_row(
        &sql,
        params![
            query.q.as_deref(),
            query.source.as_deref(),
            query.severity.as_deref(),
            query.channel.as_deref(),
            query.from,
            query.to,
            query.suppressed.as_str(),
        ],
        |row| row.get::<_, i64>(0),
    )? as usize)
}

pub(in crate::history) fn page(
    conn: &Connection,
    query: &DeliveryQuery,
) -> Result<Vec<DeliveryEntry>> {
    let sql = format!(
        r#"
SELECT ts, source, severity, title, channel, suppressed_by, emergency_receipt_id
FROM klaxond_deliveries
{FILTER_SQL}
ORDER BY ts DESC, id DESC
LIMIT ?8 OFFSET ?9
"#,
    );
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map(
        params![
            query.q.as_deref(),
            query.source.as_deref(),
            query.severity.as_deref(),
            query.channel.as_deref(),
            query.from,
            query.to,
            query.suppressed.as_str(),
            query.limit as i64,
            query.offset as i64,
        ],
        |row| {
            Ok(DeliveryEntry {
                ts: row.get(0)?,
                source: row.get(1)?,
                severity: row.get(2)?,
                title: row.get(3)?,
                channel: row.get(4)?,
                suppressed_by: row.get(5)?,
                emergency_receipt_id: row.get(6)?,
            })
        },
    )?;
    rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
}

pub(in crate::history) fn export_all(conn: &mut Connection) -> Result<Vec<DeliveryEntry>> {
    let tx = conn.unchecked_transaction()?;
    let rows = {
        let receipt_select =
            if sqlite_column_exists(&tx, "klaxond_deliveries", "emergency_receipt_id")? {
                "emergency_receipt_id"
            } else {
                "NULL AS emergency_receipt_id"
            };
        let mut stmt = tx.prepare(&format!(
            "SELECT ts, source, severity, title, channel, suppressed_by, {receipt_select} \
             FROM klaxond_deliveries ORDER BY ts ASC, id ASC"
        ))?;
        let rows = stmt.query_map([], |row| {
            Ok(DeliveryEntry {
                ts: row.get(0)?,
                source: row.get(1)?,
                severity: row.get(2)?,
                title: row.get(3)?,
                channel: row.get(4)?,
                suppressed_by: row.get(5)?,
                emergency_receipt_id: row.get(6)?,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>()?
    };
    tx.commit()?;
    Ok(rows)
}

pub(in crate::history) fn prune(conn: &Connection, retention: usize) -> Result<()> {
    if retention == 0 {
        return Ok(());
    }
    conn.execute(
        r#"
DELETE FROM klaxond_deliveries
WHERE id NOT IN (
  SELECT id FROM klaxond_deliveries ORDER BY ts DESC, id DESC LIMIT ?1
)
"#,
        params![retention as i64],
    )?;
    Ok(())
}
