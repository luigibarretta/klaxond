use super::sqlite_column_exists;
use crate::history::{
    APPROXIMATE_DELIVERY_ROW_OVERHEAD, DeliveryActivity, DeliveryEntry, DeliveryQuery, dedupe_hash,
    delivery_search_values,
};
use anyhow::Result;
use rusqlite::{Connection, params};
use std::collections::BTreeMap;

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

pub(in crate::history) fn activity(
    conn: &Connection,
    hours: u16,
    since: f64,
    until: f64,
) -> Result<DeliveryActivity> {
    let metadata_sql = format!(
        r#"
SELECT
  COUNT(*),
  MAX(ts),
  COALESCE(SUM(
    {APPROXIMATE_DELIVERY_ROW_OVERHEAD}
    + length(CAST(source AS BLOB))
    + length(CAST(severity AS BLOB))
    + length(CAST(title AS BLOB))
    + length(CAST(channel AS BLOB))
    + length(CAST(suppressed_by AS BLOB))
    + length(CAST(COALESCE(emergency_receipt_id, '') AS BLOB))
    + length(CAST(search_source AS BLOB))
    + length(CAST(search_severity AS BLOB))
    + length(CAST(search_title AS BLOB))
    + length(CAST(search_channel AS BLOB))
    + length(CAST(search_suppressed_by AS BLOB))
    + length(CAST(dedupe_hash AS BLOB))
  ), 0)
FROM klaxond_deliveries
"#
    );
    let (total_history, latest_ts, approximate_history_bytes) =
        conn.query_row(&metadata_sql, [], |row| {
            Ok((
                row.get::<_, i64>(0)? as usize,
                row.get::<_, Option<f64>>(1)?,
                row.get::<_, i64>(2)? as usize,
            ))
        })?;

    let mut by_source = BTreeMap::new();
    let mut by_severity = BTreeMap::new();
    let mut by_channel = BTreeMap::new();
    let mut latest_by_source = BTreeMap::new();
    let mut latest_by_channel = BTreeMap::new();
    let mut suppressed = 0;
    let mut stmt = conn.prepare(
        r#"
SELECT dimension, value, count, latest_ts FROM (
  SELECT 'source' AS dimension, source AS value, COUNT(*) AS count, MAX(ts) AS latest_ts
  FROM klaxond_deliveries WHERE ts >= ?1 AND ts <= ?2 GROUP BY source
  UNION ALL
  SELECT 'severity', severity, COUNT(*), MAX(ts)
  FROM klaxond_deliveries WHERE ts >= ?1 AND ts <= ?2 GROUP BY severity
  UNION ALL
  SELECT 'channel', channel, COUNT(*), MAX(ts)
  FROM klaxond_deliveries WHERE ts >= ?1 AND ts <= ?2 GROUP BY channel
  UNION ALL
  SELECT 'suppressed', 'all', COUNT(*), COALESCE(MAX(ts), 0)
  FROM klaxond_deliveries
  WHERE ts >= ?1 AND ts <= ?2 AND suppressed_by <> ''
)
ORDER BY dimension, value
"#,
    )?;
    let rows = stmt.query_map(params![since, until], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, i64>(2)? as usize,
            row.get::<_, f64>(3)?,
        ))
    })?;
    for row in rows {
        let (dimension, value, count, latest_ts) = row?;
        match dimension.as_str() {
            "source" => {
                latest_by_source.insert(value.clone(), latest_ts);
                by_source.insert(value, count)
            }
            "severity" => by_severity.insert(value, count),
            "channel" => {
                latest_by_channel.insert(value.clone(), latest_ts);
                by_channel.insert(value, count)
            }
            "suppressed" => {
                suppressed = count;
                None
            }
            _ => None,
        };
    }
    let total = by_source.values().sum();
    Ok(DeliveryActivity {
        hours,
        total,
        total_history,
        suppressed,
        by_source,
        by_severity,
        by_channel,
        latest_by_source,
        latest_by_channel,
        latest_ts,
        approximate_history_bytes,
    })
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
