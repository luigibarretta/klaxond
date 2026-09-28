use crate::history::{APPROXIMATE_DELIVERY_ROW_OVERHEAD, DeliveryActivity};
use anyhow::Result;
use rusqlite::{Connection, params};
use std::collections::BTreeMap;

type ActivityRow = (String, String, usize, f64);

#[derive(Default)]
struct ActivityGroups {
    by_source: BTreeMap<String, usize>,
    by_severity: BTreeMap<String, usize>,
    by_channel: BTreeMap<String, usize>,
    latest_by_source: BTreeMap<String, f64>,
    latest_by_channel: BTreeMap<String, f64>,
    suppressed: usize,
}

struct HistoryMetadata {
    total: usize,
    latest_ts: Option<f64>,
    approximate_bytes: usize,
}

pub(in crate::history) fn load(
    conn: &Connection,
    hours: u16,
    since: f64,
    until: f64,
) -> Result<DeliveryActivity> {
    let metadata = load_metadata(conn)?;
    let groups = load_groups(conn, since, until)?;
    Ok(DeliveryActivity {
        hours,
        total: groups.by_source.values().sum(),
        total_history: metadata.total,
        suppressed: groups.suppressed,
        by_source: groups.by_source,
        by_severity: groups.by_severity,
        by_channel: groups.by_channel,
        latest_by_source: groups.latest_by_source,
        latest_by_channel: groups.latest_by_channel,
        latest_ts: metadata.latest_ts,
        approximate_history_bytes: metadata.approximate_bytes,
    })
}

fn load_metadata(conn: &Connection) -> Result<HistoryMetadata> {
    let sql = format!(
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
    conn.query_row(&sql, [], |row| {
        Ok(HistoryMetadata {
            total: row.get::<_, i64>(0)? as usize,
            latest_ts: row.get(1)?,
            approximate_bytes: row.get::<_, i64>(2)? as usize,
        })
    })
    .map_err(Into::into)
}

fn load_groups(conn: &Connection, since: f64, until: f64) -> Result<ActivityGroups> {
    let mut stmt = conn.prepare(GROUPS_SQL)?;
    let rows = stmt.query_map(params![since, until], |row| {
        Ok((
            row.get(0)?,
            row.get(1)?,
            row.get::<_, i64>(2)? as usize,
            row.get(3)?,
        ))
    })?;
    let mut groups = ActivityGroups::default();
    for row in rows {
        groups.add(row?);
    }
    Ok(groups)
}

impl ActivityGroups {
    fn add(&mut self, (dimension, value, count, latest): ActivityRow) {
        match dimension.as_str() {
            "source" => {
                self.latest_by_source.insert(value.clone(), latest);
                self.by_source.insert(value, count);
            }
            "severity" => {
                self.by_severity.insert(value, count);
            }
            "channel" => {
                self.latest_by_channel.insert(value.clone(), latest);
                self.by_channel.insert(value, count);
            }
            "suppressed" => self.suppressed = count,
            _ => {}
        }
    }
}

const GROUPS_SQL: &str = r#"
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
"#;
