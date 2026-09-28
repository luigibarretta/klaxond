use crate::history::{APPROXIMATE_DELIVERY_ROW_OVERHEAD, DeliveryActivity};
use anyhow::Result;
use postgres::{Client, Row};
use std::collections::BTreeMap;

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

pub(in crate::history::postgres) fn load(
    client: &mut Client,
    hours: u16,
    since: f64,
    until: f64,
) -> Result<DeliveryActivity> {
    let metadata = load_metadata(client)?;
    let groups = load_groups(client, since, until)?;
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

fn load_metadata(client: &mut Client) -> Result<HistoryMetadata> {
    let sql = format!(
        r#"
SELECT
  COUNT(*),
  MAX(ts),
  COALESCE(SUM(
    {APPROXIMATE_DELIVERY_ROW_OVERHEAD}::BIGINT
    + octet_length(source)::BIGINT
    + octet_length(severity)::BIGINT
    + octet_length(title)::BIGINT
    + octet_length(channel)::BIGINT
    + octet_length(suppressed_by)::BIGINT
    + octet_length(COALESCE(emergency_receipt_id, ''))::BIGINT
    + octet_length(search_source)::BIGINT
    + octet_length(search_severity)::BIGINT
    + octet_length(search_title)::BIGINT
    + octet_length(search_channel)::BIGINT
    + octet_length(search_suppressed_by)::BIGINT
    + octet_length(dedupe_hash)::BIGINT
  ), 0)::BIGINT
FROM klaxond_deliveries
"#
    );
    let row = client.query_one(&sql, &[])?;
    Ok(HistoryMetadata {
        total: row.get::<_, i64>(0) as usize,
        latest_ts: row.get(1),
        approximate_bytes: row.get::<_, i64>(2) as usize,
    })
}

fn load_groups(client: &mut Client, since: f64, until: f64) -> Result<ActivityGroups> {
    let rows = client.query(GROUPS_SQL, &[&since, &until])?;
    let mut groups = ActivityGroups::default();
    for row in rows {
        groups.add(&row);
    }
    Ok(groups)
}

impl ActivityGroups {
    fn add(&mut self, row: &Row) {
        let dimension = row.get::<_, String>(0);
        let value = row.get::<_, String>(1);
        let count = row.get::<_, i64>(2) as usize;
        let latest = row.get::<_, f64>(3);
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
  SELECT 'source'::TEXT AS dimension, source AS value, COUNT(*) AS count, MAX(ts) AS latest_ts
  FROM klaxond_deliveries WHERE ts >= $1 AND ts <= $2 GROUP BY source
  UNION ALL
  SELECT 'severity', severity, COUNT(*), MAX(ts)
  FROM klaxond_deliveries WHERE ts >= $1 AND ts <= $2 GROUP BY severity
  UNION ALL
  SELECT 'channel', channel, COUNT(*), MAX(ts)
  FROM klaxond_deliveries WHERE ts >= $1 AND ts <= $2 GROUP BY channel
  UNION ALL
  SELECT 'suppressed', 'all', COUNT(*), COALESCE(MAX(ts), 0)
  FROM klaxond_deliveries
  WHERE ts >= $1 AND ts <= $2 AND suppressed_by <> ''
) grouped
ORDER BY dimension, value
"#;
