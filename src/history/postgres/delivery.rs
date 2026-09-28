use crate::history::{DeliveryEntry, DeliveryQuery, dedupe_hash, delivery_search_values};
use anyhow::Result;
use postgres::Client;
use postgres::types::ToSql;

mod activity;

pub(super) use activity::load as activity;

pub(super) fn insert(client: &mut Client, entry: &DeliveryEntry) -> Result<()> {
    let hash = dedupe_hash(entry);
    let search = delivery_search_values(
        &entry.source,
        &entry.severity,
        &entry.title,
        &entry.channel,
        &entry.suppressed_by,
    );
    client.execute(
        r#"
INSERT INTO klaxond_deliveries
  (ts, source, severity, title, channel, suppressed_by, emergency_receipt_id,
   search_source, search_severity, search_title, search_channel, search_suppressed_by,
   search_version, dedupe_hash)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, 1, $13)
ON CONFLICT (dedupe_hash) DO NOTHING
"#,
        &[
            &entry.ts,
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
            &hash,
        ],
    )?;
    Ok(())
}

const FILTER_SQL: &str = r#"
WHERE
  ($1::TEXT IS NULL OR
    strpos(search_source, $1) > 0 OR
    strpos(search_severity, $1) > 0 OR
    strpos(search_title, $1) > 0 OR
    strpos(search_channel, $1) > 0 OR
    strpos(search_suppressed_by, $1) > 0)
  AND ($2::TEXT IS NULL OR source = $2)
  AND ($3::TEXT IS NULL OR severity = $3)
  AND ($4::TEXT IS NULL OR channel = $4)
  AND ($5::DOUBLE PRECISION IS NULL OR ts >= $5)
  AND ($6::DOUBLE PRECISION IS NULL OR ts <= $6)
  AND (
    $7 = 'include' OR
    ($7 = 'exclude' AND suppressed_by = '') OR
    ($7 = 'only' AND suppressed_by <> '')
  )
"#;

pub(super) fn count(client: &mut Client, query: &DeliveryQuery) -> Result<usize> {
    let sql = format!("SELECT COUNT(*) FROM klaxond_deliveries {FILTER_SQL}");
    let suppressed = query.suppressed.as_str();
    let params: &[&(dyn ToSql + Sync)] = &[
        &query.q,
        &query.source,
        &query.severity,
        &query.channel,
        &query.from,
        &query.to,
        &suppressed,
    ];
    let row = client.query_one(&sql, params)?;
    Ok(row.get::<_, i64>(0) as usize)
}

pub(super) fn page(client: &mut Client, query: &DeliveryQuery) -> Result<Vec<DeliveryEntry>> {
    let sql = format!(
        r#"
SELECT ts, source, severity, title, channel, suppressed_by, emergency_receipt_id
FROM klaxond_deliveries
{FILTER_SQL}
ORDER BY ts DESC, id DESC
LIMIT $8 OFFSET $9
"#,
    );
    let suppressed = query.suppressed.as_str();
    let limit = query.limit as i64;
    let offset = query.offset as i64;
    let params: &[&(dyn ToSql + Sync)] = &[
        &query.q,
        &query.source,
        &query.severity,
        &query.channel,
        &query.from,
        &query.to,
        &suppressed,
        &limit,
        &offset,
    ];
    let rows = client.query(&sql, params)?;
    Ok(rows
        .into_iter()
        .map(|row| DeliveryEntry {
            ts: row.get(0),
            source: row.get(1),
            severity: row.get(2),
            title: row.get(3),
            channel: row.get(4),
            suppressed_by: row.get(5),
            emergency_receipt_id: row.get(6),
        })
        .collect())
}

pub(super) fn export_all(client: &mut Client) -> Result<Vec<DeliveryEntry>> {
    let mut tx = client.transaction()?;
    let has_receipt = tx.query_one(
        "SELECT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = 'klaxond_deliveries' AND column_name = 'emergency_receipt_id')",
        &[],
    )?.get::<_, bool>(0);
    let receipt_select = if has_receipt {
        "emergency_receipt_id"
    } else {
        "NULL::TEXT AS emergency_receipt_id"
    };
    let rows = tx.query(
        &format!(
            "SELECT ts, source, severity, title, channel, suppressed_by, {receipt_select} \
             FROM klaxond_deliveries ORDER BY ts ASC, id ASC"
        ),
        &[],
    )?;
    let entries = rows
        .into_iter()
        .map(|row| DeliveryEntry {
            ts: row.get(0),
            source: row.get(1),
            severity: row.get(2),
            title: row.get(3),
            channel: row.get(4),
            suppressed_by: row.get(5),
            emergency_receipt_id: row.get(6),
        })
        .collect();
    tx.commit()?;
    Ok(entries)
}

pub(super) fn prune(client: &mut Client, retention: usize) -> Result<()> {
    if retention == 0 {
        return Ok(());
    }
    client.execute(
        r#"
DELETE FROM klaxond_deliveries
WHERE id NOT IN (
  SELECT id FROM klaxond_deliveries ORDER BY ts DESC, id DESC LIMIT $1
)
"#,
        &[&(retention as i64)],
    )?;
    Ok(())
}
