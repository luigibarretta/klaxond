//! SQLite logical-schema snapshot.

use crate::error::Result;
use crate::schema::{Column, Index, LogicalSchema, LogicalType, SnapshotOptions, Table};
use rusqlite::Connection;

/// Snapshots the logical schema of the `main` database.
pub fn snapshot(conn: &Connection, options: &SnapshotOptions) -> Result<LogicalSchema> {
    let mut schema = LogicalSchema::default();
    for table_name in table_names(conn)? {
        if !options.includes(&table_name) {
            continue;
        }
        let mut table = columns(conn, &table_name)?;
        for (index_name, unique, origin, partial) in index_list(conn, &table_name)? {
            match origin.as_str() {
                "u" => {
                    let keys = index_columns(conn, &index_name)?;
                    table
                        .unique_constraints
                        .insert(keys.into_iter().map(|(name, _)| name).collect());
                }
                "c" => {
                    let index = Index {
                        table: table_name.clone(),
                        unique,
                        columns: index_columns(conn, &index_name)?,
                        partial,
                    };
                    schema.indexes.insert(index_name, index);
                }
                // "pk": the primary key is read from the table columns.
                _ => {}
            }
        }
        schema.tables.insert(table_name, table);
    }
    Ok(schema)
}

fn table_names(conn: &Connection) -> Result<Vec<String>> {
    let mut statement =
        conn.prepare("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name")?;
    let names = statement
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(names)
}

fn columns(conn: &Connection, table: &str) -> Result<Table> {
    let mut statement =
        conn.prepare("SELECT name, type, \"notnull\", pk FROM pragma_table_info(?1)")?;
    let rows = statement
        .query_map([table], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)? != 0,
                row.get::<_, i64>(3)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let mut table = Table::default();
    let mut primary_key = Vec::new();
    for (name, declared, not_null, pk) in rows {
        if pk > 0 {
            primary_key.push((pk, name.clone()));
        }
        let column = Column {
            logical_type: LogicalType::from_sqlite(&declared),
            not_null: not_null || pk > 0,
        };
        table.columns.insert(name, column);
    }
    primary_key.sort();
    table.primary_key = primary_key.into_iter().map(|(_, name)| name).collect();
    Ok(table)
}

type IndexListRow = (String, bool, String, bool);

fn index_list(conn: &Connection, table: &str) -> Result<Vec<IndexListRow>> {
    let mut statement = conn.prepare(
        "SELECT name, \"unique\", origin, partial FROM pragma_index_list(?1) ORDER BY name",
    )?;
    let rows = statement
        .query_map([table], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)? != 0,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)? != 0,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

fn index_columns(conn: &Connection, index: &str) -> Result<Vec<(String, bool)>> {
    let mut statement = conn.prepare(
        "SELECT name, \"desc\" FROM pragma_index_xinfo(?1) WHERE \"key\" = 1 ORDER BY seqno",
    )?;
    let rows = statement
        .query_map([index], |row| {
            Ok((
                row.get::<_, Option<String>>(0)?
                    .unwrap_or_else(|| "<expression>".to_owned()),
                row.get::<_, i64>(1)? != 0,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

/// Exact DDL fingerprint: one line per schema object (`type name table`
/// and the stored `CREATE` text), sorted, for "schema unchanged" proofs
/// where the logical snapshot is too coarse. Objects of excluded tables and
/// internal `sqlite_*` objects are skipped.
pub fn ddl_fingerprint(conn: &Connection, options: &SnapshotOptions) -> Result<Vec<String>> {
    let mut statement = conn.prepare(
        "SELECT type, name, tbl_name, coalesce(sql, '') FROM sqlite_master ORDER BY type, name",
    )?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows
        .into_iter()
        .filter(|(_, name, table, _)| options.includes(table) && !name.starts_with("sqlite_"))
        .map(|(kind, name, table, sql)| format!("{kind} {name} {table}: {sql}"))
        .collect())
}
