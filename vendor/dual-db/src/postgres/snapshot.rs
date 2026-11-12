//! PostgreSQL logical-schema snapshot of `current_schema()`.

use crate::error::Result;
use crate::schema::{Column, Index, LogicalSchema, LogicalType, SnapshotOptions, Table};
use postgres::GenericClient;

const TABLES: &str = "
SELECT table_name::text FROM information_schema.tables
 WHERE table_schema = current_schema() AND table_type = 'BASE TABLE'
 ORDER BY table_name";

const COLUMNS: &str = "
SELECT column_name::text, data_type::text, is_nullable = 'NO'
  FROM information_schema.columns
 WHERE table_schema = current_schema() AND table_name = $1";

const CONSTRAINTS: &str = "
SELECT c.contype::text,
       array(SELECT a.attname::text
               FROM unnest(c.conkey) WITH ORDINALITY AS k(attnum, ord)
               JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = k.attnum
              ORDER BY k.ord)
  FROM pg_constraint c
  JOIN pg_class t ON t.oid = c.conrelid
  JOIN pg_namespace n ON n.oid = t.relnamespace
 WHERE n.nspname = current_schema() AND t.relname = $1 AND c.contype IN ('p', 'u')";

const INDEXES: &str = "
SELECT ic.relname::text, t.relname::text, i.indisunique, i.indpred IS NOT NULL,
       array(SELECT pg_get_indexdef(i.indexrelid, k, true)
               FROM generate_series(1, i.indnkeyatts::int) AS k ORDER BY k),
       array(SELECT (i.indoption[k - 1] & 1) = 1
               FROM generate_series(1, i.indnkeyatts::int) AS k ORDER BY k)
  FROM pg_index i
  JOIN pg_class ic ON ic.oid = i.indexrelid
  JOIN pg_class t ON t.oid = i.indrelid
  JOIN pg_namespace n ON n.oid = t.relnamespace
 WHERE n.nspname = current_schema()
   AND NOT EXISTS (SELECT 1 FROM pg_constraint c WHERE c.conindid = i.indexrelid)";

/// Snapshots the logical schema of `current_schema()`.
pub fn snapshot(
    client: &mut impl GenericClient,
    options: &SnapshotOptions,
) -> Result<LogicalSchema> {
    let mut schema = LogicalSchema::default();
    for row in client.query(TABLES, &[])? {
        let name: String = row.try_get(0)?;
        if options.includes(&name) {
            let table = table(client, &name)?;
            schema.tables.insert(name, table);
        }
    }
    for row in client.query(INDEXES, &[])? {
        let table: String = row.try_get(1)?;
        if !options.includes(&table) {
            continue;
        }
        let names: Vec<String> = row.try_get(4)?;
        let descending: Vec<bool> = row.try_get(5)?;
        let index = Index {
            table,
            unique: row.try_get(2)?,
            columns: names.into_iter().zip(descending).collect(),
            partial: row.try_get(3)?,
        };
        schema.indexes.insert(row.try_get(0)?, index);
    }
    Ok(schema)
}

fn table(client: &mut impl GenericClient, name: &str) -> Result<Table> {
    let mut table = Table::default();
    for row in client.query(CONSTRAINTS, &[&name])? {
        let kind: String = row.try_get(0)?;
        let columns: Vec<String> = row.try_get(1)?;
        if kind == "p" {
            table.primary_key = columns;
        } else {
            table.unique_constraints.insert(columns);
        }
    }
    for row in client.query(COLUMNS, &[&name])? {
        let column: String = row.try_get(0)?;
        let data_type: String = row.try_get(1)?;
        let not_null: bool = row.try_get(2)?;
        let is_key = table.primary_key.contains(&column);
        table.columns.insert(
            column,
            Column {
                logical_type: LogicalType::from_postgres(&data_type),
                not_null: not_null || is_key,
            },
        );
    }
    Ok(table)
}

const FINGERPRINT: &str = "
SELECT format('column %s.%s #%s %s nullable=%s default=%s',
              table_name, column_name, ordinal_position, data_type, is_nullable,
              coalesce(column_default, '-'))
  FROM information_schema.columns
 WHERE table_schema = current_schema() AND table_name::text = ANY($1::text[])
UNION ALL
SELECT format('index %s.%s: %s', tablename, indexname,
              regexp_replace(indexdef, ' ON \\S+\\.', ' ON '))
  FROM pg_indexes
 WHERE schemaname = current_schema() AND tablename::text = ANY($1::text[])
UNION ALL
SELECT format('constraint %s.%s: %s', t.relname, c.conname, pg_get_constraintdef(c.oid))
  FROM pg_constraint c
  JOIN pg_class t ON t.oid = c.conrelid
  JOIN pg_namespace n ON n.oid = t.relnamespace
 WHERE n.nspname = current_schema() AND t.relname::text = ANY($1::text[])
ORDER BY 1";

/// Exact DDL fingerprint of `current_schema()`: every column (position,
/// type, nullability, default), index definition and constraint definition
/// of the included tables, one sorted line each, for "schema unchanged"
/// proofs where the logical snapshot is too coarse.
pub fn ddl_fingerprint(
    client: &mut impl GenericClient,
    options: &SnapshotOptions,
) -> Result<Vec<String>> {
    let mut tables = Vec::new();
    for row in client.query(TABLES, &[])? {
        let name: String = row.try_get(0)?;
        if options.includes(&name) {
            tables.push(name);
        }
    }
    let mut lines = Vec::new();
    for row in client.query(FINGERPRINT, &[&tables])? {
        lines.push(row.try_get(0)?);
    }
    Ok(lines)
}
