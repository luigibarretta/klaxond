use super::*;

#[test]
fn sqlite_affinity_rules() {
    for (declared, expected) in [
        ("INTEGER", LogicalType::Integer),
        ("BIGINT", LogicalType::Integer),
        ("int", LogicalType::Integer),
        ("TEXT", LogicalType::Text),
        ("VARCHAR(20)", LogicalType::Text),
        ("CLOB", LogicalType::Text),
        ("BLOB", LogicalType::Blob),
        ("", LogicalType::Blob),
        ("REAL", LogicalType::Real),
        ("DOUBLE PRECISION", LogicalType::Real),
        ("FLOAT", LogicalType::Real),
        ("NUMERIC", LogicalType::Numeric),
        ("BOOLEAN", LogicalType::Numeric),
        ("DATETIME", LogicalType::Numeric),
    ] {
        assert_eq!(LogicalType::from_sqlite(declared), expected, "{declared}");
    }
}

#[test]
fn postgres_type_families() {
    for (data_type, expected) in [
        ("smallint", LogicalType::Integer),
        ("integer", LogicalType::Integer),
        ("bigint", LogicalType::Integer),
        ("double precision", LogicalType::Real),
        ("real", LogicalType::Real),
        ("text", LogicalType::Text),
        ("character varying", LogicalType::Text),
        ("character", LogicalType::Text),
        ("bytea", LogicalType::Blob),
        ("numeric", LogicalType::Numeric),
        ("boolean", LogicalType::Boolean),
        (
            "timestamp with time zone",
            LogicalType::Other("timestamp with time zone".into()),
        ),
    ] {
        assert_eq!(
            LogicalType::from_postgres(data_type),
            expected,
            "{data_type}"
        );
    }
}

fn sample() -> LogicalSchema {
    let mut table = Table::default();
    table.columns.insert(
        "id".into(),
        Column {
            logical_type: LogicalType::Text,
            not_null: true,
        },
    );
    table.primary_key = vec!["id".into()];
    let mut schema = LogicalSchema::default();
    schema.tables.insert("t".into(), table);
    schema.indexes.insert(
        "idx_t".into(),
        Index {
            table: "t".into(),
            unique: false,
            columns: vec![("id".into(), true)],
            partial: false,
        },
    );
    schema
}

#[test]
fn identical_schemas_have_no_diff() {
    assert!(sample().diff(&sample()).is_empty());
}

#[test]
fn every_kind_of_difference_is_reported() {
    let base = sample();
    let mut other = sample();
    if let Some(table) = other.tables.get_mut("t") {
        table.columns.insert(
            "extra".into(),
            Column {
                logical_type: LogicalType::Integer,
                not_null: false,
            },
        );
        if let Some(id) = table.columns.get_mut("id") {
            id.logical_type = LogicalType::Integer;
        }
        table.primary_key.clear();
        table.unique_constraints.insert(vec!["id".into()]);
    }
    other.tables.insert("u".into(), Table::default());
    if let Some(index) = other.indexes.get_mut("idx_t") {
        index.partial = true;
    }
    other.indexes.insert(
        "idx_u".into(),
        Index {
            table: "u".into(),
            unique: true,
            columns: Vec::new(),
            partial: false,
        },
    );
    let diffs = base.diff(&other);
    let joined = diffs.join("\n");
    for needle in [
        "table t column extra only on the right",
        "column t.id",
        "table t primary key",
        "table t unique constraints",
        "table u only on the right",
        "index idx_t",
        "index idx_u only on the right",
    ] {
        assert!(joined.contains(needle), "missing {needle:?} in\n{joined}");
    }
    assert!(other
        .diff(&base)
        .iter()
        .any(|line| line == "table u only on the left"));
}

#[test]
fn snapshot_options_skip_internal_and_excluded_tables() {
    let options = SnapshotOptions::default().exclude("ledger");
    assert!(options.includes("app"));
    assert!(!options.includes("ledger"));
    assert!(!options.includes("sqlite_sequence"));
}
