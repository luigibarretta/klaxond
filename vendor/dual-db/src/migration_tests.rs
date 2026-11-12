use super::*;

type M = Migration<fn()>;

fn noop() {}

#[test]
fn single_sql_step_checksum_is_plain_sha256_of_the_sql() {
    // sha256("SELECT 1") computed independently (coreutils sha256sum).
    let migration = M::new(1, "one").sql("SELECT 1");
    assert_eq!(
        migration.checksum(),
        "e004ebd5b5532a4b85984a62f8ad48a81aa3460c1ca07701f386135d72cdecf5"
    );
}

#[test]
fn checksum_depends_on_every_step_field_and_order() {
    let base = M::new(1, "m")
        .sql("CREATE TABLE t (a TEXT)")
        .add_column_if_missing("t", "b", "TEXT");
    let variants = [
        M::new(1, "m")
            .sql("CREATE TABLE t (a TEXT)")
            .add_column_if_missing("t", "b", "INTEGER"),
        M::new(1, "m")
            .sql("CREATE TABLE t (a TEXT)")
            .add_column_if_missing("t", "c", "TEXT"),
        M::new(1, "m")
            .add_column_if_missing("t", "b", "TEXT")
            .sql("CREATE TABLE t (a TEXT)"),
        M::new(1, "m")
            .sql("CREATE TABLE t (a TEXT)")
            .add_column_if_missing("t", "b", "TEXT")
            .code("backfill_v1", noop),
        M::new(1, "m").sql("CREATE TABLE t (a TEXT)"),
    ];
    for variant in &variants {
        assert_ne!(variant.checksum(), base.checksum(), "{variant:?}");
    }
    let with_code = M::new(1, "m").code("backfill_v1", noop);
    assert_ne!(
        with_code.checksum(),
        M::new(1, "m").code("backfill_v2", noop).checksum()
    );
    // Name and version are ledger columns, not part of the checksum.
    assert_eq!(
        base.checksum(),
        M::new(7, "other")
            .sql("CREATE TABLE t (a TEXT)")
            .add_column_if_missing("t", "b", "TEXT")
            .checksum()
    );
}

#[test]
fn framing_prevents_field_boundary_collisions() {
    let a = M::new(1, "m").sql("ab").sql("c");
    let b = M::new(1, "m").sql("a").sql("bc");
    assert_ne!(a.checksum(), b.checksum());
}

#[test]
fn checksum_is_lowercase_hex_of_32_bytes() {
    let checksum = M::new(1, "m").sql("a").sql("b").checksum();
    assert_eq!(checksum.len(), 64);
    assert!(checksum
        .bytes()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)));
}

#[test]
fn identifiers() {
    for ok in ["a", "_a", "table_1", "A1", &"x".repeat(63)] {
        assert!(is_identifier(ok), "{ok}");
    }
    for bad in ["", "1a", "a-b", "a b", "a;", "\"a\"", "é", &"x".repeat(64)] {
        assert!(!is_identifier(bad), "{bad}");
    }
}

#[test]
fn registry_accepts_contiguous_versions_from_any_start() {
    let registry = vec![
        M::new(9, "baseline").sql("SELECT 1"),
        M::new(10, "next").sql("SELECT 2"),
    ];
    assert!(validate_registry(&registry).is_ok());
}

#[test]
fn registry_rejections() {
    let cases: Vec<Vec<M>> = vec![
        vec![],
        vec![M::new(0, "zero").sql("SELECT 1")],
        vec![
            M::new(1, "a").sql("SELECT 1"),
            M::new(3, "b").sql("SELECT 1"),
        ],
        vec![
            M::new(2, "a").sql("SELECT 1"),
            M::new(1, "b").sql("SELECT 1"),
        ],
        vec![
            M::new(1, "a").sql("SELECT 1"),
            M::new(2, "a").sql("SELECT 1"),
        ],
        vec![M::new(1, " ").sql("SELECT 1")],
        vec![M::new(1, "a")],
        vec![M::new(1, "a").sql("  ")],
        vec![M::new(1, "a").code("", noop)],
        vec![M::new(1, "a").add_column_if_missing("t;", "c", "TEXT")],
        vec![M::new(1, "a").add_column_if_missing("t", "c d", "TEXT")],
        vec![M::new(1, "a").add_column_if_missing("t", "c", "TEXT; DROP TABLE t")],
        vec![M::new(1, "a").add_column_if_missing("t", "c", " ")],
    ];
    for (index, registry) in cases.iter().enumerate() {
        let error = validate_registry(registry).err();
        assert!(
            matches!(
                error,
                Some(Error::InvalidRegistry(_) | Error::InvalidIdentifier(_))
            ),
            "case {index}: {error:?}"
        );
    }
}

#[test]
fn accessors_and_debug() {
    let migration = M::new(4, "four")
        .sql("SELECT 1")
        .add_column_if_missing("t", "c", "TEXT")
        .code("id", noop);
    assert_eq!(migration.version(), 4);
    assert_eq!(migration.name(), "four");
    assert_eq!(migration.steps().len(), 3);
    let debug = format!("{migration:?}");
    assert!(
        debug.contains("Sql") && debug.contains("AddColumnIfMissing") && debug.contains("Code")
    );
}
