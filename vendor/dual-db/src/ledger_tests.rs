use super::*;

type M = Migration<fn()>;

fn registry(first: i64, count: i64) -> Vec<M> {
    (first..first + count)
        .map(|version| {
            M::new(version, NAMES[usize::try_from(version).unwrap_or(0) % 8]).sql("SELECT 1")
        })
        .collect()
}

const NAMES: [&str; 8] = ["m0", "m1", "m2", "m3", "m4", "m5", "m6", "m7"];

fn applied(migration: &M) -> LedgerRow {
    LedgerRow {
        version: migration.version(),
        name: Some(migration.name().to_owned()),
        checksum: Some(migration.checksum()),
    }
}

fn legacy(version: i64) -> LedgerRow {
    LedgerRow {
        version,
        name: None,
        checksum: None,
    }
}

#[test]
fn config_validates_table_and_keeps_settings() {
    assert!(matches!(
        LedgerConfig::new("bad name", 1),
        Err(Error::InvalidIdentifier(_))
    ));
    let config = LedgerConfig::new("app_schema_migrations", 42)
        .map(|c| c.legacy_rows(LegacyRows::Adopt))
        .ok();
    let config = config.as_ref();
    assert_eq!(
        config.map(LedgerConfig::table),
        Some("app_schema_migrations")
    );
    assert_eq!(config.map(LedgerConfig::lock_key), Some(42));
    assert_eq!(config.map(LedgerConfig::legacy), Some(LegacyRows::Adopt));
}

#[test]
fn empty_ledger_applies_the_first_migration() {
    let migrations = registry(1, 3);
    assert_eq!(
        plan(&migrations, &[], LegacyRows::Reject).ok(),
        Some(Next::Apply(0))
    );
}

#[test]
fn partially_applied_ledger_continues_in_order() {
    let migrations = registry(1, 3);
    let rows = [applied(&migrations[0]), applied(&migrations[1])];
    assert_eq!(
        plan(&migrations, &rows, LegacyRows::Reject).ok(),
        Some(Next::Apply(2))
    );
    let all: Vec<_> = migrations.iter().map(applied).collect();
    assert_eq!(
        plan(&migrations, &all, LegacyRows::Reject).ok(),
        Some(Next::Done(Some(3)))
    );
}

#[test]
fn checksum_and_name_mismatch_are_refused() {
    let migrations = registry(1, 2);
    let mut row = applied(&migrations[0]);
    row.checksum = Some("0".repeat(64));
    assert!(matches!(
        plan(&migrations, &[row], LegacyRows::Reject),
        Err(Error::ChecksumMismatch { version: 1, .. })
    ));
    let mut row = applied(&migrations[0]);
    row.name = Some("renamed".into());
    assert!(matches!(
        plan(&migrations, &[row], LegacyRows::Reject),
        Err(Error::NameMismatch { version: 1, .. })
    ));
    let mut row = applied(&migrations[0]);
    row.name = None;
    assert!(matches!(
        plan(&migrations, &[row], LegacyRows::Reject),
        Err(Error::NameMismatch { version: 1, .. })
    ));
}

#[test]
fn ledger_ahead_of_the_binary_is_refused() {
    let migrations = registry(1, 2);
    let mut newer = applied(&migrations[1]);
    newer.version = 3;
    assert!(matches!(
        plan(&migrations, &[newer], LegacyRows::Reject),
        Err(Error::LedgerAhead {
            found: 3,
            latest: 2
        })
    ));
    assert!(matches!(
        plan(&migrations, &[legacy(5)], LegacyRows::Adopt),
        Err(Error::LedgerAhead {
            found: 5,
            latest: 2
        })
    ));
}

#[test]
fn checksummed_version_below_the_registry_is_unknown() {
    let migrations = registry(5, 2);
    let mut old = applied(&migrations[0]);
    old.version = 2;
    assert!(matches!(
        plan(&migrations, &[old], LegacyRows::Adopt),
        Err(Error::UnknownVersion(2))
    ));
}

#[test]
fn gap_before_an_applied_migration_is_refused() {
    let migrations = registry(1, 3);
    let rows = [applied(&migrations[0]), applied(&migrations[2])];
    assert!(matches!(
        plan(&migrations, &rows, LegacyRows::Reject),
        Err(Error::OutOfOrder {
            pending: 2,
            applied: 3
        })
    ));
}

#[test]
fn legacy_rows_are_rejected_by_default() {
    let migrations = registry(9, 1);
    assert!(matches!(
        plan(&migrations, &[legacy(9)], LegacyRows::Reject),
        Err(Error::LegacyRowRejected(9))
    ));
}

#[test]
fn legacy_rows_below_the_registry_are_history_and_matching_rows_are_adopted() {
    let migrations = registry(9, 2);
    let rows: Vec<_> = (1..=9).map(legacy).collect();
    assert_eq!(
        plan(&migrations, &rows, LegacyRows::Adopt).ok(),
        Some(Next::Adopt(0))
    );

    let mut rows: Vec<_> = (1..=8).map(legacy).collect();
    rows.push(applied(&migrations[0]));
    assert_eq!(
        plan(&migrations, &rows, LegacyRows::Adopt).ok(),
        Some(Next::Apply(1))
    );

    // A database last written by a release older than the baseline: only
    // history rows, so the baseline is applied (inserted), not adopted.
    let rows: Vec<_> = (1..=5).map(legacy).collect();
    assert_eq!(
        plan(&migrations, &rows, LegacyRows::Adopt).ok(),
        Some(Next::Apply(0))
    );

    let mut rows: Vec<_> = (1..=8).map(legacy).collect();
    rows.extend(migrations.iter().map(applied));
    assert_eq!(
        plan(&migrations, &rows, LegacyRows::Adopt).ok(),
        Some(Next::Done(Some(10)))
    );
}

#[test]
fn empty_registry_is_refused() {
    let migrations: Vec<M> = Vec::new();
    assert!(matches!(
        plan(&migrations, &[], LegacyRows::Reject),
        Err(Error::InvalidRegistry(_))
    ));
}
