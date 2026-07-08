use super::*;
use std::path::PathBuf;
use tempfile::TempDir;

fn sqlite_cfg(path: PathBuf, retention: usize) -> HistoryConfig {
    HistoryConfig {
        backend: "sqlite".to_string(),
        sqlite_path: path,
        postgres_url: String::new(),
        retention,
        default_limit: 500,
    }
}

fn entry(i: usize) -> DeliveryEntry {
    DeliveryEntry {
        ts: 1000.0 + i as f64,
        source: "grafana".to_string(),
        severity: "warning".to_string(),
        title: format!("Alert {i}"),
        channel: "ntfy".to_string(),
        suppressed_by: String::new(),
    }
}

#[test]
fn sqlite_history_paginates_and_prunes_by_retention() {
    let tmp = TempDir::new().unwrap();
    let store = HistoryStore::open(&sqlite_cfg(tmp.path().join("history.db"), 3)).unwrap();
    for i in 0..5 {
        store.record_delivery(&entry(i)).unwrap();
    }

    let page = store.deliveries_page(2, 0).unwrap();
    assert_eq!(page.total, 3);
    assert_eq!(page.entries.len(), 2);
    assert_eq!(page.entries[0].title, "Alert 4");
    assert_eq!(page.entries[1].title, "Alert 3");

    let second = store.deliveries_page(2, 2).unwrap();
    assert_eq!(second.entries.len(), 1);
    assert_eq!(second.entries[0].title, "Alert 2");
}

#[test]
fn sqlite_history_migration_is_idempotent() {
    let tmp = TempDir::new().unwrap();
    let src = sqlite_cfg(tmp.path().join("src.db"), 0);
    let dst = sqlite_cfg(tmp.path().join("dst.db"), 0);
    let src_store = HistoryStore::open(&src).unwrap();
    src_store.record_delivery(&entry(1)).unwrap();
    src_store.record_delivery(&entry(2)).unwrap();

    assert_eq!(migrate_between(&src, &dst).unwrap(), 2);
    assert_eq!(migrate_between(&src, &dst).unwrap(), 2);

    let dst_store = HistoryStore::open(&dst).unwrap();
    let page = dst_store.deliveries_page(10, 0).unwrap();
    assert_eq!(page.total, 2);
    assert_eq!(page.entries[0].title, "Alert 2");
}

#[test]
fn sqlite_history_migration_requires_existing_source() {
    let tmp = TempDir::new().unwrap();
    let src = sqlite_cfg(tmp.path().join("missing.db"), 0);
    let dst = sqlite_cfg(tmp.path().join("dst.db"), 0);
    let err = migrate_between(&src, &dst).unwrap_err().to_string();
    assert!(err.contains("open source history store"));
    assert!(!src.sqlite_path.exists());
}
