use super::*;

#[test]
fn sqlite_delivery_history_preserves_emergency_receipt_id() {
    let tmp = TempDir::new().unwrap();
    let store = HistoryStore::open(&sqlite_cfg(tmp.path().join("history.db"), 10)).unwrap();
    let mut delivery = entry(1);
    delivery.emergency_receipt_id = Some("receipt-123".to_string());
    store.record_delivery(&delivery).unwrap();

    let page = store.deliveries_page(10, 0).unwrap();
    assert_eq!(
        page.entries[0].emergency_receipt_id.as_deref(),
        Some("receipt-123")
    );
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
fn sqlite_delivery_query_filters_count_and_entries_identically() {
    let tmp = TempDir::new().unwrap();
    let store = HistoryStore::open(&sqlite_cfg(tmp.path().join("history.db"), 0)).unwrap();
    let deliveries = [
        DeliveryEntry {
            ts: 1_000.0,
            source: "grafana".into(),
            severity: "warning".into(),
            title: "Disk FULL".into(),
            channel: "ntfy".into(),
            suppressed_by: String::new(),
            emergency_receipt_id: None,
        },
        DeliveryEntry {
            ts: 1_001.0,
            source: "authentik".into(),
            severity: "critical".into(),
            title: "Login failure".into(),
            channel: "telegram".into(),
            suppressed_by: "repeat-rule".into(),
            emergency_receipt_id: None,
        },
        DeliveryEntry {
            ts: 1_002.0,
            source: "grafana".into(),
            severity: "info".into(),
            title: "Recovered".into(),
            channel: "smtp".into(),
            suppressed_by: String::new(),
            emergency_receipt_id: None,
        },
    ];
    for delivery in &deliveries {
        store.record_delivery(delivery).unwrap();
    }

    let mut query = DeliveryQuery::page(10, 0);
    for (search, expected_title) in [
        ("GRAFANA", "Recovered"),
        ("CRITICAL", "Login failure"),
        ("full", "Disk FULL"),
        ("TELEGRAM", "Login failure"),
        ("REPEAT", "Login failure"),
    ] {
        query.q = Some(search.into());
        let page = store.query_deliveries(&query).unwrap();
        assert!(page.total >= 1, "search {search}");
        assert_eq!(page.entries[0].title, expected_title, "search {search}");
    }

    query.q = None;
    query.source = Some("grafana".into());
    query.severity = Some("info".into());
    query.channel = Some("smtp".into());
    query.from = Some(1_001.5);
    query.to = Some(1_002.0);
    let page = store.query_deliveries(&query).unwrap();
    assert_eq!(page.total, 1);
    assert_eq!(page.entries.len(), 1);
    assert_eq!(page.entries[0].title, "Recovered");

    query = DeliveryQuery::page(1, 0);
    query.suppressed = SuppressedFilter::Exclude;
    let page = store.query_deliveries(&query).unwrap();
    assert_eq!(page.total, 2);
    assert_eq!(page.entries.len(), 1);
    assert!(page.entries[0].suppressed_by.is_empty());

    query.suppressed = SuppressedFilter::Only;
    let page = store.query_deliveries(&query).unwrap();
    assert_eq!(page.total, 1);
    assert_eq!(page.entries[0].suppressed_by, "repeat-rule");
}

#[test]
fn sqlite_delivery_query_uses_stable_newest_first_ordering() {
    let tmp = TempDir::new().unwrap();
    let store = HistoryStore::open(&sqlite_cfg(tmp.path().join("history.db"), 0)).unwrap();
    let mut first = entry(1);
    first.ts = 2_000.0;
    first.title = "first insert".into();
    let mut second = first.clone();
    second.title = "second insert".into();
    store.record_delivery(&first).unwrap();
    store.record_delivery(&second).unwrap();

    let page = store.deliveries_page(10, 0).unwrap();
    assert_eq!(page.entries[0].title, "second insert");
    assert_eq!(page.entries[1].title, "first insert");
}

#[test]
fn sqlite_delivery_search_is_unicode_case_insensitive() {
    let tmp = TempDir::new().unwrap();
    let store = HistoryStore::open(&sqlite_cfg(tmp.path().join("history.db"), 0)).unwrap();
    let delivery = DeliveryEntry {
        title: "\u{00c8} gi\u{00f9} \u{0130}STANBUL \u{039f}\u{03a3}".into(),
        ..entry(1)
    };
    store.record_delivery(&delivery).unwrap();

    let mut query = DeliveryQuery::page(10, 0);
    for search in [
        "\u{00e8}",
        "i\u{0307}s",
        "\u{03bf}\u{03c3}",
        "\u{03bf}\u{03c2}",
        "\u{039f}\u{03a3}",
    ] {
        query.q = Some(search.into());
        let page = store.query_deliveries(&query).unwrap();
        assert_eq!(page.total, 1, "search {search:?}");
        assert_eq!(page.entries[0].title, delivery.title);
        assert!(query.normalized().matches(&delivery));
    }
}

#[test]
fn sqlite_delivery_search_migration_backfills_existing_rows() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("history.db");
    let conn = rusqlite::Connection::open(&path).unwrap();
    conn.execute_batch(
        r#"
CREATE TABLE klaxond_schema_migrations (
  version INTEGER PRIMARY KEY,
  applied_at INTEGER NOT NULL DEFAULT (strftime('%s','now'))
);
INSERT INTO klaxond_schema_migrations(version) VALUES (8);
CREATE TABLE klaxond_deliveries (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts REAL NOT NULL,
  source TEXT NOT NULL,
  severity TEXT NOT NULL,
  title TEXT NOT NULL,
  channel TEXT NOT NULL,
  suppressed_by TEXT NOT NULL DEFAULT '',
  emergency_receipt_id TEXT,
  dedupe_hash TEXT NOT NULL
);
"#,
    )
    .unwrap();
    conn.execute(
        r#"
INSERT INTO klaxond_deliveries
  (ts, source, severity, title, channel, suppressed_by, emergency_receipt_id, dedupe_hash)
VALUES (1000, 'grafana', 'warning', ?1, 'ntfy', '', NULL, 'legacy-search-row')
"#,
        ["\u{0130}STANBUL \u{039f}\u{03a3}"],
    )
    .unwrap();
    drop(conn);

    let store = HistoryStore::open(&sqlite_cfg(path, 0)).unwrap();
    for search in [
        "i\u{0307}s",
        "\u{03bf}\u{03c3}",
        "\u{03bf}\u{03c2}",
        "\u{039f}\u{03a3}",
    ] {
        let mut query = DeliveryQuery::page(10, 0);
        query.q = Some(search.into());
        let page = store.query_deliveries(&query).unwrap();
        assert_eq!(page.total, 1, "search {search:?}");
    }
}

#[test]
fn sqlite_delivery_activity_aggregates_window_and_estimated_size() {
    let tmp = TempDir::new().unwrap();
    let store = HistoryStore::open(&sqlite_cfg(tmp.path().join("history.db"), 0)).unwrap();
    let mut old = entry(0);
    old.ts = 1_000.0;
    old.channel = "smtp".into();
    let mut recent = entry(1);
    recent.ts = 1_100.0;
    recent.channel = "ntfy".into();
    let mut newest = entry(2);
    newest.ts = 1_200.0;
    newest.source = "authentik".into();
    newest.severity = "critical".into();
    newest.channel = "ntfy".into();
    newest.suppressed_by = "maintenance".into();
    let mut future = entry(3);
    future.ts = 1_300.0;
    future.source = "future-source".into();
    for delivery in [&old, &recent, &newest, &future] {
        store.record_delivery(delivery).unwrap();
    }

    let activity = store.delivery_activity(24, 1_050.0, 1_200.0).unwrap();
    assert_eq!(activity.hours, 24);
    assert_eq!(activity.total, 2);
    assert_eq!(activity.total_history, 4);
    assert_eq!(activity.suppressed, 1);
    assert_eq!(activity.by_source.get("grafana"), Some(&1));
    assert_eq!(activity.by_source.get("authentik"), Some(&1));
    assert_eq!(activity.by_severity.get("critical"), Some(&1));
    assert_eq!(activity.by_channel.get("ntfy"), Some(&2));
    assert_eq!(activity.latest_by_source.get("grafana"), Some(&1_100.0));
    assert_eq!(activity.latest_by_source.get("authentik"), Some(&1_200.0));
    assert_eq!(activity.latest_by_channel.get("ntfy"), Some(&1_200.0));
    assert!(!activity.by_source.contains_key("future-source"));
    assert!(!activity.latest_by_source.contains_key("future-source"));
    assert_eq!(activity.latest_ts, Some(1_300.0));
    assert_eq!(
        activity.approximate_history_bytes,
        [&old, &recent, &newest, &future]
            .into_iter()
            .map(approximate_delivery_bytes)
            .sum::<usize>()
    );
}

#[test]
fn sqlite_empty_delivery_activity_reports_zero_size() {
    let tmp = TempDir::new().unwrap();
    let store = HistoryStore::open(&sqlite_cfg(tmp.path().join("history.db"), 0)).unwrap();
    let activity = store.delivery_activity(24, 0.0, 10_000.0).unwrap();
    assert_eq!(activity.total, 0);
    assert_eq!(activity.total_history, 0);
    assert_eq!(activity.suppressed, 0);
    assert_eq!(activity.latest_ts, None);
    assert_eq!(activity.approximate_history_bytes, 0);
    assert!(activity.latest_by_source.is_empty());
    assert!(activity.latest_by_channel.is_empty());
}
