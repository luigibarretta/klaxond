use super::*;

fn postgres_cfg(url: String) -> HistoryConfig {
    HistoryConfig {
        backend: "postgres".to_string(),
        sqlite_path: PathBuf::from("/tmp/klaxond-unused.db"),
        postgres_url: url,
        retention: 0,
        default_limit: 500,
    }
}

#[test]
#[ignore = "requires KLAXOND_TEST_POSTGRES_URL"]
fn postgres_delivery_search_matches_sqlite_unicode_casefold_contract() {
    let _guard = postgres_test_guard();
    let url = std::env::var("KLAXOND_TEST_POSTGRES_URL")
        .expect("KLAXOND_TEST_POSTGRES_URL is required for this ignored test");
    let store = HistoryStore::open(&postgres_cfg(url)).unwrap();
    let marker = crate::util::token_urlsafe(12);
    let delivery = DeliveryEntry {
        ts: crate::util::now_epoch(),
        source: format!("unicode-{marker}"),
        severity: "warning".into(),
        title: "\u{00c8} gi\u{00f9} \u{0130}STANBUL \u{039f}\u{03a3}".into(),
        channel: "ntfy".into(),
        suppressed_by: String::new(),
        emergency_receipt_id: None,
    };
    store.record_delivery(&delivery).unwrap();

    let mut query = DeliveryQuery::page(10, 0);
    query.source = Some(delivery.source.clone());
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
    }
}

#[test]
#[ignore = "requires KLAXOND_TEST_POSTGRES_URL"]
fn postgres_delivery_search_backfills_rows_inserted_by_an_older_binary() {
    let _guard = postgres_test_guard();
    let url = std::env::var("KLAXOND_TEST_POSTGRES_URL")
        .expect("KLAXOND_TEST_POSTGRES_URL is required for this ignored test");
    let cfg = postgres_cfg(url.clone());
    drop(HistoryStore::open(&cfg).unwrap());

    let marker = crate::util::token_urlsafe(12);
    let source = format!("legacy-{marker}");
    let title = "\u{0130}STANBUL \u{039f}\u{03a3}";
    let dedupe_hash = format!("legacy-search-{marker}");
    let mut client = ::postgres::Client::connect(&url, ::postgres::NoTls).unwrap();
    client
        .execute(
            r#"
INSERT INTO klaxond_deliveries
  (ts, source, severity, title, channel, suppressed_by, emergency_receipt_id, dedupe_hash)
VALUES ($1, $2, 'warning', $3, 'ntfy', '', NULL, $4)
"#,
            &[&crate::util::now_epoch(), &source, &title, &dedupe_hash],
        )
        .unwrap();
    drop(client);

    let store = HistoryStore::open(&cfg).unwrap();
    for search in ["i\u{0307}s", "\u{03bf}\u{03c3}", "\u{039f}\u{03a3}"] {
        let mut query = DeliveryQuery::page(10, 0);
        query.source = Some(source.clone());
        query.q = Some(search.into());
        let page = store.query_deliveries(&query).unwrap();
        assert_eq!(page.total, 1, "search {search:?}");
        assert_eq!(page.entries[0].title, title);
    }
}
