use super::*;
use tracing_subscriber::layer::SubscriberExt;

fn entry(id: u64, level: &str, target: &str, message: &str) -> LogEntry {
    LogEntry {
        id,
        ts: id as f64,
        timestamp: format!("2026-06-30T00:00:0{id}.000Z"),
        level: level.to_string(),
        target: target.to_string(),
        message: message.to_string(),
        fields: HashMap::new(),
        file: None,
        line: None,
    }
}

#[test]
fn query_filters_by_keyword_level_and_limit_newest_first() {
    let buffer = LogBuffer::new(3);
    {
        let mut entries = buffer.entries.lock().unwrap();
        entries.push_back(entry(1, "INFO", "klaxond", "started"));
        entries.push_back(entry(2, "WARN", "render", "Grafana returned 500"));
        entries.push_back(entry(3, "ERROR", "smtp", "send failed"));
    }

    let result = buffer.query("failed", "error", 10, 0);
    assert_eq!(result.total, 1);
    assert_eq!(result.entries[0].id, 3);

    let result = buffer.query("città", "all", 10, 0);
    assert_eq!(result.total, 0);

    let result = buffer.query("", "all", 2, 0);
    assert_eq!(result.total, 3);
    assert_eq!(
        result.entries.iter().map(|e| e.id).collect::<Vec<_>>(),
        vec![3, 2]
    );
}

#[test]
fn query_supports_offset_and_clamps_to_last_page() {
    let buffer = LogBuffer::new(5);
    {
        let mut entries = buffer.entries.lock().unwrap();
        for id in 1..=5 {
            entries.push_back(entry(id, "INFO", "klaxond", "line"));
        }
    }

    let result = buffer.query("", "all", 2, 2);
    assert_eq!(result.total, 5);
    assert_eq!(result.limit, 2);
    assert_eq!(result.offset, 2);
    assert_eq!(
        result.entries.iter().map(|e| e.id).collect::<Vec<_>>(),
        vec![3, 2]
    );

    let result = buffer.query("", "all", 2, 99);
    assert_eq!(result.offset, 4);
    assert_eq!(
        result.entries.iter().map(|e| e.id).collect::<Vec<_>>(),
        vec![1]
    );
}

#[test]
fn stats_reports_retained_capacity_and_warning_counts() {
    let buffer = LogBuffer::new(5);
    {
        let mut entries = buffer.entries.lock().unwrap();
        entries.push_back(entry(1, "INFO", "klaxond", "started"));
        entries.push_back(entry(2, "WARN", "delivery", "retry"));
        entries.push_back(entry(3, "ERROR", "smtp", "failed"));
    }

    let stats = buffer.stats();
    assert_eq!(stats.capacity, 5);
    assert_eq!(stats.retained, 3);
    assert_eq!(stats.warn, 1);
    assert_eq!(stats.error, 1);
    assert_eq!(
        stats.newest_timestamp.as_deref(),
        Some("2026-06-30T00:00:03.000Z")
    );
}

#[test]
fn captured_events_are_redacted_and_capacity_eviction_holds() {
    let buffer = Arc::new(LogBuffer::new(2));
    let subscriber = tracing_subscriber::registry().with(LogCaptureLayer::new(buffer.clone()));

    tracing::subscriber::with_default(subscriber, || {
        tracing::info!(target: "test_logs", "first line evicted");
        tracing::warn!(
            target: "test_logs",
            token = "plain-token-1234567890",
            url = "https://example.invalid/hook?token=abc123&ok=1",
            "telegram failed at https://api.telegram.org/bot123456789:ABCdefGHIjklMNOpqrSTUvwxyz012345678/sendMessage Authorization: Bearer abcdef1234567890 KLAXOND_INGEST_SECRET_GRAFANA=feedface AUTH_OIDC_CLIENT_SECRET: verysecret"
        );
        tracing::error!(
            target: "test_logs",
            client_secret = "secret-value",
            "password=\"super-secret\""
        );
    });

    let result = buffer.query("", "all", 10, 0);
    assert_eq!(result.total, 2);
    assert_eq!(result.entries[0].level, "ERROR");
    assert_eq!(result.entries[1].level, "WARN");

    let all_text = serde_json::to_string(&result.entries).unwrap();
    assert!(!all_text.contains("first line evicted"));
    assert!(!all_text.contains("ABCdefGHIjklMNOpqrSTUvwxyz012345678"));
    assert!(!all_text.contains("abcdef1234567890"));
    assert!(!all_text.contains("abc123"));
    assert!(!all_text.contains("plain-token-1234567890"));
    assert!(!all_text.contains("secret-value"));
    assert!(!all_text.contains("super-secret"));
    assert!(!all_text.contains("feedface"));
    assert!(!all_text.contains("verysecret"));
    assert!(all_text.contains("[REDACTED]"));
}

#[test]
fn query_matching_is_unicode_case_insensitive() {
    let buffer = LogBuffer::new(1);
    {
        let mut entries = buffer.entries.lock().unwrap();
        entries.push_back(entry(1, "INFO", "klaxond", "Citta aggiornata"));
        entries[0].message = "Città aggiornata".to_string();
    }

    let result = buffer.query("città", "all", 10, 0);
    assert_eq!(result.total, 1);
    let result = buffer.query("CITTÀ", "all", 10, 0);
    assert_eq!(result.total, 1);
}
