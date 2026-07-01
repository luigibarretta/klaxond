use chrono::{SecondsFormat, Utc};
use regex::{Captures, Regex};
use serde::Serialize;
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, Mutex, MutexGuard, OnceLock, TryLockError};
use tracing::field::{Field, Visit};
use tracing::{Event, Subscriber};
use tracing_subscriber::Layer;
use tracing_subscriber::layer::Context;

const MAX_LIMIT: usize = 500;

static GLOBAL_LOGS: OnceLock<Arc<LogBuffer>> = OnceLock::new();

#[derive(Clone, Debug, Serialize)]
pub struct LogEntry {
    pub id: u64,
    pub ts: f64,
    pub timestamp: String,
    pub level: String,
    pub target: String,
    pub message: String,
    pub fields: HashMap<String, String>,
    pub file: Option<String>,
    pub line: Option<u32>,
}

#[derive(Clone, Debug, Serialize)]
pub struct LogQuery {
    pub entries: Vec<LogEntry>,
    pub total: usize,
    pub limit: usize,
    pub offset: usize,
    pub query: String,
    pub level: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct LogStats {
    pub capacity: usize,
    pub retained: usize,
    pub warn: usize,
    pub error: usize,
    pub newest_timestamp: Option<String>,
}

#[derive(Debug)]
pub struct LogBuffer {
    capacity: usize,
    next_id: AtomicU64,
    entries: Mutex<VecDeque<LogEntry>>,
}

impl LogBuffer {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            next_id: AtomicU64::new(1),
            entries: Mutex::new(VecDeque::with_capacity(capacity.max(1))),
        }
    }

    fn push_event(&self, event: &Event<'_>) {
        let meta = event.metadata();
        let mut visitor = EventVisitor::default();
        event.record(&mut visitor);
        let now = Utc::now();
        let message = visitor
            .message
            .unwrap_or_else(|| fields_to_message(&visitor.fields));
        let entry = LogEntry {
            id: self.next_id.fetch_add(1, Ordering::Relaxed),
            ts: now.timestamp_millis() as f64 / 1000.0,
            timestamp: now.to_rfc3339_opts(SecondsFormat::Millis, true),
            level: meta.level().as_str().to_string(),
            target: meta.target().to_string(),
            message: redact_log_text(&message),
            fields: visitor
                .fields
                .into_iter()
                .map(|(key, value)| {
                    let redacted = if is_sensitive_key(&key) {
                        "[REDACTED]".to_string()
                    } else {
                        redact_log_text(&value)
                    };
                    (key, redacted)
                })
                .collect(),
            file: meta.file().map(ToOwned::to_owned),
            line: meta.line(),
        };

        let Some(mut entries) = self.entries_for_push() else {
            return;
        };
        if entries.len() == self.capacity {
            entries.pop_front();
        }
        entries.push_back(entry);
    }

    pub fn query(&self, query: &str, level: &str, limit: usize, offset: usize) -> LogQuery {
        let query_norm = query.trim().to_lowercase();
        let level_norm = normalize_level(level);
        let limit = limit.clamp(1, MAX_LIMIT);
        let matching = self
            .entries()
            .iter()
            .rev()
            .filter(|entry| level_matches(entry, &level_norm))
            .filter(|entry| query_matches(entry, &query_norm))
            .cloned()
            .collect::<Vec<_>>();
        let total = matching.len();
        let offset = clamped_offset(offset, limit, total);
        let entries = matching.into_iter().skip(offset).take(limit).collect();
        LogQuery {
            entries,
            total,
            limit,
            offset,
            query: query.trim().to_string(),
            level: level_norm,
        }
    }

    pub fn stats(&self) -> LogStats {
        let entries = self.entries();
        LogStats {
            capacity: self.capacity,
            retained: entries.len(),
            warn: entries.iter().filter(|entry| entry.level == "WARN").count(),
            error: entries
                .iter()
                .filter(|entry| entry.level == "ERROR")
                .count(),
            newest_timestamp: entries.back().map(|entry| entry.timestamp.clone()),
        }
    }

    fn entries(&self) -> MutexGuard<'_, VecDeque<LogEntry>> {
        self.entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn entries_for_push(&self) -> Option<MutexGuard<'_, VecDeque<LogEntry>>> {
        match self.entries.try_lock() {
            Ok(entries) => Some(entries),
            Err(TryLockError::Poisoned(poisoned)) => Some(poisoned.into_inner()),
            Err(TryLockError::WouldBlock) => None,
        }
    }
}

#[derive(Clone)]
pub struct LogCaptureLayer {
    buffer: Arc<LogBuffer>,
}

impl LogCaptureLayer {
    pub fn new(buffer: Arc<LogBuffer>) -> Self {
        Self { buffer }
    }
}

impl<S> Layer<S> for LogCaptureLayer
where
    S: Subscriber,
{
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        self.buffer.push_event(event);
    }
}

pub fn init_global(capacity: usize) -> Arc<LogBuffer> {
    GLOBAL_LOGS
        .get_or_init(|| Arc::new(LogBuffer::new(capacity)))
        .clone()
}

pub fn query_global(query: &str, level: &str, limit: usize, offset: usize) -> LogQuery {
    GLOBAL_LOGS
        .get()
        .map(|buffer| buffer.query(query, level, limit, offset))
        .unwrap_or_else(|| LogQuery {
            entries: Vec::new(),
            total: 0,
            limit: limit.clamp(1, MAX_LIMIT),
            offset: 0,
            query: query.trim().to_string(),
            level: normalize_level(level),
        })
}

pub fn stats_global() -> LogStats {
    GLOBAL_LOGS
        .get()
        .map(|buffer| buffer.stats())
        .unwrap_or(LogStats {
            capacity: 0,
            retained: 0,
            warn: 0,
            error: 0,
            newest_timestamp: None,
        })
}

fn clamped_offset(offset: usize, limit: usize, total: usize) -> usize {
    if total == 0 {
        0
    } else {
        offset.min(((total - 1) / limit) * limit)
    }
}

fn normalize_level(level: &str) -> String {
    match level.trim().to_ascii_uppercase().as_str() {
        "ERROR" => "ERROR".to_string(),
        "WARN" | "WARNING" => "WARN".to_string(),
        "INFO" => "INFO".to_string(),
        "DEBUG" => "DEBUG".to_string(),
        "TRACE" => "TRACE".to_string(),
        _ => "all".to_string(),
    }
}

fn level_matches(entry: &LogEntry, level: &str) -> bool {
    level == "all" || entry.level == level
}

fn query_matches(entry: &LogEntry, query: &str) -> bool {
    if query.is_empty() {
        return true;
    }
    entry.message.to_lowercase().contains(query)
        || entry.target.to_lowercase().contains(query)
        || entry
            .fields
            .iter()
            .any(|(k, v)| k.to_lowercase().contains(query) || v.to_lowercase().contains(query))
}

fn fields_to_message(fields: &HashMap<String, String>) -> String {
    let mut pairs = fields
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>();
    pairs.sort();
    pairs.join(" ")
}

fn redact_log_text(value: &str) -> String {
    static TELEGRAM_BOT_URL_RE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"bot\d{6,}:[A-Za-z0-9_-]{20,}").expect("valid telegram redaction regex")
    });
    static AUTH_HEADER_RE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"(?i)\b(authorization:\s*(?:bearer|basic)\s+)[^\s,;]+")
            .expect("valid auth header redaction regex")
    });
    static BEARER_RE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"(?i)\b(bearer\s+)[A-Za-z0-9._~+/=-]{12,}")
            .expect("valid bearer redaction regex")
    });
    static QUERY_SECRET_RE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(
            r"(?i)([?&](?:token|secret|access_token|id_token|refresh_token|client_secret|password|api_key|apikey|key)=)[^&\s]+",
        )
        .expect("valid query redaction regex")
    });
    static KV_SECRET_RE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(
            r#"(?i)\b(token|secret|password|client_secret|api_key|apikey|authorization)=("[^"]*"|'[^']*'|[^\s,;]+)"#,
        )
        .expect("valid key-value redaction regex")
    });
    static ENV_SECRET_RE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(
            r#"(?i)\b([A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|API_KEY|APIKEY|AUTHORIZATION)[A-Z0-9_]*)(\s*[:=]\s*)("[^"]*"|'[^']*'|[^\s,;]+)"#,
        )
        .expect("valid env-style redaction regex")
    });

    let out = TELEGRAM_BOT_URL_RE.replace_all(value, "bot[REDACTED]");
    let out = AUTH_HEADER_RE.replace_all(&out, "$1[REDACTED]");
    let out = BEARER_RE.replace_all(&out, "$1[REDACTED]");
    let out = QUERY_SECRET_RE.replace_all(&out, "$1[REDACTED]");
    let out = KV_SECRET_RE
        .replace_all(&out, |caps: &Captures<'_>| {
            format!("{}=[REDACTED]", &caps[1])
        })
        .into_owned();
    ENV_SECRET_RE
        .replace_all(&out, |caps: &Captures<'_>| {
            format!("{}{}[REDACTED]", &caps[1], &caps[2])
        })
        .into_owned()
}

fn is_sensitive_key(key: &str) -> bool {
    let key = key.to_ascii_lowercase();
    key.contains("token")
        || key.contains("secret")
        || key.contains("password")
        || key.contains("authorization")
        || key.contains("api_key")
        || key.contains("apikey")
        || key.ends_with("_key")
}

#[derive(Default)]
struct EventVisitor {
    message: Option<String>,
    fields: HashMap<String, String>,
}

impl Visit for EventVisitor {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        let rendered = format!("{value:?}");
        if field.name() == "message" {
            self.message = Some(trim_debug_string(&rendered));
        } else {
            self.fields
                .insert(field.name().to_string(), trim_debug_string(&rendered));
        }
    }
}

fn trim_debug_string(value: &str) -> String {
    if value.len() >= 2 && value.starts_with('"') && value.ends_with('"') {
        value[1..value.len() - 1]
            .replace("\\\"", "\"")
            .replace("\\n", "\n")
            .replace("\\t", "\t")
    } else {
        value.to_string()
    }
}

#[cfg(test)]
mod tests {
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
}
