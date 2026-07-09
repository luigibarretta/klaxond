#[cfg(test)]
mod tests;

mod redaction;

use chrono::{SecondsFormat, Utc};
use serde::Serialize;
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, TryLockError};
use tracing::field::{Field, Visit};
use tracing::{Event, Subscriber};
use tracing_subscriber::Layer;
use tracing_subscriber::layer::Context;

use self::redaction::{is_sensitive_key, redact_log_text};

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
