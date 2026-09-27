use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub const MAX_DELIVERY_QUERY_CHARS: usize = 256;
pub(crate) const APPROXIMATE_DELIVERY_ROW_OVERHEAD: usize = 32;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DeliveryEntry {
    pub ts: f64,
    pub source: String,
    pub severity: String,
    pub title: String,
    pub channel: String,
    pub suppressed_by: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub emergency_receipt_id: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct DeliveryPage {
    pub entries: Vec<DeliveryEntry>,
    pub total: usize,
    pub limit: usize,
    pub offset: usize,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum SuppressedFilter {
    #[default]
    Include,
    Exclude,
    Only,
}

impl SuppressedFilter {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Include => "include",
            Self::Exclude => "exclude",
            Self::Only => "only",
        }
    }
}

#[derive(Clone, Debug)]
pub struct DeliveryQuery {
    pub limit: usize,
    pub offset: usize,
    pub q: Option<String>,
    pub source: Option<String>,
    pub severity: Option<String>,
    pub channel: Option<String>,
    pub from: Option<f64>,
    pub to: Option<f64>,
    pub suppressed: SuppressedFilter,
}

impl DeliveryQuery {
    pub fn page(limit: usize, offset: usize) -> Self {
        Self {
            limit,
            offset,
            q: None,
            source: None,
            severity: None,
            channel: None,
            from: None,
            to: None,
            suppressed: SuppressedFilter::Include,
        }
    }

    pub(crate) fn normalized(&self) -> Self {
        let mut query = self.clone();
        query.limit = query.limit.clamp(1, 10_000);
        query.offset = query.offset.min(1_000_000);
        query.q = bounded_filter(query.q).map(|value| normalize_delivery_search(&value));
        query.source = bounded_filter(query.source);
        query.severity = bounded_filter(query.severity);
        query.channel = bounded_filter(query.channel);
        query
    }

    pub(crate) fn matches(&self, entry: &DeliveryEntry) -> bool {
        let search_matches = self.q.as_ref().is_none_or(|query| {
            let query = normalize_delivery_search(query);
            delivery_search_values(
                &entry.source,
                &entry.severity,
                &entry.title,
                &entry.channel,
                &entry.suppressed_by,
            )
            .iter()
            .any(|value| value.contains(&query))
        });
        search_matches
            && self
                .source
                .as_ref()
                .is_none_or(|source| entry.source == *source)
            && self
                .severity
                .as_ref()
                .is_none_or(|severity| entry.severity == *severity)
            && self
                .channel
                .as_ref()
                .is_none_or(|channel| entry.channel == *channel)
            && self.from.is_none_or(|from| entry.ts >= from)
            && self.to.is_none_or(|to| entry.ts <= to)
            && match self.suppressed {
                SuppressedFilter::Include => true,
                SuppressedFilter::Exclude => entry.suppressed_by.is_empty(),
                SuppressedFilter::Only => !entry.suppressed_by.is_empty(),
            }
    }
}

pub(crate) fn delivery_search_values(
    source: &str,
    severity: &str,
    title: &str,
    channel: &str,
    suppressed_by: &str,
) -> [String; 5] {
    [source, severity, title, channel, suppressed_by].map(normalize_delivery_search)
}

fn normalize_delivery_search(value: &str) -> String {
    value
        .chars()
        .flat_map(char::to_lowercase)
        // Unicode case folding treats the two lowercase sigma forms as equivalent.
        .map(|character| {
            if character == '\u{03c2}' {
                '\u{03c3}'
            } else {
                character
            }
        })
        .collect()
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct DeliveryActivity {
    pub hours: u16,
    pub total: usize,
    pub total_history: usize,
    pub suppressed: usize,
    pub by_source: BTreeMap<String, usize>,
    pub by_severity: BTreeMap<String, usize>,
    pub by_channel: BTreeMap<String, usize>,
    pub latest_by_source: BTreeMap<String, f64>,
    pub latest_by_channel: BTreeMap<String, f64>,
    pub latest_ts: Option<f64>,
    pub approximate_history_bytes: usize,
}

pub(crate) fn dedupe_hash(entry: &DeliveryEntry) -> String {
    let mut hash = Sha256::new();
    hash.update(entry.ts.to_bits().to_be_bytes());
    hash.update(b"\0");
    hash.update(entry.source.as_bytes());
    hash.update(b"\0");
    hash.update(entry.severity.as_bytes());
    hash.update(b"\0");
    hash.update(entry.title.as_bytes());
    hash.update(b"\0");
    hash.update(entry.channel.as_bytes());
    hash.update(b"\0");
    hash.update(entry.suppressed_by.as_bytes());
    if let Some(receipt_id) = &entry.emergency_receipt_id {
        hash.update(b"\0");
        hash.update(receipt_id.as_bytes());
    }
    hex::encode(hash.finalize())
}

#[cfg(test)]
pub(crate) fn approximate_delivery_bytes(entry: &DeliveryEntry) -> usize {
    let search = delivery_search_values(
        &entry.source,
        &entry.severity,
        &entry.title,
        &entry.channel,
        &entry.suppressed_by,
    );
    APPROXIMATE_DELIVERY_ROW_OVERHEAD
        + entry.source.len()
        + entry.severity.len()
        + entry.title.len()
        + entry.channel.len()
        + entry.suppressed_by.len()
        + entry.emergency_receipt_id.as_deref().map_or(0, str::len)
        + search.iter().map(String::len).sum::<usize>()
        + dedupe_hash(entry).len()
}

fn bounded_filter(value: Option<String>) -> Option<String> {
    value.and_then(|value| {
        let value = value.trim();
        if value.is_empty() {
            None
        } else {
            Some(value.chars().take(MAX_DELIVERY_QUERY_CHARS).collect())
        }
    })
}
