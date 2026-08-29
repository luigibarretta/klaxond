//! Canonical application-event payloads accepted by Klaxond's Grafana ingest.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Warning,
    Critical,
}

impl Severity {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Critical => "critical",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Firing,
    Resolved,
}

impl Status {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Firing => "firing",
            Self::Resolved => "resolved",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Event {
    pub kind: String,
    pub severity: Severity,
    pub status: Status,
    pub title: String,
    pub body: String,
    pub occurred_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dedup_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runbook_url: Option<String>,
    #[serde(default)]
    pub labels: BTreeMap<String, String>,
}

impl Event {
    /// Renders the stable event contract into the Alertmanager-compatible
    /// envelope consumed by Klaxond's `/webhook/{severity}` endpoint.
    pub fn alertmanager_payload(&self, source: &str) -> Value {
        let mut labels = serde_json::Map::new();
        labels.insert("alertname".into(), Value::String(self.title.clone()));
        labels.insert("component".into(), Value::String(source.to_owned()));
        labels.insert("source".into(), Value::String(source.to_owned()));
        labels.insert("kind".into(), Value::String(self.kind.clone()));
        labels.insert(
            "severity".into(),
            Value::String(self.severity.as_str().to_owned()),
        );
        if let Some(dedup_key) = self.dedup_key.as_deref() {
            labels.insert("dedup_key".into(), Value::String(dedup_key.to_owned()));
        }
        for (key, value) in &self.labels {
            labels.insert(key.clone(), Value::String(value.clone()));
        }

        let mut annotations = serde_json::Map::new();
        annotations.insert("summary".into(), Value::String(self.title.clone()));
        annotations.insert("description".into(), Value::String(self.body.clone()));
        if let Some(runbook_url) = self.runbook_url.as_deref() {
            annotations.insert("runbook_url".into(), Value::String(runbook_url.to_owned()));
        }

        json!({
            "status": self.status.as_str(),
            "receiver": source,
            "commonLabels": labels,
            "commonAnnotations": annotations,
            "alerts": [{
                "status": self.status.as_str(),
                "labels": labels,
                "annotations": annotations,
                "startsAt": self.occurred_at,
            }],
        })
    }

    pub fn endpoint_path(&self) -> String {
        format!("/webhook/{}", self.severity.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn example() -> Event {
        Event {
            kind: "indexer_down".into(),
            severity: Severity::Warning,
            status: Status::Firing,
            title: "Indexer down: example".into(),
            body: "The indexer timed out.".into(),
            occurred_at: "2026-07-31T12:00:00Z".into(),
            dedup_key: Some("indexer:example".into()),
            runbook_url: Some("https://example.test/runbook".into()),
            labels: BTreeMap::from([("host".into(), "storage-01".into())]),
        }
    }

    #[test]
    fn event_renders_the_stable_alertmanager_envelope() {
        let event = example();
        let payload = event.alertmanager_payload("lampo");

        assert_eq!(event.endpoint_path(), "/webhook/warning");
        assert_eq!(payload["status"], "firing");
        assert_eq!(payload["commonLabels"]["component"], "lampo");
        assert_eq!(payload["commonLabels"]["kind"], "indexer_down");
        assert_eq!(payload["commonLabels"]["dedup_key"], "indexer:example");
        assert_eq!(payload["alerts"][0]["startsAt"], "2026-07-31T12:00:00Z");
        assert_eq!(
            payload["commonAnnotations"]["description"],
            "The indexer timed out."
        );
    }

    #[test]
    fn resolved_events_keep_the_original_severity_route() {
        let mut event = example();
        event.status = Status::Resolved;

        let payload = event.alertmanager_payload("blackstart");

        assert_eq!(event.endpoint_path(), "/webhook/warning");
        assert_eq!(payload["status"], "resolved");
        assert_eq!(payload["alerts"][0]["status"], "resolved");
    }
}
