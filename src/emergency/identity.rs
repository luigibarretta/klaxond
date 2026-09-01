use crate::parsers::Parts;
use sha2::{Digest, Sha256};
use std::collections::HashMap;

pub(super) fn fingerprint(source: &str, parts: &Parts, labels: &HashMap<String, String>) -> String {
    if let Some(incident_key) = labels
        .get("__klaxond_incident_key")
        .map(String::as_str)
        .filter(|value| !value.is_empty())
    {
        return digest(&[source, "alertmanager-group", incident_key]);
    }
    legacy_fingerprint(source, parts, labels)
}

pub(super) fn legacy_fingerprint(
    source: &str,
    parts: &Parts,
    labels: &HashMap<String, String>,
) -> String {
    let alertname = labels
        .get("alertname")
        .map(String::as_str)
        .filter(|value| !value.is_empty())
        .unwrap_or({
            if parts.alertname.is_empty() {
                parts.title.as_str()
            } else {
                parts.alertname.as_str()
            }
        });
    let host = labels
        .get("host")
        .or_else(|| labels.get("instance_name"))
        .or_else(|| labels.get("instance"))
        .map(String::as_str)
        .unwrap_or("");
    let component = labels.get("component").map(String::as_str).unwrap_or("");
    digest(&[source, alertname, host, component])
}

fn digest(values: &[&str]) -> String {
    let mut hash = Sha256::new();
    for value in values {
        hash.update(value.trim().to_ascii_lowercase().as_bytes());
        hash.update(b"\0");
    }
    hex::encode(hash.finalize())
}
