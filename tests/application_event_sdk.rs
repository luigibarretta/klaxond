//! Contract test between the `klaxond-protocol` SDK and the daemon: every event
//! shape the SDK can render must be accepted by the real ingest router and
//! parsed into the expected notification.

use axum::body::{Body, Bytes, to_bytes};
use axum::extract::{ConnectInfo, State};
use axum::http::{HeaderMap, HeaderValue, Method, Response, StatusCode, Uri};
use klaxond::config::NtfyTopic;
use klaxond::state::AppState;
use klaxond_protocol::{Event, Severity, Status};
use serde_json::Value;
use std::collections::BTreeMap;
use std::net::SocketAddr;
use tempfile::TempDir;

#[path = "parity/support.rs"]
#[allow(dead_code)]
mod support;

const SECRET: &str = "sdk-contract-secret";
const SOURCE: &str = "sdk-contract";
const SEVERITIES: [Severity; 3] = [Severity::Info, Severity::Warning, Severity::Critical];
const STATUSES: [Status; 2] = [Status::Firing, Status::Resolved];

fn state_with_grafana_secret() -> (TempDir, AppState) {
    let tmp = TempDir::new().unwrap();
    let state = AppState::new(support::temp_paths(&tmp)).unwrap();
    let mut cfg = state.cfg();
    cfg.ntfy_topics = ["info", "warning", "critical"]
        .into_iter()
        .map(|severity| NtfyTopic {
            name: format!("{severity}-topic"),
            token: format!("tk_{severity}"),
            handles: vec![severity.into()],
        })
        .collect();
    let mut secrets = toml::map::Map::new();
    secrets.insert("grafana".into(), toml::Value::String(SECRET.into()));
    let mut ingest = toml::map::Map::new();
    ingest.insert("secrets".into(), toml::Value::Table(secrets));
    cfg.toml
        .as_table_mut()
        .expect("runtime TOML is a table")
        .insert("ingest".into(), toml::Value::Table(ingest));
    state.replace_config(cfg);
    (tmp, state)
}

fn event(severity: Severity, status: Status, optional_fields: bool) -> Event {
    Event {
        kind: "backup_failed".into(),
        severity,
        status,
        title: format!("Backup failed ({})", severity.as_str()),
        body: "The nightly backup exited with status 2.".into(),
        occurred_at: "2026-10-23T12:00:00Z".into(),
        dedup_key: optional_fields.then(|| "backup:nightly".into()),
        runbook_url: optional_fields.then(|| "https://runbooks.example.test/backup".into()),
        labels: if optional_fields {
            BTreeMap::from([("host".into(), "storage-01".into())])
        } else {
            BTreeMap::new()
        },
    }
}

async fn post(state: &AppState, path: &str, token: Option<&str>, body: Vec<u8>) -> Response<Body> {
    let mut headers = HeaderMap::new();
    headers.insert("content-type", HeaderValue::from_static("application/json"));
    if let Some(token) = token {
        headers.insert(
            "authorization",
            HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
        );
    }
    klaxond::handlers::dispatch(
        State(state.clone()),
        ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 40000))),
        Method::POST,
        path.parse::<Uri>().unwrap(),
        headers,
        Bytes::from(body),
    )
    .await
}

async fn json_body(response: Response<Body>) -> Value {
    let bytes = to_bytes(response.into_body(), 1 << 20).await.unwrap();
    serde_json::from_slice(&bytes).unwrap_or_else(|err| {
        panic!(
            "non-JSON response {err}: {}",
            String::from_utf8_lossy(&bytes)
        )
    })
}

async fn dry_run(state: &AppState, event: &Event) -> Value {
    let path = format!("{}?dry_run=1", event.endpoint_path());
    let body = serde_json::to_vec(&event.alertmanager_payload(SOURCE)).unwrap();
    let response = post(state, &path, Some(SECRET), body).await;
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "{path} rejected the SDK payload"
    );
    json_body(response).await
}

#[tokio::test]
async fn every_sdk_severity_and_status_is_accepted_and_parsed() {
    let (_tmp, state) = state_with_grafana_secret();
    for severity in SEVERITIES {
        for status in STATUSES {
            for optional_fields in [false, true] {
                let event = event(severity, status, optional_fields);
                let case = format!("{severity:?}/{status:?}/optional={optional_fields}");
                let response = dry_run(&state, &event).await;

                assert_eq!(response["dry_run"], true, "{case}");
                assert_eq!(response["would_send"], true, "{case}: {response}");
                assert_eq!(response["source"], "grafana", "{case}");
                let delivery_severity = match status {
                    Status::Firing => severity.as_str(),
                    Status::Resolved => "resolved",
                };
                assert_eq!(response["severity"], delivery_severity, "{case}");

                assert_parsed_notification(&state, &event, &response["parsed"], &case);
            }
        }
    }
}

fn assert_parsed_notification(state: &AppState, event: &Event, parsed: &Value, case: &str) {
    let resolved = event.status == Status::Resolved;
    let severity = event.severity.as_str();
    let (icon, tag_prefix, priority) = state.with_cfg(|cfg| {
        let state_key = if resolved { "resolved" } else { severity };
        (
            cfg.icon(state_key),
            cfg.tag_prefix(state_key),
            if resolved {
                "low".to_owned()
            } else {
                cfg.priority(severity)
            },
        )
    });

    let title = parsed["title"].as_str().unwrap();
    let expected_title = format!("{icon} Grafana: {}", event.title);
    assert!(
        title.starts_with(&expected_title),
        "{case}: title {title:?} does not start with {expected_title:?}"
    );

    let body = parsed["body"].as_str().unwrap();
    assert_eq!(
        body.starts_with("Status: RESOLVED"),
        resolved,
        "{case}: {body:?}"
    );
    assert!(
        body.contains(&event.title),
        "{case}: summary missing from {body:?}"
    );
    assert!(
        body.contains(&event.body),
        "{case}: description missing from {body:?}"
    );

    assert_eq!(parsed["priority"], priority.as_str(), "{case}");

    let mut expected_tags = vec![tag_prefix];
    if !resolved {
        expected_tags.push(severity.to_owned());
    }
    expected_tags.extend(["grafana".to_owned(), SOURCE.to_owned()]);
    assert_eq!(parsed["tags"], serde_json::json!(expected_tags), "{case}");

    let runbook = serde_json::json!(["view", "📖 Runbook", "https://runbooks.example.test/backup"]);
    let actions = parsed["actions"].as_array().unwrap();
    assert_eq!(
        actions.contains(&runbook),
        event.runbook_url.is_some(),
        "{case}: runbook action mismatch in {actions:?}"
    );
}

#[tokio::test]
async fn firing_priority_follows_the_sdk_severity() {
    let (_tmp, state) = state_with_grafana_secret();
    let mut priorities = Vec::new();
    for severity in SEVERITIES {
        let response = dry_run(&state, &event(severity, Status::Firing, true)).await;
        priorities.push(response["parsed"]["priority"].as_str().unwrap().to_owned());
    }
    let expected = state.with_cfg(|cfg| {
        SEVERITIES
            .iter()
            .map(|severity| cfg.priority(severity.as_str()))
            .collect::<Vec<_>>()
    });
    assert_eq!(priorities, expected);
}

#[tokio::test]
async fn sdk_payload_without_the_source_secret_is_rejected() {
    let (_tmp, state) = state_with_grafana_secret();
    let event = event(Severity::Critical, Status::Firing, true);
    let body = serde_json::to_vec(&event.alertmanager_payload(SOURCE)).unwrap();

    let missing = post(&state, &event.endpoint_path(), None, body.clone()).await;
    assert_eq!(missing.status(), StatusCode::UNAUTHORIZED);
    let wrong = post(&state, &event.endpoint_path(), Some("wrong-secret"), body).await;
    assert_eq!(wrong.status(), StatusCode::UNAUTHORIZED);
}
