use super::{NtfyTopic, Paths};
use crate::util::{atomic_write_json, env_string, toml_get};
use anyhow::Result;
use serde_json::json;
use std::collections::HashMap;
use std::fs;

pub(super) fn load_ntfy_topics(paths: &Paths, toml: &toml::Value) -> Result<Vec<NtfyTopic>> {
    let mut topics: Option<Vec<NtfyTopic>> = None;
    if paths.ntfy_topics.exists() {
        let raw: serde_json::Value = serde_json::from_slice(&fs::read(&paths.ntfy_topics)?)?;
        if let Some(arr) = raw.get("topics").and_then(|v| v.as_array()) {
            topics = Some(arr.iter().filter_map(topic_from_json).collect());
        }
    }
    if topics.is_none() {
        topics = ntfy_topics_from_toml(toml);
    }
    let mut out = topics.unwrap_or_else(|| {
        vec![
            NtfyTopic {
                name: env_string("TOPIC_INFO"),
                token: String::new(),
                handles: vec!["info".into()],
            },
            NtfyTopic {
                name: env_string("TOPIC_WARN"),
                token: String::new(),
                handles: vec!["warning".into()],
            },
            NtfyTopic {
                name: env_string("TOPIC_CRIT"),
                token: String::new(),
                handles: vec!["critical".into()],
            },
        ]
    });

    let env_name = HashMap::from([
        ("info", env_string("TOPIC_INFO")),
        ("warning", env_string("TOPIC_WARN")),
        ("critical", env_string("TOPIC_CRIT")),
    ]);
    let env_token = HashMap::from([
        ("info", env_string("NTFY_TOKEN_INFO")),
        ("warning", env_string("NTFY_TOKEN_WARN")),
        ("critical", env_string("NTFY_TOKEN_CRIT")),
    ]);
    for t in &mut out {
        for h in &mut t.handles {
            *h = h.to_ascii_lowercase();
        }
        if t.handles.len() == 1 {
            let sev = t.handles[0].as_str();
            if let Some(name) = env_name.get(sev).filter(|v| !v.is_empty()) {
                t.name = name.clone();
            }
            if t.token.is_empty()
                && let Some(tok) = env_token.get(sev).filter(|v| !v.is_empty())
            {
                t.token = tok.clone();
            }
        }
    }
    out.retain(|t| !t.name.is_empty());
    Ok(out)
}

pub(super) fn ntfy_topics_from_toml(toml: &toml::Value) -> Option<Vec<NtfyTopic>> {
    let v = toml_get(toml, &["ntfy", "topics"])?;
    if let Some(arr) = v.as_array() {
        return Some(
            arr.iter()
                .filter_map(|t| {
                    Some(NtfyTopic {
                        name: t.get("name")?.as_str()?.to_string(),
                        token: t
                            .get("token")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string(),
                        handles: t
                            .get("handles")
                            .and_then(|v| v.as_array())
                            .map(|a| {
                                a.iter()
                                    .filter_map(|x| x.as_str().map(|s| s.to_ascii_lowercase()))
                                    .collect()
                            })
                            .unwrap_or_default(),
                    })
                })
                .collect(),
        );
    }
    v.as_table().map(|table| {
        vec![
            NtfyTopic {
                name: table
                    .get("info")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                token: String::new(),
                handles: vec!["info".into()],
            },
            NtfyTopic {
                name: table
                    .get("warning")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                token: String::new(),
                handles: vec!["warning".into()],
            },
            NtfyTopic {
                name: table
                    .get("critical")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                token: String::new(),
                handles: vec!["critical".into()],
            },
        ]
    })
}

fn topic_from_json(v: &serde_json::Value) -> Option<NtfyTopic> {
    Some(NtfyTopic {
        name: v.get("name")?.as_str()?.to_string(),
        token: v
            .get("token")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string(),
        handles: v
            .get("handles")
            .and_then(|x| x.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(|s| s.to_ascii_lowercase()))
                    .collect()
            })
            .unwrap_or_default(),
    })
}

pub fn save_ntfy_topics(paths: &Paths, topics: &[NtfyTopic]) -> Result<()> {
    atomic_write_json(paths.ntfy_topics.as_path(), &json!({ "topics": topics }))
}
