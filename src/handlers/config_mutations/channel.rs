use super::super::config_admin::persist_reload;
use super::super::{json_body, json_response, text};
use crate::state::AppState;
use crate::util::toml_table_mut;
use axum::body::{Body, Bytes};
use axum::http::{Response, StatusCode};
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

pub(in crate::handlers) fn update_channel_config(state: &AppState, body: Bytes) -> Response<Body> {
    let Ok(payload) = json_body(&body) else {
        return text(StatusCode::BAD_REQUEST, "bad json");
    };
    let request = ChannelConfigRequest::from_value(payload);
    state
        .with_config_write_lock(|| {
            let mut cfg = state.cfg();
            request.apply_to(&mut cfg.toml);
            persist_reload(state, cfg.toml)
                .map(|_| json_response(json!({"ok": true})))
                .unwrap_or_else(|err| text(StatusCode::INTERNAL_SERVER_ERROR, &err))
        })
        .unwrap_or_else(|err| text(StatusCode::INTERNAL_SERVER_ERROR, &err))
}

#[derive(Debug, Default, Deserialize)]
struct ChannelConfigRequest {
    #[serde(default, deserialize_with = "optional_object")]
    ntfy: Option<NtfyChannelPatch>,
    #[serde(default, deserialize_with = "optional_object")]
    telegram: Option<TelegramChannelPatch>,
    #[serde(default, deserialize_with = "optional_object")]
    smtp: Option<SmtpChannelPatch>,
}

impl ChannelConfigRequest {
    fn from_value(value: Value) -> Self {
        if !value.is_object() {
            return Self::default();
        }
        serde_json::from_value(value).unwrap_or_default()
    }

    fn apply_to(self, toml: &mut toml::Value) {
        if let Some(ntfy) = self.ntfy {
            ntfy.apply_to(toml);
        }
        if let Some(telegram) = self.telegram {
            telegram.apply_to(toml);
        }
        if let Some(smtp) = self.smtp {
            smtp.apply_to(toml);
        }
    }
}

#[derive(Debug, Default, Deserialize)]
struct NtfyChannelPatch {
    #[serde(default, deserialize_with = "optional_string")]
    url: Option<String>,
    #[serde(default, deserialize_with = "optional_object")]
    topics: Option<NtfyTopicsPatch>,
}

impl NtfyChannelPatch {
    fn apply_to(self, toml: &mut toml::Value) {
        {
            let ntfy = toml_table_mut(toml, &["ntfy"]);
            if let Some(url) = self.url {
                ntfy.insert(
                    "url".into(),
                    toml::Value::String(url.trim_end_matches('/').into()),
                );
            }
        }
        if let Some(topics) = self.topics {
            topics.apply_to(toml);
        }
    }
}

#[derive(Debug, Default, Deserialize)]
struct NtfyTopicsPatch {
    #[serde(default, deserialize_with = "optional_string")]
    info: Option<String>,
    #[serde(default, deserialize_with = "optional_string")]
    warning: Option<String>,
    #[serde(default, deserialize_with = "optional_string")]
    critical: Option<String>,
}

impl NtfyTopicsPatch {
    fn apply_to(self, toml: &mut toml::Value) {
        let ntfy_topics = toml_table_mut(toml, &["ntfy", "topics"]);
        for (severity, topic) in [
            ("info", self.info),
            ("warning", self.warning),
            ("critical", self.critical),
        ] {
            if let Some(topic) = topic {
                ntfy_topics.insert(severity.into(), toml::Value::String(topic));
            }
        }
    }
}

#[derive(Debug, Default, Deserialize)]
struct TelegramChannelPatch {
    #[serde(default, deserialize_with = "optional_string")]
    chat_id: Option<String>,
    #[serde(default, deserialize_with = "optional_string")]
    api_base: Option<String>,
    #[serde(default, deserialize_with = "optional_string")]
    bot_token: Option<String>,
}

impl TelegramChannelPatch {
    fn apply_to(self, toml: &mut toml::Value) {
        let telegram = toml_table_mut(toml, &["telegram"]);
        insert_string(telegram, "chat_id", self.chat_id);
        if let Some(api_base) = self.api_base {
            telegram.insert(
                "api_base".into(),
                toml::Value::String(api_base.trim_end_matches('/').into()),
            );
        }
        if let Some(token) = self.bot_token.filter(|value| value != "***SET***") {
            telegram.insert("bot_token".into(), toml::Value::String(token));
        }
    }
}

#[derive(Debug, Default, Deserialize)]
struct SmtpChannelPatch {
    #[serde(default, deserialize_with = "optional_string")]
    host: Option<String>,
    #[serde(default, deserialize_with = "optional_i64")]
    port: Option<i64>,
    #[serde(default, deserialize_with = "optional_string")]
    from_addr: Option<String>,
    #[serde(default, deserialize_with = "optional_string")]
    to_addr: Option<String>,
    #[serde(default, deserialize_with = "optional_string")]
    user: Option<String>,
    #[serde(default, deserialize_with = "optional_string")]
    password: Option<String>,
    #[serde(default, deserialize_with = "optional_bool")]
    starttls: Option<bool>,
}

impl SmtpChannelPatch {
    fn apply_to(self, toml: &mut toml::Value) {
        let smtp = toml_table_mut(toml, &["smtp"]);
        insert_string(smtp, "host", self.host);
        insert_string(smtp, "from_addr", self.from_addr);
        insert_string(smtp, "to_addr", self.to_addr);
        insert_string(smtp, "user", self.user);
        if let Some(password) = self.password.filter(|value| value != "***SET***") {
            smtp.insert("password".into(), toml::Value::String(password));
        }
        if let Some(port) = self.port {
            smtp.insert("port".into(), toml::Value::Integer(port));
        }
        if let Some(starttls) = self.starttls {
            smtp.insert("starttls".into(), toml::Value::Boolean(starttls));
        }
    }
}

fn optional_object<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: DeserializeOwned + Default,
{
    Ok(match Option::<Value>::deserialize(deserializer)? {
        Some(value @ Value::Object(_)) => Some(serde_json::from_value(value).unwrap_or_default()),
        _ => None,
    })
}

fn optional_string<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Ok(match Option::<Value>::deserialize(deserializer)? {
        Some(Value::String(value)) => Some(value),
        _ => None,
    })
}

fn optional_i64<'de, D>(deserializer: D) -> Result<Option<i64>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Ok(match Option::<Value>::deserialize(deserializer)? {
        Some(Value::Number(value)) => value.as_i64(),
        _ => None,
    })
}

fn optional_bool<'de, D>(deserializer: D) -> Result<Option<bool>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Ok(match Option::<Value>::deserialize(deserializer)? {
        Some(Value::Bool(value)) => Some(value),
        _ => None,
    })
}

fn insert_string(
    target: &mut toml::map::Map<String, toml::Value>,
    key: &str,
    value: Option<String>,
) {
    if let Some(value) = value {
        target.insert(key.into(), toml::Value::String(value));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn channel_config_request_preserves_normalization_and_secret_sentinels() {
        let mut toml = seed_toml();
        let request = ChannelConfigRequest::from_value(json!({
            "ntfy": {
                "url": "https://push.example.test///",
                "topics": {
                    "info": "info-topic",
                    "warning": 42,
                    "critical": "critical-topic",
                    "custom": "ignored"
                }
            },
            "telegram": {
                "chat_id": "new-chat",
                "api_base": "https://telegram.example.test///",
                "bot_token": "***SET***"
            },
            "smtp": {
                "host": "smtp.example.test",
                "port": -1,
                "from_addr": "from@example.test",
                "to_addr": "to@example.test",
                "user": "smtp-user",
                "password": "",
                "starttls": true
            }
        }));

        request.apply_to(&mut toml);

        assert_eq!(
            toml_str(&toml, &["ntfy", "url"]),
            "https://push.example.test"
        );
        assert_eq!(toml_str(&toml, &["ntfy", "topics", "info"]), "info-topic");
        assert_eq!(
            toml_str(&toml, &["ntfy", "topics", "warning"]),
            "old-warning"
        );
        assert_eq!(
            toml_str(&toml, &["ntfy", "topics", "critical"]),
            "critical-topic"
        );
        assert!(toml_get(&toml, &["ntfy", "topics", "custom"]).is_none());
        assert_eq!(toml_str(&toml, &["telegram", "chat_id"]), "new-chat");
        assert_eq!(
            toml_str(&toml, &["telegram", "api_base"]),
            "https://telegram.example.test"
        );
        assert_eq!(
            toml_str(&toml, &["telegram", "bot_token"]),
            "old-telegram-token"
        );
        assert_eq!(toml_str(&toml, &["smtp", "host"]), "smtp.example.test");
        assert_eq!(toml_str(&toml, &["smtp", "from_addr"]), "from@example.test");
        assert_eq!(toml_str(&toml, &["smtp", "to_addr"]), "to@example.test");
        assert_eq!(toml_str(&toml, &["smtp", "user"]), "smtp-user");
        assert_eq!(toml_str(&toml, &["smtp", "password"]), "");
        assert_eq!(toml_int(&toml, &["smtp", "port"]), -1);
        assert!(toml_bool(&toml, &["smtp", "starttls"]));
    }

    #[test]
    fn channel_config_request_ignores_non_object_channel_patches() {
        let mut toml = seed_toml();
        let before = toml.clone();
        let request = ChannelConfigRequest::from_value(json!({
            "ntfy": [],
            "telegram": "bad",
            "smtp": false
        }));

        request.apply_to(&mut toml);

        assert_eq!(toml, before);
    }

    #[test]
    fn channel_config_request_preserves_empty_object_table_creation() {
        let mut toml = toml::Value::Table(toml::map::Map::new());
        let request = ChannelConfigRequest::from_value(json!({
            "ntfy": {},
            "telegram": {},
            "smtp": {}
        }));

        request.apply_to(&mut toml);

        assert!(toml_get(&toml, &["ntfy"]).is_some());
        assert!(toml_get(&toml, &["telegram"]).is_some());
        assert!(toml_get(&toml, &["smtp"]).is_some());
    }

    fn seed_toml() -> toml::Value {
        toml::from_str(
            r#"
[ntfy]
url = "https://old-push.example.test/"

[ntfy.topics]
info = "old-info"
warning = "old-warning"
critical = "old-critical"

[telegram]
chat_id = "old-chat"
api_base = "https://old-telegram.example.test/"
bot_token = "old-telegram-token"

[smtp]
host = "old-smtp.example.test"
port = 25
from_addr = "old-from@example.test"
to_addr = "old-to@example.test"
user = "old-user"
password = "old-smtp-password"
starttls = false
"#,
        )
        .expect("seed toml")
    }

    fn toml_get<'a>(value: &'a toml::Value, path: &[&str]) -> Option<&'a toml::Value> {
        let mut current = value;
        for key in path {
            current = current.as_table()?.get(*key)?;
        }
        Some(current)
    }

    fn toml_str<'a>(value: &'a toml::Value, path: &[&str]) -> &'a str {
        toml_get(value, path)
            .and_then(toml::Value::as_str)
            .expect("string value")
    }

    fn toml_int(value: &toml::Value, path: &[&str]) -> i64 {
        toml_get(value, path)
            .and_then(toml::Value::as_integer)
            .expect("integer value")
    }

    fn toml_bool(value: &toml::Value, path: &[&str]) -> bool {
        toml_get(value, path)
            .and_then(toml::Value::as_bool)
            .expect("bool value")
    }
}
