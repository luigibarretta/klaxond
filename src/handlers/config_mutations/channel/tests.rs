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

    assert_channel_values(&toml);
}

fn assert_channel_values(toml: &toml::Value) {
    assert_eq!(
        toml_str(toml, &["ntfy", "url"]),
        "https://push.example.test"
    );
    assert_eq!(toml_str(toml, &["ntfy", "topics", "info"]), "info-topic");
    assert_eq!(
        toml_str(toml, &["ntfy", "topics", "warning"]),
        "old-warning"
    );
    assert_eq!(
        toml_str(toml, &["ntfy", "topics", "critical"]),
        "critical-topic"
    );
    assert!(toml_get(toml, &["ntfy", "topics", "custom"]).is_none());
    assert_eq!(toml_str(toml, &["telegram", "chat_id"]), "new-chat");
    assert_eq!(
        toml_str(toml, &["telegram", "api_base"]),
        "https://telegram.example.test"
    );
    assert_eq!(
        toml_str(toml, &["telegram", "bot_token"]),
        "old-telegram-token"
    );
    assert_eq!(toml_str(toml, &["smtp", "host"]), "smtp.example.test");
    assert_eq!(toml_str(toml, &["smtp", "from_addr"]), "from@example.test");
    assert_eq!(toml_str(toml, &["smtp", "to_addr"]), "to@example.test");
    assert_eq!(toml_str(toml, &["smtp", "user"]), "smtp-user");
    assert_eq!(toml_str(toml, &["smtp", "password"]), "");
    assert_eq!(toml_int(toml, &["smtp", "port"]), -1);
    assert!(toml_bool(toml, &["smtp", "starttls"]));
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
