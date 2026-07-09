use axum::body::Bytes;
use serde::Deserialize;
use serde::de::Deserializer;
use serde_json::Value;
use url::form_urlencoded;

#[derive(Clone, Debug, Default, Deserialize)]
pub(in crate::auth) struct LoginPayload {
    #[serde(default, deserialize_with = "string_like")]
    username: String,
    #[serde(default, deserialize_with = "string_like")]
    password: String,
    #[serde(default, deserialize_with = "string_like")]
    totp: String,
    #[serde(default, deserialize_with = "string_like")]
    code: String,
    #[serde(default, deserialize_with = "string_like")]
    secret: String,
    #[serde(default, deserialize_with = "optional_string_like")]
    return_to: Option<String>,
    #[serde(default, deserialize_with = "string_like")]
    fetch: String,
}

impl LoginPayload {
    pub(in crate::auth) fn username(&self) -> &str {
        &self.username
    }

    pub(in crate::auth) fn password(&self) -> &str {
        &self.password
    }

    pub(in crate::auth) fn totp(&self) -> &str {
        &self.totp
    }

    pub(in crate::auth) fn code(&self) -> &str {
        &self.code
    }

    pub(in crate::auth) fn secret(&self) -> &str {
        &self.secret
    }

    pub(in crate::auth) fn return_to_or_status(&self) -> &str {
        self.return_to.as_deref().unwrap_or("/status")
    }

    pub(in crate::auth) fn wants_json(&self, body: &Bytes) -> bool {
        self.fetch == "1" || body_is_json(body)
    }

    fn apply_form_field(&mut self, key: &str, value: String) {
        match key {
            "username" => self.username = value,
            "password" => self.password = value,
            "totp" => self.totp = value,
            "code" => self.code = value,
            "secret" => self.secret = value,
            "return_to" => self.return_to = Some(value),
            "fetch" => self.fetch = value,
            _ => {}
        }
    }
}

pub(in crate::auth) fn login_payload(body: &Bytes) -> LoginPayload {
    let raw = std::str::from_utf8(body).unwrap_or("");
    if body_is_json(body) {
        return serde_json::from_str::<LoginPayload>(raw).unwrap_or_default();
    }
    let mut payload = LoginPayload::default();
    for (key, value) in form_urlencoded::parse(raw.as_bytes()) {
        payload.apply_form_field(&key, value.into_owned());
    }
    payload
}

fn string_like<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    Ok(value_to_login_string(Value::deserialize(deserializer)?))
}

fn optional_string_like<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    Ok(Some(value_to_login_string(Value::deserialize(
        deserializer,
    )?)))
}

fn value_to_login_string(value: Value) -> String {
    match value {
        Value::String(value) => value,
        other => other.to_string(),
    }
}

fn body_is_json(body: &Bytes) -> bool {
    std::str::from_utf8(body)
        .map(|s| s.trim_start().starts_with('{'))
        .unwrap_or(false)
}
