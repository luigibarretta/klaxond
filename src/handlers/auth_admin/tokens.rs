use super::super::{json_body, json_response, text};
use crate::auth::{self, User};
use crate::config::{AuthToken, save_auth};
use crate::state::AppState;
use crate::util::{random_hex, token_urlsafe};
use axum::body::{Body, Bytes};
use axum::http::{Response, StatusCode};
use serde::Deserialize;
use serde_json::{Value, json};

pub(in crate::handlers) fn create_auth_token(
    state: &AppState,
    body: Bytes,
    current_user: Option<&User>,
) -> Response<Body> {
    let Ok(payload) = json_body(&body) else {
        return text(StatusCode::BAD_REQUEST, "bad json");
    };
    let payload = CreateTokenRequest::from_value(payload);
    let name = payload.name();
    if name.is_empty() {
        return text(StatusCode::BAD_REQUEST, "token name is required");
    }
    let kind = payload.kind();
    if !matches!(kind, "api-key" | "pat") {
        return text(StatusCode::BAD_REQUEST, "kind must be api-key or pat");
    }
    if payload.scopes.is_empty() {
        return text(StatusCode::BAD_REQUEST, "at least one scope is required");
    }
    for scope in &payload.scopes {
        if !auth::TOKEN_SCOPES.contains(&scope.as_str()) {
            return text(StatusCode::BAD_REQUEST, &format!("invalid scope '{scope}'"));
        }
    }
    if !token_scopes_allowed_for_actor(current_user, &payload.scopes) {
        return text(
            StatusCode::FORBIDDEN,
            "requested token scopes exceed the authenticated token scope",
        );
    }
    let now = crate::util::now_epoch_i64();
    let expires_at = payload.expires_at(now);
    let token = format!(
        "klx_{}_{}",
        if kind == "pat" { "pat" } else { "key" },
        token_urlsafe(32)
    );
    let record = AuthToken {
        id: random_hex(8),
        name: name.to_string(),
        kind: kind.to_string(),
        prefix: token.chars().take(18).collect(),
        token_hash: auth::token_hash(&token),
        scopes: payload.scopes,
        created_at: now,
        expires_at,
        last_used_at: None,
        enabled: true,
    };
    state
        .with_config_write_lock(|| {
            let mut cfg = state.cfg();
            cfg.auth.api_keys.push(record.clone());
            if let Err(err) = save_auth(&state.paths, &cfg.auth) {
                return text(StatusCode::INTERNAL_SERVER_ERROR, &err.to_string());
            }
            state.replace_config(cfg);
            json_response(json!({
                "ok": true,
                "token": token,
                "record": auth::public_token(&record),
            }))
        })
        .unwrap_or_else(|err| text(StatusCode::INTERNAL_SERVER_ERROR, &err))
}

fn token_scopes_allowed_for_actor(current_user: Option<&User>, requested: &[String]) -> bool {
    let Some(user) = current_user else {
        return true;
    };
    if !user.via_authorization {
        return true;
    }
    requested
        .iter()
        .all(|scope| auth::scopes_allow(&user.groups, scope))
}

pub(in crate::handlers) fn revoke_auth_token(state: &AppState, id: &str) -> Response<Body> {
    if id.is_empty() {
        return text(StatusCode::BAD_REQUEST, "token id is required");
    }
    state
        .with_config_write_lock(|| {
            let mut cfg = state.cfg();
            let mut changed = false;
            for token in &mut cfg.auth.api_keys {
                if token.id == id {
                    token.enabled = false;
                    changed = true;
                }
            }
            if !changed {
                return text(StatusCode::NOT_FOUND, "token not found");
            }
            if let Err(err) = save_auth(&state.paths, &cfg.auth) {
                return text(StatusCode::INTERNAL_SERVER_ERROR, &err.to_string());
            }
            state.replace_config(cfg);
            json_response(json!({"ok": true}))
        })
        .unwrap_or_else(|err| text(StatusCode::INTERNAL_SERVER_ERROR, &err))
}

pub(in crate::handlers) fn password_policy_response() -> Response<Body> {
    let profile = auth_modules::security_profile::GoldAuthProfile::personal_default();
    let policy = profile.password_policy;
    json_response(json!({
        "min_length": policy.min_length,
        "max_length": policy.max_length,
    }))
}

#[derive(Debug, Default, Deserialize)]
struct CreateTokenRequest {
    #[serde(default, deserialize_with = "optional_trimmed_string")]
    name: Option<String>,
    #[serde(default, deserialize_with = "optional_trimmed_string")]
    kind: Option<String>,
    #[serde(default, deserialize_with = "string_scope_list")]
    scopes: Vec<String>,
    #[serde(default, deserialize_with = "positive_u64")]
    expires_in_days: Option<u64>,
    #[serde(default, deserialize_with = "integer_timestamp")]
    expires_at: Option<i64>,
}

impl CreateTokenRequest {
    fn from_value(value: Value) -> Self {
        if !value.is_object() {
            return Self::default();
        }
        serde_json::from_value(value).unwrap_or_default()
    }

    fn name(&self) -> &str {
        self.name.as_deref().unwrap_or("")
    }

    fn kind(&self) -> &str {
        self.kind.as_deref().unwrap_or("api-key")
    }

    fn expires_at(&self, now: i64) -> Option<i64> {
        self.expires_in_days
            .map(|days| now + (days.min(3650) * 86_400) as i64)
            .or_else(|| self.expires_at.filter(|expires_at| *expires_at > now))
    }
}

fn optional_trimmed_string<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Ok(match Option::<Value>::deserialize(deserializer)? {
        Some(Value::String(value)) => Some(value.trim().to_string()),
        _ => None,
    })
}

fn string_scope_list<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Ok(match Option::<Value>::deserialize(deserializer)? {
        Some(Value::Array(values)) => values
            .into_iter()
            .filter_map(|value| match value {
                Value::String(scope) => {
                    let scope = scope.trim().to_string();
                    (!scope.is_empty()).then_some(scope)
                }
                _ => None,
            })
            .collect(),
        _ => Vec::new(),
    })
}

fn positive_u64<'de, D>(deserializer: D) -> Result<Option<u64>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Ok(match Option::<Value>::deserialize(deserializer)? {
        Some(Value::Number(value)) => value.as_u64().filter(|days| *days > 0),
        _ => None,
    })
}

fn integer_timestamp<'de, D>(deserializer: D) -> Result<Option<i64>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Ok(match Option::<Value>::deserialize(deserializer)? {
        Some(Value::Number(value)) => value.as_i64(),
        _ => None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_token_request_preserves_lenient_json_compatibility() {
        let request = CreateTokenRequest::from_value(json!({
            "name": "  ops token  ",
            "kind": " pat ",
            "scopes": [" admin:read ", "", 42, null, "logs:read"],
            "expires_in_days": 4000,
            "expires_at": 1
        }));

        assert_eq!(request.name(), "ops token");
        assert_eq!(request.kind(), "pat");
        assert_eq!(request.scopes, vec!["admin:read", "logs:read"]);
        assert_eq!(request.expires_at(100), Some(100 + 3650 * 86_400));
    }

    #[test]
    fn create_token_request_defaults_non_object_and_invalid_fields() {
        let request = CreateTokenRequest::from_value(json!(["not", "an", "object"]));
        assert_eq!(request.name(), "");
        assert_eq!(request.kind(), "api-key");
        assert!(request.scopes.is_empty());

        let request = CreateTokenRequest::from_value(json!({
            "name": 42,
            "kind": 42,
            "scopes": "admin:*",
            "expires_in_days": 0,
            "expires_at": 99
        }));
        assert_eq!(request.name(), "");
        assert_eq!(request.kind(), "api-key");
        assert!(request.scopes.is_empty());
        assert_eq!(request.expires_at(100), None);
    }
}
