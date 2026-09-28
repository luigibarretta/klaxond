use super::{ingest_endpoint, ingest_secret_env_key};
use crate::config::{
    MAX_CUSTOM_INGEST_SOURCES, RuntimeConfig, environment_custom_ingest_secrets,
    environment_custom_ingest_sources, source_is_builtin, valid_ingest_source_slug,
};
use crate::handlers::config_admin::persist_reload;
use crate::handlers::{json_body, json_response, text};
use crate::state::AppState;
use crate::util::{env_string, random_hex, toml_table_mut};
use axum::body::{Body, Bytes};
use axum::http::{Response, StatusCode};
use serde::Deserialize;
use serde_json::json;

#[derive(Deserialize)]
struct IngestAuthRequest {
    source: String,
    action: String,
    #[serde(default)]
    secret: String,
    #[serde(default)]
    display_name: String,
}

#[derive(Clone, Copy)]
enum IngestAuthAction {
    Add,
    Set,
    Generate,
    Clear,
    Remove,
}

impl IngestAuthAction {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "add" => Some(Self::Add),
            "set" => Some(Self::Set),
            "generate" => Some(Self::Generate),
            "clear" => Some(Self::Clear),
            "remove" => Some(Self::Remove),
            _ => None,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Add => "add",
            Self::Set => "set",
            Self::Generate => "generate",
            Self::Clear => "clear",
            Self::Remove => "remove",
        }
    }
}

struct PreparedRequest {
    source: String,
    action: IngestAuthAction,
    secret: String,
    display_name: String,
}

struct RequestError {
    status: StatusCode,
    message: String,
}

pub(in crate::handlers) fn update_ingest_auth(state: &AppState, body: Bytes) -> Response<Body> {
    let request = match parse_request(state, &body) {
        Ok(request) => request,
        Err(error) => return text(error.status, &error.message),
    };
    let source = request.source.clone();
    let action = request.action;
    let new_secret = match state.with_config_write_lock(|| {
        let mut cfg = state.cfg();
        let new_secret = apply_request(&mut cfg.toml, &request);
        persist_reload(state, cfg.toml).map(|_| new_secret)
    }) {
        Ok(Ok(new_secret)) => new_secret,
        Ok(Err(err)) | Err(err) => return text(StatusCode::INTERNAL_SERVER_ERROR, &err),
    };
    let endpoint = state.with_cfg(|cfg| ingest_endpoint(cfg, &source));
    let mut response = json!({
        "ok": true,
        "source": source,
        "action": action.as_str(),
        "endpoint": endpoint,
    });
    if let Some(secret) = new_secret {
        response["secret"] = json!(secret);
    }
    json_response(response)
}

fn parse_request(state: &AppState, body: &Bytes) -> Result<PreparedRequest, RequestError> {
    let payload = json_body(body).map_err(|_| error(StatusCode::BAD_REQUEST, "bad json"))?;
    let request = serde_json::from_value::<IngestAuthRequest>(payload).map_err(|parse_error| {
        error(
            StatusCode::BAD_REQUEST,
            format!("invalid request: {parse_error}"),
        )
    })?;
    prepare_request(state, request)
}

fn prepare_request(
    state: &AppState,
    request: IngestAuthRequest,
) -> Result<PreparedRequest, RequestError> {
    let source = request.source.trim().to_ascii_lowercase();
    let action = IngestAuthAction::parse(&request.action.trim().to_ascii_lowercase()).ok_or(
        RequestError {
            status: StatusCode::BAD_REQUEST,
            message: "action must be one of: add, set, generate, clear, remove".to_string(),
        },
    )?;
    let prepared = PreparedRequest {
        source,
        action,
        secret: request.secret.trim().to_string(),
        display_name: request.display_name.trim().to_string(),
    };
    validate_request(&state.cfg(), &prepared)?;
    Ok(prepared)
}

fn validate_request(cfg: &RuntimeConfig, request: &PreparedRequest) -> Result<(), RequestError> {
    let source = request.source.as_str();
    let is_custom = cfg.custom_ingest_source(source).is_some();
    match request.action {
        IngestAuthAction::Add => validate_new_source(cfg, request)?,
        _ if !source_is_builtin(source) && !is_custom => {
            return Err(error(StatusCode::BAD_REQUEST, "source is not registered"));
        }
        IngestAuthAction::Remove if source_is_builtin(source) => {
            return Err(error(
                StatusCode::BAD_REQUEST,
                "built-in sources cannot be removed",
            ));
        }
        IngestAuthAction::Set if request.secret.len() < 16 => {
            return Err(error(
                StatusCode::BAD_REQUEST,
                "secret missing or shorter than 16 chars",
            ));
        }
        _ => {}
    }
    validate_environment_ownership(request)
}

fn validate_new_source(cfg: &RuntimeConfig, request: &PreparedRequest) -> Result<(), RequestError> {
    if !valid_ingest_source_slug(&request.source) {
        return Err(error(
            StatusCode::BAD_REQUEST,
            "source must be 2-40 lowercase letters, digits or single hyphens",
        ));
    }
    if source_is_builtin(&request.source) || cfg.custom_ingest_source(&request.source).is_some() {
        return Err(error(StatusCode::CONFLICT, "source already exists"));
    }
    if request.display_name.is_empty() || request.display_name.chars().count() > 64 {
        return Err(error(
            StatusCode::BAD_REQUEST,
            "display_name must contain 1-64 characters",
        ));
    }
    if cfg.custom_ingest_sources.len() >= MAX_CUSTOM_INGEST_SOURCES {
        return Err(error(
            StatusCode::BAD_REQUEST,
            "custom source limit reached",
        ));
    }
    Ok(())
}

fn validate_environment_ownership(request: &PreparedRequest) -> Result<(), RequestError> {
    if matches!(request.action, IngestAuthAction::Remove)
        && environment_custom_ingest_sources().contains_key(&request.source)
    {
        return Err(error(
            StatusCode::CONFLICT,
            "environment-managed source definitions cannot be removed from the UI",
        ));
    }
    if matches!(
        request.action,
        IngestAuthAction::Remove | IngestAuthAction::Clear
    ) && (!env_string(&ingest_secret_env_key(&request.source))
        .trim()
        .is_empty()
        || environment_custom_ingest_secrets().contains_key(&request.source))
    {
        return Err(error(
            StatusCode::CONFLICT,
            "environment-managed sources cannot be cleared or removed from the UI",
        ));
    }
    Ok(())
}

fn error(status: StatusCode, message: impl Into<String>) -> RequestError {
    RequestError {
        status,
        message: message.into(),
    }
}

fn apply_request(toml: &mut toml::Value, request: &PreparedRequest) -> Option<String> {
    let secrets = &["ingest", "secrets"];
    match request.action {
        IngestAuthAction::Add => {
            toml_table_mut(toml, &["ingest", "custom_sources"]).insert(
                request.source.clone(),
                toml::Value::String(request.display_name.clone()),
            );
            set_generated_secret(toml, &request.source)
        }
        IngestAuthAction::Remove => {
            toml_table_mut(toml, secrets).remove(&request.source);
            toml_table_mut(toml, &["ingest", "custom_sources"]).remove(&request.source);
            None
        }
        IngestAuthAction::Clear => {
            toml_table_mut(toml, secrets).remove(&request.source);
            None
        }
        IngestAuthAction::Generate => set_generated_secret(toml, &request.source),
        IngestAuthAction::Set => {
            toml_table_mut(toml, secrets).insert(
                request.source.clone(),
                toml::Value::String(request.secret.clone()),
            );
            None
        }
    }
}

fn set_generated_secret(toml: &mut toml::Value, source: &str) -> Option<String> {
    let secret = random_hex(32);
    toml_table_mut(toml, &["ingest", "secrets"])
        .insert(source.to_string(), toml::Value::String(secret.clone()));
    Some(secret)
}
