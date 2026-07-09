use super::super::text;
use crate::auth::User;
use axum::body::{Body, Bytes};
use axum::http::{Response, StatusCode};
use serde_json::Value;

struct ClientLogEvent {
    level: String,
    key: String,
    message: String,
    path: String,
    stack: String,
    user_agent: String,
}

pub(in crate::handlers) fn client_log_response(
    body: Bytes,
    authed_user: Option<&User>,
) -> Response<Body> {
    let event = match parse_client_log(body) {
        Ok(event) => event,
        Err((status, message)) => return text(status, message),
    };
    emit_client_log(&event, frontend_user(authed_user));
    Response::builder()
        .status(StatusCode::NO_CONTENT)
        .body(Body::empty())
        .unwrap()
}

fn parse_client_log(body: Bytes) -> Result<ClientLogEvent, (StatusCode, &'static str)> {
    if body.len() > 8192 {
        return Err((
            StatusCode::PAYLOAD_TOO_LARGE,
            "client log payload too large",
        ));
    }
    let payload = serde_json::from_slice::<Value>(&body)
        .map_err(|_| (StatusCode::BAD_REQUEST, "invalid client log payload"))?;
    Ok(ClientLogEvent {
        level: payload
            .get("level")
            .and_then(Value::as_str)
            .unwrap_or("error")
            .trim()
            .to_ascii_lowercase(),
        key: client_log_field(&payload, "key", 96),
        message: client_log_field(&payload, "message", 512),
        path: client_log_field(&payload, "path", 160),
        stack: client_log_field(&payload, "stack", 1024),
        user_agent: client_log_field(&payload, "userAgent", 256),
    })
}

fn frontend_user(user: Option<&User>) -> &str {
    user.map(|user| {
        if user.sub.is_empty() {
            "anonymous"
        } else {
            user.sub.as_str()
        }
    })
    .unwrap_or("anonymous")
}

fn emit_client_log(event: &ClientLogEvent, user: &str) {
    match event.level.as_str() {
        "warn" | "warning" => tracing::warn!(
            target: "klaxond::frontend",
            ui_context = %event.key,
            ui_path = %event.path,
            ui_user = %user,
            ui_user_agent = %event.user_agent,
            ui_stack = %event.stack,
            "frontend warning [{}]: {}", event.key, event.message
        ),
        "info" => tracing::info!(
            target: "klaxond::frontend",
            ui_context = %event.key,
            ui_path = %event.path,
            ui_user = %user,
            ui_user_agent = %event.user_agent,
            ui_stack = %event.stack,
            "frontend info [{}]: {}", event.key, event.message
        ),
        _ => tracing::error!(
            target: "klaxond::frontend",
            ui_context = %event.key,
            ui_path = %event.path,
            ui_user = %user,
            ui_user_agent = %event.user_agent,
            ui_stack = %event.stack,
            "frontend error [{}]: {}", event.key, event.message
        ),
    }
}

fn client_log_field(payload: &Value, key: &str, max_chars: usize) -> String {
    let raw = payload.get(key).and_then(Value::as_str).unwrap_or("");
    let compact = raw
        .chars()
        .map(|ch| {
            if ch.is_control() && ch != '\n' && ch != '\t' {
                ' '
            } else {
                ch
            }
        })
        .collect::<String>();
    compact.chars().take(max_chars).collect()
}
