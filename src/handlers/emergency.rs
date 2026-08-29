use super::{html, json_response, parse_query, text};
use crate::auth::User;
use crate::emergency;
use crate::state::AppState;
use axum::body::Body;
use axum::http::{HeaderMap, Response, StatusCode};
use axum::response::IntoResponse;
use serde_json::json;

pub(super) fn confirmation(state: &AppState, path: &str) -> Response<Body> {
    let token = path
        .trim_start_matches("/emergency/")
        .split('?')
        .next()
        .unwrap_or("");
    match emergency::confirmation_page(state, token) {
        Ok(page) => html(StatusCode::OK, &page),
        Err(reason) => html(
            StatusCode::BAD_REQUEST,
            &format!("<h1>Emergency acknowledgement rejected</h1><p>{reason}</p>"),
        ),
    }
}

pub(super) async fn confirmation_ack(state: &AppState, path: &str) -> Response<Body> {
    let token = path
        .trim_start_matches("/emergency/")
        .split('?')
        .next()
        .unwrap_or("");
    let Some(receipt) = emergency::confirmation_token_receipt(state, token) else {
        return html(
            StatusCode::BAD_REQUEST,
            "<h1>Emergency acknowledgement rejected</h1><p>Invalid or expired token.</p>",
        );
    };
    match emergency::acknowledge(state, &receipt, "web-confirmation").await {
        Ok(incident) => html(
            StatusCode::OK,
            &format!(
                "<h1>Emergency acknowledged</h1><p>Retries for <strong>{}</strong> have stopped. This page can be closed.</p>",
                crate::util::html_escape(&incident.title)
            ),
        ),
        Err(reason) => html(
            StatusCode::CONFLICT,
            &format!("<h1>Emergency acknowledgement not applied</h1><p>{reason}</p>"),
        ),
    }
}

pub(super) async fn ntfy_ack(state: &AppState, path: &str, headers: &HeaderMap) -> Response<Body> {
    let receipt = path
        .trim_start_matches("/api/emergency/")
        .trim_end_matches("/ack")
        .trim_matches('/');
    let token = emergency::token_from_headers(headers);
    if receipt.is_empty() || !emergency::verify_receipt_token(state, receipt, token) {
        return text(
            StatusCode::UNAUTHORIZED,
            "invalid or expired emergency token",
        );
    }
    match emergency::acknowledge(state, receipt, "ntfy-action").await {
        Ok(incident) => json_response(
            json!({"ok":true,"receipt_id":incident.receipt_id,"state":incident.state}),
        ),
        Err(reason) => text(StatusCode::CONFLICT, &reason),
    }
}

pub(super) fn list(state: &AppState, full_path: &str) -> Response<Body> {
    let query = parse_query(full_path);
    let filter = query
        .get("state")
        .map(String::as_str)
        .filter(|v| !v.is_empty() && *v != "all");
    let limit = query
        .get("limit")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(200)
        .clamp(1, 1_000);
    match emergency::list(state, filter, limit) {
        Ok(incidents) => json_response(json!({"incidents":incidents,"limit":limit})),
        Err(reason) => text(StatusCode::SERVICE_UNAVAILABLE, &reason),
    }
}

pub(super) fn detail(state: &AppState, path: &str) -> Response<Body> {
    let receipt = path
        .trim_start_matches("/api/emergencies/")
        .trim_matches('/');
    match emergency::get(state, receipt) {
        Ok(Some(incident)) => json_response(incident),
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(reason) => text(StatusCode::SERVICE_UNAVAILABLE, &reason),
    }
}

pub(super) async fn admin_action(
    state: &AppState,
    path: &str,
    user: Option<&User>,
) -> Response<Body> {
    let remainder = path
        .trim_start_matches("/api/emergencies/")
        .trim_matches('/');
    let Some((receipt, action)) = remainder.rsplit_once('/') else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let actor = user.map(|u| u.sub.as_str()).unwrap_or("admin");
    match action {
        "ack" => match emergency::acknowledge(state, receipt, actor).await {
            Ok(incident) => json_response(json!({"ok":true,"incident":incident})),
            Err(reason) => text(StatusCode::CONFLICT, &reason),
        },
        "cancel" => match emergency::cancel(state, receipt, actor).await {
            Ok(incident) => json_response(json!({"ok":true,"incident":incident})),
            Err(reason) => text(StatusCode::CONFLICT, &reason),
        },
        "retry" => match emergency::retry_now(state, receipt) {
            Ok(true) => json_response(json!({"ok":true,"receipt_id":receipt,"scheduled":"now"})),
            Ok(false) => text(StatusCode::CONFLICT, "receipt is not active"),
            Err(reason) => text(StatusCode::SERVICE_UNAVAILABLE, &reason),
        },
        _ => StatusCode::NOT_FOUND.into_response(),
    }
}
