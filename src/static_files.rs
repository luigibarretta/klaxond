//! Static UI and rendered image responses.

use crate::state::{AppState, lock_mutex};
use axum::body::Body;
use axum::http::header::{CACHE_CONTROL, CONTENT_LENGTH, CONTENT_TYPE};
use axum::http::{Response, StatusCode};
use axum::response::IntoResponse;
use std::fs;

const UI_ROUTES: &[&str] = &[
    "status",
    "flow",
    "inhibitions",
    "deliveries",
    "logs",
    "audit",
    "setup",
    "render",
    "routing",
    "cascade",
    "delivery",
    "grouping",
    "auth",
    "preview",
    "simulator",
    "test",
    "privacy",
    "accessibility",
    "terms",
    "cookies",
    "legal",
];

pub fn image_response(state: &AppState, path: &str) -> Response<Body> {
    let mut token = path
        .trim_start_matches("/img/")
        .split('?')
        .next()
        .unwrap_or("")
        .to_string();
    if let Some(t) = token.strip_suffix(".png") {
        token = t.into();
    }
    let now = crate::util::now_epoch();
    let img = {
        let mut imgs = lock_mutex(&state.rendered_images, "rendered images");
        imgs.retain(|_, img| img.expires_at > now);
        imgs.get(&token).cloned()
    };
    let Some(img) = img else {
        return StatusCode::NOT_FOUND.into_response();
    };
    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "image/png")
        .header(CACHE_CONTROL, "private, max-age=900")
        .header(CONTENT_LENGTH, img.bytes.len().to_string())
        .body(Body::from(img.bytes))
        .unwrap()
}

pub fn ui_response(state: &AppState, rel: &str) -> Response<Body> {
    let safe = sanitize_static_rel(rel);
    let route = safe.trim_matches('/');
    if route == "meta.js" {
        return ui_meta_response();
    }
    if route.is_empty() || route == "index.html" || UI_ROUTES.contains(&route) {
        return static_response(state, "index.html");
    }
    static_response(state, &safe)
}

fn sanitize_static_rel(rel: &str) -> String {
    rel.trim_start_matches('/')
        .split('/')
        .filter(|p| *p != "..")
        .collect::<Vec<_>>()
        .join("/")
}

fn ui_meta_response() -> Response<Body> {
    let body = format!(
        "window.KLAXOND_META=Object.freeze({{version:{},authorName:{},authorUrl:{}}});\n",
        serde_json::to_string(crate::config::VERSION).unwrap_or_else(|_| "\"\"".into()),
        serde_json::to_string(crate::config::AUTHOR_NAME).unwrap_or_else(|_| "\"\"".into()),
        serde_json::to_string(crate::config::AUTHOR_URL).unwrap_or_else(|_| "\"\"".into())
    );
    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/javascript; charset=utf-8")
        .header(CONTENT_LENGTH, body.len().to_string())
        .header(CACHE_CONTROL, "no-store")
        .body(Body::from(body))
        .unwrap()
}

fn static_response(state: &AppState, rel: &str) -> Response<Body> {
    let safe = sanitize_static_rel(rel);
    let full = state
        .paths
        .static_dir
        .join(if safe.is_empty() { "index.html" } else { &safe });
    if !full.is_file() {
        return StatusCode::NOT_FOUND.into_response();
    }
    let Ok(bytes) = fs::read(&full) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let mime = mime_guess::from_path(&full)
        .first_or_octet_stream()
        .to_string();
    let cache = full
        .file_name()
        .and_then(|n| n.to_str())
        .map(|n| n.to_ascii_lowercase().contains("mermaid") || n.contains("vendor"))
        .unwrap_or(false);
    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, format!("{mime}; charset=utf-8"))
        .header(CONTENT_LENGTH, bytes.len().to_string())
        .header(
            CACHE_CONTROL,
            if cache {
                "public, max-age=86400, immutable"
            } else {
                "no-store"
            },
        )
        .body(Body::from(bytes))
        .unwrap()
}
