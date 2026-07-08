use crate::static_files;
use axum::http::HeaderMap;
use axum::http::header::ACCEPT;

pub(super) fn legal_tab_from_path(path: &str) -> Option<&'static str> {
    match path.trim_end_matches('/') {
        "/legal/privacy" => Some("privacy"),
        "/legal/accessibility" => Some("accessibility"),
        "/legal/terms" => Some("terms"),
        "/legal/cookies" => Some("cookies"),
        "/legal/notice" => Some("legal"),
        _ => None,
    }
}

pub(super) fn legacy_legal_redirect(path: &str) -> Option<&'static str> {
    match path.trim_end_matches('/') {
        "/ui/privacy" => Some("/legal/privacy"),
        "/ui/accessibility" => Some("/legal/accessibility"),
        "/ui/terms" => Some("/legal/terms"),
        "/ui/cookies" => Some("/legal/cookies"),
        "/ui/legal" => Some("/legal/notice"),
        _ => None,
    }
}

pub(super) fn root_ui_tab_from_path(path: &str, headers: &HeaderMap) -> Option<&'static str> {
    let route = path.trim_matches('/');
    if route == "inhibitions" && !prefers_html(headers) {
        return None;
    }
    static_files::tab_for_root_route(route)
}

pub(super) fn legacy_ui_redirect(path: &str) -> Option<&'static str> {
    let route = path.strip_prefix("/ui/")?.trim_matches('/');
    if route.is_empty() || route == "index.html" {
        return Some("/status");
    }
    static_files::root_route_for_tab(route).map(|root| match root {
        "authentication" => "/authentication",
        "status" => "/status",
        "flow" => "/flow",
        "inhibitions" => "/inhibitions",
        "deliveries" => "/deliveries",
        "logs" => "/logs",
        "audit" => "/audit",
        "setup" => "/setup",
        "render" => "/render",
        "routing" => "/routing",
        "cascade" => "/cascade",
        "delivery" => "/delivery",
        "grouping" => "/grouping",
        "preview" => "/preview",
        "simulator" => "/simulator",
        "test" => "/test",
        _ => "/status",
    })
}

pub(super) fn path_id(path: &str, prefix: &str) -> Option<String> {
    let raw = path.strip_prefix(prefix)?;
    if raw.is_empty() || raw.contains('/') {
        return None;
    }
    Some(urlencoding::decode(raw).ok()?.into_owned())
}

fn prefers_html(headers: &HeaderMap) -> bool {
    headers
        .get(ACCEPT)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|accept| accept.contains("text/html"))
}
