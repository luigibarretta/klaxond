use super::{json_body, json_response, json_to_toml, text};
use crate::state::AppState;
use axum::body::{Body, Bytes};
use axum::http::Response;
use serde_json::json;
use std::sync::atomic::Ordering;

mod cascade;
mod channel;
mod dedup;
mod delivery;
mod ntfy_topics;
mod render;
#[cfg(test)]
mod tests;

pub(super) use self::cascade::update_cascade_config;
pub(super) use self::channel::update_channel_config;
pub(super) use self::dedup::update_dedup_config;
pub(super) use self::delivery::update_delivery_config;
pub(super) use self::ntfy_topics::update_ntfy_topics;
pub(super) use self::render::{render_preview, update_render_config};

#[cfg(test)]
use self::cascade::CascadeConfigRequest;
#[cfg(test)]
use self::dedup::DedupConfigRequest;
#[cfg(test)]
use crate::config::default_dedup;
#[cfg(test)]
use serde_json::Value;

pub(super) fn cascade_toggle(state: &AppState, body: Bytes) -> Response<Body> {
    let payload = json_body(&body).unwrap_or_else(|_| json!({}));
    let next = if let Some(enabled) = payload.get("enabled").and_then(|value| value.as_bool()) {
        enabled
    } else {
        !state.cascade_runtime_enabled.load(Ordering::Relaxed)
    };
    state.cascade_runtime_enabled.store(next, Ordering::Relaxed);
    json_response(json!({"cascade_enabled_runtime": next}))
}
