use super::super::{json_response, parse_query, text};
use crate::history::{DeliveryEntry, DeliveryPage, DeliveryQuery, SuppressedFilter};
use crate::state::AppState;
use axum::body::Body;
use axum::http::{Response, StatusCode};
use chrono::Utc;
use std::collections::HashMap;

enum DeliveryResponse {
    Legacy(Vec<DeliveryEntry>),
    Page(DeliveryPage),
}

pub(in crate::handlers) async fn response(state: &AppState, full_path: &str) -> Response<Body> {
    let default_limit = state.with_cfg(|cfg| cfg.history.default_limit);
    let query = match query_from_path(full_path, default_limit) {
        Ok(query) => query,
        Err(error) => return text(StatusCode::BAD_REQUEST, &error),
    };
    let permit = match state.history_read_slots.clone().acquire_owned().await {
        Ok(permit) => permit,
        Err(_) => {
            return text(
                StatusCode::SERVICE_UNAVAILABLE,
                "history worker is unavailable",
            );
        }
    };
    let worker_state = state.clone();
    match tokio::task::spawn_blocking(move || {
        let _permit = permit;
        match query {
            Some(query) => DeliveryResponse::Page(worker_state.query_deliveries(&query)),
            None => DeliveryResponse::Legacy(worker_state.recent_deliveries()),
        }
    })
    .await
    {
        Ok(DeliveryResponse::Legacy(entries)) => json_response(entries),
        Ok(DeliveryResponse::Page(page)) => json_response(page),
        Err(error) => {
            tracing::error!("delivery history worker failed: {error}");
            text(StatusCode::SERVICE_UNAVAILABLE, "history worker failed")
        }
    }
}

pub(in crate::handlers) async fn activity_response(
    state: &AppState,
    full_path: &str,
) -> Response<Body> {
    let hours = match activity_hours_from_path(full_path) {
        Ok(hours) => hours,
        Err(error) => return text(StatusCode::BAD_REQUEST, &error),
    };
    let generation = state.history_generation();
    if let Some(activity) = state.cached_delivery_activity(hours, generation) {
        return json_response(activity);
    }
    let permit = match state.delivery_activity_slots.clone().acquire_owned().await {
        Ok(permit) => permit,
        Err(_) => {
            return text(
                StatusCode::SERVICE_UNAVAILABLE,
                "activity worker is unavailable",
            );
        }
    };
    let generation = state.history_generation();
    if let Some(activity) = state.cached_delivery_activity(hours, generation) {
        return json_response(activity);
    }
    let worker_state = state.clone();
    match tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let now = Utc::now().timestamp_millis() as f64 / 1_000.0;
        let result = worker_state.delivery_activity(hours, now);
        if let Ok(activity) = &result {
            worker_state.cache_delivery_activity(generation, activity.clone());
        }
        result
    })
    .await
    {
        Ok(Ok(activity)) => json_response(activity),
        Ok(Err(error)) => {
            tracing::error!("read delivery activity failed: {error}");
            text(
                StatusCode::SERVICE_UNAVAILABLE,
                "persistent delivery activity is unavailable",
            )
        }
        Err(error) => {
            tracing::error!("delivery activity worker failed: {error}");
            text(StatusCode::SERVICE_UNAVAILABLE, "activity worker failed")
        }
    }
}

fn query_from_path(full_path: &str, default_limit: usize) -> Result<Option<DeliveryQuery>, String> {
    let query = parse_query(full_path);
    if query.is_empty() {
        return Ok(None);
    }
    let from = parse_optional_timestamp(&query, "from")?;
    let to = parse_optional_timestamp(&query, "to")?;
    if from.zip(to).is_some_and(|(from, to)| from > to) {
        return Err("from must be less than or equal to to".to_string());
    }
    let suppressed = match query.get("suppressed").map(|value| value.trim()) {
        None | Some("include") => SuppressedFilter::Include,
        Some("exclude") => SuppressedFilter::Exclude,
        Some("only") => SuppressedFilter::Only,
        Some(_) => return Err("suppressed must be include, exclude, or only".to_string()),
    };
    let limit = query
        .get("limit")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(default_limit);
    let offset = query
        .get("offset")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(0);
    Ok(Some(
        DeliveryQuery {
            limit,
            offset,
            q: query.get("q").cloned(),
            source: query.get("source").cloned(),
            severity: query.get("severity").cloned(),
            channel: query.get("channel").cloned(),
            from,
            to,
            suppressed,
        }
        .normalized(),
    ))
}

fn parse_optional_timestamp(
    query: &HashMap<String, String>,
    name: &str,
) -> Result<Option<f64>, String> {
    let Some(raw) = query.get(name) else {
        return Ok(None);
    };
    let value = raw
        .parse::<f64>()
        .map_err(|_| format!("{name} must be a Unix timestamp in seconds"))?;
    if !value.is_finite() {
        return Err(format!("{name} must be a finite Unix timestamp"));
    }
    Ok(Some(value))
}

fn activity_hours_from_path(full_path: &str) -> Result<u16, String> {
    let query = parse_query(full_path);
    let Some(raw) = query.get("hours") else {
        return Ok(24);
    };
    let hours = raw
        .parse::<u16>()
        .map_err(|_| "hours must be an integer from 1 to 168".to_string())?;
    if !(1..=168).contains(&hours) {
        return Err("hours must be an integer from 1 to 168".to_string());
    }
    Ok(hours)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::history::MAX_DELIVERY_QUERY_CHARS;

    #[test]
    fn legacy_shape_is_used_only_without_query_parameters() {
        assert!(query_from_path("/api/deliveries", 500).unwrap().is_none());
        let query = query_from_path("/api/deliveries?q=host", 500)
            .unwrap()
            .unwrap();
        assert_eq!(query.q.as_deref(), Some("host"));
        assert_eq!(query.limit, 500);
    }

    #[test]
    fn invalid_time_range_and_suppressed_mode_are_rejected() {
        for path in [
            "/api/deliveries?from=not-a-time",
            "/api/deliveries?to=NaN",
            "/api/deliveries?from=20&to=10",
            "/api/deliveries?suppressed=",
            "/api/deliveries?suppressed=sometimes",
        ] {
            assert!(query_from_path(path, 500).is_err(), "{path}");
        }
    }

    #[test]
    fn pagination_and_filter_lengths_are_clamped() {
        let value = "x".repeat(MAX_DELIVERY_QUERY_CHARS + 20);
        let path = format!("/api/deliveries?limit=20000&offset=2000000&q={value}");
        let query = query_from_path(&path, 500).unwrap().unwrap();
        assert_eq!(query.limit, 10_000);
        assert_eq!(query.offset, 1_000_000);
        assert_eq!(query.q.unwrap().chars().count(), MAX_DELIVERY_QUERY_CHARS);
    }

    #[test]
    fn activity_hours_default_and_enforce_bounds() {
        assert_eq!(
            activity_hours_from_path("/api/status/activity").unwrap(),
            24
        );
        assert_eq!(
            activity_hours_from_path("/api/status/activity?hours=168").unwrap(),
            168
        );
        for path in [
            "/api/status/activity?hours=0",
            "/api/status/activity?hours=169",
            "/api/status/activity?hours=day",
        ] {
            assert!(activity_hours_from_path(path).is_err(), "{path}");
        }
    }
}
