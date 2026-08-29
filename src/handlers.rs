use axum::body::{Body, Bytes};
use axum::http::header::{CONTENT_LENGTH, CONTENT_TYPE};
use axum::http::{Response, StatusCode};
use serde_json::{Value, json};
use std::collections::HashMap;
use url::form_urlencoded;

mod auth_admin;
mod config_admin;
mod config_mutations;
mod emergency;
mod ingest;
mod observability;
mod passkeys;
mod router;
mod rules;
mod step_up;

pub use router::dispatch;

fn json_body(body: &Bytes) -> Result<Value, serde_json::Error> {
    if body.is_empty() {
        Ok(json!({}))
    } else {
        serde_json::from_slice(body)
    }
}

fn parse_query(full_path: &str) -> HashMap<String, String> {
    let query = full_path.split_once('?').map(|(_, q)| q).unwrap_or("");
    form_urlencoded::parse(query.as_bytes())
        .into_owned()
        .collect()
}

fn json_to_toml(v: Value) -> toml::Value {
    match v {
        Value::Null => toml::Value::String(String::new()),
        Value::Bool(b) => toml::Value::Boolean(b),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                toml::Value::Integer(i)
            } else {
                toml::Value::Float(n.as_f64().unwrap_or(0.0))
            }
        }
        Value::String(s) => toml::Value::String(s),
        Value::Array(a) => toml::Value::Array(a.into_iter().map(json_to_toml).collect()),
        Value::Object(o) => {
            toml::Value::Table(o.into_iter().map(|(k, v)| (k, json_to_toml(v))).collect())
        }
    }
}

fn json_response<T: serde::Serialize>(value: T) -> Response<Body> {
    let body = serde_json::to_vec_pretty(&value).unwrap_or_else(|_| b"{}".to_vec());
    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .header(CONTENT_LENGTH, body.len().to_string())
        .body(Body::from(body))
        .unwrap()
}

fn text(status: StatusCode, body: &str) -> Response<Body> {
    Response::builder()
        .status(status)
        .body(Body::from(body.to_string()))
        .unwrap()
}

fn html(status: StatusCode, body: &str) -> Response<Body> {
    Response::builder()
        .status(status)
        .header(CONTENT_TYPE, "text/html; charset=utf-8")
        .body(Body::from(body.to_string()))
        .unwrap()
}

fn redirect(location: &str) -> Response<Body> {
    Response::builder()
        .status(StatusCode::FOUND)
        .header("Location", location)
        .body(Body::empty())
        .unwrap()
}
