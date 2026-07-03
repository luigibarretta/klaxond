//! Serves the bundled OpenAPI contract.

use axum::body::Body;
use axum::http::header::{CONTENT_LENGTH, CONTENT_TYPE};
use axum::http::{Response, StatusCode};

const OPENAPI_YAML: &str = include_str!("../docs/openapi.yaml");

pub fn response() -> Response<Body> {
    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/yaml; charset=utf-8")
        .header(CONTENT_LENGTH, OPENAPI_YAML.len().to_string())
        .body(Body::from(OPENAPI_YAML))
        .unwrap()
}
