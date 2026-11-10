use super::{inline_script_hashes, security_headers, security_headers_layer};
use axum::Router;
use axum::body::Body;
use axum::http::{Request, Response, StatusCode};
use std::path::PathBuf;
use tower::ServiceExt;

fn static_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("static")
}

fn static_pages() -> Vec<String> {
    ["index.html", "swagger.html"]
        .iter()
        .map(|name| std::fs::read_to_string(static_dir().join(name)).unwrap())
        .collect()
}

#[test]
fn inline_scripts_are_hashed_and_external_ones_skipped() {
    let html =
        "<script>a()</script><script src=\"/x.js\"></script><script type=\"module\">b()</script>";
    let hashes = inline_script_hashes(html);
    assert_eq!(hashes.len(), 2);
    // printf 'a()' | openssl dgst -sha256 -binary | openssl base64
    assert_eq!(
        hashes[0],
        "'sha256-qVpDBgj7bpq5hMAcGp3AOc79J3Y1Z4HvySTwKrWDoy4='"
    );
}

#[test]
fn csp_allows_every_inline_script_by_hash_without_unsafe_inline() {
    let policy = security_headers("http://127.0.0.1:8181", &static_pages()).unwrap();
    let csp = policy.get("content-security-policy").unwrap();
    let script_src = csp
        .split(';')
        .map(str::trim)
        .find(|directive| directive.starts_with("script-src"))
        .unwrap();
    assert!(!script_src.contains("unsafe-inline"), "{script_src}");
    assert!(!script_src.contains("unsafe-eval"), "{script_src}");
    let mut expected = Vec::new();
    for page in static_pages() {
        expected.extend(inline_script_hashes(&page));
    }
    expected.extend(inline_script_hashes(crate::handlers::PASSKEY_LOGIN_HTML));
    expected.extend(inline_script_hashes(crate::handlers::STEP_UP_HTML));
    assert_eq!(
        expected.len(),
        4,
        "index, swagger, passkey and step-up scripts"
    );
    for hash in expected {
        assert!(
            script_src.contains(&hash),
            "{hash} missing from {script_src}"
        );
    }
    assert!(csp.contains("frame-ancestors 'none'"));
    assert!(csp.contains("object-src 'none'"));
}

#[test]
fn hsts_only_for_an_https_public_url() {
    let http = security_headers("http://192.168.50.110:8181", &[]).unwrap();
    assert!(http.get("strict-transport-security").is_none());
    let https = security_headers("https://klaxond.example", &[]).unwrap();
    assert!(
        https
            .get("strict-transport-security")
            .is_some_and(|value| value.contains("max-age="))
    );
}

async fn respond(route_corp: Option<&'static str>, method: &str) -> Response<Body> {
    let layer = security_headers_layer(&static_dir(), "https://klaxond.example").unwrap();
    let app = Router::new()
        .fallback(move || async move {
            let mut response = Response::builder().status(StatusCode::ACCEPTED);
            if let Some(value) = route_corp {
                response = response.header("cross-origin-resource-policy", value);
            }
            response
                .header("x-frame-options", "ALLOWALL")
                .body(Body::empty())
                .unwrap()
        })
        .layer(layer);
    let request = Request::builder()
        .method(method)
        .uri("/webhook/critical")
        .body(Body::empty())
        .unwrap();
    app.oneshot(request).await.unwrap()
}

#[tokio::test]
async fn layer_overwrites_handler_headers_but_keeps_the_route_corp() {
    let ingest = respond(None, "POST").await;
    assert_eq!(ingest.status(), StatusCode::ACCEPTED);
    let headers = ingest.headers();
    assert_eq!(headers["x-frame-options"], "DENY");
    assert_eq!(headers["x-content-type-options"], "nosniff");
    assert_eq!(headers["cross-origin-resource-policy"], "same-origin");
    assert!(headers.contains_key("content-security-policy"));

    let image = respond(Some("cross-origin"), "GET").await;
    assert_eq!(
        image.headers()["cross-origin-resource-policy"],
        "cross-origin"
    );
}
