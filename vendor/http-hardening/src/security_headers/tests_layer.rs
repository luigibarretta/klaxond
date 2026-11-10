//! tower layer tests with a hand-written inner service (no runtime needed).

use std::convert::Infallible;
use std::future::{ready, Future, Ready};
use std::pin::pin;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};

use http::{Request, Response};
use tower_layer::Layer;
use tower_service::Service;

use super::{SecurityHeaders, SecurityHeadersLayer};

/// Inner service answering with an optional pre-set CSP.
#[derive(Clone)]
struct Handler {
    preset_csp: Option<&'static str>,
}

impl Service<Request<()>> for Handler {
    type Response = Response<&'static str>;
    type Error = Infallible;
    type Future = Ready<Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _: Request<()>) -> Self::Future {
        let mut response = Response::new("body");
        if let Some(csp) = self.preset_csp {
            response
                .headers_mut()
                .insert("content-security-policy", csp.parse().unwrap());
        }
        ready(Ok(response))
    }
}

fn run<F: Future>(future: F) -> F::Output {
    let mut future = pin!(future);
    let mut cx = Context::from_waker(Waker::noop());
    match future.as_mut().poll(&mut cx) {
        Poll::Ready(output) => output,
        Poll::Pending => panic!("test futures are always ready"),
    }
}

fn call(layer: &SecurityHeadersLayer, preset_csp: Option<&'static str>) -> Response<&'static str> {
    let mut service = layer.layer(Handler { preset_csp });
    let mut cx = Context::from_waker(Waker::noop());
    assert!(matches!(service.poll_ready(&mut cx), Poll::Ready(Ok(()))));
    let request = Request::new(());
    match run(service.call(request)) {
        Ok(response) => response,
        Err(never) => match never {},
    }
}

#[test]
fn layer_adds_headers_and_keeps_opted_in_handler_values() {
    let policy = SecurityHeaders::builder()
        .keep_if_present(&["content-security-policy"])
        .build()
        .unwrap();
    let layer = SecurityHeadersLayer::new(policy);
    let plain = call(&layer, None);
    assert_eq!(plain.headers()["x-frame-options"], "DENY");
    assert!(plain.headers()["content-security-policy"]
        .to_str()
        .unwrap()
        .starts_with("default-src 'none'"));
    assert_eq!(*plain.body(), "body");

    let preview = call(&layer, Some("sandbox; default-src 'self'"));
    assert_eq!(
        preview.headers()["content-security-policy"],
        "sandbox; default-src 'self'"
    );
    assert_eq!(preview.headers()["x-content-type-options"], "nosniff");
}

#[test]
fn shared_default_policy_overwrites() {
    let policy = SecurityHeaders::strict().unwrap();
    let layer = SecurityHeadersLayer::from_shared(Arc::new(policy));
    let response = call(&layer, Some("sandbox"));
    assert_ne!(response.headers()["content-security-policy"], "sandbox");
}
