//! tower `Layer` applying [`SecurityHeaders`] to every response (feature
//! `tower`). Works with any http 1.x service, axum 0.8 routers included:
//!
//! ```ignore
//! let headers = SecurityHeaders::strict()?;
//! let app = Router::new().route("/", get(index)).layer(SecurityHeadersLayer::new(headers));
//! ```

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{ready, Context, Poll};

use http::{Request, Response};
use tower_layer::Layer;
use tower_service::Service;

use super::SecurityHeaders;

/// Layer wrapping services with [`SecurityHeadersService`].
#[derive(Clone, Debug)]
pub struct SecurityHeadersLayer {
    policy: Arc<SecurityHeaders>,
}

impl SecurityHeadersLayer {
    /// Layer owning `policy`.
    pub fn new(policy: SecurityHeaders) -> Self {
        Self {
            policy: Arc::new(policy),
        }
    }

    /// Layer sharing an existing policy.
    pub fn from_shared(policy: Arc<SecurityHeaders>) -> Self {
        Self { policy }
    }
}

impl<S> Layer<S> for SecurityHeadersLayer {
    type Service = SecurityHeadersService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        SecurityHeadersService {
            inner,
            policy: Arc::clone(&self.policy),
        }
    }
}

/// Service adding the security headers to the inner service's responses.
#[derive(Clone, Debug)]
pub struct SecurityHeadersService<S> {
    inner: S,
    policy: Arc<SecurityHeaders>,
}

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for SecurityHeadersService<S>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>>,
{
    type Response = Response<ResBody>;
    type Error = S::Error;
    type Future = ResponseFuture<S::Future>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: Request<ReqBody>) -> Self::Future {
        ResponseFuture {
            inner: self.inner.call(request),
            policy: Arc::clone(&self.policy),
        }
    }
}

pin_project_lite::pin_project! {
    /// Future returned by [`SecurityHeadersService`].
    pub struct ResponseFuture<F> {
        #[pin]
        inner: F,
        policy: Arc<SecurityHeaders>,
    }
}

impl<F, ResBody, E> Future for ResponseFuture<F>
where
    F: Future<Output = Result<Response<ResBody>, E>>,
{
    type Output = Result<Response<ResBody>, E>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();
        let mut response = ready!(this.inner.poll(cx))?;
        this.policy.apply(response.headers_mut());
        Poll::Ready(Ok(response))
    }
}
