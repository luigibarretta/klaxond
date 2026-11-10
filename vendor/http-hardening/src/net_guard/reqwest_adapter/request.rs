//! Request builder that cannot leak the guarded client or its URL.
//!
//! `reqwest::RequestBuilder::build_split()` returns the inner `Client`, and a
//! built `Request` has `url_mut()`; either would let a caller send to an
//! unchecked URL. [`GuardedRequest`] wraps the builder privately and offers
//! only methods that change headers, body and timeout.

use std::fmt::Display;
use std::time::Duration;

use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use reqwest::{Body, RequestBuilder, Response};

/// Request to a URL already checked by the guard.
#[derive(Debug)]
pub struct GuardedRequest {
    inner: RequestBuilder,
}

impl GuardedRequest {
    pub(super) fn new(inner: RequestBuilder) -> Self {
        Self { inner }
    }

    /// Adds a header (same bounds as `reqwest::RequestBuilder::header`).
    pub fn header<K, V>(self, key: K, value: V) -> Self
    where
        HeaderName: TryFrom<K>,
        <HeaderName as TryFrom<K>>::Error: Into<http::Error>,
        HeaderValue: TryFrom<V>,
        <HeaderValue as TryFrom<V>>::Error: Into<http::Error>,
    {
        Self::new(self.inner.header(key, value))
    }

    /// Merges a header map.
    pub fn headers(self, headers: HeaderMap) -> Self {
        Self::new(self.inner.headers(headers))
    }

    /// `Authorization: Bearer <token>` (marked sensitive).
    pub fn bearer_auth<T: Display>(self, token: T) -> Self {
        Self::new(self.inner.bearer_auth(token))
    }

    /// Request body.
    pub fn body<T: Into<Body>>(self, body: T) -> Self {
        Self::new(self.inner.body(body))
    }

    /// Timeout of this request (each redirect hop restarts it; the worst case
    /// is `(max_hops + 1) * timeout`).
    pub fn timeout(self, timeout: Duration) -> Self {
        Self::new(self.inner.timeout(timeout))
    }

    /// Sends the request.
    pub async fn send(self) -> Result<Response, reqwest::Error> {
        self.inner.send().await
    }
}

#[cfg(feature = "reqwest-serde")]
impl GuardedRequest {
    /// JSON body (feature `reqwest-serde`).
    pub fn json<T: serde::Serialize + ?Sized>(self, json: &T) -> Self {
        Self::new(self.inner.json(json))
    }

    /// URL-encoded form body (feature `reqwest-serde`).
    pub fn form<T: serde::Serialize + ?Sized>(self, form: &T) -> Self {
        Self::new(self.inner.form(form))
    }

    /// Appends query parameters (feature `reqwest-serde`). Only the query
    /// changes; host, port and scheme stay the checked ones.
    pub fn query<T: serde::Serialize + ?Sized>(self, query: &T) -> Self {
        Self::new(self.inner.query(query))
    }
}
