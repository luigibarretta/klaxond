//! `GuardedRequest`: the builder methods reach the wire; nothing exposes the
//! inner client or a mutable URL (checked at compile time by the API shape).

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use reqwest::header::{HeaderMap, HeaderValue};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use url::Url;

use crate::net_guard::reqwest_adapter::GuardedClient;
use crate::net_guard::{NetGuard, Scheme};

const OK: &str = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";

/// Serves one connection and sends back the lowercased request.
async fn serve() -> (SocketAddr, oneshot::Receiver<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = oneshot::channel();
    tokio::spawn(async move {
        let Ok((mut stream, _)) = listener.accept().await else {
            return;
        };
        let mut buf = vec![0_u8; 8192];
        let mut len = 0;
        // Read until the body sentinel arrives or the peer stops sending.
        for _ in 0..16 {
            let Ok(read) = stream.read(&mut buf[len..]).await else {
                break;
            };
            len += read;
            if read == 0 || String::from_utf8_lossy(&buf[..len]).contains("end-of-body") {
                break;
            }
        }
        let _ = tx.send(String::from_utf8_lossy(&buf[..len]).to_ascii_lowercase());
        let _ = stream.write_all(OK.as_bytes()).await;
        let _ = stream.shutdown().await;
    });
    (addr, rx)
}

fn client() -> GuardedClient {
    let guard = NetGuard::builder()
        .allow_scheme(Scheme::Http)
        .allow_cidr_list("127.0.0.1/32")
        .unwrap()
        .build();
    GuardedClient::new(Arc::new(guard)).unwrap()
}

#[tokio::test]
async fn builder_methods_reach_the_wire() {
    let (addr, rx) = serve().await;
    let mut extra = HeaderMap::new();
    extra.insert("x-extra", HeaderValue::from_static("1"));
    let url = Url::parse(&format!("http://{addr}/hook")).unwrap();
    let response = client()
        .post(&url)
        .unwrap()
        .header("x-event", "ping")
        .headers(extra)
        .bearer_auth("token-123")
        .timeout(Duration::from_secs(5))
        .body("payload end-of-body")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let seen = rx.await.unwrap();
    assert!(seen.starts_with("post /hook"), "{seen}");
    for needle in [
        "x-event: ping",
        "x-extra: 1",
        "authorization: bearer token-123",
        "payload end-of-body",
    ] {
        assert!(seen.contains(needle), "missing {needle}: {seen}");
    }
}

#[cfg(feature = "reqwest-serde")]
#[tokio::test]
async fn serde_helpers_change_only_body_and_query() {
    let (addr, rx) = serve().await;
    let url = Url::parse(&format!("http://{addr}/api")).unwrap();
    let response = client()
        .post(&url)
        .unwrap()
        .query(&[("k", "v")])
        .json(&["end-of-body"])
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let seen = rx.await.unwrap();
    assert!(seen.starts_with("post /api?k=v "), "{seen}");
    assert!(seen.contains("content-type: application/json"), "{seen}");
    assert!(seen.contains("[\"end-of-body\"]"), "{seen}");
}
