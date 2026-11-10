//! `GuardedAgent::send` redirect rules: caller headers and body never follow
//! a redirect to another origin.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::sync::mpsc::{channel, Receiver};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use url::Url;

use crate::net_guard::ureq_adapter::GuardedAgent;
use crate::net_guard::{NetGuard, RedirectPolicy, Scheme};

fn agent() -> GuardedAgent {
    let guard = NetGuard::builder()
        .allow_scheme(Scheme::Http)
        .allow_cidr_list("127.0.0.1/32")
        .unwrap()
        .redirects(RedirectPolicy::revalidate(3))
        .build();
    GuardedAgent::new(Arc::new(guard))
}

/// Serves one connection per response on the same listener; every request
/// head is sent back.
fn serve(responses: Vec<String>) -> (SocketAddr, Receiver<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = channel();
    thread::spawn(move || {
        for response in responses {
            let Ok((mut stream, _)) = listener.accept() else {
                return;
            };
            let mut buf = [0_u8; 4096];
            let read = stream.read(&mut buf).unwrap_or(0);
            let _ = tx.send(String::from_utf8_lossy(&buf[..read]).to_ascii_lowercase());
            let _ = stream.write_all(response.as_bytes());
        }
    });
    (addr, rx)
}

fn redirect(status: &str, location: &str) -> String {
    format!("HTTP/1.1 {status}\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
}

const OK: &str = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";

fn url(addr: SocketAddr, path: &str) -> Url {
    Url::parse(&format!("http://{addr}{path}")).unwrap()
}

#[test]
// The closure returns ureq's own `Result<Response, ureq::Error>`.
#[allow(clippy::result_large_err)]
fn cross_origin_307_is_not_replayed() {
    let (other, other_rx) = serve(vec![OK.to_owned()]);
    let (first, _) = serve(vec![redirect(
        "307 Temporary Redirect",
        &format!("http://{other}/steal"),
    )]);
    let response = agent()
        .send("POST", &url(first, "/hook"), |r| {
            r.set("authorization", "Bearer secret")
                .send_string("payload")
        })
        .unwrap();
    assert_eq!(response.status(), 307);
    assert!(other_rx.recv_timeout(Duration::from_millis(300)).is_err());
}

#[test]
#[allow(clippy::result_large_err)]
fn same_origin_307_replays_method_headers_and_body() {
    let (addr, rx) = serve(vec![
        redirect("307 Temporary Redirect", "/moved"),
        OK.to_owned(),
    ]);
    let response = agent()
        .send("POST", &url(addr, "/hook"), |r| {
            r.set("authorization", "Bearer secret")
                .send_string("payload")
        })
        .unwrap();
    assert_eq!(response.status(), 200);
    assert!(rx.recv().unwrap().starts_with("post /hook"));
    let second = rx.recv().unwrap();
    assert!(second.starts_with("post /moved"), "{second}");
    assert!(second.contains("authorization: bearer secret"), "{second}");
}

#[test]
#[allow(clippy::result_large_err)]
fn see_other_and_moved_drop_caller_headers_even_same_origin() {
    for status in ["301 Moved Permanently", "302 Found", "303 See Other"] {
        let (addr, rx) = serve(vec![redirect(status, "/next"), OK.to_owned()]);
        let response = agent()
            .send("GET", &url(addr, "/"), |r| {
                r.set("authorization", "Bearer secret").call()
            })
            .unwrap();
        assert_eq!(response.status(), 200, "{status}");
        assert!(rx.recv().unwrap().contains("authorization"), "{status}");
        let second = rx.recv().unwrap();
        assert!(second.starts_with("get /next"), "{status}: {second}");
        assert!(!second.contains("authorization"), "{status}: {second}");
    }
}

#[test]
fn head_stays_head_after_303() {
    let empty = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_owned();
    let (addr, rx) = serve(vec![redirect("303 See Other", "/next"), empty]);
    let response = agent().call("HEAD", &url(addr, "/")).unwrap();
    assert_eq!(response.status(), 200);
    assert!(rx.recv().unwrap().starts_with("head /"));
    let second = rx.recv().unwrap();
    assert!(second.starts_with("head /next"), "{second}");
}
