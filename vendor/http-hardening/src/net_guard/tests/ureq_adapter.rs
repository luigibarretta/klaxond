//! ureq adapter: netloc parsing, guarded calls, manual redirects, proxies.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::sync::mpsc::{channel, Receiver};
use std::sync::Arc;
use std::thread;

use url::Url;

use super::assert_blocked;
use crate::net_guard::ureq_adapter::{
    agent_builder_unchecked, AgentOptions, GuardedAgent, GuardedCallError, UreqResolver,
};
use crate::net_guard::{AddressClass as C, NetGuard, NetGuardError, RedirectPolicy, Scheme};

fn loopback_guard(redirects: RedirectPolicy) -> Arc<NetGuard> {
    Arc::new(
        NetGuard::builder()
            .allow_scheme(Scheme::Http)
            .allow_cidr_list("127.0.0.1/32 ::1/128")
            .unwrap()
            .redirects(redirects)
            .build(),
    )
}

/// Serves one connection with `response`; the request head is sent back.
fn serve(response: String) -> (SocketAddr, Receiver<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = channel();
    thread::spawn(move || {
        let Ok((mut stream, _)) = listener.accept() else {
            return;
        };
        let mut buf = [0_u8; 4096];
        let read = stream.read(&mut buf).unwrap_or(0);
        let _ = tx.send(String::from_utf8_lossy(&buf[..read]).into_owned());
        let _ = stream.write_all(response.as_bytes());
    });
    (addr, rx)
}

fn redirect(status: &str, location: &str) -> String {
    format!("HTTP/1.1 {status}\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
}

fn ok(body: &str) -> String {
    format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

fn url(raw: &str) -> Url {
    Url::parse(raw).unwrap()
}

#[test]
fn netloc_literals_and_names_are_checked() {
    let resolver = UreqResolver::new(Arc::new(NetGuard::strict()));
    assert_blocked(resolver.resolve_netloc("127.0.0.1:80"), C::Loopback, "v4");
    assert_blocked(resolver.resolve_netloc("[::1]:80"), C::Loopback, "v6");
    assert_blocked(
        resolver.resolve_netloc("[::ffff:10.0.0.1]:80"),
        C::Private,
        "mapped",
    );
    assert_blocked(
        resolver.resolve_netloc("[64:ff9b::a9fe:a9fe]:80"),
        C::LinkLocal,
        "nat64",
    );
    assert_blocked(resolver.resolve_netloc("localhost:80"), C::Loopback, "name");
    let public = resolver.resolve_netloc("8.8.8.8:443").unwrap();
    assert_eq!(public, vec!["8.8.8.8:443".parse::<SocketAddr>().unwrap()]);
    let lookup = |_: &str, port: u16| Ok(vec![SocketAddr::from(([10, 0, 0, 1], port))]);
    assert_blocked(
        resolver.resolve_netloc_with("lan.example:443", &lookup),
        C::Private,
        "dns",
    );
}

#[test]
fn malformed_netlocs_and_ports_are_refused() {
    let resolver = UreqResolver::new(Arc::new(NetGuard::builder().allowed_ports(&[443]).build()));
    for netloc in [
        "8.8.8.8",
        "8.8.8.8:",
        ":443",
        "8.8.8.8:99999",
        "::1:443",
        "[zz]:443",
    ] {
        let result = resolver.resolve_netloc(netloc);
        assert!(
            matches!(
                result,
                Err(NetGuardError::InvalidHost(_) | NetGuardError::PortNotAllowed(_))
            ),
            "{netloc}: {result:?}"
        );
    }
    let error = std::io::Error::from(resolver.resolve_netloc("8.8.8.8:80").unwrap_err());
    assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
}

#[test]
fn guarded_agent_checks_the_url_before_any_request() {
    let agent = GuardedAgent::new(Arc::new(
        NetGuard::builder().allow_scheme(Scheme::Http).build(),
    ));
    let result = agent.call("GET", &url("http://0x7f.1/"));
    assert!(matches!(
        result,
        Err(GuardedCallError::Guard(
            NetGuardError::BlockedAddress { .. }
        ))
    ));
    assert_blocked(
        agent.request("GET", &url("http://10.0.0.1/")),
        C::Private,
        "request",
    );
}

#[test]
fn redirect_hop_to_blocked_address_is_refused() {
    let (addr, _) = serve(redirect(
        "302 Found",
        "http://169.254.169.254/latest/meta-data/",
    ));
    let agent = GuardedAgent::new(loopback_guard(RedirectPolicy::revalidate(3)));
    let error = agent
        .call("GET", &url(&format!("http://{addr}/")))
        .unwrap_err();
    assert!(error.to_string().contains("link-local"), "{error}");
}

#[test]
fn redirects_disabled_return_the_3xx() {
    let (addr, _) = serve(redirect("302 Found", "http://10.0.0.1/"));
    let agent = GuardedAgent::new(loopback_guard(RedirectPolicy::Disabled));
    let response = agent.call("GET", &url(&format!("http://{addr}/"))).unwrap();
    assert_eq!(response.status(), 302);
}

#[test]
// The closure returns ureq's own `Result<Response, ureq::Error>`.
#[allow(clippy::result_large_err)]
fn allowed_redirects_are_followed_and_303_switches_to_get() {
    let (second, second_rx) = serve(ok("done"));
    let (first, first_rx) = serve(redirect("303 See Other", &format!("http://{second}/next")));
    let agent = GuardedAgent::with_options(
        loopback_guard(RedirectPolicy::revalidate(2)),
        &AgentOptions {
            user_agent: Some("guarded-test".into()),
            ..AgentOptions::default()
        },
    );
    let response = agent
        .send("POST", &url(&format!("http://{first}/submit")), |r| {
            r.send_string("payload")
        })
        .unwrap();
    assert_eq!(response.into_string().unwrap(), "done");
    assert!(first_rx.recv().unwrap().starts_with("POST /submit"));
    let second_head = second_rx.recv().unwrap();
    assert!(second_head.starts_with("GET /next"), "{second_head}");
    assert!(second_head.contains("guarded-test"));
}

#[test]
fn hop_limit_is_enforced_by_the_guard() {
    let (third, _) = serve(ok("never"));
    let (second, _) = serve(redirect("302 Found", &format!("http://{third}/")));
    let (first, _) = serve(redirect("302 Found", &format!("http://{second}/")));
    let agent = GuardedAgent::new(loopback_guard(RedirectPolicy::revalidate(1)));
    let result = agent.call("GET", &url(&format!("http://{first}/")));
    assert!(matches!(
        result,
        Err(GuardedCallError::Guard(NetGuardError::TooManyRedirects(1)))
    ));
}

#[test]
fn unchecked_builder_never_follows_redirects_itself() {
    let (addr, _) = serve(redirect("302 Found", "http://10.0.0.1/"));
    let agent = agent_builder_unchecked(loopback_guard(RedirectPolicy::revalidate(5))).build();
    let response = agent.get(&format!("http://{addr}/")).call().unwrap();
    assert_eq!(response.status(), 302);
}

#[test]
fn proxy_environment_is_ignored() {
    let (proxy, proxy_rx) = serve(ok("proxied"));
    let (target, _) = serve(ok("direct"));
    let proxy_url = format!("http://{proxy}");
    for var in ["HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"] {
        std::env::set_var(var, &proxy_url);
    }
    // The dev-dependency enables ureq's `proxy-from-env`, so a plain agent
    // honours HTTP_PROXY here; the guarded one must not.
    let plain = ureq::AgentBuilder::new().build();
    let proxied = plain.get(&format!("http://{target}/")).call();
    let agent = GuardedAgent::new(loopback_guard(RedirectPolicy::Disabled));
    let direct = agent.call("GET", &url(&format!("http://{target}/")));
    for var in ["HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"] {
        std::env::remove_var(var);
    }
    assert_eq!(proxied.unwrap().into_string().unwrap(), "proxied");
    assert!(proxy_rx.recv().unwrap().contains(&target.to_string()));
    assert_eq!(direct.unwrap().into_string().unwrap(), "direct");
}

#[test]
fn https_only_agent_blocks_plain_http() {
    let strict = GuardedAgent::new(Arc::new(NetGuard::strict()));
    assert!(matches!(
        strict.call("GET", &url("http://example.com/")),
        Err(GuardedCallError::Guard(NetGuardError::SchemeNotAllowed(_)))
    ));
    let raw = agent_builder_unchecked(Arc::new(NetGuard::strict())).build();
    assert!(raw.get("http://example.com/").call().is_err());
}
