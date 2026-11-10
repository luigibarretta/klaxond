//! reqwest adapter: resolvers, guarded clients and redirect handling against
//! local one-shot HTTP servers.

use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;

use reqwest::dns::{Name, Resolve};
use reqwest::Method;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use url::Url;

use super::assert_blocked;
use crate::net_guard::reqwest_adapter::{
    client_builder_unchecked, GuardedClient, GuardedResolver, PinnedClient, PinnedResolver,
};
use crate::net_guard::{AddressClass as C, NetGuard, NetGuardError, RedirectPolicy, Scheme};

fn guard_for(cidrs: &str, redirects: RedirectPolicy) -> Arc<NetGuard> {
    let guard = NetGuard::builder()
        .allow_scheme(Scheme::Http)
        .allow_cidr_list(cidrs)
        .unwrap()
        .redirects(redirects)
        .build();
    Arc::new(guard)
}

fn loopback_guard(redirects: RedirectPolicy) -> Arc<NetGuard> {
    guard_for("127.0.0.1/32 ::1/128", redirects)
}

/// Serves one connection on `bind` with a canned response.
async fn serve_on(bind: &str, response: String) -> SocketAddr {
    let listener = TcpListener::bind(bind).await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let Ok((mut stream, _)) = listener.accept().await else {
            return;
        };
        let mut buf = [0_u8; 2048];
        let _ = stream.read(&mut buf).await;
        let _ = stream.write_all(response.as_bytes()).await;
        let _ = stream.shutdown().await;
    });
    addr
}

async fn serve(response: String) -> SocketAddr {
    serve_on("127.0.0.1:0", response).await
}

fn redirect_to(location: &str) -> String {
    format!("HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
}

const OK: &str = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";

fn url(raw: &str) -> Url {
    Url::parse(raw).unwrap()
}

#[tokio::test]
async fn guarded_resolver_refuses_loopback_unless_allowlisted() {
    let strict = GuardedResolver::new(Arc::new(NetGuard::strict()));
    let error = strict
        .resolve(Name::from_str("localhost").unwrap())
        .await
        .err()
        .unwrap();
    assert!(error.to_string().contains("loopback"), "{error}");
    let allowed = GuardedResolver::new(loopback_guard(RedirectPolicy::Disabled));
    let addrs: Vec<SocketAddr> = allowed
        .resolve(Name::from_str("localhost").unwrap())
        .await
        .unwrap()
        .collect();
    assert!(!addrs.is_empty() && addrs.iter().all(|a| a.ip().is_loopback()));
}

#[tokio::test]
async fn pinned_resolver_answers_only_for_its_host() {
    let lookup = |_: &str, _: u16| Ok(vec!["93.184.215.14:0".parse().unwrap()]);
    let target = NetGuard::strict()
        .resolve_with(&url("https://Hooks.Example/"), &lookup)
        .unwrap();
    let pinned = PinnedResolver::new(&target);
    let addrs: Vec<SocketAddr> = pinned
        .resolve(Name::from_str("hooks.example").unwrap())
        .await
        .unwrap()
        .collect();
    assert_eq!(addrs, vec!["93.184.215.14:443".parse().unwrap()]);
    let error = pinned
        .resolve(Name::from_str("other.example").unwrap())
        .await
        .err()
        .unwrap();
    assert!(
        error.to_string().contains("pinned to 'hooks.example'"),
        "{error}"
    );
}

#[tokio::test]
async fn guarded_client_checks_literal_urls_before_any_request() {
    let client = GuardedClient::new(Arc::new(
        NetGuard::builder().allow_scheme(Scheme::Http).build(),
    ))
    .unwrap();
    for (raw, class) in [
        ("http://10.0.0.1/", C::Private),
        ("http://0x7f.1/", C::Loopback),
        ("http://[::ffff:169.254.169.254]/", C::LinkLocal),
    ] {
        assert_blocked(client.get(&url(raw)), class, raw);
    }
    let ports = NetGuard::builder().allowed_ports(&[443]).build();
    let client = GuardedClient::new(Arc::new(ports)).unwrap();
    assert!(matches!(
        client.post(&url("https://example.com:8443/")),
        Err(NetGuardError::PortNotAllowed(8443))
    ));
    assert!(client
        .request(Method::GET, &url("https://example.com/"))
        .is_ok());
    assert!(matches!(
        client.get(&url("http://example.com/")),
        Err(NetGuardError::SchemeNotAllowed(_))
    ));
}

#[tokio::test]
async fn unchecked_builder_lets_literal_urls_through() {
    // Documents why GuardedClient exists: the raw client only guards DNS
    // names and redirects, a literal address in the first URL is not checked.
    let addr = serve(OK.to_owned()).await;
    let client = client_builder_unchecked(Arc::new(
        NetGuard::builder().allow_scheme(Scheme::Http).build(),
    ))
    .build()
    .unwrap();
    let response = client.get(format!("http://{addr}/")).send().await.unwrap();
    assert_eq!(response.status(), 200);
}

#[tokio::test]
async fn disabled_redirects_return_the_3xx_response() {
    let addr = serve(redirect_to("http://10.0.0.1/")).await;
    let client = GuardedClient::new(loopback_guard(RedirectPolicy::Disabled)).unwrap();
    let response = client
        .get(&url(&format!("http://{addr}/")))
        .unwrap()
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 302);
}

#[tokio::test]
async fn redirect_to_private_literal_is_refused() {
    let addr = serve(redirect_to("http://10.0.0.1/")).await;
    let client = GuardedClient::new(loopback_guard(RedirectPolicy::revalidate(3))).unwrap();
    let error = client
        .get(&url(&format!("http://{addr}/")))
        .unwrap()
        .send()
        .await
        .unwrap_err();
    assert!(error.is_redirect(), "{error:?}");
    assert!(
        format!("{error:?}").to_lowercase().contains("private"),
        "{error:?}"
    );
}

#[tokio::test]
async fn redirect_to_localhost_name_is_refused() {
    let addr = serve_on("127.0.0.2:0", redirect_to("http://localhost/")).await;
    let client =
        GuardedClient::new(guard_for("127.0.0.2/32", RedirectPolicy::revalidate(3))).unwrap();
    let error = client
        .get(&url(&format!("http://{addr}/")))
        .unwrap()
        .send()
        .await
        .unwrap_err();
    assert!(error.is_redirect(), "{error:?}");
    assert!(
        format!("{error:?}").to_lowercase().contains("loopback"),
        "{error:?}"
    );
}

#[tokio::test]
async fn dns_names_go_through_the_guarded_resolver() {
    let addr = serve_on("127.0.0.2:0", OK.to_owned()).await;
    let client = client_builder_unchecked(guard_for("127.0.0.2/32", RedirectPolicy::Disabled))
        .build()
        .unwrap();
    // The unchecked client skips check_url and its localhost-name rule; the
    // resolver alone refuses the 127.0.0.1 / ::1 answer.
    let error = client
        .get(format!("http://localhost:{}/", addr.port()))
        .send()
        .await
        .unwrap_err();
    assert!(
        format!("{error:?}").to_lowercase().contains("loopback"),
        "{error:?}"
    );
    let response = client.get(format!("http://{addr}/")).send().await.unwrap();
    assert_eq!(response.status(), 200);
}

#[tokio::test]
async fn allowed_redirect_is_followed() {
    let second = serve(OK.to_owned()).await;
    let first = serve(redirect_to(&format!("http://{second}/next"))).await;
    let client = GuardedClient::new(loopback_guard(RedirectPolicy::revalidate(2))).unwrap();
    let response = client
        .get(&url(&format!("http://{first}/")))
        .unwrap()
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(response.text().await.unwrap(), "ok");
}

#[tokio::test]
async fn pinned_client_enforces_target_host_and_port() {
    let addr = serve(OK.to_owned()).await;
    let guard = loopback_guard(RedirectPolicy::Disabled);
    let lookup = |_: &str, _: u16| Ok(vec![SocketAddr::from(([127, 0, 0, 1], 0))]);
    let raw = format!("http://pinned.test:{}/", addr.port());
    let target = guard.resolve_with(&url(&raw), &lookup).unwrap();
    let client = PinnedClient::new(Arc::clone(&guard), target).unwrap();
    let other_port = url(&format!(
        "http://pinned.test:{}/x",
        addr.port().wrapping_add(1)
    ));
    assert!(matches!(
        client.request(Method::GET, &other_port),
        Err(NetGuardError::TargetMismatch { .. })
    ));
    assert!(matches!(
        client.request(Method::GET, &url("http://unpinned.test/")),
        Err(NetGuardError::TargetMismatch { .. })
    ));
    let same = url(&format!("http://PINNED.test:{}/other", addr.port()));
    assert!(client.request(Method::GET, &same).is_ok());
    let response = client.request_target(Method::GET).send().await.unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(client.target().port(), addr.port());
}

#[tokio::test]
async fn https_only_client_refuses_plain_http_even_unchecked() {
    let client = client_builder_unchecked(Arc::new(NetGuard::strict()))
        .build()
        .unwrap();
    assert!(client.get("http://example.com/").send().await.is_err());
    let configured = GuardedClient::with_config(Arc::new(NetGuard::strict()), |b| {
        b.https_only(false).user_agent("test")
    })
    .unwrap();
    assert!(configured.guard().redirect_policy() == RedirectPolicy::Disabled);
}
