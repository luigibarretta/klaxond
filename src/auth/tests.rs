use super::login::{callback_url, oidc_client_config};
use super::magic_link::{
    MagicLinkError, consume_magic_link, issue_magic_link, magic_link_ttl_seconds,
};
use super::session::{cookie_values, sanitize_return_to};
use super::test_support::{temp_paths, test_user};
use super::*;
use crate::state::{AppState, PendingMagicLink, lock_mutex};
use auth_modules::one_time_token;
use axum::body::Bytes;
use axum::http::header::{HOST, SET_COOKIE, WWW_AUTHENTICATE};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use tempfile::TempDir;

#[test]
fn password_helpers_use_shared_argon2_contract() {
    let hash = hash_password("correct horse battery staple").unwrap();

    assert_eq!(
        MIN_PASSWORD_LEN,
        auth_modules::password::DEFAULT_MIN_PASSWORD_LENGTH
    );
    assert!(hash.starts_with("$argon2id$"));
    assert!(validate_password_policy("Unique passphrase 123", Some("luigi")).is_ok());
    assert!(validate_password_policy("welcome12345", Some("luigi")).is_err());
    assert!(verify_password("correct horse battery staple", &hash));
    assert!(!verify_password("wrong password", &hash));
}

#[test]
fn cookie_values_keeps_duplicate_session_cookies_in_order() {
    let values = cookie_values(
        "klaxond_session=stale; theme=dark; klaxond_session=fresh",
        AUTH_SESSION_COOKIE,
    );

    assert_eq!(values, vec!["stale", "fresh"]);
}

#[test]
fn sanitize_return_to_allows_only_local_non_auth_paths() {
    assert_eq!(sanitize_return_to("/inhibitions"), "/inhibitions");
    assert_eq!(sanitize_return_to("/authentication"), "/authentication");
    assert_eq!(sanitize_return_to("https://example.test/"), "/");
    assert_eq!(sanitize_return_to("//example.test/"), "/");
    assert_eq!(sanitize_return_to("/ui\r\nLocation: //example.test"), "/");
    assert_eq!(sanitize_return_to("/api/auth/login?return_to=%2F"), "/");
    assert_eq!(sanitize_return_to("/api/auth"), "/");
    assert_eq!(sanitize_return_to("/api/auth/callback"), "/");
    assert_eq!(sanitize_return_to(""), "/");
}

#[test]
fn login_payload_preserves_form_and_json_compatibility() {
    let form =
        Bytes::from_static(b"username=%20luigi%20&password=secret&return_to=&fetch=1&totp=123456");
    let payload = login_payload(&form);
    assert_eq!(payload.username(), " luigi ");
    assert_eq!(payload.password(), "secret");
    assert_eq!(payload.totp(), "123456");
    assert_eq!(payload.return_to_or_status(), "");
    assert!(payload.wants_json(&form));

    let json = Bytes::from_static(br#"{"username":42,"password":true,"fetch":0}"#);
    let payload = login_payload(&json);
    assert_eq!(payload.username(), "42");
    assert_eq!(payload.password(), "true");
    assert_eq!(payload.return_to_or_status(), "/status");
    assert!(payload.wants_json(&json));
}

#[test]
fn invalid_basic_realm_does_not_panic_while_challenging() {
    let _env_guard = crate::config::TEST_ENV_LOCK.lock().unwrap();
    let tmp = TempDir::new().unwrap();
    let state = AppState::new(temp_paths(&tmp)).unwrap();
    let mut auth = state.cfg().auth;
    auth.mode = "basic".to_string();
    auth.basic.realm = "bad\rrealm".to_string();

    let headers = HeaderMap::new();
    let AuthOutcome::Rejected(resp) =
        super::local::authenticate_basic(&state, &auth, &headers, "/status")
    else {
        panic!("missing credentials should be rejected");
    };

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        resp.headers().get(WWW_AUTHENTICATE),
        Some(&HeaderValue::from_static("Basic realm=\"klaxond\""))
    );
}

#[test]
fn oidc_client_config_preserves_exact_issuer_trailing_slash() {
    let cfg = crate::config::OidcConfig {
        provider: "authentik".to_string(),
        issuer: " https://authentik.example/application/o/klaxond/ ".to_string(),
        client_id: "client".to_string(),
        client_secret: "secret".to_string(),
        scopes: "openid email profile".to_string(),
        required_group: String::new(),
        redirect_path: "/api/auth/callback".to_string(),
    };

    let shared = oidc_client_config(&cfg, "https://klaxond.example/api/auth/callback");
    assert_eq!(
        shared.issuer_url,
        "https://authentik.example/application/o/klaxond/"
    );
}

#[test]
fn oidc_callback_url_parser_rejects_malformed_uri() {
    assert!(callback_url("/api/auth/callback?code=abc&state=xyz").is_ok());
    assert!(callback_url("api/auth/callback?code=abc&state=xyz").is_err());
    assert!(callback_url("\0").is_err());
}

#[test]
fn magic_link_issue_and_consume_is_single_use() {
    let _env_guard = crate::config::TEST_ENV_LOCK.lock().unwrap();
    let tmp = TempDir::new().unwrap();
    let state = AppState::new(temp_paths(&tmp)).unwrap();
    let mut runtime = state.cfg();
    runtime.public_url = "https://klaxond.example.test".to_string();
    runtime.auth.mode = "basic".to_string();
    runtime.auth.basic.username = "luigi".to_string();
    runtime.auth.basic.password_hash = hash_password("correct horse battery staple").unwrap();
    state.replace_config(runtime.clone());

    assert!(magic_link_enabled(&runtime.auth));
    assert!(issue_magic_link(&state, &runtime.auth, "nobody", "/status").is_none());

    let token = issue_magic_link(&state, &runtime.auth, "luigi", "/status").expect("token");
    assert_eq!(
        magic_link_callback_url(&runtime.public_url, &token),
        format!("https://klaxond.example.test/api/auth/magic/callback/{token}")
    );
    {
        let pending = lock_mutex(&state.magic_links, "magic links");
        let stored = pending
            .get(&one_time_token::hash_token(&token))
            .expect("stored token hash only");
        assert_eq!(stored.username, "luigi");
        assert!(stored.created_at <= stored.expires_at);
    }

    let (user, return_to) =
        consume_magic_link(&state, &runtime.auth, &token).expect("consume token");
    assert_eq!(user.sub, "luigi");
    assert_eq!(user.mode, "magic_link");
    assert_eq!(return_to, "/status");
    assert!(matches!(
        consume_magic_link(&state, &runtime.auth, &token),
        Err(MagicLinkError::Used)
    ));

    let expired = "expired-token";
    {
        let mut pending = lock_mutex(&state.magic_links, "magic links");
        let now = crate::util::now_epoch();
        pending.insert(
            one_time_token::hash_token(expired),
            PendingMagicLink {
                created_at: now - magic_link_ttl_seconds() as f64,
                expires_at: now - 1.0,
                username: "luigi".to_string(),
                return_to: "/status".to_string(),
                used_at: None,
            },
        );
    }
    assert!(matches!(
        consume_magic_link(&state, &runtime.auth, expired),
        Err(MagicLinkError::Expired)
    ));
}

#[test]
fn legal_ui_pages_and_assets_are_public_but_admin_routes_are_not() {
    assert!(is_public("/legal/privacy"));
    assert!(is_public("/legal/accessibility"));
    assert!(is_public("/legal/terms"));
    assert!(is_public("/legal/cookies"));
    assert!(is_public("/legal/notice"));
    assert!(is_public("/ui/privacy"));
    assert!(is_public("/ui/accessibility"));
    assert!(is_public("/ui/style.css"));
    assert!(is_public("/ui/meta.js"));
    assert!(is_public("/ui/app.js"));
    assert!(is_public("/"));
    assert!(is_public("/ui"));
    assert!(is_public("/ui/deliveries"));
    assert!(is_public("/ui/auth"));
    assert!(!is_public("/status"));
    assert!(!is_public("/authentication"));
}

#[test]
fn client_log_remains_csrf_exempt_for_interactive_sessions() {
    let headers = HeaderMap::new();
    let mut user = test_user("basic");

    assert!(!csrf_required(&headers, "/api/client-log", &user));
    assert!(csrf_required(&headers, "/api/cascade/toggle", &user));

    user.via_authorization = true;
    assert!(!csrf_required(&headers, "/api/cascade/toggle", &user));
}

#[test]
fn logout_clears_host_and_parent_domain_cookie_variants() {
    let mut headers = HeaderMap::new();
    headers.insert(HOST, HeaderValue::from_static("klaxond.example.com"));
    let resp = api_logout(&headers);
    assert_eq!(resp.status(), StatusCode::OK);
    let cookies = resp
        .headers()
        .get_all(SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .collect::<Vec<_>>();

    assert!(
        cookies
            .iter()
            .any(|c| c.starts_with("klaxond_session=;") && c.contains("Path=/;"))
    );
    assert!(cookies.iter().any(|c| c.contains("Domain=example.com")));
    assert!(cookies.iter().any(|c| c.contains("Domain=.example.com")));
    assert!(
        cookies
            .iter()
            .any(|c| c.contains("Path=/api/auth/callback;"))
    );
}

#[test]
fn shared_auth_modules_are_enabled_for_app_contract() {
    use auth_modules::audit::{AuthAuditEvent, AuthAuditKind};
    use auth_modules::security_profile::GoldAuthProfile;
    use auth_modules::testing::CapturedEvents;
    use auth_modules::{errors, methods};

    let profile = GoldAuthProfile::personal_default();
    assert_eq!(profile.password_policy.min_length, MIN_PASSWORD_LEN);
    assert_eq!(errors::INVALID_CREDENTIALS, "invalid_credentials");

    let event = AuthAuditEvent::login_failure("alice", methods::PASSWORD);
    assert_eq!(event.kind, AuthAuditKind::LoginFailure);
    assert_eq!(event.method, Some(methods::PASSWORD));

    let mut captured = CapturedEvents::new();
    captured.push(event);
    assert_eq!(
        captured.as_slice()[0].kind.as_str(),
        AuthAuditKind::LoginFailure.as_str()
    );
}
