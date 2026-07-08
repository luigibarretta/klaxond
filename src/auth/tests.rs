use super::login::oidc_client_config;
use super::magic_link::{
    MagicLinkError, consume_magic_link, issue_magic_link, magic_link_ttl_seconds,
};
use super::session::{cookie_values, sanitize_return_to};
use super::*;
use crate::config::Paths;
use crate::state::{PendingMagicLink, lock_mutex};
use auth_modules::one_time_token;
use axum::http::header::{HOST, SET_COOKIE};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use std::path::PathBuf;
use tempfile::TempDir;

fn temp_paths(tmp: &TempDir) -> Paths {
    let data = tmp.path();
    Paths {
        config: data.join("klaxond.toml"),
        default_config: PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("klaxond.default.toml"),
        render_config: data.join("render-config.json"),
        ntfy_topics: data.join("ntfy-topics.json"),
        dedup_config: data.join("dedup-config.json"),
        dedup_pending_dir: data.join("dedup_pending"),
        auth_config: data.join("auth-config.json"),
        auth_session_key: data.join("auth-session.key"),
        backup_dir: data.join("backups"),
        static_dir: PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("static"),
        beszel_db: data.join("missing-beszel.db"),
        history_db: data.join("klaxond.db"),
    }
}

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
fn ui_fetch_auth_required_is_machine_readable() {
    let mut headers = HeaderMap::new();
    headers.insert("X-Klaxond-Request", HeaderValue::from_static("fetch"));
    assert!(is_ui_fetch(&headers));

    let resp = auth_required("/api/auth/login?return_to=%2Fstatus");
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        resp.headers()
            .get("X-Klaxond-Login")
            .and_then(|v| v.to_str().ok()),
        Some("/api/auth/login?return_to=%2Fstatus")
    );
    assert_eq!(
        resp.headers()
            .get("Cache-Control")
            .and_then(|v| v.to_str().ok()),
        Some("no-store")
    );
}

fn test_user(mode: &str) -> User {
    User {
        sub: "test-user".into(),
        email: String::new(),
        name: String::new(),
        groups: vec![],
        mode: mode.into(),
        exp: 0,
        csrf: "csrf-token".into(),
        sudo_until: 0,
        via_authorization: false,
    }
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
