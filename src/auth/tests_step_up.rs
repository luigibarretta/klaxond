use super::test_support::{temp_paths, test_user};
use super::*;
use crate::state::AppState;
use auth_modules::step_up::PrimaryAuthMethod;
use axum::http::header::{AUTHORIZATION, LOCATION, WWW_AUTHENTICATE};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode};
use base64::Engine as _;
use tempfile::TempDir;
use url::Url;

#[test]
fn basic_authorization_primary_auth_opens_interactive_step_up() {
    let _env_guard = crate::config::TEST_ENV_LOCK.lock().unwrap();
    let tmp = TempDir::new().unwrap();
    let state = AppState::new(temp_paths(&tmp)).unwrap();
    let auth = basic_auth_requiring_passkey_step_up();
    let headers = basic_headers("luigi", "correct horse battery staple");

    let AuthOutcome::Rejected(resp) =
        super::local::authenticate_basic(&state, &auth, &headers, "/status")
    else {
        panic!("valid primary auth should require step-up before session issue");
    };

    assert_eq!(resp.status(), StatusCode::FOUND);
    assert!(resp.headers().get(WWW_AUTHENTICATE).is_none());
    let location = resp
        .headers()
        .get(LOCATION)
        .and_then(|value| value.to_str().ok())
        .expect("step-up redirect");
    assert!(location.starts_with("/api/auth/step-up?"));

    let pending =
        pending_step_up_challenge(&state, &step_up_token(location)).expect("pending challenge");
    assert_eq!(pending.user.sub, "luigi");
    assert_eq!(pending.user.mode, "basic");
    assert_eq!(pending.factor, "passkey");
    assert_eq!(pending.return_to, "/status");
}

#[tokio::test]
async fn ui_fetch_basic_primary_auth_preserves_step_up_location() {
    let tmp = TempDir::new().unwrap();
    let state = {
        let _env_guard = crate::config::TEST_ENV_LOCK.lock().unwrap();
        let state = AppState::new(temp_paths(&tmp)).unwrap();
        let mut runtime = state.cfg();
        runtime.auth = basic_auth_requiring_passkey_step_up();
        state.replace_config(runtime);
        state
    };
    let mut headers = basic_headers("luigi", "correct horse battery staple");
    headers.insert("X-Klaxond-Request", HeaderValue::from_static("fetch"));

    let AuthOutcome::Rejected(resp) =
        authenticate(&state, &headers, &Method::GET, "/status", None).await
    else {
        panic!("valid primary auth should require step-up before session issue");
    };

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert!(resp.headers().get(WWW_AUTHENTICATE).is_none());
    let location = resp
        .headers()
        .get("X-Klaxond-Login")
        .and_then(|value| value.to_str().ok())
        .expect("step-up login hint");
    assert!(location.starts_with("/api/auth/step-up?"));

    let pending =
        pending_step_up_challenge(&state, &step_up_token(location)).expect("pending challenge");
    assert_eq!(pending.user.sub, "luigi");
    assert_eq!(pending.factor, "passkey");
}

#[test]
fn ldap_primary_auth_uses_interactive_step_up_response() {
    let _env_guard = crate::config::TEST_ENV_LOCK.lock().unwrap();
    let tmp = TempDir::new().unwrap();
    let state = AppState::new(temp_paths(&tmp)).unwrap();
    let mut auth = crate::config::AuthConfig::default();
    auth.step_up.required_after_primary = true;
    auth.step_up.factor = "totp".to_string();
    let mut headers = HeaderMap::new();
    headers.insert("X-Klaxond-Request", HeaderValue::from_static("fetch"));
    let user = test_user("ldap");

    let resp = super::step_up::primary_step_up_response(
        &state,
        &auth,
        &user,
        "/deliveries",
        PrimaryAuthMethod::Ldap,
        &headers,
    )
    .expect("ldap primary auth should require step-up");

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let location = resp
        .headers()
        .get("X-Klaxond-Login")
        .and_then(|value| value.to_str().ok())
        .expect("step-up login hint");
    let pending =
        pending_step_up_challenge(&state, &step_up_token(location)).expect("pending challenge");
    assert_eq!(pending.user.mode, "ldap");
    assert_eq!(pending.factor, "totp");
    assert_eq!(pending.return_to, "/deliveries");
}

#[test]
fn primary_auth_step_up_creates_challenge_before_session_issue() {
    let _env_guard = crate::config::TEST_ENV_LOCK.lock().unwrap();
    let tmp = TempDir::new().unwrap();
    let state = AppState::new(temp_paths(&tmp)).unwrap();
    let mut auth = crate::config::AuthConfig::default();
    auth.step_up.required_after_primary = true;
    auth.step_up.factor = "totp".to_string();
    let user = test_user("oidc");

    let location = super::step_up::redirect_location_after_primary(
        &state,
        &auth,
        user,
        "/status",
        PrimaryAuthMethod::Oidc,
    )
    .expect("step-up location");
    let token = step_up_token(&location);

    let pending = pending_step_up_challenge(&state, &token).expect("pending challenge");
    assert_eq!(pending.factor, "totp");
    assert_eq!(pending.return_to, "/status");

    let (finished, return_to) =
        finish_totp_step_up(&state, &token, "test-user").expect("finish step-up");
    assert_eq!(finished.mode, "oidc");
    assert_eq!(finished.second_factor, "totp");
    assert_eq!(return_to, "/status");
    assert!(pending_step_up_challenge(&state, &token).is_none());
}

#[test]
fn passkey_step_up_rejects_other_primary_user() {
    let _env_guard = crate::config::TEST_ENV_LOCK.lock().unwrap();
    let tmp = TempDir::new().unwrap();
    let state = AppState::new(temp_paths(&tmp)).unwrap();
    let mut auth = crate::config::AuthConfig::default();
    auth.step_up.required_after_primary = true;
    auth.step_up.factor = "passkey".to_string();
    let location = super::step_up::redirect_location_after_primary(
        &state,
        &auth,
        test_user("oidc"),
        "/status",
        PrimaryAuthMethod::Oidc,
    )
    .expect("step-up location");
    let token = step_up_token(&location);

    let err = finish_webauthn_step_up(&state, &token, "other-user").expect_err("user mismatch");

    assert!(err.contains("does not match"));
    assert!(pending_step_up_challenge(&state, &token).is_some());
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

fn basic_auth_requiring_passkey_step_up() -> crate::config::AuthConfig {
    crate::config::AuthConfig {
        mode: "basic".to_string(),
        basic: crate::config::BasicAuthConfig {
            username: "luigi".to_string(),
            password_hash: hash_password("correct horse battery staple").unwrap(),
            realm: "klaxond".to_string(),
            totp_enabled: false,
            totp_secret: String::new(),
        },
        step_up: crate::config::AuthStepUpConfig {
            required_after_primary: true,
            factor: "passkey".to_string(),
            ..Default::default()
        },
        ..Default::default()
    }
}

fn basic_headers(username: &str, password: &str) -> HeaderMap {
    let credentials = format!("{username}:{password}");
    let value = format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(credentials)
    );
    let mut headers = HeaderMap::new();
    headers.insert(AUTHORIZATION, HeaderValue::from_str(&value).unwrap());
    headers
}

fn step_up_token(location: &str) -> String {
    Url::parse(&format!("http://localhost{location}"))
        .unwrap()
        .query_pairs()
        .find(|(key, _)| key == "token")
        .map(|(_, value)| value.to_string())
        .expect("step-up token")
}
