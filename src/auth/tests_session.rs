use super::session::{
    api_logout, issue_session, persistent_session_hash, rotate_session, verify_session,
};
use super::test_support::{temp_paths, test_user};
use super::{AUTH_SESSION_COOKIE, AuthOutcome, authenticate};
use crate::state::AppState;
use axum::http::header::COOKIE;
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode};
use tempfile::TempDir;

#[tokio::test]
async fn persistent_session_is_verified_and_revoked_by_logout() {
    let tmp = TempDir::new().unwrap();
    let state = test_state(&tmp, false);
    let mut user = test_user("basic");
    let cookie = issue_session(&state, &state.cfg().auth, &mut user).unwrap();
    let token = session_token(&cookie);

    assert!(persistent_session_hash(token).is_some());
    let verified = verify_session(&state, token)
        .await
        .unwrap()
        .expect("persistent session");
    assert_eq!(verified.user.sub, user.sub);
    assert!(!verified.legacy);

    let headers = session_headers(token);
    let response = api_logout(&state, &headers).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(verify_session(&state, token).await.unwrap().is_none());
}

#[tokio::test]
async fn logout_with_pre_rotation_token_revokes_the_session_family() {
    let tmp = TempDir::new().unwrap();
    let state = test_state(&tmp, false);
    let mut user = test_user("basic");
    let original_cookie = issue_session(&state, &state.cfg().auth, &mut user).unwrap();
    let original_token = session_token(&original_cookie);
    let rotated_cookie = rotate_session(&state, &state.cfg().auth, &mut user).unwrap();
    let rotated_token = session_token(&rotated_cookie);

    assert_eq!(
        api_logout(&state, &session_headers(original_token))
            .await
            .status(),
        StatusCode::OK
    );
    assert!(
        verify_session(&state, rotated_token)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        verify_session(&state, original_token)
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn concurrent_rotation_retry_reuses_the_same_session_and_cookie() {
    let tmp = TempDir::new().unwrap();
    let state = test_state(&tmp, true);
    let mut original = test_user("basic");
    let original_cookie = issue_session(&state, &state.cfg().auth, &mut original).unwrap();
    let original_token = session_token(&original_cookie);
    let mut first_request = original.clone();
    let mut second_request = original;

    let first_cookie = rotate_session(&state, &state.cfg().auth, &mut first_request).unwrap();
    let second_cookie = rotate_session(&state, &state.cfg().auth, &mut second_request).unwrap();

    assert_eq!(first_cookie, second_cookie);
    assert_eq!(
        first_request.session_id_hash,
        second_request.session_id_hash
    );
    let recovered = verify_session(&state, original_token)
        .await
        .unwrap()
        .expect("recent predecessor should recover its rotation successor");
    assert_eq!(
        recovered.user.session_id_hash,
        first_request.session_id_hash
    );
    assert_eq!(
        recovered.replacement_cookie.as_deref().map(session_token),
        Some(session_token(&first_cookie))
    );

    let AuthOutcome::Authorized(_, Some(replacement_cookie)) = authenticate(
        &state,
        &session_headers(original_token),
        &Method::GET,
        "/status",
        None,
    )
    .await
    else {
        panic!("a concurrent request must recover the newly rotated session");
    };
    assert_eq!(
        session_token(&replacement_cookie),
        session_token(&first_cookie)
    );
}

fn test_state(tmp: &TempDir, enable_basic: bool) -> AppState {
    let _env_guard = crate::config::TEST_ENV_LOCK.lock().unwrap();
    let state = AppState::new(temp_paths(tmp)).unwrap();
    if enable_basic {
        let mut runtime = state.cfg();
        runtime.auth.mode = "basic".to_string();
        state.replace_config(runtime);
    }
    state
}

fn session_headers(token: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        COOKIE,
        HeaderValue::from_str(&format!("{AUTH_SESSION_COOKIE}={token}")).unwrap(),
    );
    headers
}

fn session_token(cookie: &str) -> &str {
    cookie
        .split(';')
        .next()
        .and_then(|pair| pair.split_once('='))
        .map(|(_, value)| value)
        .expect("session cookie token")
}
