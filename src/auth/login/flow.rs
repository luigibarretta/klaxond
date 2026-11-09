//! Browser binding and expiry of pending OIDC authorization flows.
//!
//! The `state` sent to the provider is also stored in an HttpOnly,
//! SameSite=Lax flow cookie. The callback looks the pending flow up by that
//! cookie and lets `exchange_callback` compare the returned `state` with it in
//! constant time, so a callback URL started in another browser (login CSRF /
//! session swap) finds no flow or a mismatching state and is rejected.

use crate::auth::session::cookie_values;
use crate::state::{AppState, PendingOidcState, lock_mutex};
use crate::util::now_epoch;
use axum::body::Body;
use axum::http::header::{COOKIE, SET_COOKIE};
use axum::http::{HeaderMap, HeaderValue, Response};

pub(super) const OIDC_FLOW_COOKIE: &str = "klaxond_oidc_flow";
/// Lifetime of a pending flow and of its cookie.
pub(super) const OIDC_FLOW_TTL_SECONDS: u64 = 600;

/// A pending flow taken from the store by the browser's flow cookie.
pub(super) struct BoundFlow {
    /// The state this browser started, the `expected_state` of the callback.
    pub expected_state: String,
    pub pending: PendingOidcState,
}

pub(super) fn store_pending_flow(state: &AppState, state_token: &str, pending: PendingOidcState) {
    let mut states = lock_mutex(&state.oidc_states, "oidc states");
    let cutoff = pending.created_at - OIDC_FLOW_TTL_SECONDS as f64;
    states.insert(state_token.to_string(), pending);
    states.retain(|_, pending| pending.created_at >= cutoff);
}

/// Removes and returns the flow named by this browser's cookie. The flow is
/// consumed even when it turns out to be expired, so it can never be retried.
pub(super) fn take_bound_flow(state: &AppState, headers: &HeaderMap) -> Option<BoundFlow> {
    let cookie = headers.get(COOKIE).and_then(|value| value.to_str().ok())?;
    // Exactly one flow cookie: a second copy (tossed from a sibling subdomain)
    // fails closed instead of letting an attacker pick or burn pending flows.
    let [value] = cookie_values(cookie, OIDC_FLOW_COOKIE)[..] else {
        return None;
    };
    let (expected_state, pending) =
        lock_mutex(&state.oidc_states, "oidc states").remove_entry(value)?;
    let age = now_epoch() - pending.created_at;
    if !(0.0..=OIDC_FLOW_TTL_SECONDS as f64).contains(&age) {
        return None;
    }
    Some(BoundFlow {
        expected_state,
        pending,
    })
}

pub(super) fn flow_cookie(state: &AppState, value: &str, max_age: u64) -> String {
    let secure = if state.with_cfg(|cfg| cfg.public_url.starts_with("https://")) {
        "; Secure"
    } else {
        ""
    };
    format!("{OIDC_FLOW_COOKIE}={value}; HttpOnly{secure}; Path=/; SameSite=Lax; Max-Age={max_age}")
}

/// Appends (never replaces) a Set-Cookie header, so a session cookie set on
/// the same response survives.
pub(super) fn append_cookie(response: &mut Response<Body>, cookie: &str) {
    match HeaderValue::from_str(cookie) {
        Ok(value) => {
            response.headers_mut().append(SET_COOKIE, value);
        }
        Err(err) => tracing::error!(?err, "failed to build OIDC flow cookie header"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::test_support::temp_paths;
    use tempfile::TempDir;

    fn pending(created_at: f64) -> PendingOidcState {
        PendingOidcState {
            created_at,
            return_to: "/status".into(),
            nonce: "nonce".into(),
            code_verifier: "verifier".into(),
        }
    }

    fn cookie_headers(value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            COOKIE,
            HeaderValue::from_str(&format!("other=1; {OIDC_FLOW_COOKIE}={value}")).unwrap(),
        );
        headers
    }

    fn state(tmp: &TempDir) -> AppState {
        AppState::new(temp_paths(tmp)).unwrap()
    }

    #[test]
    fn a_callback_without_the_flow_cookie_finds_no_flow() {
        let tmp = TempDir::new().unwrap();
        let state = state(&tmp);
        store_pending_flow(&state, "victim-state", pending(now_epoch()));
        assert!(take_bound_flow(&state, &HeaderMap::new()).is_none());
        assert!(take_bound_flow(&state, &cookie_headers("attacker-state")).is_none());
        // The victim's own flow is still intact.
        assert_eq!(
            take_bound_flow(&state, &cookie_headers("victim-state"))
                .unwrap()
                .expected_state,
            "victim-state"
        );
    }

    #[test]
    fn flows_are_single_use() {
        let tmp = TempDir::new().unwrap();
        let state = state(&tmp);
        store_pending_flow(&state, "s1", pending(now_epoch()));
        assert!(take_bound_flow(&state, &cookie_headers("s1")).is_some());
        assert!(take_bound_flow(&state, &cookie_headers("s1")).is_none());
    }

    #[test]
    fn expired_flows_are_rejected_and_consumed() {
        let tmp = TempDir::new().unwrap();
        let state = state(&tmp);
        let stale = now_epoch() - OIDC_FLOW_TTL_SECONDS as f64 - 1.0;
        lock_mutex(&state.oidc_states, "oidc states").insert("old".into(), pending(stale));
        assert!(take_bound_flow(&state, &cookie_headers("old")).is_none());
        assert!(lock_mutex(&state.oidc_states, "oidc states").is_empty());
    }

    #[test]
    fn flow_cookie_is_http_only_lax_and_bounded() {
        let tmp = TempDir::new().unwrap();
        let state = state(&tmp);
        let cookie = flow_cookie(&state, "abc", OIDC_FLOW_TTL_SECONDS);
        assert!(cookie.starts_with("klaxond_oidc_flow=abc; HttpOnly"));
        assert!(cookie.contains("SameSite=Lax"));
        assert!(cookie.ends_with("Max-Age=600"));
    }
}
