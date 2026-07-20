use super::verify_password;
use crate::config::AuthConfig;
use crate::state::AppState;
use std::time::Duration;

pub(crate) const AUTH_STORE_TIMEOUT: Duration = Duration::from_secs(10);

pub(super) async fn verify_password_on_worker(
    state: &AppState,
    password: &str,
    hash: &str,
) -> bool {
    let password = password.to_string();
    let hash = hash.to_string();
    match run(state, move || verify_password(&password, &hash)).await {
        Ok(valid) => valid,
        Err(err) => {
            tracing::error!("password verification worker failed: {err}");
            false
        }
    }
}

pub(super) async fn authenticate_ldap(
    state: &AppState,
    cfg: &AuthConfig,
    username: &str,
    password: &str,
) -> Result<auth_modules::ldap::LdapIdentity, String> {
    let ldap = cfg
        .ldap
        .to_auth_modules_config()
        .ok_or_else(|| "LDAP is not configured".to_string())?;
    let username = username.to_string();
    let password = password.to_string();
    run(state, move || {
        ldap.authenticate(&username, &password)
            .map_err(|err| err.to_string())
    })
    .await?
}

pub(crate) async fn run<T, F>(state: &AppState, task: F) -> Result<T, String>
where
    T: Send + 'static,
    F: FnOnce() -> T + Send + 'static,
{
    let permit = state
        .auth_blocking_slots
        .clone()
        .acquire_owned()
        .await
        .map_err(|_| "authentication worker pool is closed".to_string())?;
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        task()
    })
    .await
    .map_err(|err| format!("authentication worker failed: {err}"))
}

pub(crate) async fn run_with_timeout<T, F>(
    state: &AppState,
    timeout: Duration,
    task: F,
) -> Result<T, String>
where
    T: Send + 'static,
    F: FnOnce() -> T + Send + 'static,
{
    tokio::time::timeout(timeout, run(state, task))
        .await
        .map_err(|_| {
            format!(
                "authentication worker timed out after {}s",
                timeout.as_secs()
            )
        })?
}
