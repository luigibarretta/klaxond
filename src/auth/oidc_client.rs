use crate::state::AppState;
use auth_modules::oidc::{OidcClientConfig, PreparedAsyncOidcClient};
use std::sync::atomic::Ordering;
use std::time::Duration;

const OIDC_REFRESH_INTERVAL: Duration = Duration::from_secs(15 * 60);

#[derive(Clone)]
pub(crate) struct OidcProviderCache {
    generation: u64,
    config: OidcClientConfig,
    client: PreparedAsyncOidcClient,
}

pub(super) async fn client_for(
    state: &AppState,
    config: &OidcClientConfig,
) -> Result<PreparedAsyncOidcClient, auth_modules::oidc::OidcError> {
    let generation = state.oidc_config_generation.load(Ordering::Relaxed);
    let mut cached = state.oidc_provider.lock().await;
    if let Some(cached) = cached.as_ref()
        && cached.generation == generation
    {
        return if cached.config == *config {
            Ok(cached.client.clone())
        } else {
            Err(auth_modules::oidc::OidcError::new(
                "OIDC request configuration does not match the prepared provider",
            ))
        };
    }

    let client = PreparedAsyncOidcClient::discover(config).await?;
    *cached = Some(OidcProviderCache {
        generation,
        config: config.clone(),
        client: client.clone(),
    });
    Ok(client)
}

pub(super) async fn cached_client_for(
    state: &AppState,
    config: &OidcClientConfig,
) -> Result<PreparedAsyncOidcClient, auth_modules::oidc::OidcError> {
    let generation = state.oidc_config_generation.load(Ordering::Relaxed);
    let cached = state.oidc_provider.lock().await;
    let cached = cached
        .as_ref()
        .ok_or_else(|| auth_modules::oidc::OidcError::new("OIDC provider is not prepared"))?;
    if cached.generation != generation || cached.config != *config {
        return Err(auth_modules::oidc::OidcError::new(
            "OIDC provider cache does not match the active configuration",
        ));
    }
    Ok(cached.client.clone())
}

pub async fn warm(state: &AppState) {
    let runtime = state.cfg();
    if runtime.auth.mode != "oidc" {
        return;
    }
    let Ok(public_url) = url::Url::parse(&runtime.public_url) else {
        tracing::warn!("cannot prepare OIDC provider: KLAXOND_PUBLIC_URL is not configured");
        return;
    };
    if !matches!(public_url.scheme(), "http" | "https") || public_url.host_str().is_none() {
        tracing::warn!("cannot prepare OIDC provider: KLAXOND_PUBLIC_URL is not an HTTP origin");
        return;
    }
    let redirect_uri = format!(
        "{}{}",
        runtime.public_url.trim_end_matches('/'),
        runtime.auth.oidc.redirect_path
    );
    let config = super::login::oidc_client_config(&runtime.auth.oidc, &redirect_uri);
    if let Err(err) = client_for(state, &config).await {
        tracing::warn!("prepare OIDC provider failed; login will retry on demand: {err}");
    }
}

pub fn spawn_refresh(state: AppState) {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(OIDC_REFRESH_INTERVAL).await;
            refresh(&state).await;
        }
    });
}

async fn refresh(state: &AppState) {
    let snapshot = {
        let cached = state.oidc_provider.lock().await;
        cached
            .as_ref()
            .map(|cached| (cached.generation, cached.config.clone()))
    };
    let Some((generation, config)) = snapshot else {
        return;
    };

    let refreshed = match PreparedAsyncOidcClient::discover(&config).await {
        Ok(client) => client,
        Err(err) => {
            tracing::warn!("refresh OIDC provider metadata failed; retaining cached client: {err}");
            return;
        }
    };
    let mut cached = state.oidc_provider.lock().await;
    if cached
        .as_ref()
        .is_some_and(|current| current.generation == generation && current.config == config)
        && state.oidc_config_generation.load(Ordering::Relaxed) == generation
    {
        *cached = Some(OidcProviderCache {
            generation,
            config,
            client: refreshed,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refresh_interval_is_bounded() {
        assert!(OIDC_REFRESH_INTERVAL >= Duration::from_secs(5 * 60));
        assert!(OIDC_REFRESH_INTERVAL <= Duration::from_secs(60 * 60));
    }
}
