use anyhow::Result;
use axum::Router;
use klaxond::{config::Paths, state::AppState};
use std::net::SocketAddr;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_target(false)
        .init();

    let paths = Paths::from_env();
    let state = AppState::new(paths)?;
    klaxond::dedup::restore_pending(&state).await;
    spawn_scheduler(state.clone());
    spawn_shutdown_flush(state.clone());

    let port = std::env::var("PORT")
        .ok()
        .and_then(|v| v.parse::<u16>().ok())
        .unwrap_or(8181);
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let (cascade_default, enabled) = state.with_cfg(|cfg| {
        let enabled = cfg
            .dedup
            .iter()
            .filter(|(_, s)| s.enabled)
            .map(|(k, _)| k.clone())
            .collect::<Vec<_>>();
        (cfg.cascade_default, enabled)
    });
    tracing::info!(
        "klaxond listening on :{}  (cascade_enabled={}, dedup_sources_enabled={:?})",
        port,
        cascade_default,
        enabled
    );

    let app = Router::new()
        .fallback(klaxond::handlers::dispatch)
        .with_state(state);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    Ok(())
}

fn spawn_scheduler(state: AppState) {
    tokio::spawn(async move {
        loop {
            klaxond::inhibition::scheduler_tick(&state);
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let sleep_s = 60 - (now % 60) + 5;
            tokio::time::sleep(std::time::Duration::from_secs(sleep_s)).await;
        }
    });
}

fn spawn_shutdown_flush(state: AppState) {
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            tracing::info!("received shutdown signal -> flushing dedup buffer before exit");
            klaxond::dedup::flush_all(&state).await;
            std::process::exit(0);
        }
    });
}
