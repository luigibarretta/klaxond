use super::session::load_or_create_session_key;
use super::{AppState, DedupQueues, DeliveryLog, Metrics};
use crate::config::{EmergencyProfile, Paths, RuntimeConfig, load_runtime_config};
use crate::history::HistoryStore;
use anyhow::{Context, Result};
use std::collections::HashMap;
use std::fs;
use std::sync::atomic::{AtomicBool, AtomicU64};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Instant;
use tokio::sync::{Mutex as AsyncMutex, Semaphore};

pub(super) fn new(paths: Paths) -> Result<AppState> {
    prepare_runtime_dirs(&paths)?;
    let cfg = load_runtime_config(&paths)?;
    let cascade_runtime_enabled = cfg.cascade_default;
    let session_key = load_or_create_session_key(&paths, &cfg)?;
    let history = Arc::new(HistoryStore::open(&cfg.history)?);
    materialize_legacy_emergency_policy(&cfg, &history)?;
    let queues = dedup_queues(&cfg);
    Ok(AppState {
        paths,
        http: reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .context("build reqwest client")?,
        started: Instant::now(),
        config: Arc::new(RwLock::new(cfg)),
        config_write_lock: Arc::new(Mutex::new(())),
        session_key: Arc::new(session_key),
        cascade_runtime_enabled: Arc::new(AtomicBool::new(cascade_runtime_enabled)),
        history: Arc::new(RwLock::new(history)),
        auth_store_transition: Arc::new(RwLock::new(())),
        delivery_log: Arc::new(Mutex::new(DeliveryLog::with_capacity(50))),
        delivery_activity_cache: Arc::new(Mutex::new(HashMap::new())),
        history_generation: Arc::new(AtomicU64::new(0)),
        delivery_activity_slots: Arc::new(Semaphore::new(1)),
        history_read_slots: Arc::new(Semaphore::new(4)),
        suppressions: Arc::new(Mutex::new(Vec::new())),
        ack_suppressions: Arc::new(Mutex::new(HashMap::new())),
        active_mutes: Arc::new(Mutex::new(HashMap::new())),
        rendered_images: Arc::new(Mutex::new(HashMap::new())),
        metrics: Arc::new(Metrics::default()),
        dedup: Arc::new(AsyncMutex::new(queues)),
        oidc_provider: Arc::new(AsyncMutex::new(None)),
        oidc_config_generation: Arc::new(AtomicU64::new(0)),
        oidc_states: Arc::new(Mutex::new(HashMap::new())),
        step_up_states: Arc::new(Mutex::new(HashMap::new())),
        magic_links: Arc::new(Mutex::new(HashMap::new())),
        passkey_registrations: Arc::new(Mutex::new(HashMap::new())),
        passkey_authentications: Arc::new(Mutex::new(HashMap::new())),
        totp_registrations: Arc::new(Mutex::new(HashMap::new())),
        auth_failures: auth_modules::rate_limit::InMemoryRateLimiter::default(),
        auth_blocking_slots: Arc::new(Semaphore::new(8)),
    })
}

fn materialize_legacy_emergency_policy(cfg: &RuntimeConfig, history: &HistoryStore) -> Result<()> {
    let fallback = cfg
        .emergency
        .profiles
        .iter()
        .find(|profile| profile.id == cfg.emergency.fallback_profile)
        .cloned()
        .unwrap_or_else(EmergencyProfile::legacy_default);
    let snapshot = crate::emergency::snapshot_from_profile(&fallback);
    let snapshot_json =
        serde_json::to_string(&snapshot).context("serialize legacy emergency policy snapshot")?;
    let materialized = history.emergency_materialize_policy_snapshot(
        &fallback.id,
        &fallback.name,
        &snapshot_json,
    )?;
    if materialized > 0 {
        tracing::info!(
            materialized,
            policy_id = %fallback.id,
            "materialized policy snapshots for active legacy emergency receipts"
        );
    }
    Ok(())
}

fn dedup_queues(cfg: &RuntimeConfig) -> DedupQueues {
    let mut queues = DedupQueues::default();
    for source in cfg.dedup.keys() {
        queues.queues.insert(source.clone(), Vec::new());
        queues.timer_active.insert(source.clone(), false);
    }
    queues
}

fn prepare_runtime_dirs(paths: &Paths) -> Result<()> {
    fs::create_dir_all(&paths.backup_dir)
        .with_context(|| format!("create backup dir {}", paths.backup_dir.display()))?;
    Ok(())
}
