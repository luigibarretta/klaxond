#[cfg(test)]
mod tests;

mod delivery;
mod locks;
mod metrics;
mod session;
mod types;

pub use self::locks::{lock_mutex, read_lock, write_lock};
pub use self::metrics::esc_label;
pub use self::types::{
    DedupItem, DedupQueues, PendingMagicLink, PendingOidcState, PendingPasskeyAuthentication,
    PendingPasskeyRegistration, PendingStepUpState, PendingTotpRegistration, RenderedImage,
    Suppression,
};
use crate::config::{Paths, RuntimeConfig, load_runtime_config};
use crate::history::{DeliveryActivity, HistoryStore, snapshot_runtime_auth_state};
use crate::util::tmp_path;
use anyhow::{Context, Result};
use fs2::FileExt;
use std::collections::HashMap;
use std::fs;
use std::fs::OpenOptions;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Instant;
use tokio::sync::{Mutex as AsyncMutex, Semaphore};

use self::metrics::metric_key;
use self::session::load_or_create_session_key;
use self::types::{DeliveryLog, Metrics};

type DeliveryActivityCache = Arc<Mutex<HashMap<u16, (Instant, u64, DeliveryActivity)>>>;

#[derive(Clone)]
pub struct AppState {
    pub paths: Paths,
    pub http: reqwest::Client,
    pub started: Instant,
    pub config: Arc<RwLock<RuntimeConfig>>,
    pub config_write_lock: Arc<Mutex<()>>,
    pub session_key: Arc<Vec<u8>>,
    pub cascade_runtime_enabled: Arc<AtomicBool>,
    pub history: Arc<RwLock<Arc<HistoryStore>>>,
    pub(crate) auth_store_transition: Arc<RwLock<()>>,
    pub delivery_log: Arc<Mutex<DeliveryLog>>,
    pub(crate) delivery_activity_cache: DeliveryActivityCache,
    pub(crate) history_generation: Arc<AtomicU64>,
    pub(crate) delivery_activity_slots: Arc<Semaphore>,
    pub(crate) history_read_slots: Arc<Semaphore>,
    pub suppressions: Arc<Mutex<Vec<Suppression>>>,
    pub ack_suppressions: Arc<Mutex<HashMap<String, f64>>>,
    pub active_mutes: Arc<Mutex<HashMap<String, f64>>>,
    pub rendered_images: Arc<Mutex<HashMap<String, RenderedImage>>>,
    pub metrics: Arc<Metrics>,
    pub dedup: Arc<AsyncMutex<DedupQueues>>,
    pub(crate) oidc_provider: Arc<AsyncMutex<Option<crate::auth::OidcProviderCache>>>,
    pub(crate) oidc_config_generation: Arc<AtomicU64>,
    pub oidc_states: Arc<Mutex<HashMap<String, PendingOidcState>>>,
    pub step_up_states: Arc<Mutex<HashMap<String, PendingStepUpState>>>,
    pub magic_links: Arc<Mutex<HashMap<String, PendingMagicLink>>>,
    pub passkey_registrations: Arc<Mutex<HashMap<String, PendingPasskeyRegistration>>>,
    pub passkey_authentications: Arc<Mutex<HashMap<String, PendingPasskeyAuthentication>>>,
    pub totp_registrations: Arc<Mutex<HashMap<String, PendingTotpRegistration>>>,
    pub auth_failures: auth_modules::rate_limit::InMemoryRateLimiter,
    pub auth_blocking_slots: Arc<Semaphore>,
}

impl AppState {
    pub fn new(paths: Paths) -> Result<Self> {
        prepare_runtime_dirs(&paths)?;
        let cfg = load_runtime_config(&paths)?;
        let cascade_runtime_enabled = cfg.cascade_default;
        let session_key = load_or_create_session_key(&paths, &cfg)?;
        let history = Arc::new(HistoryStore::open(&cfg.history)?);
        let fallback = cfg
            .emergency
            .profiles
            .iter()
            .find(|profile| profile.id == cfg.emergency.fallback_profile)
            .cloned()
            .unwrap_or_else(crate::config::EmergencyProfile::legacy_default);
        let snapshot = crate::emergency::snapshot_from_profile(&fallback);
        let snapshot_json = serde_json::to_string(&snapshot)
            .context("serialize legacy emergency policy snapshot")?;
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
        let mut queues = DedupQueues::default();
        for src in cfg.dedup.keys() {
            queues.queues.insert(src.clone(), Vec::new());
            queues.timer_active.insert(src.clone(), false);
        }
        Ok(Self {
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

    pub fn cfg(&self) -> RuntimeConfig {
        read_lock(&self.config, "config").clone()
    }

    pub fn with_cfg<R>(&self, f: impl FnOnce(&RuntimeConfig) -> R) -> R {
        let cfg = read_lock(&self.config, "config");
        f(&cfg)
    }

    pub fn try_replace_config(&self, cfg: RuntimeConfig) -> Result<(), String> {
        self.commit_config_replacement(cfg, true, || Ok(()), || Ok(()))
    }

    pub fn replace_config(&self, cfg: RuntimeConfig) {
        if let Err(err) = self.try_replace_config(cfg) {
            tracing::error!("failed to replace runtime config: {err}");
        }
    }

    pub fn try_replace_config_preserving_runtime(&self, cfg: RuntimeConfig) -> Result<(), String> {
        self.commit_config_replacement(cfg, false, || Ok(()), || Ok(()))
    }

    pub fn replace_config_preserving_runtime(&self, cfg: RuntimeConfig) {
        if let Err(err) = self.try_replace_config_preserving_runtime(cfg) {
            tracing::error!("failed to replace runtime config: {err}");
        }
    }

    pub(crate) fn try_replace_config_with_commit<R>(
        &self,
        cfg: RuntimeConfig,
        commit: impl FnOnce() -> Result<R, String>,
        rollback: impl FnOnce() -> Result<(), String>,
    ) -> Result<R, String> {
        self.commit_config_replacement(cfg, true, commit, rollback)
    }

    fn commit_config_replacement<R>(
        &self,
        cfg: RuntimeConfig,
        update_cascade_runtime: bool,
        commit: impl FnOnce() -> Result<R, String>,
        rollback: impl FnOnce() -> Result<(), String>,
    ) -> Result<R, String> {
        let mut rollback = Some(rollback);
        let current = self.with_cfg(|current| current.history.clone());
        if current == cfg.history {
            let result = commit().map_err(|err| rollback_after(err, &mut rollback))?;
            self.apply_runtime_config(cfg, update_cascade_runtime);
            return Ok(result);
        }
        let _transition = write_lock(&self.auth_store_transition, "auth store transition");
        let current_store = self.history_store();
        let auth_state = snapshot_runtime_auth_state(&current_store)
            .map_err(|err| format!("snapshot authentication state: {err}"))?;
        let result = commit().map_err(|err| rollback_after(err, &mut rollback))?;
        let store = HistoryStore::open(&cfg.history).map_err(|err| {
            rollback_after(
                format!("open replacement history store: {err}"),
                &mut rollback,
            )
        })?;
        store
            .import_runtime_auth_state(&auth_state)
            .map_err(|err| {
                rollback_after(
                    format!("copy authentication state to replacement history store: {err}"),
                    &mut rollback,
                )
            })?;
        let mut activity_cache =
            lock_mutex(&self.delivery_activity_cache, "delivery activity cache");
        *write_lock(&self.history, "history store") = Arc::new(store);
        self.history_generation.fetch_add(1, Ordering::SeqCst);
        activity_cache.clear();
        drop(activity_cache);
        self.apply_runtime_config(cfg, update_cascade_runtime);
        Ok(result)
    }

    fn apply_runtime_config(&self, cfg: RuntimeConfig, update_cascade_runtime: bool) {
        if update_cascade_runtime {
            self.cascade_runtime_enabled
                .store(cfg.cascade_default, Ordering::Relaxed);
        }
        let oidc_changed = replace_runtime_config(&self.config, cfg);
        self.mark_oidc_config_change(oidc_changed);
    }

    fn mark_oidc_config_change(&self, changed: bool) {
        if changed {
            self.oidc_config_generation.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub(crate) fn history_store(&self) -> Arc<HistoryStore> {
        read_lock(&self.history, "history store").clone()
    }

    pub(crate) fn with_auth_store<R>(&self, f: impl FnOnce(&HistoryStore) -> R) -> R {
        let _transition = read_lock(&self.auth_store_transition, "auth store transition");
        let store = self.history_store();
        f(&store)
    }

    pub fn with_config_write_lock<R>(&self, f: impl FnOnce() -> R) -> Result<R, String> {
        let _guard = lock_mutex(&self.config_write_lock, "config writes");
        if let Some(parent) = self.paths.config.parent() {
            fs::create_dir_all(parent).map_err(|err| format!("create config dir: {err}"))?;
        }
        let lock_path = tmp_path(&self.paths.config, "lock");
        let lock = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(&lock_path)
            .map_err(|err| format!("open {}: {err}", lock_path.display()))?;
        lock.lock_exclusive()
            .map_err(|err| format!("lock {}: {err}", lock_path.display()))?;
        let result = f();
        if let Err(err) = lock.unlock() {
            tracing::error!("unlock {} failed: {err}", lock_path.display());
        }
        Ok(result)
    }

    pub fn metric_inc(&self, name: &str, labels: &[(&str, &str)], by: i64) {
        let key = metric_key(name, labels);
        let mut counters = lock_mutex(&self.metrics.counters, "metrics counters");
        *counters.entry(key).or_insert(0) += by;
    }

    pub fn metric_set(&self, name: &str, labels: &[(&str, &str)], value: f64) {
        let key = metric_key(name, labels);
        lock_mutex(&self.metrics.gauges, "metrics gauges").insert(key, value);
    }
}

fn rollback_after<F>(error: String, rollback: &mut Option<F>) -> String
where
    F: FnOnce() -> Result<(), String>,
{
    let Some(rollback) = rollback.take() else {
        return error;
    };
    match rollback() {
        Ok(()) => error,
        Err(rollback_error) => format!("{error}; rollback failed: {rollback_error}"),
    }
}

fn replace_runtime_config(config: &RwLock<RuntimeConfig>, cfg: RuntimeConfig) -> bool {
    let mut current = write_lock(config, "config");
    let oidc_changed = current.auth.oidc != cfg.auth.oidc || current.public_url != cfg.public_url;
    *current = cfg;
    oidc_changed
}

fn prepare_runtime_dirs(paths: &Paths) -> Result<()> {
    fs::create_dir_all(&paths.backup_dir)
        .with_context(|| format!("create backup dir {}", paths.backup_dir.display()))?;
    Ok(())
}
