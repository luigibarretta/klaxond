use crate::util::atomic_write;
use anyhow::{Context, Result};
use std::fs;
#[cfg(test)]
use std::sync::Mutex;

mod auth_sidecar;
mod dedup_config;
mod defaults;
mod models;
mod ntfy_topics;
mod paths;
mod preflight;
mod readers;
mod render;
mod runtime;
mod sidecars;
#[cfg(test)]
mod tests;

pub use auth_sidecar::save_auth;
pub use dedup_config::save_dedup;
pub use defaults::{
    DEDUP_SOURCES, INGEST_SOURCES, NTFY_RECOMMENDED_TIMEOUT_SECONDS, TIER_TIMEOUT_MAX_SECONDS,
    TIER_TIMEOUT_MIN_SECONDS, default_component_dashboards, default_dedup, default_icons,
    default_inhibition_rules, default_priorities, default_tag_prefixes, default_tiers,
    recommended_tier_timeout,
};
pub use models::{
    AuthConfig, AuthStepUpConfig, AuthToken, BasicAuthConfig, DedupSetting, DeliveryConfig,
    DeliveryPolicy, DeliveryRule, EmergencyConfig, HistoryConfig, InhibitionRule, LdapConfig,
    NoiseControlRule, NoiseMatchField, NoiseMatchOperator, NoiseRuleAction, NtfyTopic, OidcConfig,
    PasskeyRecord, RuntimeConfig, Schedule, Tier, TotpRecord, TrustedProxyConfig, WebauthnConfig,
};
pub use ntfy_topics::save_ntfy_topics;
pub use paths::Paths;
pub use preflight::validate_runtime_config;
pub use render::save_render_config;
pub use runtime::load_runtime_config;
pub use sidecars::restore_sidecars_from_toml;
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const AUTHOR_NAME: &str = "Luigi Barretta";
pub const AUTHOR_URL: &str = "https://github.com/luigibarretta";
#[cfg(test)]
pub(crate) static TEST_ENV_LOCK: Mutex<()> = Mutex::new(());
pub fn bootstrap_config(paths: &Paths) -> Result<()> {
    if paths.config.exists() {
        return Ok(());
    }
    if let Some(parent) = paths.config.parent() {
        fs::create_dir_all(parent).ok();
    }
    if paths.default_config.exists() {
        fs::copy(&paths.default_config, &paths.config).with_context(|| {
            format!(
                "bootstrap {} from {}",
                paths.config.display(),
                paths.default_config.display()
            )
        })?;
    }
    Ok(())
}

pub fn save_toml(paths: &Paths, cfg: &toml::Value) -> Result<()> {
    let text = toml::to_string_pretty(cfg)?;
    atomic_write(&paths.config, text.as_bytes())
}
