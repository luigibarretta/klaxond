use crate::util::{atomic_write, env_bool, env_string, toml_bool, toml_get, toml_string};
use anyhow::{Context, Result};
use std::collections::HashMap;
use std::fs;
#[cfg(test)]
use std::sync::Mutex;

mod auth_sidecar;
mod dedup_config;
mod defaults;
mod models;
mod ntfy_topics;
mod paths;
mod readers;
mod render;
mod sidecars;
#[cfg(test)]
mod tests;

pub use auth_sidecar::save_auth;
pub use dedup_config::save_dedup;
pub use defaults::{
    DEDUP_SOURCES, default_component_dashboards, default_dedup, default_icons,
    default_inhibition_rules, default_priorities, default_tag_prefixes, default_tiers,
};
pub use models::{
    AuthConfig, AuthStepUpConfig, AuthToken, BasicAuthConfig, DedupSetting, DeliveryConfig,
    DeliveryPolicy, DeliveryRule, HistoryConfig, InhibitionRule, LdapConfig, NtfyTopic, OidcConfig,
    PasskeyRecord, RuntimeConfig, Schedule, Tier, TotpRecord, TrustedProxyConfig, WebauthnConfig,
};
pub use ntfy_topics::save_ntfy_topics;
pub use paths::Paths;
pub use render::save_render_config;
pub use sidecars::restore_sidecars_from_toml;

use auth_sidecar::load_auth;
use dedup_config::load_dedup;
use ntfy_topics::load_ntfy_topics;
use readers::{read_delivery, read_history, read_inhibition_rules, read_schedules, read_tiers};
use render::{load_render_config, read_component_dashboards, read_component_image};
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

pub fn load_runtime_config(paths: &Paths) -> Result<RuntimeConfig> {
    bootstrap_config(paths)?;
    let toml_text = fs::read_to_string(&paths.config).unwrap_or_default();
    let toml: toml::Value =
        toml::from_str(&toml_text).unwrap_or_else(|_| toml::Value::Table(toml::map::Map::new()));

    let mut priorities = default_priorities();
    merge_string_map_toml(
        &mut priorities,
        toml_get(&toml, &["render", "severity_priority"]),
    );
    let mut icons = default_icons();
    merge_string_map_toml(&mut icons, toml_get(&toml, &["render", "severity_emoji"]));
    let mut tag_prefixes = default_tag_prefixes();
    merge_string_map_toml(
        &mut tag_prefixes,
        toml_get(&toml, &["render", "severity_tag_prefix"]),
    );

    let mut fallback_runbooks = HashMap::from([
        ("beszel".to_string(), String::new()),
        ("healthchecks".to_string(), String::new()),
    ]);
    merge_string_map_toml(
        &mut fallback_runbooks,
        toml_get(&toml, &["render", "fallback_runbooks"]),
    );

    let render_seed =
        read_component_dashboards(toml_get(&toml, &["render", "component_dashboards"]));
    let component_dashboards = load_render_config(paths, &render_seed)?;

    let component_image = read_component_image(toml_get(&toml, &["render", "component_image"]));
    let grafana_base = std::env::var("GRAFANA_BASE")
        .ok()
        .filter(|s| !s.is_empty())
        .or_else(|| {
            toml_get(&toml, &["render", "grafana_base"])
                .and_then(|v| v.as_str())
                .map(ToOwned::to_owned)
        })
        .unwrap_or_else(|| "https://grafana.example.com".to_string())
        .trim_end_matches('/')
        .to_string();

    let cascade_default_toml = toml_bool(
        toml_get(&toml, &["cascade", "default_enabled_for_webhook"]),
        false,
    );
    let cascade_default = env_bool("CASCADE_ENABLED", cascade_default_toml);
    let tiers = read_tiers(toml_get(&toml, &["cascade", "tiers"])).unwrap_or_else(default_tiers);

    let delivery = read_delivery(&toml);
    let inhibition_rules = read_inhibition_rules(&toml);
    let dedup = load_dedup(paths, toml_get(&toml, &["dedup"]))?;
    let auth = load_auth(paths, toml_get(&toml, &["auth"]))?;
    let schedules = read_schedules(&toml);
    let history = read_history(&toml, paths);
    let ntfy_url = env_string("NTFY_URL")
        .trim_end_matches('/')
        .to_string()
        .if_empty_else(|| {
            toml_string(toml_get(&toml, &["ntfy", "url"]))
                .trim_end_matches('/')
                .to_string()
        });
    let ntfy_topics = load_ntfy_topics(paths, &toml)?;

    let smtp_port = std::env::var("SMTP_PORT")
        .ok()
        .and_then(|v| v.parse::<u16>().ok())
        .or_else(|| {
            toml_get(&toml, &["smtp", "port"])
                .and_then(|v| v.as_integer())
                .map(|v| v as u16)
        })
        .unwrap_or(587);
    let smtp_starttls_toml = toml_bool(toml_get(&toml, &["smtp", "starttls"]), true);
    let smtp_starttls = env_bool("SMTP_STARTTLS", smtp_starttls_toml);
    let smtp_user =
        env_string("SMTP_USER").if_empty_else(|| toml_string(toml_get(&toml, &["smtp", "user"])));
    let smtp_pass = env_string("SMTP_PASSWORD")
        .if_empty_else(|| toml_string(toml_get(&toml, &["smtp", "password"])));
    let tg_token = env_string("TELEGRAM_BOT_TOKEN")
        .if_empty_else(|| toml_string(toml_get(&toml, &["telegram", "bot_token"])));
    let telegram_api_base = env_string("TELEGRAM_API_BASE")
        .if_empty_else(|| toml_string(toml_get(&toml, &["telegram", "api_base"])))
        .trim_end_matches('/')
        .to_string()
        .if_empty_else(|| "https://api.telegram.org".to_string());
    let grafana_render_base = env_string("GRAFANA_RENDER_BASE")
        .if_empty_else(|| toml_string(toml_get(&toml, &["render", "grafana_render_base"])))
        .trim_end_matches('/')
        .to_string();
    let grafana_render_token = env_string("GRAFANA_RENDER_TOKEN")
        .if_empty_else(|| toml_string(toml_get(&toml, &["render", "grafana_render_token"])));
    let render_image_ttl = std::env::var("RENDER_IMAGE_TTL")
        .ok()
        .and_then(|v| v.parse().ok())
        .or_else(|| {
            toml_get(&toml, &["render", "render_image_ttl"])
                .and_then(|v| v.as_integer())
                .map(|v| v.max(1) as u64)
        })
        .unwrap_or(900);
    let public_url = std::env::var("KLAXOND_PUBLIC_URL")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .or_else(|| {
            toml_get(&toml, &["server", "public_url"])
                .and_then(|v| v.as_str())
                .map(ToOwned::to_owned)
        })
        .unwrap_or_else(|| "http://localhost:8181".to_string())
        .trim_end_matches('/')
        .to_string();
    let ack_default_ttl = std::env::var("ACK_DEFAULT_TTL_SECONDS")
        .ok()
        .and_then(|v| v.parse().ok())
        .or_else(|| {
            toml_get(&toml, &["acks", "default_ttl_seconds"])
                .and_then(|v| v.as_integer())
                .map(|v| v.max(1) as u64)
        })
        .unwrap_or(3600);
    let port = std::env::var("PORT")
        .ok()
        .and_then(|v| v.parse::<u16>().ok())
        .or_else(|| {
            toml_get(&toml, &["server", "port"])
                .and_then(|v| v.as_integer())
                .and_then(|v| u16::try_from(v).ok())
        })
        .unwrap_or(8181);
    Ok(RuntimeConfig {
        toml,
        port,
        ntfy_url,
        ntfy_topics,
        priorities,
        icons,
        tag_prefixes,
        fallback_runbooks,
        component_dashboards,
        component_image,
        cascade_default,
        tiers,
        delivery,
        inhibition_rules,
        dedup,
        auth,
        schedules,
        history,
        tg_chat: String::new(),
        smtp_host: String::new(),
        smtp_port,
        smtp_starttls,
        smtp_from: String::new(),
        smtp_to: String::new(),
        tg_token,
        telegram_api_base,
        smtp_user,
        smtp_pass,
        grafana_base,
        grafana_render_base,
        grafana_render_token,
        render_image_ttl,
        public_url,
        ack_default_ttl,
        beszel_db: paths.beszel_db.clone(),
    }
    .with_channels())
}

trait EmptyExt {
    fn if_empty_else<F: FnOnce() -> String>(self, f: F) -> String;
}

impl EmptyExt for String {
    fn if_empty_else<F: FnOnce() -> String>(self, f: F) -> String {
        if self.is_empty() { f() } else { self }
    }
}

fn merge_string_map_toml(target: &mut HashMap<String, String>, value: Option<&toml::Value>) {
    if let Some(table) = value.and_then(|v| v.as_table()) {
        for (k, v) in table {
            if let Some(s) = v.as_str() {
                target.insert(k.to_string(), s.to_string());
            }
        }
    }
}

pub fn save_toml(paths: &Paths, cfg: &toml::Value) -> Result<()> {
    let text = toml::to_string_pretty(cfg)?;
    atomic_write(&paths.config, text.as_bytes())
}
