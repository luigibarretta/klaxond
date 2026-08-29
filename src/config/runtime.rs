use super::auth_sidecar::load_auth;
use super::dedup_config::load_dedup;
use super::ntfy_topics::load_ntfy_topics;
use super::readers::{
    read_delivery, read_emergency, read_history, read_inhibition_rules, read_schedules, read_tiers,
};
use super::render::{load_render_config, read_component_dashboards, read_component_image};
use super::{
    AuthConfig, DedupSetting, DeliveryConfig, EmergencyConfig, HistoryConfig, InhibitionRule,
    NtfyTopic, Paths, RuntimeConfig, Schedule, Tier, bootstrap_config, default_icons,
    default_priorities, default_tag_prefixes, default_tiers,
};
use crate::util::{env_bool, env_string, toml_bool, toml_get, toml_string};
use anyhow::Result;
use std::collections::HashMap;
use std::fs;

struct RenderRuntime {
    priorities: HashMap<String, String>,
    icons: HashMap<String, String>,
    tag_prefixes: HashMap<String, String>,
    fallback_runbooks: HashMap<String, String>,
    component_dashboards: HashMap<String, [String; 2]>,
    component_image: HashMap<String, (String, Option<u64>)>,
    grafana_base: String,
    grafana_render_base: String,
    grafana_render_token: String,
    render_image_ttl: u64,
}

struct RoutingRuntime {
    cascade_default: bool,
    tiers: Vec<Tier>,
    delivery: DeliveryConfig,
    inhibition_rules: Vec<InhibitionRule>,
    dedup: HashMap<String, DedupSetting>,
    auth: AuthConfig,
    schedules: Vec<Schedule>,
    history: HistoryConfig,
    emergency: EmergencyConfig,
}

struct ChannelRuntime {
    ntfy_url: String,
    ntfy_topics: Vec<NtfyTopic>,
    smtp_port: u16,
    smtp_starttls: bool,
    tg_token: String,
    telegram_api_base: String,
    smtp_user: String,
    smtp_pass: String,
}

struct ServerRuntime {
    port: u16,
    public_url: String,
    ack_default_ttl: u64,
}

pub fn load_runtime_config(paths: &Paths) -> Result<RuntimeConfig> {
    bootstrap_config(paths)?;
    let toml = read_toml(paths);
    let render = load_render(paths, &toml)?;
    let routing = load_routing(paths, &toml)?;
    let channels = load_channels(paths, &toml)?;
    let server = load_server(&toml);
    Ok(assemble(paths, toml, render, routing, channels, server).with_channels())
}

fn read_toml(paths: &Paths) -> toml::Value {
    let text = fs::read_to_string(&paths.config).unwrap_or_default();
    toml::from_str(&text).unwrap_or_else(|_| toml::Value::Table(toml::map::Map::new()))
}

fn load_render(paths: &Paths, toml: &toml::Value) -> Result<RenderRuntime> {
    let mut priorities = default_priorities();
    merge_string_map(
        &mut priorities,
        toml_get(toml, &["render", "severity_priority"]),
    );
    let mut icons = default_icons();
    merge_string_map(&mut icons, toml_get(toml, &["render", "severity_emoji"]));
    let mut tag_prefixes = default_tag_prefixes();
    merge_string_map(
        &mut tag_prefixes,
        toml_get(toml, &["render", "severity_tag_prefix"]),
    );
    let mut fallback_runbooks = HashMap::from([
        ("beszel".to_string(), String::new()),
        ("healthchecks".to_string(), String::new()),
    ]);
    merge_string_map(
        &mut fallback_runbooks,
        toml_get(toml, &["render", "fallback_runbooks"]),
    );
    let seed = read_component_dashboards(toml_get(toml, &["render", "component_dashboards"]));
    Ok(RenderRuntime {
        priorities,
        icons,
        tag_prefixes,
        fallback_runbooks,
        component_dashboards: load_render_config(paths, &seed)?,
        component_image: read_component_image(toml_get(toml, &["render", "component_image"])),
        grafana_base: nonempty_env_or_toml("GRAFANA_BASE", toml, &["render", "grafana_base"])
            .if_empty_else(|| "https://grafana.example.com".to_string())
            .trim_end_matches('/')
            .to_string(),
        grafana_render_base: nonempty_env_or_toml(
            "GRAFANA_RENDER_BASE",
            toml,
            &["render", "grafana_render_base"],
        )
        .trim_end_matches('/')
        .to_string(),
        grafana_render_token: nonempty_env_or_toml(
            "GRAFANA_RENDER_TOKEN",
            toml,
            &["render", "grafana_render_token"],
        ),
        render_image_ttl: env_or_positive_toml_u64(
            "RENDER_IMAGE_TTL",
            toml,
            &["render", "render_image_ttl"],
            900,
        ),
    })
}

fn load_routing(paths: &Paths, toml: &toml::Value) -> Result<RoutingRuntime> {
    let cascade_default = env_bool(
        "CASCADE_ENABLED",
        toml_bool(
            toml_get(toml, &["cascade", "default_enabled_for_webhook"]),
            false,
        ),
    );
    Ok(RoutingRuntime {
        cascade_default,
        tiers: read_tiers(toml_get(toml, &["cascade", "tiers"])).unwrap_or_else(default_tiers),
        delivery: read_delivery(toml),
        inhibition_rules: read_inhibition_rules(toml),
        dedup: load_dedup(paths, toml_get(toml, &["dedup"]))?,
        auth: load_auth(paths, toml_get(toml, &["auth"]))?,
        schedules: read_schedules(toml),
        history: read_history(toml, paths),
        emergency: read_emergency(toml)?,
    })
}

fn load_channels(paths: &Paths, toml: &toml::Value) -> Result<ChannelRuntime> {
    let smtp_port = std::env::var("SMTP_PORT")
        .ok()
        .and_then(|value| value.parse::<u16>().ok())
        .or_else(|| {
            toml_get(toml, &["smtp", "port"])
                .and_then(toml::Value::as_integer)
                .map(|value| value as u16)
        })
        .unwrap_or(587);
    Ok(ChannelRuntime {
        ntfy_url: nonempty_env_or_toml("NTFY_URL", toml, &["ntfy", "url"])
            .trim_end_matches('/')
            .to_string(),
        ntfy_topics: load_ntfy_topics(paths, toml)?,
        smtp_port,
        smtp_starttls: env_bool(
            "SMTP_STARTTLS",
            toml_bool(toml_get(toml, &["smtp", "starttls"]), true),
        ),
        tg_token: nonempty_env_or_toml("TELEGRAM_BOT_TOKEN", toml, &["telegram", "bot_token"]),
        telegram_api_base: nonempty_env_or_toml(
            "TELEGRAM_API_BASE",
            toml,
            &["telegram", "api_base"],
        )
        .trim_end_matches('/')
        .to_string()
        .if_empty_else(|| "https://api.telegram.org".to_string()),
        smtp_user: nonempty_env_or_toml("SMTP_USER", toml, &["smtp", "user"]),
        smtp_pass: nonempty_env_or_toml("SMTP_PASSWORD", toml, &["smtp", "password"]),
    })
}

fn load_server(toml: &toml::Value) -> ServerRuntime {
    let port = std::env::var("PORT")
        .ok()
        .and_then(|value| value.parse::<u16>().ok())
        .or_else(|| {
            toml_get(toml, &["server", "port"])
                .and_then(toml::Value::as_integer)
                .and_then(|value| u16::try_from(value).ok())
        })
        .unwrap_or(8181);
    let public_url = std::env::var("KLAXOND_PUBLIC_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| {
            toml_get(toml, &["server", "public_url"])
                .and_then(toml::Value::as_str)
                .map(ToOwned::to_owned)
        })
        .unwrap_or_else(|| "http://localhost:8181".to_string())
        .trim_end_matches('/')
        .to_string();
    ServerRuntime {
        port,
        public_url,
        ack_default_ttl: env_or_positive_toml_u64(
            "ACK_DEFAULT_TTL_SECONDS",
            toml,
            &["acks", "default_ttl_seconds"],
            3600,
        ),
    }
}

fn assemble(
    paths: &Paths,
    toml: toml::Value,
    render: RenderRuntime,
    routing: RoutingRuntime,
    channels: ChannelRuntime,
    server: ServerRuntime,
) -> RuntimeConfig {
    RuntimeConfig {
        toml,
        port: server.port,
        ntfy_url: channels.ntfy_url,
        ntfy_topics: channels.ntfy_topics,
        priorities: render.priorities,
        icons: render.icons,
        tag_prefixes: render.tag_prefixes,
        fallback_runbooks: render.fallback_runbooks,
        component_dashboards: render.component_dashboards,
        component_image: render.component_image,
        cascade_default: routing.cascade_default,
        tiers: routing.tiers,
        delivery: routing.delivery,
        inhibition_rules: routing.inhibition_rules,
        dedup: routing.dedup,
        auth: routing.auth,
        schedules: routing.schedules,
        history: routing.history,
        emergency: routing.emergency,
        tg_chat: String::new(),
        smtp_host: String::new(),
        smtp_port: channels.smtp_port,
        smtp_starttls: channels.smtp_starttls,
        smtp_from: String::new(),
        smtp_to: String::new(),
        tg_token: channels.tg_token,
        telegram_api_base: channels.telegram_api_base,
        smtp_user: channels.smtp_user,
        smtp_pass: channels.smtp_pass,
        grafana_base: render.grafana_base,
        grafana_render_base: render.grafana_render_base,
        grafana_render_token: render.grafana_render_token,
        render_image_ttl: render.render_image_ttl,
        public_url: server.public_url,
        ack_default_ttl: server.ack_default_ttl,
        beszel_db: paths.beszel_db.clone(),
    }
}

fn nonempty_env_or_toml(env: &str, toml: &toml::Value, path: &[&str]) -> String {
    env_string(env).if_empty_else(|| toml_string(toml_get(toml, path)))
}

fn env_or_positive_toml_u64(env: &str, toml: &toml::Value, path: &[&str], fallback: u64) -> u64 {
    std::env::var(env)
        .ok()
        .and_then(|value| value.parse().ok())
        .or_else(|| {
            toml_get(toml, path)
                .and_then(toml::Value::as_integer)
                .map(|value| value.max(1) as u64)
        })
        .unwrap_or(fallback)
}

trait EmptyExt {
    fn if_empty_else<F: FnOnce() -> String>(self, fallback: F) -> String;
}

impl EmptyExt for String {
    fn if_empty_else<F: FnOnce() -> String>(self, fallback: F) -> String {
        if self.is_empty() { fallback() } else { self }
    }
}

fn merge_string_map(target: &mut HashMap<String, String>, value: Option<&toml::Value>) {
    if let Some(table) = value.and_then(toml::Value::as_table) {
        for (key, value) in table {
            if let Some(value) = value.as_str() {
                target.insert(key.to_string(), value.to_string());
            }
        }
    }
}
