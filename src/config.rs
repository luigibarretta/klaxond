use crate::util::{
    atomic_write, atomic_write_json, env_bool, env_string, toml_bool, toml_get, toml_string,
};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use webauthn_rs::prelude::Passkey;

pub const VERSION: &str = "0.14.10";
pub const AUTHOR_NAME: &str = "Luigi Barretta";
pub const AUTHOR_URL: &str = "https://github.com/luigibarretta";
pub const DEDUP_SOURCES: &[&str] = &[
    "grafana",
    "beszel",
    "healthchecks",
    "wud",
    "authentik",
    "shelfmark",
    "prowlarr",
    "decypharr",
];
#[derive(Clone, Debug)]
pub struct Paths {
    pub config: PathBuf,
    pub default_config: PathBuf,
    pub render_config: PathBuf,
    pub ntfy_topics: PathBuf,
    pub dedup_config: PathBuf,
    pub dedup_pending_dir: PathBuf,
    pub auth_config: PathBuf,
    pub auth_session_key: PathBuf,
    pub backup_dir: PathBuf,
    pub static_dir: PathBuf,
    pub beszel_db: PathBuf,
}

impl Paths {
    pub fn from_env() -> Self {
        let default_config = if Path::new("/app/klaxond.default.toml").exists() {
            PathBuf::from("/app/klaxond.default.toml")
        } else {
            PathBuf::from("klaxond.default.toml")
        };
        let static_dir = if Path::new("/app/static").is_dir() {
            PathBuf::from("/app/static")
        } else {
            PathBuf::from("static")
        };
        Self {
            config: PathBuf::from(
                std::env::var("KLAXOND_CONFIG").unwrap_or_else(|_| "/data/klaxond.toml".into()),
            ),
            default_config,
            render_config: PathBuf::from(
                std::env::var("RENDER_CONFIG_PATH")
                    .unwrap_or_else(|_| "/data/render-config.json".into()),
            ),
            ntfy_topics: PathBuf::from(
                std::env::var("NTFY_TOPICS_PATH")
                    .unwrap_or_else(|_| "/data/ntfy-topics.json".into()),
            ),
            dedup_config: PathBuf::from(
                std::env::var("DEDUP_CONFIG_PATH")
                    .unwrap_or_else(|_| "/data/dedup-config.json".into()),
            ),
            dedup_pending_dir: PathBuf::from(
                std::env::var("DEDUP_PENDING_DIR").unwrap_or_else(|_| "/data/dedup_pending".into()),
            ),
            auth_config: PathBuf::from(
                std::env::var("AUTH_CONFIG_PATH")
                    .unwrap_or_else(|_| "/data/auth-config.json".into()),
            ),
            auth_session_key: PathBuf::from(
                std::env::var("AUTH_SESSION_KEY_PATH")
                    .unwrap_or_else(|_| "/data/auth-session.key".into()),
            ),
            backup_dir: PathBuf::from(
                std::env::var("KLAXOND_BACKUP_DIR").unwrap_or_else(|_| "/data/backups".into()),
            ),
            static_dir,
            beszel_db: PathBuf::from(
                std::env::var("BESZEL_DB_PATH").unwrap_or_else(|_| "/beszel_data/data.db".into()),
            ),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct NtfyTopic {
    pub name: String,
    #[serde(default)]
    pub token: String,
    #[serde(default)]
    pub handles: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Tier {
    pub name: String,
    #[serde(default = "default_timeout")]
    pub timeout_seconds: u64,
}

fn default_timeout() -> u64 {
    5
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DeliveryPolicy {
    pub name: String,
    #[serde(default = "cascade_mode")]
    pub mode: String,
    #[serde(default)]
    pub tiers: Vec<Tier>,
}

fn cascade_mode() -> String {
    "cascade".to_string()
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DeliveryRule {
    #[serde(default)]
    pub r#match: HashMap<String, String>,
    pub policy: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DeliveryConfig {
    pub default_policy: String,
    pub policies: Vec<DeliveryPolicy>,
    pub rules: Vec<DeliveryRule>,
}

impl Default for DeliveryConfig {
    fn default() -> Self {
        Self {
            default_policy: "cascade".to_string(),
            policies: Vec::new(),
            rules: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InhibitionRule {
    pub source: String,
    #[serde(default)]
    pub match_by: Option<String>,
    #[serde(default)]
    pub match_label: Option<String>,
    #[serde(default)]
    pub match_regex: Option<String>,
    #[serde(default)]
    pub match_all: bool,
    #[serde(default)]
    pub applies_to: Vec<String>,
    #[serde(default = "default_ttl")]
    pub ttl_seconds: u64,
}

fn default_ttl() -> u64 {
    900
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DedupSetting {
    pub enabled: bool,
    pub window_s: u64,
    pub strategy: String,
    pub override_critical: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthConfig {
    pub mode: String,
    pub session_timeout_hours: u64,
    pub basic: BasicAuthConfig,
    pub oidc: OidcConfig,
    pub trusted_proxy: TrustedProxyConfig,
    #[serde(default)]
    pub webauthn: WebauthnConfig,
    #[serde(default)]
    pub api_keys: Vec<AuthToken>,
    #[serde(default)]
    pub passkeys: Vec<PasskeyRecord>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BasicAuthConfig {
    pub username: String,
    pub password_hash: String,
    pub realm: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OidcConfig {
    pub provider: String,
    pub issuer: String,
    pub client_id: String,
    pub client_secret: String,
    pub scopes: String,
    pub required_group: String,
    pub redirect_path: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TrustedProxyConfig {
    pub user_header: String,
    pub email_header: String,
    pub groups_header: String,
    pub trusted_cidrs: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WebauthnConfig {
    pub enabled: bool,
    pub rp_id: String,
    pub origin: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthToken {
    pub id: String,
    pub name: String,
    pub kind: String,
    pub prefix: String,
    pub token_hash: String,
    pub scopes: Vec<String>,
    pub created_at: i64,
    #[serde(default)]
    pub expires_at: Option<i64>,
    #[serde(default)]
    pub last_used_at: Option<i64>,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PasskeyRecord {
    pub id: String,
    pub name: String,
    pub user_sub: String,
    pub user_name: String,
    pub user_email: String,
    pub user_uuid: String,
    pub created_at: i64,
    #[serde(default)]
    pub last_used_at: Option<i64>,
    pub credential: Passkey,
}

impl Default for WebauthnConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            rp_id: String::new(),
            origin: String::new(),
        }
    }
}

fn default_true() -> bool {
    true
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            mode: "none".to_string(),
            session_timeout_hours: 8,
            basic: BasicAuthConfig {
                username: String::new(),
                password_hash: String::new(),
                realm: "klaxond".to_string(),
            },
            oidc: OidcConfig {
                provider: "authentik".to_string(),
                issuer: String::new(),
                client_id: String::new(),
                client_secret: String::new(),
                scopes: "openid profile email".to_string(),
                required_group: String::new(),
                redirect_path: "/auth/callback".to_string(),
            },
            trusted_proxy: TrustedProxyConfig {
                user_header: "X-Forwarded-User".to_string(),
                email_header: "X-Forwarded-Email".to_string(),
                groups_header: "X-Forwarded-Groups".to_string(),
                trusted_cidrs: vec![
                    "127.0.0.1/32".to_string(),
                    "192.168.0.0/16".to_string(),
                    "10.0.0.0/8".to_string(),
                    "172.16.0.0/12".to_string(),
                ],
            },
            webauthn: WebauthnConfig::default(),
            api_keys: Vec::new(),
            passkeys: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Schedule {
    pub name: String,
    pub cron: String,
    pub duration_minutes: u64,
    #[serde(default)]
    pub r#match: HashMap<String, String>,
    #[serde(default)]
    pub applies_to: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct RuntimeConfig {
    pub toml: toml::Value,
    pub ntfy_url: String,
    pub ntfy_topics: Vec<NtfyTopic>,
    pub priorities: HashMap<String, String>,
    pub icons: HashMap<String, String>,
    pub tag_prefixes: HashMap<String, String>,
    pub fallback_runbooks: HashMap<String, String>,
    pub component_dashboards: HashMap<String, [String; 2]>,
    pub component_image: HashMap<String, (String, Option<u64>)>,
    pub cascade_default: bool,
    pub tiers: Vec<Tier>,
    pub delivery: DeliveryConfig,
    pub inhibition_rules: Vec<InhibitionRule>,
    pub dedup: HashMap<String, DedupSetting>,
    pub auth: AuthConfig,
    pub schedules: Vec<Schedule>,
    pub tg_chat: String,
    pub smtp_host: String,
    pub smtp_port: u16,
    pub smtp_starttls: bool,
    pub smtp_from: String,
    pub smtp_to: String,
    pub tg_token: String,
    pub telegram_api_base: String,
    pub smtp_user: String,
    pub smtp_pass: String,
    pub grafana_base: String,
    pub grafana_render_base: String,
    pub grafana_render_token: String,
    pub render_image_ttl: u64,
    pub public_url: String,
    pub ack_default_ttl: u64,
    pub beszel_db: PathBuf,
}

pub fn default_tiers() -> Vec<Tier> {
    vec![
        Tier {
            name: "ntfy".into(),
            timeout_seconds: 5,
        },
        Tier {
            name: "telegram".into(),
            timeout_seconds: 8,
        },
        Tier {
            name: "smtp".into(),
            timeout_seconds: 10,
        },
    ]
}

pub fn default_priorities() -> HashMap<String, String> {
    [
        ("info", "default"),
        ("warning", "high"),
        ("critical", "urgent"),
        ("resolved", "low"),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .collect()
}

pub fn default_icons() -> HashMap<String, String> {
    [
        ("info", "ℹ️"),
        ("warning", "⚠️"),
        ("critical", "🚨"),
        ("resolved", "✅"),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .collect()
}

pub fn default_tag_prefixes() -> HashMap<String, String> {
    [
        ("info", "information_source"),
        ("warning", "warning"),
        ("critical", "rotating_light"),
        ("resolved", "white_check_mark"),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .collect()
}

pub fn default_component_dashboards() -> HashMap<String, [String; 2]> {
    [
        ("host", ["Logs", "/d/your-logs-dashboard"]),
        ("traefik", ["Traefik", "/d/your-traefik-dashboard"]),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), [v[0].to_string(), v[1].to_string()]))
    .collect()
}

pub fn default_dedup() -> HashMap<String, DedupSetting> {
    [
        ("grafana", false, 90, "key", false),
        ("beszel", false, 90, "key", false),
        ("healthchecks", false, 90, "key", false),
        ("wud", true, 90, "key", false),
        ("authentik", false, 60, "key", false),
        ("shelfmark", true, 120, "key", false),
        ("prowlarr", true, 90, "key", false),
        ("decypharr", true, 60, "key", false),
    ]
    .into_iter()
    .map(|(src, enabled, window_s, strategy, override_critical)| {
        (
            src.to_string(),
            DedupSetting {
                enabled,
                window_s,
                strategy: strategy.to_string(),
                override_critical,
            },
        )
    })
    .collect()
}

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
    let mut component_dashboards = load_render_config(paths, &render_seed)?;
    if !render_seed.is_empty() {
        component_dashboards = render_seed;
    }

    let component_image = read_component_image(toml_get(&toml, &["render", "component_image"]));
    let grafana_base = std::env::var("GRAFANA_BASE")
        .ok()
        .filter(|s| !s.is_empty())
        .or_else(|| {
            toml_get(&toml, &["render", "grafana_base"])
                .and_then(|v| v.as_str())
                .map(ToOwned::to_owned)
        })
        .unwrap_or_else(|| "https://grafana.example.com".to_string());

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
    let smtp_user = env_string("SMTP_USER");
    Ok(RuntimeConfig {
        toml,
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
        tg_chat: String::new(),
        smtp_host: String::new(),
        smtp_port,
        smtp_starttls: true,
        smtp_from: String::new(),
        smtp_to: String::new(),
        tg_token: env_string("TELEGRAM_BOT_TOKEN"),
        telegram_api_base: env_string("TELEGRAM_API_BASE")
            .trim_end_matches('/')
            .to_string()
            .if_empty_else(|| "https://api.telegram.org".to_string()),
        smtp_user,
        smtp_pass: env_string("SMTP_PASSWORD"),
        grafana_base,
        grafana_render_base: env_string("GRAFANA_RENDER_BASE")
            .trim_end_matches('/')
            .to_string(),
        grafana_render_token: env_string("GRAFANA_RENDER_TOKEN"),
        render_image_ttl: std::env::var("RENDER_IMAGE_TTL")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(900),
        public_url: std::env::var("KLAXOND_PUBLIC_URL")
            .unwrap_or_else(|_| "http://localhost:8181".to_string()),
        ack_default_ttl: std::env::var("ACK_DEFAULT_TTL_SECONDS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(3600),
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

impl RuntimeConfig {
    fn with_channels(mut self) -> Self {
        let toml = self.toml.clone();
        self.tg_chat = env_string("TELEGRAM_CHAT_ID")
            .if_empty_else(|| toml_string(toml_get(&toml, &["telegram", "chat_id"])));
        self.smtp_host = env_string("SMTP_HOST")
            .if_empty_else(|| toml_string(toml_get(&toml, &["smtp", "host"])));
        self.smtp_from = env_string("SMTP_FROM")
            .if_empty_else(|| toml_string(toml_get(&toml, &["smtp", "from_addr"])))
            .if_empty_else(|| self.smtp_user.clone());
        self.smtp_to = env_string("SMTP_TO")
            .if_empty_else(|| toml_string(toml_get(&toml, &["smtp", "to_addr"])));
        self
    }

    pub fn known_severities(&self) -> Vec<String> {
        let mut out: Vec<String> = self
            .ntfy_topics
            .iter()
            .flat_map(|t| t.handles.iter().cloned())
            .collect();
        out.push("resolved".to_string());
        out.sort();
        out.dedup();
        out
    }

    pub fn handles_severity(&self, severity: &str) -> bool {
        severity == "resolved"
            || self
                .ntfy_topics
                .iter()
                .any(|t| t.handles.iter().any(|h| h == severity))
    }

    pub fn topics_for(&self, severity: &str) -> Vec<NtfyTopic> {
        self.ntfy_topics
            .iter()
            .filter(|t| t.handles.iter().any(|h| h == severity))
            .cloned()
            .collect()
    }

    pub fn icon(&self, severity: &str) -> String {
        self.icons
            .get(severity)
            .or_else(|| self.icons.get("info"))
            .cloned()
            .unwrap_or_else(|| "ℹ️".to_string())
    }

    pub fn tag_prefix(&self, severity: &str) -> String {
        self.tag_prefixes
            .get(severity)
            .cloned()
            .unwrap_or_else(|| "bell".to_string())
    }

    pub fn priority(&self, severity: &str) -> String {
        self.priorities
            .get(severity)
            .cloned()
            .unwrap_or_else(|| "default".to_string())
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

fn read_component_dashboards(value: Option<&toml::Value>) -> HashMap<String, [String; 2]> {
    let mut out = HashMap::new();
    if let Some(table) = value.and_then(|v| v.as_table()) {
        for (k, v) in table {
            if let Some(arr) = v.as_array() {
                let label = arr
                    .first()
                    .and_then(|x| x.as_str())
                    .unwrap_or("")
                    .to_string();
                let url = arr
                    .get(1)
                    .and_then(|x| x.as_str())
                    .unwrap_or("")
                    .to_string();
                if !label.is_empty() && !url.is_empty() {
                    out.insert(k.to_string(), [label, url]);
                }
            }
        }
    }
    out
}

fn read_component_image(value: Option<&toml::Value>) -> HashMap<String, (String, Option<u64>)> {
    let mut out = HashMap::new();
    if let Some(table) = value.and_then(|v| v.as_table()) {
        for (comp, spec) in table {
            let s = spec.as_str().unwrap_or("").trim();
            if s.is_empty() {
                continue;
            }
            if let Some((uid, panel)) = s.rsplit_once(':')
                && !uid.is_empty()
            {
                out.insert(
                    comp.to_string(),
                    (uid.to_string(), panel.parse::<u64>().ok()),
                );
                continue;
            }
            out.insert(comp.to_string(), (s.to_string(), None));
        }
    }
    out
}

fn load_render_config(
    paths: &Paths,
    seed: &HashMap<String, [String; 2]>,
) -> Result<HashMap<String, [String; 2]>> {
    if paths.render_config.exists() {
        let raw: serde_json::Value = serde_json::from_slice(&fs::read(&paths.render_config)?)?;
        let mut out = HashMap::new();
        if let Some(obj) = raw.get("component_dashboards").and_then(|v| v.as_object()) {
            for (k, v) in obj {
                if let Some(arr) = v.as_array() {
                    let label = arr
                        .first()
                        .and_then(|x| x.as_str())
                        .unwrap_or("")
                        .to_string();
                    let url = arr
                        .get(1)
                        .and_then(|x| x.as_str())
                        .unwrap_or("")
                        .to_string();
                    if !label.is_empty() && !url.is_empty() {
                        out.insert(k.to_string(), [label, url]);
                    }
                }
            }
        }
        return Ok(out);
    }
    let initial = if seed.is_empty() {
        default_component_dashboards()
    } else {
        seed.clone()
    };
    save_render_config(paths, &initial)?;
    Ok(initial)
}

pub fn save_render_config(paths: &Paths, dashboards: &HashMap<String, [String; 2]>) -> Result<()> {
    atomic_write_json(
        &paths.render_config,
        &json!({ "component_dashboards": dashboards }),
    )
}

fn read_tiers(value: Option<&toml::Value>) -> Option<Vec<Tier>> {
    let arr = value?.as_array()?;
    let mut tiers = Vec::new();
    for item in arr {
        let name = item
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        if name.is_empty() {
            continue;
        }
        tiers.push(Tier {
            name,
            timeout_seconds: item
                .get("timeout_seconds")
                .and_then(|v| v.as_integer())
                .unwrap_or(5)
                .max(1) as u64,
        });
    }
    if tiers.is_empty() { None } else { Some(tiers) }
}

fn read_delivery(toml: &toml::Value) -> DeliveryConfig {
    let Some(delivery) = toml_get(toml, &["delivery"]) else {
        return DeliveryConfig::default();
    };
    let default_policy = delivery
        .get("default_policy")
        .and_then(|v| v.as_str())
        .unwrap_or("cascade")
        .to_string();
    let policies = delivery
        .get("policies")
        .and_then(|v| v.as_array())
        .unwrap_or(&Vec::new())
        .iter()
        .filter_map(|p| {
            let name = p.get("name")?.as_str()?.to_string();
            let mode = p
                .get("mode")
                .and_then(|v| v.as_str())
                .unwrap_or("cascade")
                .to_string();
            let tiers = read_tiers(p.get("tiers")).unwrap_or_default();
            Some(DeliveryPolicy { name, mode, tiers })
        })
        .collect();
    let rules = delivery
        .get("rules")
        .and_then(|v| v.as_array())
        .unwrap_or(&Vec::new())
        .iter()
        .filter_map(|r| {
            let policy = r.get("policy")?.as_str()?.to_string();
            let mut m = HashMap::new();
            if let Some(t) = r.get("match").and_then(|v| v.as_table()) {
                for (k, v) in t {
                    if let Some(s) = v.as_str() {
                        m.insert(k.to_string(), s.to_string());
                    }
                }
            }
            Some(DeliveryRule { r#match: m, policy })
        })
        .collect();
    DeliveryConfig {
        default_policy,
        policies,
        rules,
    }
}

fn read_inhibition_rules(toml: &toml::Value) -> Vec<InhibitionRule> {
    let Some(arr) = toml.get("inhibitions").and_then(|v| v.as_array()) else {
        return default_inhibition_rules();
    };
    let mut out = Vec::new();
    for r in arr {
        let source = r
            .get("source")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        if source.is_empty() {
            continue;
        }
        out.push(InhibitionRule {
            source,
            match_by: r
                .get("match_by")
                .and_then(|v| v.as_str())
                .map(ToOwned::to_owned),
            match_label: r
                .get("match_label")
                .and_then(|v| v.as_str())
                .map(ToOwned::to_owned),
            match_regex: r
                .get("match_regex")
                .and_then(|v| v.as_str())
                .map(ToOwned::to_owned),
            match_all: r
                .get("match_all")
                .and_then(|v| v.as_bool())
                .unwrap_or(false),
            applies_to: r
                .get("applies_to")
                .and_then(|v| v.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|x| x.as_str().map(ToOwned::to_owned))
                        .collect()
                })
                .unwrap_or_default(),
            ttl_seconds: r
                .get("ttl_seconds")
                .and_then(|v| v.as_integer())
                .unwrap_or(900)
                .max(1) as u64,
        });
    }
    if out.is_empty() {
        default_inhibition_rules()
    } else {
        out
    }
}

pub fn default_inhibition_rules() -> Vec<InhibitionRule> {
    vec![
        InhibitionRule {
            source: "node-down".into(),
            match_by: Some("host".into()),
            match_label: None,
            match_regex: None,
            match_all: false,
            applies_to: vec![],
            ttl_seconds: 900,
        },
        InhibitionRule {
            source: "traefik-down".into(),
            match_by: None,
            match_label: Some("job".into()),
            match_regex: Some("^blackbox-(https|http).*".into()),
            match_all: false,
            applies_to: vec!["grafana".into()],
            ttl_seconds: 900,
        },
        InhibitionRule {
            source: "authentik-down".into(),
            match_by: None,
            match_label: Some("job".into()),
            match_regex: Some("^blackbox-https.*".into()),
            match_all: false,
            applies_to: vec!["grafana".into()],
            ttl_seconds: 900,
        },
        InhibitionRule {
            source: "cluster-wide-restart".into(),
            match_by: None,
            match_label: None,
            match_regex: None,
            match_all: true,
            applies_to: vec![],
            ttl_seconds: 1800,
        },
    ]
}

fn load_dedup(paths: &Paths, seed: Option<&toml::Value>) -> Result<HashMap<String, DedupSetting>> {
    if paths.dedup_config.exists() {
        let mut out = default_dedup();
        let raw: HashMap<String, DedupSetting> =
            serde_json::from_slice(&fs::read(&paths.dedup_config)?)?;
        for (k, v) in raw {
            out.insert(k, v);
        }
        return Ok(out);
    }
    let out = dedup_from_toml(seed);
    save_dedup(paths, &out)?;
    Ok(out)
}

fn dedup_from_toml(seed: Option<&toml::Value>) -> HashMap<String, DedupSetting> {
    let mut out = default_dedup();
    if let Some(seed_table) = seed.and_then(|v| v.as_table()) {
        for src in DEDUP_SOURCES {
            if let Some(t) = seed_table.get(*src).and_then(|v| v.as_table())
                && let Some(s) = out.get_mut(*src)
            {
                if let Some(v) = t.get("enabled").and_then(|v| v.as_bool()) {
                    s.enabled = v;
                }
                if let Some(v) = t.get("window_s").and_then(|v| v.as_integer()) {
                    s.window_s = v.max(1) as u64;
                }
                if let Some(v) = t.get("strategy").and_then(|v| v.as_str()) {
                    s.strategy = v.to_string();
                }
                if let Some(v) = t.get("override_critical").and_then(|v| v.as_bool()) {
                    s.override_critical = v;
                }
            }
        }
    }
    out
}

pub fn save_dedup(paths: &Paths, settings: &HashMap<String, DedupSetting>) -> Result<()> {
    atomic_write_json(&paths.dedup_config, settings)
}

fn load_auth(paths: &Paths, seed: Option<&toml::Value>) -> Result<AuthConfig> {
    let mut out = AuthConfig::default();
    if paths.auth_config.exists() {
        let raw: AuthConfig = serde_json::from_slice(&fs::read(&paths.auth_config)?)?;
        out = merge_auth(out, raw);
    } else {
        if let Some(seed) = seed {
            out = merge_auth_toml(out, seed);
        }
        if let Ok(sec) = std::env::var("AUTH_OIDC_CLIENT_SECRET")
            && !sec.is_empty()
        {
            out.oidc.client_secret = sec;
        }
        if let Ok(hash) = std::env::var("AUTH_BASIC_PASSWORD_HASH")
            && !hash.is_empty()
        {
            out.basic.password_hash = hash;
        }
        save_auth(paths, &out)?;
    }
    Ok(out)
}

pub fn save_auth(paths: &Paths, auth: &AuthConfig) -> Result<()> {
    atomic_write_json(&paths.auth_config, auth)
}

fn merge_auth(mut base: AuthConfig, raw: AuthConfig) -> AuthConfig {
    base.mode = raw.mode;
    base.session_timeout_hours = raw.session_timeout_hours;
    base.basic = raw.basic;
    base.oidc = raw.oidc;
    base.trusted_proxy = raw.trusted_proxy;
    base.webauthn = raw.webauthn;
    base.api_keys = raw.api_keys;
    base.passkeys = raw.passkeys;
    base
}

fn merge_auth_toml(mut base: AuthConfig, seed: &toml::Value) -> AuthConfig {
    if let Some(mode) = seed.get("mode").and_then(|v| v.as_str()) {
        base.mode = mode.to_string();
    }
    if let Some(h) = seed
        .get("session_timeout_hours")
        .and_then(|v| v.as_integer())
    {
        base.session_timeout_hours = h.max(1) as u64;
    }
    for (section, setter) in [
        ("basic", 0_usize),
        ("oidc", 1_usize),
        ("trusted_proxy", 2_usize),
    ] {
        let Some(t) = seed.get(section).and_then(|v| v.as_table()) else {
            continue;
        };
        match setter {
            0 => {
                if let Some(v) = t.get("username").and_then(|v| v.as_str()) {
                    base.basic.username = v.to_string();
                }
                if let Some(v) = t.get("password_hash").and_then(|v| v.as_str()) {
                    base.basic.password_hash = v.to_string();
                }
                if let Some(v) = t.get("realm").and_then(|v| v.as_str()) {
                    base.basic.realm = v.to_string();
                }
            }
            1 => {
                if let Some(v) = t.get("provider").and_then(|v| v.as_str()) {
                    base.oidc.provider = v.to_string();
                }
                if let Some(v) = t.get("issuer").and_then(|v| v.as_str()) {
                    base.oidc.issuer = v.to_string();
                }
                if let Some(v) = t.get("client_id").and_then(|v| v.as_str()) {
                    base.oidc.client_id = v.to_string();
                }
                if let Some(v) = t.get("client_secret").and_then(|v| v.as_str()) {
                    base.oidc.client_secret = v.to_string();
                }
                if let Some(v) = t.get("scopes").and_then(|v| v.as_str()) {
                    base.oidc.scopes = v.to_string();
                }
                if let Some(v) = t.get("required_group").and_then(|v| v.as_str()) {
                    base.oidc.required_group = v.to_string();
                }
                if let Some(v) = t.get("redirect_path").and_then(|v| v.as_str()) {
                    base.oidc.redirect_path = v.to_string();
                }
            }
            _ => {
                if let Some(v) = t.get("user_header").and_then(|v| v.as_str()) {
                    base.trusted_proxy.user_header = v.to_string();
                }
                if let Some(v) = t.get("email_header").and_then(|v| v.as_str()) {
                    base.trusted_proxy.email_header = v.to_string();
                }
                if let Some(v) = t.get("groups_header").and_then(|v| v.as_str()) {
                    base.trusted_proxy.groups_header = v.to_string();
                }
                if let Some(arr) = t.get("trusted_cidrs").and_then(|v| v.as_array()) {
                    base.trusted_proxy.trusted_cidrs = arr
                        .iter()
                        .filter_map(|x| x.as_str().map(ToOwned::to_owned))
                        .collect();
                }
            }
        }
    }
    base
}

fn read_schedules(toml: &toml::Value) -> Vec<Schedule> {
    let Some(arr) = toml.get("schedules").and_then(|v| v.as_array()) else {
        return Vec::new();
    };
    arr.iter()
        .filter_map(|s| {
            let name = s.get("name")?.as_str()?.trim().to_string();
            let cron = s.get("cron")?.as_str()?.trim().to_string();
            if name.is_empty() || cron.is_empty() {
                return None;
            }
            let mut m = HashMap::new();
            if let Some(t) = s.get("match").and_then(|v| v.as_table()) {
                for (k, v) in t {
                    if let Some(v) = v.as_str() {
                        m.insert(k.to_string(), v.to_string());
                    }
                }
            }
            let applies_to = s
                .get("applies_to")
                .and_then(|v| v.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|x| x.as_str().map(ToOwned::to_owned))
                        .collect()
                })
                .unwrap_or_default();
            Some(Schedule {
                name,
                cron,
                duration_minutes: s
                    .get("duration_minutes")
                    .and_then(|v| v.as_integer())
                    .unwrap_or(30)
                    .max(1) as u64,
                r#match: m,
                applies_to,
            })
        })
        .collect()
}

fn load_ntfy_topics(paths: &Paths, toml: &toml::Value) -> Result<Vec<NtfyTopic>> {
    let mut topics: Option<Vec<NtfyTopic>> = None;
    if paths.ntfy_topics.exists() {
        let raw: serde_json::Value = serde_json::from_slice(&fs::read(&paths.ntfy_topics)?)?;
        if let Some(arr) = raw.get("topics").and_then(|v| v.as_array()) {
            topics = Some(arr.iter().filter_map(topic_from_json).collect());
        }
    }
    if topics.is_none() {
        topics = ntfy_topics_from_toml(toml);
    }
    let mut out = topics.unwrap_or_else(|| {
        vec![
            NtfyTopic {
                name: env_string("TOPIC_INFO"),
                token: String::new(),
                handles: vec!["info".into()],
            },
            NtfyTopic {
                name: env_string("TOPIC_WARN"),
                token: String::new(),
                handles: vec!["warning".into()],
            },
            NtfyTopic {
                name: env_string("TOPIC_CRIT"),
                token: String::new(),
                handles: vec!["critical".into()],
            },
        ]
    });

    let env_name = HashMap::from([
        ("info", env_string("TOPIC_INFO")),
        ("warning", env_string("TOPIC_WARN")),
        ("critical", env_string("TOPIC_CRIT")),
    ]);
    let env_token = HashMap::from([
        ("info", env_string("NTFY_TOKEN_INFO")),
        ("warning", env_string("NTFY_TOKEN_WARN")),
        ("critical", env_string("NTFY_TOKEN_CRIT")),
    ]);
    for t in &mut out {
        for h in &mut t.handles {
            *h = h.to_ascii_lowercase();
        }
        if t.handles.len() == 1 {
            let sev = t.handles[0].as_str();
            if let Some(name) = env_name.get(sev).filter(|v| !v.is_empty()) {
                t.name = name.clone();
            }
            if t.token.is_empty()
                && let Some(tok) = env_token.get(sev).filter(|v| !v.is_empty())
            {
                t.token = tok.clone();
            }
        }
    }
    out.retain(|t| !t.name.is_empty());
    Ok(out)
}

fn ntfy_topics_from_toml(toml: &toml::Value) -> Option<Vec<NtfyTopic>> {
    let v = toml_get(toml, &["ntfy", "topics"])?;
    if let Some(arr) = v.as_array() {
        return Some(
            arr.iter()
                .filter_map(|t| {
                    Some(NtfyTopic {
                        name: t.get("name")?.as_str()?.to_string(),
                        token: t
                            .get("token")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string(),
                        handles: t
                            .get("handles")
                            .and_then(|v| v.as_array())
                            .map(|a| {
                                a.iter()
                                    .filter_map(|x| x.as_str().map(|s| s.to_ascii_lowercase()))
                                    .collect()
                            })
                            .unwrap_or_default(),
                    })
                })
                .collect(),
        );
    }
    v.as_table().map(|table| {
        vec![
            NtfyTopic {
                name: table
                    .get("info")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                token: String::new(),
                handles: vec!["info".into()],
            },
            NtfyTopic {
                name: table
                    .get("warning")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                token: String::new(),
                handles: vec!["warning".into()],
            },
            NtfyTopic {
                name: table
                    .get("critical")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                token: String::new(),
                handles: vec!["critical".into()],
            },
        ]
    })
}

pub fn restore_sidecars_from_toml(paths: &Paths, toml: &toml::Value) -> Result<Vec<&'static str>> {
    let mut restored = Vec::new();
    if toml_get(toml, &["render", "component_dashboards"]).is_some() {
        let dashboards =
            read_component_dashboards(toml_get(toml, &["render", "component_dashboards"]));
        if !dashboards.is_empty() {
            save_render_config(paths, &dashboards)?;
            restored.push("render");
        }
    }
    if toml_get(toml, &["dedup"]).is_some() {
        let dedup = dedup_from_toml(toml_get(toml, &["dedup"]));
        save_dedup(paths, &dedup)?;
        restored.push("dedup");
    }
    if let Some(auth_seed) = toml_get(toml, &["auth"]) {
        let auth = merge_auth_toml(AuthConfig::default(), auth_seed);
        save_auth(paths, &auth)?;
        restored.push("auth");
    }
    if let Some(topics) = ntfy_topics_from_toml(toml) {
        let topics = topics
            .into_iter()
            .filter(|t| !t.name.is_empty())
            .collect::<Vec<_>>();
        if !topics.is_empty() {
            save_ntfy_topics(paths, &topics)?;
            restored.push("ntfy_topics");
        }
    }
    Ok(restored)
}

fn topic_from_json(v: &serde_json::Value) -> Option<NtfyTopic> {
    Some(NtfyTopic {
        name: v.get("name")?.as_str()?.to_string(),
        token: v
            .get("token")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string(),
        handles: v
            .get("handles")
            .and_then(|x| x.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(|s| s.to_ascii_lowercase()))
                    .collect()
            })
            .unwrap_or_default(),
    })
}

pub fn save_ntfy_topics(paths: &Paths, topics: &[NtfyTopic]) -> Result<()> {
    atomic_write_json(paths.ntfy_topics.as_path(), &json!({ "topics": topics }))
}

pub fn save_toml(paths: &Paths, cfg: &toml::Value) -> Result<()> {
    let text = toml::to_string_pretty(cfg)?;
    atomic_write(&paths.config, text.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use tempfile::TempDir;

    fn temp_paths(tmp: &TempDir) -> Paths {
        let data = tmp.path();
        Paths {
            config: data.join("klaxond.toml"),
            default_config: PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("klaxond.default.toml"),
            render_config: data.join("render-config.json"),
            ntfy_topics: data.join("ntfy-topics.json"),
            dedup_config: data.join("dedup-config.json"),
            dedup_pending_dir: data.join("dedup_pending"),
            auth_config: data.join("auth-config.json"),
            auth_session_key: data.join("auth-session.key"),
            backup_dir: data.join("backups"),
            static_dir: PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("static"),
            beszel_db: data.join("missing-beszel.db"),
        }
    }

    #[test]
    fn restore_sidecars_from_toml_replaces_stale_sidecar_values() {
        let tmp = TempDir::new().unwrap();
        let paths = temp_paths(&tmp);
        save_ntfy_topics(
            &paths,
            &[NtfyTopic {
                name: "stale-topic".into(),
                token: "stale-token".into(),
                handles: vec!["critical".into(), "warning".into()],
            }],
        )
        .unwrap();
        save_auth(
            &paths,
            &AuthConfig {
                mode: "none".into(),
                ..AuthConfig::default()
            },
        )
        .unwrap();
        save_render_config(
            &paths,
            &HashMap::from([("host".into(), ["Stale".to_string(), "/d/stale".to_string()])]),
        )
        .unwrap();
        save_dedup(
            &paths,
            &HashMap::from([(
                "wud".into(),
                DedupSetting {
                    enabled: true,
                    window_s: 999,
                    strategy: "key".into(),
                    override_critical: false,
                },
            )]),
        )
        .unwrap();
        let restored_toml: toml::Value = toml::from_str(
            r#"
[render.component_dashboards]
host = ["Restored", "/d/restored"]

[auth]
mode = "basic"
session_timeout_hours = 12

[auth.basic]
username = "restored"
password_hash = "$2b$12$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWX"
realm = "klaxond"

[ntfy]
topics = [
  { name = "restored-topic", token = "restored-token", handles = ["critical", "warning"] },
]

[dedup.wud]
enabled = false
window_s = 42
strategy = "time"
override_critical = true
"#,
        )
        .unwrap();
        save_toml(&paths, &restored_toml).unwrap();

        let restored = restore_sidecars_from_toml(&paths, &restored_toml).unwrap();
        let cfg = load_runtime_config(&paths).unwrap();

        assert_eq!(restored, vec!["render", "dedup", "auth", "ntfy_topics"]);
        assert_eq!(
            cfg.component_dashboards.get("host").unwrap(),
            &["Restored".to_string(), "/d/restored".to_string()]
        );
        assert_eq!(cfg.auth.mode, "basic");
        assert_eq!(cfg.auth.basic.username, "restored");
        assert_eq!(cfg.topics_for("critical")[0].name, "restored-topic");
        assert_eq!(cfg.topics_for("critical")[0].token, "restored-token");
        assert!(!cfg.dedup["wud"].enabled);
        assert_eq!(cfg.dedup["wud"].window_s, 42);
        assert_eq!(cfg.dedup["wud"].strategy, "time");
        assert!(cfg.dedup["wud"].override_critical);
    }
}
