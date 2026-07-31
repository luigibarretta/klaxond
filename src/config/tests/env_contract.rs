use super::*;
use std::fs;
use std::path::PathBuf;

const COMPOSE_FILE_CONFIG_EQUIVALENTS: &[(&str, &str)] = &[
    ("NTFY_URL", "TOML [ntfy].url"),
    (
        "NTFY_TOKEN_INFO",
        "TOML/JSON ntfy topic token for handles=[info]",
    ),
    (
        "NTFY_TOKEN_WARN",
        "TOML/JSON ntfy topic token for handles=[warning]",
    ),
    (
        "NTFY_TOKEN_CRIT",
        "TOML/JSON ntfy topic token for handles=[critical]",
    ),
    ("TOPIC_INFO", "TOML/JSON ntfy topic name for handles=[info]"),
    (
        "TOPIC_WARN",
        "TOML/JSON ntfy topic name for handles=[warning]",
    ),
    (
        "TOPIC_CRIT",
        "TOML/JSON ntfy topic name for handles=[critical]",
    ),
    (
        "CASCADE_ENABLED",
        "TOML [cascade].default_enabled_for_webhook",
    ),
    ("TELEGRAM_BOT_TOKEN", "TOML [telegram].bot_token"),
    ("TELEGRAM_CHAT_ID", "TOML [telegram].chat_id"),
    ("TELEGRAM_API_BASE", "TOML [telegram].api_base"),
    ("SMTP_HOST", "TOML [smtp].host"),
    ("SMTP_PORT", "TOML [smtp].port"),
    ("SMTP_STARTTLS", "TOML [smtp].starttls"),
    ("SMTP_USER", "TOML [smtp].user"),
    ("SMTP_PASSWORD", "TOML [smtp].password"),
    ("SMTP_FROM", "TOML [smtp].from_addr"),
    ("SMTP_TO", "TOML [smtp].to_addr"),
    ("GRAFANA_BASE", "TOML [render].grafana_base"),
    ("GRAFANA_RENDER_BASE", "TOML [render].grafana_render_base"),
    ("GRAFANA_RENDER_TOKEN", "TOML [render].grafana_render_token"),
    ("RENDER_IMAGE_TTL", "TOML [render].render_image_ttl"),
    ("KLAXOND_PUBLIC_URL", "TOML [server].public_url"),
    ("ACK_DEFAULT_TTL_SECONDS", "TOML [acks].default_ttl_seconds"),
    ("AUTH_SESSION_SECRET", "TOML/JSON auth.session_secret"),
    (
        "AUTH_OIDC_CLIENT_SECRET",
        "TOML/JSON auth.oidc.client_secret",
    ),
    (
        "AUTH_BASIC_PASSWORD_HASH",
        "TOML/JSON auth.basic.password_hash",
    ),
    (
        "AUTH_TRUSTED_PROXY_CIDRS",
        "TOML/JSON auth.trusted_proxy.trusted_cidrs",
    ),
    (
        "KLAXOND_INGEST_SECRET_GRAFANA",
        "TOML [ingest.secrets].grafana",
    ),
    (
        "KLAXOND_INGEST_SECRET_BESZEL",
        "TOML [ingest.secrets].beszel",
    ),
    (
        "KLAXOND_INGEST_SECRET_HEALTHCHECKS",
        "TOML [ingest.secrets].healthchecks",
    ),
    (
        "KLAXOND_INGEST_SECRET_UPTIME_KUMA",
        "TOML [ingest.secrets].uptime-kuma",
    ),
    ("KLAXOND_INGEST_SECRET_WUD", "TOML [ingest.secrets].wud"),
    (
        "KLAXOND_INGEST_SECRET_AUTHENTIK",
        "TOML [ingest.secrets].authentik",
    ),
    (
        "KLAXOND_INGEST_SECRET_SHELFMARK",
        "TOML [ingest.secrets].shelfmark",
    ),
    (
        "KLAXOND_INGEST_SECRET_PROWLARR",
        "TOML [ingest.secrets].prowlarr",
    ),
    (
        "KLAXOND_INGEST_SECRET_DECYPHARR",
        "TOML [ingest.secrets].decypharr",
    ),
    ("PORT", "TOML [server].port"),
    ("RENDER_CONFIG_PATH", "TOML [paths].render_config"),
    ("NTFY_TOPICS_PATH", "TOML [paths].ntfy_topics"),
    ("DEDUP_CONFIG_PATH", "TOML [paths].dedup_config"),
    ("AUTH_CONFIG_PATH", "TOML [paths].auth_config"),
    ("AUTH_SESSION_KEY_PATH", "TOML [paths].auth_session_key"),
    ("KLAXOND_BACKUP_DIR", "TOML [paths].backup_dir"),
    ("DEDUP_PENDING_DIR", "TOML [paths].dedup_pending_dir"),
    ("BESZEL_DB_PATH", "TOML [paths].beszel_db"),
    ("KLAXOND_SQLITE_PATH", "TOML [paths].history_db"),
    ("KLAXOND_HISTORY_BACKEND", "TOML [history].backend"),
    ("KLAXOND_POSTGRES_URL", "TOML [history].postgres_url"),
    ("KLAXOND_HISTORY_RETENTION", "TOML [history].retention"),
    (
        "KLAXOND_HISTORY_DEFAULT_LIMIT",
        "TOML [history].default_limit",
    ),
];

const SPLIT_COMPOSE_ENV_KEYS: &[&str] = &[
    "KLAXOND_BACKEND_IMAGE",
    "KLAXOND_BACKEND_CONTAINER",
    "KLAXOND_BACKEND_BIND",
    "KLAXOND_FRONTEND_IMAGE",
    "KLAXOND_FRONTEND_CONTAINER",
    "KLAXOND_FRONTEND_BIND",
    "KLAXOND_FRONTEND_MAX_BODY_SIZE",
    "KLAXOND_BACKEND_URL",
    "KLAXOND_STATE_IMAGE",
    "KLAXOND_STATE_CONTAINER",
    "KLAXOND_DATA_VOLUME",
    "KLAXOND_POSTGRES_IMAGE",
    "KLAXOND_POSTGRES_CONTAINER",
    "KLAXOND_POSTGRES_BIND",
    "KLAXOND_POSTGRES_DB",
    "KLAXOND_POSTGRES_USER",
    "KLAXOND_POSTGRES_PASSWORD",
    "KLAXOND_POSTGRES_VOLUME",
];

fn compose_env_keys(compose: &str) -> Vec<String> {
    compose
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim_start();
            if !line.starts_with("      ") || trimmed.starts_with('#') {
                return None;
            }
            let (key, _) = trimmed.split_once(':')?;
            if key.starts_with("POSTGRES_") {
                return None;
            }
            if key
                .chars()
                .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
            {
                Some(key.to_string())
            } else {
                None
            }
        })
        .collect()
}
#[test]
fn compose_env_vars_have_toml_or_json_equivalent_declared() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let compose = fs::read_to_string(root.join("docker-compose.yml")).unwrap();
    let compose_keys = compose_env_keys(&compose);
    let mut missing = Vec::new();
    for key in &compose_keys {
        if BOOTSTRAP_ONLY_COMPOSE_ENV_KEYS.contains(&key.as_str()) {
            continue;
        }
        let equivalent = COMPOSE_FILE_CONFIG_EQUIVALENTS
            .iter()
            .find(|(mapped, _)| *mapped == key.as_str())
            .map(|(_, target)| *target);
        match equivalent {
            Some(target) if target.contains("TOML") || target.contains("JSON") => {}
            _ => missing.push(key.clone()),
        }
    }
    assert!(
        missing.is_empty(),
        "compose env vars without TOML/JSON equivalent: {missing:?}"
    );
}
#[test]
fn reference_compose_and_env_example_cover_runtime_env_vars() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let compose = fs::read_to_string(root.join("docker-compose.yml")).unwrap();
    let split_compose = fs::read_to_string(root.join("docker-compose.split.yml")).unwrap();
    let env_example = fs::read_to_string(root.join(".env.example")).unwrap();
    let compose_keys = compose_env_keys(&compose);
    let split_compose_keys = compose_env_keys(&split_compose);
    assert!(
        !compose_keys.is_empty(),
        "docker-compose.yml has no env keys"
    );
    assert!(
        !split_compose_keys.is_empty(),
        "docker-compose.split.yml has no env keys"
    );
    for key in &compose_keys {
        assert!(
            RUNTIME_COMPOSE_ENV_KEYS.contains(&key.as_str()),
            "RUNTIME_COMPOSE_ENV_KEYS missing compose env {key}"
        );
    }
    for key in RUNTIME_COMPOSE_ENV_KEYS {
        assert!(
            compose.contains(&format!("{key}: ${{{key}")),
            "docker-compose.yml missing {key}"
        );
        assert!(
            env_example
                .lines()
                .any(|line| line.starts_with(&format!("{key}="))
                    || line.starts_with(&format!("# {key}="))),
            ".env.example missing {key}"
        );
    }
    for key in RUNTIME_COMPOSE_ENV_KEYS {
        assert!(
            split_compose.contains(&format!("{key}: ${{{key}")),
            "docker-compose.split.yml missing backend runtime env {key}"
        );
    }
    for key in SPLIT_COMPOSE_ENV_KEYS {
        assert!(
            split_compose.contains(&format!("${{{key}")),
            "docker-compose.split.yml missing split env {key}"
        );
        assert!(
            env_example
                .lines()
                .any(|line| line.starts_with(&format!("{key}="))
                    || line.starts_with(&format!("# {key}="))),
            ".env.example missing split env {key}"
        );
    }
    assert!(
        split_compose.contains(r#"profiles: ["backend", "all"]"#),
        "split compose must allow backend-only startup"
    );
    assert!(
        split_compose.contains(r#"profiles: ["frontend", "all"]"#),
        "split compose must allow frontend-only startup"
    );
    assert!(
        split_compose.contains(r#"profiles: ["db", "state", "all"]"#),
        "split compose must allow db/state-only startup"
    );
}
#[test]
fn split_frontend_proxy_template_covers_backend_routes() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let nginx = fs::read_to_string(root.join("deploy/frontend/nginx.conf.template")).unwrap();

    for expected in [
        "KLAXOND_BACKEND_URL",
        "map $http_x_forwarded_proto $klaxond_forwarded_proto",
        "map $http_host $klaxond_forwarded_host",
        "proxy_set_header Host $klaxond_forwarded_host",
        "proxy_set_header X-Forwarded-Proto $klaxond_forwarded_proto",
        "proxy_set_header X-Forwarded-Host $klaxond_forwarded_host",
        "absolute_redirect off",
        "location ~ ^/api/",
        "location ~ ^/(webhook|beszel|healthchecks|wud|authentik|shelfmark|prowlarr|decypharr|pve)(/|$)",
        "location ~ ^/img/",
        "location ~ ^/(swagger|api/docs|api/swagger|api/swagger-ui)(/|$)",
        "location = /ui/meta.js",
        "location = /ui/auth",
        "return 302 /authentication",
        "try_files $uri /index.html",
    ] {
        assert!(
            nginx.contains(expected),
            "frontend nginx template missing {expected}"
        );
    }
}
