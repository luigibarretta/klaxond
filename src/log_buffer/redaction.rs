use regex::{Captures, Regex};
use std::sync::LazyLock;

static TELEGRAM_BOT_URL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"bot\d{6,}:[A-Za-z0-9_-]{20,}").expect("valid telegram redaction regex")
});
static AUTH_HEADER_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b(authorization:\s*(?:bearer|basic)\s+)[^\s,;]+")
        .expect("valid auth header redaction regex")
});
static BEARER_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b(bearer\s+)[A-Za-z0-9._~+/=-]{12,}").expect("valid bearer redaction regex")
});
static QUERY_SECRET_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)([?&](?:token|secret|access_token|id_token|refresh_token|client_secret|password|api_key|apikey|key)=)[^&\s]+",
    )
    .expect("valid query redaction regex")
});
static KV_SECRET_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)\b(token|secret|password|client_secret|api_key|apikey|authorization)=("[^"]*"|'[^']*'|[^\s,;]+)"#,
    )
    .expect("valid key-value redaction regex")
});
static ENV_SECRET_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)\b([A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|API_KEY|APIKEY|AUTHORIZATION)[A-Z0-9_]*)(\s*[:=]\s*)("[^"]*"|'[^']*'|[^\s,;]+)"#,
    )
    .expect("valid env-style redaction regex")
});

pub(super) fn redact_log_text(value: &str) -> String {
    let out = redact_transport_secrets(value);
    let out = redact_query_secrets(&out);
    let out = redact_key_value_secrets(&out);
    redact_env_secrets(&out)
}

pub(super) fn is_sensitive_key(key: &str) -> bool {
    let key = key.to_ascii_lowercase();
    key.contains("token")
        || key.contains("secret")
        || key.contains("password")
        || key.contains("authorization")
        || key.contains("api_key")
        || key.contains("apikey")
        || key.ends_with("_key")
}

fn redact_transport_secrets(value: &str) -> String {
    let out = TELEGRAM_BOT_URL_RE.replace_all(value, "bot[REDACTED]");
    let out = AUTH_HEADER_RE.replace_all(&out, "$1[REDACTED]");
    BEARER_RE.replace_all(&out, "$1[REDACTED]").into_owned()
}

fn redact_query_secrets(value: &str) -> String {
    QUERY_SECRET_RE
        .replace_all(value, "$1[REDACTED]")
        .into_owned()
}

fn redact_key_value_secrets(value: &str) -> String {
    KV_SECRET_RE
        .replace_all(value, |caps: &Captures<'_>| {
            format!("{}=[REDACTED]", &caps[1])
        })
        .into_owned()
}

fn redact_env_secrets(value: &str) -> String {
    ENV_SECRET_RE
        .replace_all(value, |caps: &Captures<'_>| {
            format!("{}{}[REDACTED]", &caps[1], &caps[2])
        })
        .into_owned()
}
