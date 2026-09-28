use super::RuntimeConfig;
use anyhow::{Context, Result, ensure};
use url::Url;

const EMERGENCY_LEASE_MARGIN_SECONDS: u64 = 5;

pub fn validate_runtime_config(cfg: &RuntimeConfig) -> Result<()> {
    cfg.delivery.validate().map_err(anyhow::Error::msg)?;
    validate_render_urls(cfg)?;
    if !cfg.emergency.enabled {
        return Ok(());
    }
    validate_emergency_urls(cfg)?;
    let max_ntfy_targets = validate_ntfy_targets(cfg)?;
    let (telegram_ready, smtp_ready) = validate_fallbacks(cfg)?;
    validate_profile_fallbacks(cfg, telegram_ready, smtp_ready)?;
    validate_leases(cfg, max_ntfy_targets, telegram_ready, smtp_ready)
}

fn validate_render_urls(cfg: &RuntimeConfig) -> Result<()> {
    validate_http_url("render.grafana_base", &cfg.grafana_base, true, true)?;
    for (source, value) in &cfg.source_urls {
        if !value.trim().is_empty() {
            validate_http_url(&format!("render.source_urls.{source}"), value, true, false)?;
        }
    }
    Ok(())
}

fn validate_emergency_urls(cfg: &RuntimeConfig) -> Result<()> {
    validate_http_url(
        "server.public_url",
        &cfg.public_url,
        cfg.emergency.allow_insecure_public_url,
        true,
    )?;
    validate_http_url(
        "ntfy.url",
        &cfg.ntfy_url,
        cfg.emergency.allow_insecure_public_url,
        false,
    )
}

fn validate_ntfy_targets(cfg: &RuntimeConfig) -> Result<u64> {
    let known = cfg
        .known_severities()
        .into_iter()
        .filter(|severity| severity != "resolved")
        .collect::<Vec<_>>();
    let routed = cfg
        .emergency
        .profiles
        .iter()
        .filter(|profile| profile.enabled)
        .flat_map(|profile| routed_profile_severities(profile, &known))
        .collect::<std::collections::HashSet<_>>();
    let mut maximum = 0;
    for severity in routed {
        let targets = cfg
            .topics_for(&severity)
            .into_iter()
            .filter(|topic| !topic.name.trim().is_empty() && !topic.token.trim().is_empty())
            .count() as u64;
        ensure!(
            targets > 0,
            "emergency severity '{severity}' requires an ntfy topic with a publish token"
        );
        maximum = maximum.max(targets);
    }
    Ok(maximum)
}

fn routed_profile_severities(profile: &super::EmergencyProfile, known: &[String]) -> Vec<String> {
    if profile.severities.is_empty() {
        return known.to_vec();
    }
    profile
        .severities
        .iter()
        .flat_map(|matcher| match matcher.strip_prefix("re:") {
            Some(pattern) => regex::Regex::new(pattern)
                .map(|regex| {
                    known
                        .iter()
                        .filter(|value| regex.is_match(value))
                        .cloned()
                        .collect()
                })
                .unwrap_or_default(),
            None => vec![matcher.clone()],
        })
        .collect()
}

fn validate_fallbacks(cfg: &RuntimeConfig) -> Result<(bool, bool)> {
    let telegram_any = !cfg.tg_token.trim().is_empty() || !cfg.tg_chat.trim().is_empty();
    let telegram_ready = !cfg.tg_token.trim().is_empty() && !cfg.tg_chat.trim().is_empty();
    ensure!(
        !telegram_any || telegram_ready,
        "emergency Telegram fallback is incomplete: configure both bot_token and chat_id"
    );
    if telegram_ready {
        validate_http_url(
            "telegram.api_base",
            &cfg.telegram_api_base,
            cfg.emergency.allow_insecure_public_url,
            false,
        )?;
    }
    let smtp_values = [
        cfg.smtp_host.trim(),
        cfg.smtp_user.trim(),
        cfg.smtp_pass.trim(),
        cfg.smtp_from.trim(),
        cfg.smtp_to.trim(),
    ];
    let smtp_any = smtp_values.iter().any(|value| !value.is_empty());
    let smtp_ready = smtp_values.iter().all(|value| !value.is_empty());
    ensure!(
        !smtp_any || smtp_ready,
        "emergency SMTP fallback is incomplete: configure host, user, password, from and to"
    );
    Ok((telegram_ready, smtp_ready))
}

fn validate_profile_fallbacks(
    cfg: &RuntimeConfig,
    telegram_ready: bool,
    smtp_ready: bool,
) -> Result<()> {
    let telegram_any = !cfg.tg_token.trim().is_empty() || !cfg.tg_chat.trim().is_empty();
    let smtp_any = [
        cfg.smtp_host.trim(),
        cfg.smtp_user.trim(),
        cfg.smtp_pass.trim(),
        cfg.smtp_from.trim(),
        cfg.smtp_to.trim(),
    ]
    .iter()
    .any(|value| !value.is_empty());
    for profile in cfg
        .emergency
        .profiles
        .iter()
        .filter(|profile| profile.enabled)
    {
        ensure!(
            !profile.telegram.enabled || !telegram_any || telegram_ready,
            "emergency profile '{}' enables Telegram but the fallback is incomplete",
            profile.id
        );
        ensure!(
            !profile.smtp.enabled || !smtp_any || smtp_ready,
            "emergency profile '{}' enables SMTP but the fallback is incomplete",
            profile.id
        );
        ensure!(
            cfg.emergency.allow_ntfy_only
                || (profile.telegram.enabled && telegram_ready)
                || (profile.smtp.enabled && smtp_ready),
            "emergency profile '{}' requires a Telegram or SMTP fallback; set emergency.allow_ntfy_only=true only for a deliberate single-channel deployment",
            profile.id
        );
    }
    Ok(())
}

fn validate_leases(
    cfg: &RuntimeConfig,
    max_ntfy_targets: u64,
    telegram_ready: bool,
    smtp_ready: bool,
) -> Result<()> {
    let ntfy_budget = tier_timeout(cfg, "ntfy", 15).saturating_mul(max_ntfy_targets);
    for profile in cfg
        .emergency
        .profiles
        .iter()
        .filter(|profile| profile.enabled)
    {
        let required = ntfy_budget
            .saturating_add(if profile.telegram.enabled && telegram_ready {
                tier_timeout(cfg, "telegram", 8)
            } else {
                0
            })
            .saturating_add(if profile.smtp.enabled && smtp_ready {
                tier_timeout(cfg, "smtp", 10)
            } else {
                0
            })
            .saturating_add(EMERGENCY_LEASE_MARGIN_SECONDS);
        ensure!(
            profile.lease_seconds >= required,
            "emergency profile '{}' lease_seconds must be at least {required} for the configured sequential channel timeouts",
            profile.id
        );
    }
    Ok(())
}

fn validate_http_url(
    name: &str,
    value: &str,
    allow_insecure: bool,
    origin_only: bool,
) -> Result<()> {
    let parsed = Url::parse(value).with_context(|| format!("{name} must be an absolute URL"))?;
    ensure!(
        matches!(parsed.scheme(), "http" | "https") && parsed.host_str().is_some(),
        "{name} must be an absolute HTTP(S) URL"
    );
    ensure!(
        allow_insecure || parsed.scheme() == "https",
        "{name} must use HTTPS while emergency mode is enabled"
    );
    ensure!(
        parsed.username().is_empty() && parsed.password().is_none(),
        "{name} must not contain credentials"
    );
    ensure!(
        parsed.query().is_none() && parsed.fragment().is_none(),
        "{name} must not contain a query string or fragment"
    );
    if origin_only {
        ensure!(
            parsed.path().is_empty() || parsed.path() == "/",
            "{name} must be an origin URL without a path"
        );
    }
    Ok(())
}

fn tier_timeout(cfg: &RuntimeConfig, name: &str, fallback: u64) -> u64 {
    cfg.tiers
        .iter()
        .find(|tier| tier.name.eq_ignore_ascii_case(name))
        .map(|tier| tier.timeout_seconds)
        .unwrap_or(fallback)
}
