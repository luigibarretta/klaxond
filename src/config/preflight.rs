use super::RuntimeConfig;
use anyhow::{Context, Result, ensure};
use url::Url;

const EMERGENCY_LEASE_MARGIN_SECONDS: u64 = 5;

pub fn validate_runtime_config(cfg: &RuntimeConfig) -> Result<()> {
    validate_http_url("render.grafana_base", &cfg.grafana_base, true, true)?;
    for (source, value) in &cfg.source_urls {
        if !value.trim().is_empty() {
            validate_http_url(&format!("render.source_urls.{source}"), value, true, false)?;
        }
    }
    if !cfg.emergency.enabled {
        return Ok(());
    }

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
    )?;

    let mut max_ntfy_targets = 0_u64;
    let known_severities = cfg
        .known_severities()
        .into_iter()
        .filter(|severity| severity != "resolved")
        .collect::<Vec<_>>();
    let routed_severities = cfg
        .emergency
        .profiles
        .iter()
        .filter(|profile| profile.enabled)
        .flat_map(|profile| {
            if profile.severities.is_empty() {
                known_severities.clone()
            } else {
                profile
                    .severities
                    .iter()
                    .flat_map(|matcher| {
                        if let Some(pattern) = matcher.strip_prefix("re:") {
                            regex::Regex::new(pattern)
                                .map(|regex| {
                                    known_severities
                                        .iter()
                                        .filter(|severity| regex.is_match(severity))
                                        .cloned()
                                        .collect::<Vec<_>>()
                                })
                                .unwrap_or_default()
                        } else {
                            vec![matcher.clone()]
                        }
                    })
                    .collect()
            }
        })
        .collect::<std::collections::HashSet<_>>();
    for severity in &routed_severities {
        let targets = cfg
            .topics_for(severity)
            .into_iter()
            .filter(|topic| !topic.name.trim().is_empty() && !topic.token.trim().is_empty())
            .count() as u64;
        ensure!(
            targets > 0,
            "emergency severity '{severity}' requires an ntfy topic with a publish token"
        );
        max_ntfy_targets = max_ntfy_targets.max(targets);
    }

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

    let ntfy_budget = tier_timeout(cfg, "ntfy", 15).saturating_mul(max_ntfy_targets);
    for profile in cfg
        .emergency
        .profiles
        .iter()
        .filter(|profile| profile.enabled)
    {
        let required_lease = ntfy_budget
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
            profile.lease_seconds >= required_lease,
            "emergency profile '{}' lease_seconds must be at least {required_lease} for the configured sequential channel timeouts",
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
