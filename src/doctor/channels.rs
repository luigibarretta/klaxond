use super::{Check, CheckStatus, check};
use crate::config::RuntimeConfig;

pub(super) fn channel_checks(cfg: &RuntimeConfig, checks: &mut Vec<Check>) {
    checks.push(admin_authentication_check(cfg));
    checks.push(ntfy_routing_check(cfg));
    checks.push(channel_check("Telegram fallback", telegram_ready(cfg)));
    checks.push(channel_check("SMTP fallback", smtp_ready(cfg)));
}

fn admin_authentication_check(cfg: &RuntimeConfig) -> Check {
    let public_is_local = url::Url::parse(&cfg.public_url)
        .ok()
        .and_then(|url| url.host_str().map(ToOwned::to_owned))
        .is_some_and(|host| {
            host.eq_ignore_ascii_case("localhost")
                || host
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(|address| address.is_loopback())
        });
    let status = if cfg.auth.mode == "none" && !public_is_local {
        CheckStatus::Error
    } else if cfg.auth.mode == "none" {
        CheckStatus::Warn
    } else {
        CheckStatus::Ok
    };
    let detail = if cfg.auth.mode == "none" {
        "disabled; do not expose the admin UI beyond loopback"
    } else {
        "enabled"
    };
    check("admin authentication", status, detail)
}

fn ntfy_routing_check(cfg: &RuntimeConfig) -> Check {
    let tokens = cfg
        .ntfy_topics
        .iter()
        .filter(|topic| !topic.token.trim().is_empty())
        .count();
    check(
        "ntfy routing",
        if tokens > 0 {
            CheckStatus::Ok
        } else {
            CheckStatus::Warn
        },
        format!("{tokens} publish-token topic(s) configured"),
    )
}

fn channel_check(name: &str, ready: bool) -> Check {
    check(
        name,
        if ready {
            CheckStatus::Ok
        } else {
            CheckStatus::Warn
        },
        if ready {
            "configured"
        } else {
            "not configured"
        },
    )
}

pub(super) fn telegram_ready(cfg: &RuntimeConfig) -> bool {
    !cfg.tg_token.trim().is_empty() && !cfg.tg_chat.trim().is_empty()
}

pub(super) fn smtp_ready(cfg: &RuntimeConfig) -> bool {
    [
        cfg.smtp_host.trim(),
        cfg.smtp_user.trim(),
        cfg.smtp_pass.trim(),
        cfg.smtp_from.trim(),
        cfg.smtp_to.trim(),
    ]
    .iter()
    .all(|value| !value.is_empty())
}
