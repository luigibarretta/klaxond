use crate::config::{DeliveryPolicy, RuntimeConfig, Tier, default_tiers};
use crate::inhibition::ack_sign;
use crate::parsers::Parts;
use crate::state::{AppState, RenderedImage, lock_mutex};
use crate::util::{html_escape, now_epoch, strip_non_ascii, token_urlsafe};
use anyhow::{Context, Result};
use base64::{Engine as _, engine::general_purpose};
use lettre::message::header::ContentType;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{Message, SmtpTransport, Transport};
use regex::Regex;
use serde_json::Value;
use serde_json::json;
use std::collections::HashMap;
use std::time::Duration;
use tokio::time::timeout;

pub async fn deliver(
    state: &AppState,
    severity: &str,
    mut parts: Parts,
    with_cascade: bool,
    labels: HashMap<String, String>,
    source: &str,
) -> (bool, String) {
    let mut labels = labels;
    labels.insert("severity".into(), severity.to_string());
    let cfg = state.cfg();
    let (policy, reason) = pick_policy(&cfg, &labels);
    tracing::info!(
        "policy picked: {} (mode={}, {} tiers)",
        reason,
        policy.mode,
        policy.tiers.len()
    );

    if !cfg.grafana_render_base.is_empty()
        && let Some(slug) = parts.render_slug.as_deref()
        && parts.attach_url.is_none()
        && let Some(png) = render_alert_image(
            state,
            &cfg,
            slug,
            &parts.render_instance,
            parts.render_panel,
        )
        .await
    {
        let tok = token_urlsafe(12);
        let url = format!("{}/img/{tok}.png", cfg.public_url);
        lock_mutex(&state.rendered_images, "rendered images").insert(
            tok,
            RenderedImage {
                bytes: png,
                expires_at: now_epoch() + cfg.render_image_ttl as f64,
            },
        );
        parts.attach_url = Some(url);
    }

    let started = now_epoch();
    let mut attempted = Vec::new();

    if policy.mode == "broadcast" {
        let mut succeeded = Vec::new();
        for tier in &policy.tiers {
            if post_tier(state, severity, &parts, tier).await {
                succeeded.push(tier.name.clone());
            }
            attempted.push(tier.name.clone());
        }
        let ok = !succeeded.is_empty();
        let channel = if ok {
            succeeded.join("+")
        } else {
            "broadcast-all-failed".into()
        };
        audit_log_delivery(
            state, severity, &parts, &labels, source, &attempted, ok, &channel, started,
        );
        return (ok, channel);
    }

    let tiers = if policy.tiers.is_empty() {
        default_tiers()
    } else {
        policy.tiers
    };
    let first = tiers.first().cloned();
    if let Some(first) = first {
        attempted.push(first.name.clone());
        if post_tier(state, severity, &parts, &first).await {
            audit_log_delivery(
                state,
                severity,
                &parts,
                &labels,
                source,
                &attempted,
                true,
                &first.name,
                started,
            );
            return (true, first.name);
        }
        if !with_cascade {
            let channel = format!("{}-failed", first.name);
            audit_log_delivery(
                state, severity, &parts, &labels, source, &attempted, false, &channel, started,
            );
            return (false, channel);
        }
        for tier in tiers.iter().skip(1) {
            attempted.push(tier.name.clone());
            if post_tier(state, severity, &parts, tier).await {
                audit_log_delivery(
                    state, severity, &parts, &labels, source, &attempted, true, &tier.name, started,
                );
                return (true, tier.name.clone());
            }
        }
    }
    audit_log_delivery(
        state,
        severity,
        &parts,
        &labels,
        source,
        &attempted,
        false,
        "all-failed",
        started,
    );
    (false, "all-failed".into())
}

async fn post_tier(state: &AppState, severity: &str, parts: &Parts, tier: &Tier) -> bool {
    match tier.name.as_str() {
        "ntfy" => post_to_ntfy(state, severity, parts, tier.timeout_seconds).await,
        "telegram" => post_to_telegram(state, severity, parts, tier.timeout_seconds).await,
        "smtp" => post_to_smtp(state, severity, parts, tier.timeout_seconds).await,
        _ => false,
    }
}

pub async fn post_to_ntfy(state: &AppState, severity: &str, parts: &Parts, timeout_s: u64) -> bool {
    let cfg = state.cfg();
    let topics = cfg.topics_for(severity);
    if topics.is_empty() {
        tracing::warn!("ntfy: no topic handles severity '{}'", severity);
        return false;
    }
    let title_b64 = general_purpose::STANDARD.encode(parts.title.as_bytes());
    let encoded_title = format!("=?UTF-8?B?{title_b64}?=");
    let mut actions = parts.actions.iter().take(2).cloned().collect::<Vec<_>>();
    let mut alertname = parts.alertname.trim().to_string();
    if alertname.is_empty() {
        let mut t = parts.title.clone();
        if let Some((before, _)) = t.split_once(" — ") {
            t = before.to_string();
        }
        alertname = t
            .chars()
            .filter(|c| !c.is_ascii() || c.is_alphanumeric() || "-_./ ".contains(*c))
            .collect::<String>()
            .trim()
            .to_string();
    }
    if !alertname.is_empty() && !parts.skip_snooze {
        let tok = ack_sign(state, &alertname, cfg.ack_default_ttl);
        actions.push([
            "view".into(),
            "Snooze 1h".into(),
            format!("{}/api/ack/{tok}", cfg.public_url),
        ]);
    }
    let actions_header = if actions.is_empty() {
        None
    } else {
        Some(
            actions
                .iter()
                .take(3)
                .map(|[kind, label, target]| {
                    format!("{kind}, {}, {target}", strip_non_ascii(label))
                })
                .collect::<Vec<_>>()
                .join("; "),
        )
    };
    let mut any_ok = false;
    for topic in topics {
        if topic.token.is_empty() {
            tracing::warn!("ntfy: topic '{}' has no token", topic.name);
            continue;
        }
        let url = format!("{}/{}", cfg.ntfy_url, topic.name);
        let mut req = state
            .http
            .post(&url)
            .timeout(Duration::from_secs(timeout_s))
            .header("Authorization", format!("Bearer {}", topic.token))
            .header("Title", encoded_title.clone())
            .header("Tags", parts.tags.join(","))
            .header("Priority", parts.priority.clone())
            .body(parts.body.clone());
        if let Some(actions) = &actions_header {
            req = req.header("Actions", actions);
        }
        if let Some(attach) = &parts.attach_url {
            req = req.header("Attach", attach);
        }
        match req.send().await {
            Ok(resp) if resp.status().is_success() => any_ok = true,
            Ok(resp) => tracing::warn!("ntfy POST to {} returned {}", topic.name, resp.status()),
            Err(err) => tracing::warn!("ntfy POST to {} failed: {}", topic.name, err),
        }
    }
    any_ok
}

pub async fn post_to_telegram(
    state: &AppState,
    severity: &str,
    parts: &Parts,
    timeout_s: u64,
) -> bool {
    let cfg = state.cfg();
    if cfg.tg_token.is_empty() || cfg.tg_chat.is_empty() {
        return false;
    }
    let msg = format!(
        "<b>{}</b>\nseverity: <code>{}</code>\n\n{}",
        html_escape(&parts.title),
        html_escape(severity),
        html_escape(&parts.body)
    );
    let mut payload = vec![
        ("chat_id".to_string(), cfg.tg_chat),
        ("parse_mode".to_string(), "HTML".into()),
        ("text".to_string(), msg),
        ("disable_web_page_preview".to_string(), "true".into()),
    ];
    if !parts.actions.is_empty() {
        let buttons = parts
            .actions
            .iter()
            .take(5)
            .filter(|[_, _, target]| !target.is_empty())
            .map(|[_, label, target]| json!([{ "text": label, "url": target }]))
            .collect::<Vec<_>>();
        payload.push((
            "reply_markup".into(),
            json!({ "inline_keyboard": buttons }).to_string(),
        ));
    }
    let url = format!(
        "{}/bot{}/sendMessage",
        cfg.telegram_api_base.trim_end_matches('/'),
        cfg.tg_token
    );
    match state
        .http
        .post(url)
        .timeout(Duration::from_secs(timeout_s))
        .form(&payload)
        .send()
        .await
    {
        Ok(resp) => resp.status().is_success(),
        Err(err) => {
            tracing::warn!("telegram POST failed: {}", err.without_url());
            false
        }
    }
}

pub async fn post_to_smtp(state: &AppState, severity: &str, parts: &Parts, timeout_s: u64) -> bool {
    let cfg = state.cfg();
    if cfg.smtp_host.is_empty()
        || cfg.smtp_user.is_empty()
        || cfg.smtp_pass.is_empty()
        || cfg.smtp_to.is_empty()
    {
        return false;
    }
    let mut body = format!("{}\n\nseverity: {severity}\n", parts.body);
    if !parts.actions.is_empty() {
        body.push('\n');
        body.push_str(
            &parts
                .actions
                .iter()
                .map(|[_, label, target]| format!("{label}: {target}"))
                .collect::<Vec<_>>()
                .join("\n"),
        );
    }
    let from = cfg.smtp_from.clone();
    let to = cfg.smtp_to.clone();
    let subject = format!("[{severity}] {}", parts.title);
    let host = cfg.smtp_host.clone();
    let port = cfg.smtp_port;
    let starttls = cfg.smtp_starttls;
    let user = cfg.smtp_user.clone();
    let pass = cfg.smtp_pass.clone();
    let fut = tokio::task::spawn_blocking(move || -> Result<()> {
        let email = Message::builder()
            .from(from.parse()?)
            .to(to.parse()?)
            .subject(subject)
            .header(ContentType::TEXT_PLAIN)
            .body(body)?;
        let creds = Credentials::new(user, pass);
        let builder = if starttls {
            SmtpTransport::starttls_relay(&host)?
        } else {
            SmtpTransport::builder_dangerous(&host)
        };
        let mailer = builder.port(port).credentials(creds).build();
        mailer.send(&email).context("smtp send")?;
        Ok(())
    });
    match timeout(Duration::from_secs(timeout_s), fut).await {
        Ok(Ok(Ok(()))) => true,
        Ok(Ok(Err(err))) => {
            tracing::warn!("smtp send failed: {}", err);
            false
        }
        Ok(Err(err)) => {
            tracing::warn!("smtp task failed: {}", err);
            false
        }
        Err(_) => {
            tracing::warn!("smtp send timed out");
            false
        }
    }
}

fn pick_policy(cfg: &RuntimeConfig, labels: &HashMap<String, String>) -> (DeliveryPolicy, String) {
    for (idx, rule) in cfg.delivery.rules.iter().enumerate() {
        if matcher_matches(&rule.r#match, labels)
            && let Some(policy) = resolve_policy(cfg, &rule.policy)
        {
            return (policy, format!("rule#{}→{}", idx + 1, rule.policy));
        }
    }
    if let Some(policy) = resolve_policy(cfg, &cfg.delivery.default_policy) {
        return (policy, format!("default→{}", cfg.delivery.default_policy));
    }
    (legacy_cascade_policy(cfg), "fallback→legacy".into())
}

fn resolve_policy(cfg: &RuntimeConfig, name: &str) -> Option<DeliveryPolicy> {
    if name == "cascade" {
        return Some(legacy_cascade_policy(cfg));
    }
    cfg.delivery
        .policies
        .iter()
        .find(|p| p.name == name)
        .cloned()
}

fn legacy_cascade_policy(cfg: &RuntimeConfig) -> DeliveryPolicy {
    DeliveryPolicy {
        name: "cascade".into(),
        mode: "cascade".into(),
        tiers: if cfg.tiers.is_empty() {
            default_tiers()
        } else {
            cfg.tiers.clone()
        },
    }
}

fn matcher_matches(matcher: &HashMap<String, String>, labels: &HashMap<String, String>) -> bool {
    for (k, v) in matcher {
        let actual = labels.get(k).map(String::as_str).unwrap_or("");
        if let Some(pattern) = v.strip_prefix("re:") {
            if !Regex::new(pattern)
                .map(|r| r.is_match(actual))
                .unwrap_or(false)
            {
                return false;
            }
        } else if actual != v {
            return false;
        }
    }
    true
}

#[allow(clippy::too_many_arguments)]
pub fn audit_log_delivery(
    state: &AppState,
    severity: &str,
    parts: &Parts,
    labels: &HashMap<String, String>,
    source: &str,
    tiers_attempted: &[String],
    ok: bool,
    channel: &str,
    started_at: f64,
) {
    let ended_at = now_epoch();
    let record = json!({
        "audit": "delivery",
        "source": source,
        "severity": severity,
        "alertname": labels.get("alertname").cloned().unwrap_or_else(|| parts.title.chars().take(120).collect()),
        "component": labels.get("component").cloned().unwrap_or_default(),
        "host": labels.get("host").or_else(|| labels.get("instance_name")).cloned().unwrap_or_default(),
        "title": parts.title.chars().take(200).collect::<String>(),
        "tiers_attempted": tiers_attempted,
        "ok": ok,
        "channel": channel,
        "duration_ms": ((ended_at - started_at) * 1000.0) as i64,
        "timestamp": (ended_at * 1000.0) as i64,
    });
    tracing::info!("AUDIT {}", record);
    state.metric_inc(
        "klaxond_deliveries_total",
        &[
            ("source", source),
            ("severity", severity),
            ("channel", channel),
            ("ok", if ok { "1" } else { "0" }),
        ],
        1,
    );
}

async fn render_alert_image(
    state: &AppState,
    cfg: &RuntimeConfig,
    slug: &str,
    instance: &str,
    panel: Option<u64>,
) -> Option<Vec<u8>> {
    if cfg.grafana_render_base.is_empty()
        || cfg.grafana_render_token.is_empty()
        || slug.is_empty()
        || !slug.starts_with("/d/")
    {
        return None;
    }
    let uid = slug
        .trim_start_matches("/d/")
        .split(['/', '?'])
        .next()
        .unwrap_or("");
    let pid = match panel {
        Some(pid) => Some(pid),
        None => first_render_panel(state, cfg, uid).await,
    };
    let url = if let Some(pid) = pid {
        let mut params = vec![
            ("orgId", "1".to_string()),
            ("theme", "dark".into()),
            ("width", "1000".into()),
            ("height", "500".into()),
            ("panelId", pid.to_string()),
            ("from", "now-3h".into()),
            ("to", "now".into()),
        ];
        if !instance.is_empty() {
            params.push(("var-instance", instance.to_string()));
        }
        format!(
            "{}/render/d-solo/{}/x?{}",
            cfg.grafana_render_base,
            uid,
            serde_urlencoded(params)
        )
    } else {
        let mut params = vec![
            ("orgId", "1".to_string()),
            ("theme", "dark".into()),
            ("width", "1000".into()),
            ("height", "800".into()),
            ("from", "now-3h".into()),
            ("to", "now".into()),
        ];
        if !instance.is_empty() {
            params.push(("var-instance", instance.to_string()));
        }
        format!(
            "{}/render{}?{}",
            cfg.grafana_render_base,
            slug,
            serde_urlencoded(params)
        )
    };
    match state
        .http
        .get(url)
        .timeout(Duration::from_secs(25))
        .bearer_auth(&cfg.grafana_render_token)
        .send()
        .await
    {
        Ok(resp) if resp.status().is_success() => {
            let bytes = resp.bytes().await.ok()?.to_vec();
            if bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
                Some(bytes)
            } else {
                tracing::warn!("render: non-PNG response ({} bytes)", bytes.len());
                None
            }
        }
        Ok(resp) => {
            tracing::warn!("render: Grafana returned {}", resp.status());
            None
        }
        Err(err) => {
            tracing::warn!("render: failed: {}", err);
            None
        }
    }
}

async fn first_render_panel(state: &AppState, cfg: &RuntimeConfig, uid: &str) -> Option<u64> {
    if cfg.grafana_render_base.is_empty() || uid.is_empty() {
        return None;
    }
    let base = cfg.grafana_render_base.trim_end_matches('/');
    let url = format!("{}/api/dashboards/uid/{}", base, urlencoding::encode(uid));
    let resp = state
        .http
        .get(url)
        .timeout(Duration::from_secs(10))
        .bearer_auth(&cfg.grafana_render_token)
        .send()
        .await
        .ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let body = resp.json::<Value>().await.ok()?;
    first_render_panel_from_dashboard(&body)
}

fn first_render_panel_from_dashboard(body: &Value) -> Option<u64> {
    let panels = body
        .get("dashboard")
        .and_then(|d| d.get("panels"))
        .and_then(Value::as_array)?;
    first_render_panel_in(panels)
}

fn first_render_panel_in(panels: &[Value]) -> Option<u64> {
    for panel in panels {
        let panel_type = panel.get("type").and_then(Value::as_str).unwrap_or("");
        if !matches!(
            panel_type,
            "row" | "text" | "news" | "dashlist" | "alertlist"
        ) && let Some(id) = panel.get("id").and_then(Value::as_u64)
        {
            return Some(id);
        }
        if let Some(nested) = panel.get("panels").and_then(Value::as_array)
            && let Some(id) = first_render_panel_in(nested)
        {
            return Some(id);
        }
    }
    None
}

fn serde_urlencoded(params: Vec<(&str, String)>) -> String {
    params
        .into_iter()
        .map(|(k, v)| format!("{}={}", urlencoding::encode(k), urlencoding::encode(&v)))
        .collect::<Vec<_>>()
        .join("&")
}

#[cfg(test)]
mod tests {
    use super::{
        first_render_panel_from_dashboard, post_to_ntfy, post_to_smtp, post_to_telegram,
        render_alert_image,
    };
    use crate::config::{NtfyTopic, Paths};
    use crate::parsers::Parts;
    use crate::state::AppState;
    use serde_json::json;
    use std::io::{BufRead, BufReader, Write};
    use std::path::PathBuf;
    use std::time::Duration as StdDuration;
    use tempfile::TempDir;
    use tokio::net::TcpListener;
    use tokio::sync::oneshot;

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

    fn test_state() -> (TempDir, AppState) {
        let tmp = TempDir::new().unwrap();
        let state = AppState::new(temp_paths(&tmp)).unwrap();
        (tmp, state)
    }

    fn sample_parts() -> Parts {
        Parts {
            title: "Test alert".into(),
            body: "alert body".into(),
            tags: vec!["warning".into()],
            actions: vec![[
                "view".into(),
                "Open".into(),
                "http://example.test/runbook".into(),
            ]],
            priority: "urgent".into(),
            alertname: "TestAlert".into(),
            skip_snooze: false,
            render_slug: None,
            render_panel: None,
            render_instance: String::new(),
            attach_url: None,
        }
    }

    fn http_response(content_type: &str, body: &[u8]) -> Vec<u8> {
        let mut response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: {content_type}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .into_bytes();
        response.extend_from_slice(body);
        response
    }

    async fn spawn_http_once(response: Vec<u8>) -> (String, oneshot::Receiver<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = oneshot::channel();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let request = read_http_request(&stream).await;
            let _ = tx.send(String::from_utf8_lossy(&request).to_string());
            write_all(&stream, &response).await;
        });
        (format!("http://{addr}"), rx)
    }

    async fn read_http_request(stream: &tokio::net::TcpStream) -> Vec<u8> {
        let mut buf = vec![0_u8; 4096];
        let mut read = 0;
        loop {
            if read == buf.len() {
                buf.resize(buf.len() * 2, 0);
            }
            stream.readable().await.unwrap();
            match stream.try_read(&mut buf[read..]) {
                Ok(0) => break,
                Ok(n) => {
                    read += n;
                    if request_complete(&buf[..read]) {
                        break;
                    }
                }
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => continue,
                Err(err) => panic!("read fake HTTP request: {err}"),
            }
        }
        buf.truncate(read);
        buf
    }

    async fn write_all(stream: &tokio::net::TcpStream, mut bytes: &[u8]) {
        while !bytes.is_empty() {
            stream.writable().await.unwrap();
            match stream.try_write(bytes) {
                Ok(0) => panic!("fake HTTP socket closed while writing"),
                Ok(n) => bytes = &bytes[n..],
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => continue,
                Err(err) => panic!("write fake HTTP response: {err}"),
            }
        }
    }

    fn request_complete(buf: &[u8]) -> bool {
        let Some(header_end) = buf.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4) else {
            return false;
        };
        let headers = String::from_utf8_lossy(&buf[..header_end]);
        for line in headers.lines() {
            let Some((name, value)) = line.split_once(':') else {
                continue;
            };
            if name.eq_ignore_ascii_case("content-length") {
                let len = value.trim().parse::<usize>().unwrap_or(0);
                return buf.len().saturating_sub(header_end) >= len;
            }
        }
        true
    }

    #[test]
    fn first_panel_skips_non_renderable_dashboard_blocks() {
        let body = json!({
            "dashboard": {
                "panels": [
                    { "id": 1, "type": "row", "panels": [
                        { "id": 2, "type": "text" },
                        { "id": 7, "type": "timeseries" }
                    ]},
                    { "id": 9, "type": "stat" }
                ]
            }
        });

        assert_eq!(first_render_panel_from_dashboard(&body), Some(7));
    }

    #[tokio::test]
    async fn ntfy_posts_to_fake_server_with_bearer_token() {
        let (_tmp, state) = test_state();
        let (base, request_rx) = spawn_http_once(http_response("text/plain", b"ok")).await;
        let mut cfg = state.cfg();
        cfg.ntfy_url = base;
        cfg.ntfy_topics = vec![NtfyTopic {
            name: "critical-topic".into(),
            token: "secret-token".into(),
            handles: vec!["critical".into()],
        }];
        cfg.public_url = "http://klaxond.test".into();
        state.replace_config(cfg);

        assert!(post_to_ntfy(&state, "critical", &sample_parts(), 2).await);
        let request = request_rx.await.unwrap();
        let lower = request.to_ascii_lowercase();

        assert!(request.starts_with("POST /critical-topic HTTP/1.1"));
        assert!(lower.contains("authorization: bearer secret-token"));
        assert!(lower.contains("title: =?utf-8?b?"));
        assert!(lower.contains("priority: urgent"));
        assert!(request.contains("alert body"));
    }

    #[tokio::test]
    async fn telegram_posts_to_fake_server_without_real_api() {
        let (_tmp, state) = test_state();
        let (base, request_rx) =
            spawn_http_once(http_response("application/json", b"{\"ok\":true}")).await;
        let mut cfg = state.cfg();
        cfg.telegram_api_base = base;
        cfg.tg_token = "123:abc".into();
        cfg.tg_chat = "42".into();
        state.replace_config(cfg);

        assert!(post_to_telegram(&state, "warning", &sample_parts(), 2).await);
        let request = request_rx.await.unwrap();
        let lower = request.to_ascii_lowercase();

        assert!(request.starts_with("POST /bot123:abc/sendMessage HTTP/1.1"));
        assert!(lower.contains("content-type: application/x-www-form-urlencoded"));
        assert!(request.contains("chat_id=42"));
        assert!(request.contains("parse_mode=HTML"));
        assert!(request.contains("disable_web_page_preview=true"));
        assert!(request.contains("severity%3A+%3Ccode%3Ewarning%3C%2Fcode%3E"));
    }

    #[tokio::test]
    async fn render_uses_fake_grafana_and_accepts_png() {
        let (_tmp, state) = test_state();
        let png = b"\x89PNG\r\n\x1a\nfake-png";
        let (base, request_rx) = spawn_http_once(http_response("image/png", png)).await;
        let mut cfg = state.cfg();
        cfg.grafana_render_base = base;
        cfg.grafana_render_token = "grafana-token".into();
        state.replace_config(cfg);
        let cfg = state.cfg();

        let rendered = render_alert_image(
            &state,
            &cfg,
            "/d/renderuid/node-overview",
            "host-a",
            Some(7),
        )
        .await
        .unwrap();
        let request = request_rx.await.unwrap();
        let lower = request.to_ascii_lowercase();

        assert_eq!(rendered, png);
        assert!(request.starts_with("GET /render/d-solo/renderuid/x?"));
        assert!(request.contains("panelId=7"));
        assert!(request.contains("var-instance=host-a"));
        assert!(lower.contains("authorization: bearer grafana-token"));
    }

    #[tokio::test]
    async fn smtp_posts_to_fake_server_without_starttls() {
        let (_tmp, state) = test_state();
        let (host, port, transcript_rx) = spawn_smtp_once();
        let mut cfg = state.cfg();
        cfg.smtp_host = host;
        cfg.smtp_port = port;
        cfg.smtp_starttls = false;
        cfg.smtp_user = "sender@example.test".into();
        cfg.smtp_pass = "secret".into();
        cfg.smtp_from = "sender@example.test".into();
        cfg.smtp_to = "ops@example.test".into();
        state.replace_config(cfg);

        assert!(post_to_smtp(&state, "critical", &sample_parts(), 5).await);
        let transcript = transcript_rx
            .recv_timeout(StdDuration::from_secs(2))
            .unwrap();
        let upper = transcript.to_ascii_uppercase();

        assert!(upper.contains("AUTH "));
        assert!(upper.contains("MAIL FROM:<SENDER@EXAMPLE.TEST>"));
        assert!(upper.contains("RCPT TO:<OPS@EXAMPLE.TEST>"));
        assert!(transcript.contains("Subject: [critical] Test alert"));
        assert!(transcript.contains("alert body"));
    }

    fn spawn_smtp_once() -> (String, u16, std::sync::mpsc::Receiver<String>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let transcript = handle_smtp_client(stream);
            let _ = tx.send(transcript);
        });
        ("127.0.0.1".into(), addr.port(), rx)
    }

    fn handle_smtp_client(mut stream: std::net::TcpStream) -> String {
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        let mut transcript = String::new();
        smtp_reply(&mut stream, "220 localhost ESMTP");
        let mut in_data = false;
        loop {
            let mut line = String::new();
            if reader.read_line(&mut line).unwrap() == 0 {
                break;
            }
            transcript.push_str(&line);
            let command = line.trim_end_matches(['\r', '\n']);
            if in_data {
                if command == "." {
                    smtp_reply(&mut stream, "250 queued");
                    in_data = false;
                }
                continue;
            }
            let upper = command.to_ascii_uppercase();
            if upper.starts_with("EHLO") || upper.starts_with("HELO") {
                smtp_reply(&mut stream, "250-localhost");
                smtp_reply(&mut stream, "250-AUTH PLAIN LOGIN");
                smtp_reply(&mut stream, "250 OK");
            } else if upper == "AUTH LOGIN" {
                smtp_reply(&mut stream, "334 VXNlcm5hbWU6");
                read_smtp_line(&mut reader, &mut transcript);
                smtp_reply(&mut stream, "334 UGFzc3dvcmQ6");
                read_smtp_line(&mut reader, &mut transcript);
                smtp_reply(&mut stream, "235 authenticated");
            } else if upper == "AUTH PLAIN" {
                smtp_reply(&mut stream, "334 ");
                read_smtp_line(&mut reader, &mut transcript);
                smtp_reply(&mut stream, "235 authenticated");
            } else if upper.starts_with("AUTH PLAIN ") {
                smtp_reply(&mut stream, "235 authenticated");
            } else if upper.starts_with("MAIL FROM") || upper.starts_with("RCPT TO") {
                smtp_reply(&mut stream, "250 OK");
            } else if upper == "DATA" {
                smtp_reply(&mut stream, "354 end with dot");
                in_data = true;
            } else if upper == "QUIT" {
                smtp_reply(&mut stream, "221 bye");
                break;
            } else {
                smtp_reply(&mut stream, "250 OK");
            }
        }
        transcript
    }

    fn read_smtp_line(reader: &mut BufReader<std::net::TcpStream>, transcript: &mut String) {
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        transcript.push_str(&line);
    }

    fn smtp_reply(stream: &mut std::net::TcpStream, line: &str) {
        stream.write_all(line.as_bytes()).unwrap();
        stream.write_all(b"\r\n").unwrap();
        stream.flush().unwrap();
    }
}
