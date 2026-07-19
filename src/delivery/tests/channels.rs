use super::super::channels::{
    post_to_ntfy, post_to_ntfy_with_config, post_to_smtp, post_to_telegram,
};
use super::support::{
    http_response, sample_parts, smtp_transcript_timeout, spawn_http_once, spawn_smtp_once,
    test_state,
};
use crate::config::NtfyTopic;

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
async fn ntfy_dispatch_uses_the_reserved_config_snapshot() {
    let (_tmp, state) = test_state();
    let (base, request_rx) = spawn_http_once(http_response("text/plain", b"ok")).await;
    let mut snapshot = state.cfg();
    snapshot.ntfy_url = base;
    snapshot.ntfy_topics = vec![NtfyTopic {
        name: "warning-topic".into(),
        token: "snapshot-token".into(),
        handles: vec!["warning".into()],
    }];
    let mut replacement = snapshot.clone();
    replacement.ntfy_url = "http://127.0.0.1:9".into();
    replacement.ntfy_topics.push(NtfyTopic {
        name: "late-topic".into(),
        token: "late-token".into(),
        handles: vec!["warning".into()],
    });
    state.replace_config(replacement);

    assert!(post_to_ntfy_with_config(&state, &snapshot, "warning", &sample_parts(), 2).await);
    let request = request_rx.await.unwrap();
    assert!(request.starts_with("POST /warning-topic HTTP/1.1"));
    assert!(!request.contains("late-token"));
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
        .recv_timeout(smtp_transcript_timeout())
        .unwrap();
    let upper = transcript.to_ascii_uppercase();

    assert!(upper.contains("AUTH "));
    assert!(upper.contains("MAIL FROM:<SENDER@EXAMPLE.TEST>"));
    assert!(upper.contains("RCPT TO:<OPS@EXAMPLE.TEST>"));
    assert!(transcript.contains("Subject: [critical] Test alert"));
    assert!(transcript.contains("alert body"));
}
