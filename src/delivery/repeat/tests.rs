use super::{RepeatGate, fingerprint, repeat_candidate, reservation_ttl_s, reserve};
use crate::config::{DeliveryPolicy, NtfyTopic, Tier};
use crate::delivery::tests::support::test_state;
use crate::parsers::{Parts, action};

fn parts(title: &str, body: &str) -> Parts {
    Parts {
        title: title.to_string(),
        body: body.to_string(),
        tags: vec!["warning".to_string(), "grafana".to_string()],
        actions: vec![action("view", "Dashboard", "https://example.test")],
        priority: "high".to_string(),
        alertname: "HostDown".to_string(),
        skip_snooze: false,
        render_slug: None,
        render_panel: None,
        render_instance: String::new(),
        attach_url: None,
    }
}

#[test]
fn fingerprint_tracks_all_stable_rendered_content() {
    let first = parts("Host down", "node-a");
    let mut changed_action = first.clone();
    changed_action.actions = vec![action(
        "view",
        "Dashboard",
        "https://example.test/new-token",
    )];
    let changed = parts("Host down", "node-b");

    assert_ne!(
        fingerprint("grafana", "warning", &first),
        fingerprint("grafana", "warning", &changed_action)
    );
    assert_ne!(
        fingerprint("grafana", "warning", &first),
        fingerprint("grafana", "warning", &changed)
    );
}

#[test]
fn fingerprint_ignores_generated_attachment_url() {
    let first = parts("Host down", "node-a");
    let mut with_attachment = first.clone();
    with_attachment.attach_url = Some("https://example.test/img/random-token.png".to_string());

    assert_eq!(
        fingerprint("grafana", "warning", &first),
        fingerprint("grafana", "warning", &with_attachment)
    );
}

#[test]
fn reservation_lease_covers_render_and_all_channel_timeouts() {
    let (_tmp, state) = test_state();
    let mut cfg = state.cfg();
    cfg.ntfy_topics = vec![
        NtfyTopic {
            name: "one".into(),
            token: "token".into(),
            handles: vec!["warning".into()],
        },
        NtfyTopic {
            name: "two".into(),
            token: "token".into(),
            handles: vec!["warning".into()],
        },
    ];
    let policy = DeliveryPolicy {
        name: "all".to_string(),
        mode: "broadcast".to_string(),
        tiers: vec![
            Tier {
                name: "ntfy".to_string(),
                timeout_seconds: 30,
            },
            Tier {
                name: "smtp".to_string(),
                timeout_seconds: 60,
            },
        ],
    };
    let mut rendered = parts("Host down", "node-a");
    rendered.render_slug = Some("/d/host/host".to_string());

    assert_eq!(
        reservation_ttl_s(&cfg, "warning", &policy, true, &rendered),
        185.0
    );
}

#[tokio::test]
async fn in_flight_duplicate_takes_over_after_first_delivery_fails() {
    let (_tmp, state) = test_state();
    let mut cfg = state.cfg();
    cfg.dedup
        .get_mut("grafana")
        .expect("grafana setting")
        .repeat_suppression_enabled = true;
    let rendered = parts("Host down", "node-a");
    let policy = DeliveryPolicy {
        name: "ntfy".into(),
        mode: "cascade".into(),
        tiers: vec![Tier {
            name: "ntfy".into(),
            timeout_seconds: 5,
        }],
    };
    let fingerprint = fingerprint("grafana", "warning", &rendered);
    let store = state.history_store();
    let initial = repeat_candidate(
        fingerprint.clone(),
        "grafana",
        "warning",
        &rendered,
        7_200,
        120.0,
    );
    let initial_token = initial.reservation_token.clone();
    assert!(matches!(
        store.reserve_repeat(&initial).unwrap(),
        crate::history::RepeatDecision::Deliver { .. }
    ));

    let waiting = reserve(
        &state, &cfg, "grafana", "warning", &rendered, &policy, false,
    );
    let release = async {
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        store
            .complete_repeat(&fingerprint, &initial_token, None)
            .unwrap();
    };
    let (gate, ()) = tokio::join!(waiting, release);

    assert!(matches!(gate, RepeatGate::Deliver(Some(_))));
}
