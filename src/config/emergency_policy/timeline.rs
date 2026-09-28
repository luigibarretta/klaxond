pub fn emergency_timeline(profile: &EmergencyProfile) -> Vec<EmergencyTimelineEvent> {
    let mut events = initial_events(profile);
    events.extend(retry_events(profile));
    events.extend(terminal_events(profile, &events));
    events.sort_by_key(|event| event.at_seconds);
    events
}

fn initial_events(profile: &EmergencyProfile) -> Vec<EmergencyTimelineEvent> {
    let mut events = vec![EmergencyTimelineEvent {
        at_seconds: 0,
        attempt: Some(1),
        kind: "initial".to_string(),
        channel: Some("ntfy".to_string()),
    }];
    for (channel, enabled, after_attempts) in [
        (
            "telegram",
            profile.telegram.enabled,
            profile.telegram.after_attempts,
        ),
        ("smtp", profile.smtp.enabled, profile.smtp.after_attempts),
    ] {
        if enabled && after_attempts == 1 {
            events.push(EmergencyTimelineEvent {
                at_seconds: 0,
                attempt: Some(1),
                kind: "escalation".to_string(),
                channel: Some(channel.to_string()),
            });
        }
    }
    events
}

fn retry_events(profile: &EmergencyProfile) -> Vec<EmergencyTimelineEvent> {
    let mut events = Vec::new();
    for attempt in 2..=profile.max_attempts {
        let at_seconds = u64::from(attempt - 1).saturating_mul(profile.retry_seconds);
        if at_seconds >= profile.expire_seconds {
            break;
        }
        events.push(EmergencyTimelineEvent {
            at_seconds,
            attempt: Some(attempt),
            kind: "retry".to_string(),
            channel: Some("ntfy".to_string()),
        });
        for (channel, enabled, after_attempts) in [
            (
                "telegram",
                profile.telegram.enabled,
                profile.telegram.after_attempts,
            ),
            ("smtp", profile.smtp.enabled, profile.smtp.after_attempts),
        ] {
            if enabled && after_attempts == attempt {
                events.push(EmergencyTimelineEvent {
                    at_seconds,
                    attempt: Some(attempt),
                    kind: "escalation".to_string(),
                    channel: Some(channel.to_string()),
                });
            }
        }
    }
    events
}

fn terminal_events(
    profile: &EmergencyProfile,
    events: &[EmergencyTimelineEvent],
) -> Vec<EmergencyTimelineEvent> {
    let mut terminal = Vec::new();
    let attempts = events
        .iter()
        .filter_map(|event| event.attempt)
        .max()
        .unwrap_or(1);
    if attempts >= profile.max_attempts {
        terminal.push(EmergencyTimelineEvent {
            at_seconds: u64::from(profile.max_attempts.saturating_sub(1))
                .saturating_mul(profile.retry_seconds),
            attempt: Some(profile.max_attempts),
            kind: "attempt-limit".to_string(),
            channel: None,
        });
    }
    terminal.push(EmergencyTimelineEvent {
        at_seconds: profile.expire_seconds,
        attempt: None,
        kind: "expiry".to_string(),
        channel: None,
    });
    terminal
}
use super::super::EmergencyProfile;
use serde::Serialize;

#[derive(Clone, Debug, Serialize)]
pub struct EmergencyTimelineEvent {
    pub at_seconds: u64,
    pub attempt: Option<u32>,
    pub kind: String,
    pub channel: Option<String>,
}
