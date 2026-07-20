use auth_modules::rate_limit::PersistentRateLimitRecord;
use std::collections::BTreeSet;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthRateLimitRecord {
    pub key_hash: String,
    pub state: PersistentRateLimitRecord,
    pub updated_at: i64,
}

pub(in crate::history) fn merge_import(
    existing: Option<&AuthRateLimitRecord>,
    incoming: &AuthRateLimitRecord,
) -> AuthRateLimitRecord {
    let mut failure_epochs = BTreeSet::new();
    if let Some(existing) = existing {
        failure_epochs.extend(existing.state.failure_epochs.iter().copied());
    }
    failure_epochs.extend(incoming.state.failure_epochs.iter().copied());

    AuthRateLimitRecord {
        key_hash: incoming.key_hash.clone(),
        state: PersistentRateLimitRecord {
            failure_epochs: failure_epochs.into_iter().collect(),
            locked_until_epoch: strongest_lockout(
                existing.and_then(|record| record.state.locked_until_epoch),
                incoming.state.locked_until_epoch,
            ),
        },
        updated_at: existing
            .map(|record| record.updated_at.max(incoming.updated_at))
            .unwrap_or(incoming.updated_at),
    }
}

fn strongest_lockout(existing: Option<i64>, incoming: Option<i64>) -> Option<i64> {
    match (existing, incoming) {
        (Some(existing), Some(incoming)) => Some(existing.max(incoming)),
        (Some(existing), None) => Some(existing),
        (None, incoming) => incoming,
    }
}
