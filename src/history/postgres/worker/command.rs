use super::super::{worker_rate_limit, worker_session};
use crate::history::{
    DeliveryActivity, DeliveryEntry, DeliveryPage, DeliveryQuery, EmergencyAttempt,
    EmergencyCandidate, EmergencyIncident, EmergencyRegistration, RepeatCandidate, RepeatDecision,
    RepeatState, RuntimeAuthState,
};
use anyhow::Result;
use std::sync::mpsc;

pub(in crate::history::postgres) enum PostgresCommand {
    Record {
        entry: DeliveryEntry,
        reply: mpsc::Sender<Result<()>>,
    },
    Page {
        query: DeliveryQuery,
        reply: mpsc::Sender<Result<DeliveryPage>>,
    },
    Activity {
        hours: u16,
        since: f64,
        until: f64,
        reply: mpsc::Sender<Result<DeliveryActivity>>,
    },
    ExportAll {
        reply: mpsc::Sender<Result<Vec<DeliveryEntry>>>,
    },
    ReserveRepeat {
        candidate: RepeatCandidate,
        reply: mpsc::Sender<Result<RepeatDecision>>,
    },
    CompleteRepeat {
        fingerprint: String,
        reservation_token: String,
        delivered_at: Option<f64>,
        reply: mpsc::Sender<Result<()>>,
    },
    RecentRepeatSuppressions {
        limit: usize,
        reply: mpsc::Sender<Result<Vec<RepeatState>>>,
    },
    ExportRepeatStates {
        reply: mpsc::Sender<Result<Vec<RepeatState>>>,
    },
    ImportRepeatState {
        state: RepeatState,
        reply: mpsc::Sender<Result<()>>,
    },
    ImportAuthState {
        state: RuntimeAuthState,
        reply: mpsc::Sender<Result<()>>,
    },
    EmergencyRegister {
        candidate: EmergencyCandidate,
        reply: mpsc::Sender<Result<EmergencyRegistration>>,
    },
    EmergencyMaterializePolicySnapshot {
        policy_id: String,
        policy_name: String,
        snapshot_json: String,
        reply: mpsc::Sender<Result<usize>>,
    },
    EmergencyInitialAttempt {
        attempt: EmergencyAttempt,
        reply: mpsc::Sender<Result<()>>,
    },
    EmergencyReserve {
        now: f64,
        lease_until: f64,
        token: String,
        reply: mpsc::Sender<Result<Option<EmergencyIncident>>>,
    },
    EmergencyAdjustLease {
        receipt: String,
        token: String,
        lease_until: f64,
        reply: mpsc::Sender<Result<bool>>,
    },
    EmergencyComplete {
        attempt: EmergencyAttempt,
        reply: mpsc::Sender<Result<bool>>,
    },
    EmergencyTerminalize {
        receipt: String,
        state: String,
        actor: String,
        now: f64,
        reply: mpsc::Sender<Result<Option<EmergencyIncident>>>,
    },
    EmergencyTerminalizeFingerprint {
        fingerprint: String,
        state: String,
        actor: String,
        now: f64,
        reply: mpsc::Sender<Result<Option<EmergencyIncident>>>,
    },
    EmergencyExpire {
        now: f64,
        limit: usize,
        reply: mpsc::Sender<Result<Vec<EmergencyIncident>>>,
    },
    EmergencyRetry {
        receipt: String,
        now: f64,
        reply: mpsc::Sender<Result<bool>>,
    },
    EmergencyGet {
        receipt: String,
        reply: mpsc::Sender<Result<Option<EmergencyIncident>>>,
    },
    EmergencyPage {
        state: Option<String>,
        limit: usize,
        reply: mpsc::Sender<Result<Vec<EmergencyIncident>>>,
    },
    EmergencyExport {
        reply: mpsc::Sender<Result<Vec<EmergencyIncident>>>,
    },
    EmergencyImport {
        incident: EmergencyIncident,
        reply: mpsc::Sender<Result<()>>,
    },
    EmergencyStats {
        now: f64,
        reply: mpsc::Sender<Result<(usize, f64)>>,
    },
    Session(worker_session::SessionCommand),
    RateLimit(worker_rate_limit::RateLimitCommand),
}

pub(super) enum CommandDomain {
    Delivery,
    Repeat,
    Auth,
    EmergencyRegistration,
    EmergencyAttempt,
    EmergencyTerminal,
    EmergencyState,
    Session,
    RateLimit,
}

impl PostgresCommand {
    pub(super) fn domain(&self) -> CommandDomain {
        match self {
            Self::Record { .. }
            | Self::Page { .. }
            | Self::Activity { .. }
            | Self::ExportAll { .. } => CommandDomain::Delivery,
            Self::ReserveRepeat { .. }
            | Self::CompleteRepeat { .. }
            | Self::RecentRepeatSuppressions { .. }
            | Self::ExportRepeatStates { .. }
            | Self::ImportRepeatState { .. } => CommandDomain::Repeat,
            Self::ImportAuthState { .. } => CommandDomain::Auth,
            Self::EmergencyRegister { .. } | Self::EmergencyMaterializePolicySnapshot { .. } => {
                CommandDomain::EmergencyRegistration
            }
            Self::EmergencyInitialAttempt { .. }
            | Self::EmergencyReserve { .. }
            | Self::EmergencyAdjustLease { .. }
            | Self::EmergencyComplete { .. } => CommandDomain::EmergencyAttempt,
            Self::EmergencyTerminalize { .. }
            | Self::EmergencyTerminalizeFingerprint { .. }
            | Self::EmergencyExpire { .. }
            | Self::EmergencyRetry { .. } => CommandDomain::EmergencyTerminal,
            Self::EmergencyGet { .. }
            | Self::EmergencyPage { .. }
            | Self::EmergencyExport { .. }
            | Self::EmergencyImport { .. }
            | Self::EmergencyStats { .. } => CommandDomain::EmergencyState,
            Self::Session(_) => CommandDomain::Session,
            Self::RateLimit(_) => CommandDomain::RateLimit,
        }
    }
}
