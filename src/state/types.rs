use crate::history::DeliveryEntry;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Mutex;
use webauthn_rs::prelude::{PasskeyAuthentication, PasskeyRegistration, Uuid};

#[derive(Clone)]
pub struct RenderedImage {
    pub bytes: Vec<u8>,
    pub expires_at: f64,
}

#[derive(Clone, Debug)]
pub struct PendingOidcState {
    pub created_at: f64,
    pub return_to: String,
    pub nonce: String,
    pub code_verifier: String,
}

#[derive(Clone, Debug)]
pub struct PendingStepUpState {
    pub created_at: f64,
    pub return_to: String,
    pub user: crate::auth::User,
    pub factor: String,
    pub reason: String,
}

#[derive(Clone, Debug)]
pub struct PendingMagicLink {
    pub created_at: f64,
    pub expires_at: f64,
    pub username: String,
    pub return_to: String,
    pub used_at: Option<f64>,
}

#[derive(Clone, Debug)]
pub struct Suppression {
    pub rule_idx: usize,
    pub anchor: Option<String>,
    pub expiry: f64,
}

#[derive(Default)]
pub struct Metrics {
    pub counters: Mutex<HashMap<String, i64>>,
    pub gauges: Mutex<HashMap<String, f64>>,
}

#[derive(Default, Debug)]
pub struct DedupQueues {
    pub queues: HashMap<String, Vec<DedupItem>>,
    pub timer_active: HashMap<String, bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DedupItem {
    pub ts: f64,
    pub source: String,
    pub severity: String,
    pub payload: Value,
    pub parts: crate::parsers::Parts,
    pub common_labels: HashMap<String, String>,
    pub with_cascade: bool,
    pub dedup_key: String,
}

#[derive(Clone, Debug)]
pub struct PendingPasskeyRegistration {
    pub ts: f64,
    pub user_sub: String,
    pub user_name: String,
    pub user_email: String,
    pub user_uuid: Uuid,
    pub label: String,
    pub step_up: Option<String>,
    pub state: PasskeyRegistration,
}

#[derive(Clone, Debug)]
pub struct PendingPasskeyAuthentication {
    pub ts: f64,
    pub user_sub: String,
    pub rate_key: String,
    pub step_up: Option<String>,
    pub state: PasskeyAuthentication,
}

#[derive(Clone, Debug)]
pub struct PendingTotpRegistration {
    pub ts: f64,
    pub user_sub: String,
    pub user_name: String,
    pub user_email: String,
    pub label: String,
    pub step_up: String,
    pub secret: String,
}

pub type DeliveryLog = std::collections::VecDeque<DeliveryEntry>;
