use super::AuthAuditKind;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthOutcome {
    Success,
    Failure,
    Denied,
    Unknown,
}

impl AuthOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Failure => "failure",
            Self::Denied => "denied",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

impl RiskLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AuthRequestContext {
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub request_id: Option<String>,
    pub http_method: Option<String>,
    pub path: Option<String>,
}

impl AuthRequestContext {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn ip_address(mut self, value: impl Into<String>) -> Self {
        self.ip_address = Some(value.into());
        self
    }

    pub fn user_agent(mut self, value: impl Into<String>) -> Self {
        self.user_agent = Some(value.into());
        self
    }

    pub fn request_id(mut self, value: impl Into<String>) -> Self {
        self.request_id = Some(value.into());
        self
    }

    pub fn http_method(mut self, value: impl Into<String>) -> Self {
        self.http_method = Some(value.into());
        self
    }

    pub fn path(mut self, value: impl Into<String>) -> Self {
        self.path = Some(value.into());
        self
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthAuditEvent {
    pub kind: AuthAuditKind,
    pub outcome: AuthOutcome,
    pub risk_level: RiskLevel,
    pub subject: Option<String>,
    pub actor: Option<String>,
    pub method: Option<&'static str>,
    pub reason_code: Option<&'static str>,
    pub correlation_id: Option<String>,
    pub timestamp_epoch: Option<i64>,
    pub context: AuthRequestContext,
    pub details: Vec<(String, String)>,
}

impl AuthAuditEvent {
    pub fn builder(kind: AuthAuditKind) -> AuthAuditEventBuilder {
        AuthAuditEventBuilder::new(kind)
    }

    pub fn login_success(subject: impl Into<String>, method: &'static str) -> Self {
        Self::builder(AuthAuditKind::LoginSuccess)
            .outcome(AuthOutcome::Success)
            .risk_level(RiskLevel::Low)
            .subject(subject)
            .method(method)
            .build()
    }

    pub fn login_failure(subject: impl Into<String>, method: &'static str) -> Self {
        Self::builder(AuthAuditKind::LoginFailure)
            .outcome(AuthOutcome::Failure)
            .risk_level(RiskLevel::Medium)
            .subject(subject)
            .method(method)
            .build()
    }

    pub fn rate_limit_exceeded(subject: Option<String>, method: &'static str) -> Self {
        let mut builder = Self::builder(AuthAuditKind::RateLimitExceeded)
            .outcome(AuthOutcome::Denied)
            .risk_level(RiskLevel::High)
            .method(method);
        if let Some(subject) = subject {
            builder = builder.subject(subject);
        }
        builder.build()
    }

    pub fn brute_force_detected(method: &'static str) -> Self {
        Self::builder(AuthAuditKind::BruteForceDetected)
            .outcome(AuthOutcome::Denied)
            .risk_level(RiskLevel::Critical)
            .method(method)
            .build()
    }
}

#[derive(Clone, Debug)]
pub struct AuthAuditEventBuilder {
    event: AuthAuditEvent,
}

impl AuthAuditEventBuilder {
    pub fn new(kind: AuthAuditKind) -> Self {
        Self {
            event: AuthAuditEvent {
                kind,
                outcome: AuthOutcome::Unknown,
                risk_level: RiskLevel::Low,
                subject: None,
                actor: None,
                method: None,
                reason_code: None,
                correlation_id: None,
                timestamp_epoch: None,
                context: AuthRequestContext::default(),
                details: Vec::new(),
            },
        }
    }

    pub fn outcome(mut self, outcome: AuthOutcome) -> Self {
        self.event.outcome = outcome;
        self
    }

    pub fn risk_level(mut self, risk_level: RiskLevel) -> Self {
        self.event.risk_level = risk_level;
        self
    }

    pub fn subject(mut self, subject: impl Into<String>) -> Self {
        self.event.subject = Some(subject.into());
        self
    }

    pub fn actor(mut self, actor: impl Into<String>) -> Self {
        self.event.actor = Some(actor.into());
        self
    }

    pub fn method(mut self, method: &'static str) -> Self {
        self.event.method = Some(method);
        self
    }

    pub fn reason_code(mut self, reason_code: &'static str) -> Self {
        self.event.reason_code = Some(reason_code);
        self
    }

    pub fn correlation_id(mut self, correlation_id: impl Into<String>) -> Self {
        self.event.correlation_id = Some(correlation_id.into());
        self
    }

    pub fn timestamp_epoch(mut self, timestamp_epoch: i64) -> Self {
        self.event.timestamp_epoch = Some(timestamp_epoch);
        self
    }

    pub fn context(mut self, context: AuthRequestContext) -> Self {
        self.event.context = context;
        self
    }

    pub fn detail(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.event.details.push((key.into(), value.into()));
        self
    }

    pub fn build(self) -> AuthAuditEvent {
        self.event
    }
}
