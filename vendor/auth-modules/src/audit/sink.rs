use super::AuthAuditEvent;

pub trait AuditSink {
    type Error;

    fn record(&self, event: &AuthAuditEvent) -> Result<(), Self::Error>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct NoopAuditSink;

impl AuditSink for NoopAuditSink {
    type Error = core::convert::Infallible;

    fn record(&self, _event: &AuthAuditEvent) -> Result<(), Self::Error> {
        Ok(())
    }
}
