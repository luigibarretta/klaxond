use std::fmt;

use super::policy::{OneTimeTokenPolicy, OneTimeTokenPurpose};
use super::record::OneTimeTokenRecord;

/// The persistable half of an issued token: subject, purpose, SHA-256 hash
/// and expiry. It never contains the plaintext.
pub type StoredTokenHash = OneTimeTokenRecord;

/// The plaintext half of an issued one-time token.
///
/// The value can only leave this type through [`DeliverableToken::deliver`],
/// which hands it to an out-of-band [`TokenDelivery`] (mail, outbox file,
/// operator console) and returns `()` on success. It has no accessor, no
/// `Clone`, no `Display` and no `Serialize`, and `Debug` is redacted, so an
/// HTTP handler cannot put it in a response body by accident. Deliberate
/// exfiltration from inside a delivery closure is not prevented.
///
/// ```compile_fail
/// use auth_modules::one_time_token::{issue_for_delivery, OneTimeTokenPolicy, OneTimeTokenPurpose};
///
/// let (_record, token) = issue_for_delivery(
///     "alice",
///     OneTimeTokenPurpose::MagicLink,
///     OneTimeTokenPolicy::magic_link(),
///     0,
/// );
/// // There is no way to obtain the plaintext outside a delivery.
/// let body: String = token.to_string();
/// ```
///
/// ```compile_fail
/// use auth_modules::one_time_token::{issue_for_delivery, OneTimeTokenPolicy, OneTimeTokenPurpose};
///
/// let (_record, token) = issue_for_delivery(
///     "alice",
///     OneTimeTokenPurpose::MagicLink,
///     OneTimeTokenPolicy::magic_link(),
///     0,
/// );
/// let body = token.plaintext;
/// ```
#[must_use = "an issued token must be delivered or it is useless"]
pub struct DeliverableToken {
    plaintext: String,
    expires_at_epoch: i64,
}

impl DeliverableToken {
    pub fn expires_at_epoch(&self) -> i64 {
        self.expires_at_epoch
    }

    /// Consumes the token and passes the plaintext to `delivery`.
    pub fn deliver<D: TokenDelivery>(self, delivery: D) -> Result<(), D::Error> {
        delivery.deliver(&self.plaintext)
    }
}

impl fmt::Debug for DeliverableToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeliverableToken")
            .field("plaintext", &"[REDACTED]")
            .field("expires_at_epoch", &self.expires_at_epoch)
            .finish()
    }
}

/// An out-of-band channel that receives a one-time token exactly once.
///
/// Closures `FnOnce(&str) -> Result<(), E>` implement it, so a mailer can be
/// passed inline: `token.deliver(|token: &str| mailer.send_link(&email, token))`.
pub trait TokenDelivery {
    type Error;

    fn deliver(self, token: &str) -> Result<(), Self::Error>;
}

impl<F, E> TokenDelivery for F
where
    F: FnOnce(&str) -> Result<(), E>,
{
    type Error = E;

    fn deliver(self, token: &str) -> Result<(), E> {
        self(token)
    }
}

/// Issues a token whose plaintext can only be delivered out of band.
///
/// Persist the returned [`StoredTokenHash`] (it holds only the hash), then
/// call [`DeliverableToken::deliver`], and answer the HTTP request with
/// [`super::generic_delivery_acknowledgement`].
///
/// ```
/// use auth_modules::one_time_token::{
///     issue_for_delivery, OneTimeTokenPolicy, OneTimeTokenPurpose,
/// };
///
/// let (record, token) = issue_for_delivery(
///     "alice@example.test",
///     OneTimeTokenPurpose::MagicLink,
///     OneTimeTokenPolicy::magic_link(),
///     1_000,
/// );
/// // store `record` (hash only) in the database, then:
/// let mut outbox = Vec::new();
/// token
///     .deliver(|token: &str| {
///         outbox.push(format!("https://app.example.test/auth/magic?token={token}"));
///         Ok::<(), std::convert::Infallible>(())
///     })
///     .expect("delivery");
/// assert!(!outbox[0].contains(&record.token_hash));
/// ```
pub fn issue_for_delivery(
    subject: impl Into<String>,
    purpose: OneTimeTokenPurpose,
    policy: OneTimeTokenPolicy,
    now_epoch: i64,
) -> (StoredTokenHash, DeliverableToken) {
    let (plaintext, record) = super::issue_parts(subject.into(), purpose, policy, now_epoch);
    let token = DeliverableToken {
        plaintext,
        expires_at_epoch: record.expires_at_epoch,
    };
    (record, token)
}
