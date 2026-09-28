use super::{PostgresCommand, PostgresWorker};
use crate::history::{AuthSessionRecord, OidcLogoutResult, OidcLogoutTokenRecord};
use anyhow::{Context, Result};
use std::sync::mpsc;

mod command;

pub(super) use command::{SessionCommand, execute};

impl PostgresWorker {
    pub(in crate::history) fn create_auth_session(
        &self,
        record: &AuthSessionRecord,
        replace_id_hash: Option<&str>,
        max_concurrent: usize,
        now: i64,
    ) -> Result<()> {
        self.session_request(
            |reply| SessionCommand::Create {
                record: record.clone(),
                replace_id_hash: replace_id_hash.map(str::to_string),
                max_concurrent,
                now,
                reply,
            },
            "session creation",
        )
    }

    pub(in crate::history) fn auth_session(
        &self,
        id_hash: &str,
        now: i64,
        idle_timeout_seconds: i64,
    ) -> Result<Option<AuthSessionRecord>> {
        self.session_request(
            |reply| SessionCommand::Lookup {
                id_hash: id_hash.to_string(),
                now,
                idle_timeout_seconds,
                reply,
            },
            "session lookup",
        )
    }

    pub(in crate::history) fn auth_session_rotation_successor(
        &self,
        predecessor_hash: &str,
        successor_hash: &str,
        now: i64,
        idle_timeout_seconds: i64,
    ) -> Result<Option<AuthSessionRecord>> {
        self.session_request(
            |reply| SessionCommand::LookupRotationSuccessor {
                predecessor_hash: predecessor_hash.to_string(),
                successor_hash: successor_hash.to_string(),
                now,
                idle_timeout_seconds,
                reply,
            },
            "session rotation successor lookup",
        )
    }

    pub(in crate::history) fn revoke_auth_session(&self, id_hash: &str, now: i64) -> Result<bool> {
        self.session_request(
            |reply| SessionCommand::Revoke {
                id_hash: id_hash.to_string(),
                now,
                reply,
            },
            "session revocation",
        )
    }

    pub(in crate::history) fn revoke_auth_session_family(
        &self,
        id_hash: &str,
        now: i64,
    ) -> Result<usize> {
        self.session_request(
            |reply| SessionCommand::RevokeFamily {
                id_hash: id_hash.to_string(),
                now,
                reply,
            },
            "session family revocation",
        )
    }

    pub(in crate::history) fn consume_oidc_logout(
        &self,
        token: &OidcLogoutTokenRecord,
        provider_session_id: Option<&str>,
        subject: Option<&str>,
        now: i64,
    ) -> Result<OidcLogoutResult> {
        self.session_request(
            |reply| SessionCommand::ConsumeOidcLogout {
                token: token.clone(),
                provider_session_id: provider_session_id.map(str::to_string),
                subject: subject.map(str::to_string),
                now,
                reply,
            },
            "OIDC logout",
        )
    }

    pub(in crate::history) fn export_auth_sessions(&self) -> Result<Vec<AuthSessionRecord>> {
        self.session_request(
            |reply| SessionCommand::ExportSessions { reply },
            "session export",
        )
    }

    pub(in crate::history) fn export_oidc_logout_tokens(
        &self,
    ) -> Result<Vec<OidcLogoutTokenRecord>> {
        self.session_request(
            |reply| SessionCommand::ExportLogoutTokens { reply },
            "OIDC logout token export",
        )
    }

    fn session_request<T>(
        &self,
        command: impl FnOnce(mpsc::Sender<Result<T>>) -> SessionCommand,
        operation: &str,
    ) -> Result<T> {
        let (reply, result) = mpsc::channel();
        self.tx
            .send(PostgresCommand::Session(command(reply)))
            .with_context(|| format!("send postgres history {operation} request"))?;
        result
            .recv()
            .with_context(|| format!("receive postgres history {operation} response"))?
    }
}
