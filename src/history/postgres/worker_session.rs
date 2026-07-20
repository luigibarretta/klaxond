use super::{PostgresCommand, PostgresWorker, postgres_with_retry, session};
use crate::history::{AuthSessionRecord, OidcLogoutResult, OidcLogoutTokenRecord};
use anyhow::{Context, Result};
use postgres::Client;
use std::sync::mpsc;

pub(super) enum SessionCommand {
    Create {
        record: AuthSessionRecord,
        replace_id_hash: Option<String>,
        max_concurrent: usize,
        now: i64,
        reply: mpsc::Sender<Result<()>>,
    },
    Lookup {
        id_hash: String,
        now: i64,
        idle_timeout_seconds: i64,
        reply: mpsc::Sender<Result<Option<AuthSessionRecord>>>,
    },
    Revoke {
        id_hash: String,
        now: i64,
        reply: mpsc::Sender<Result<bool>>,
    },
    RevokeFamily {
        id_hash: String,
        now: i64,
        reply: mpsc::Sender<Result<usize>>,
    },
    ConsumeOidcLogout {
        token: OidcLogoutTokenRecord,
        provider_session_id: Option<String>,
        subject: Option<String>,
        now: i64,
        reply: mpsc::Sender<Result<OidcLogoutResult>>,
    },
    ExportSessions {
        reply: mpsc::Sender<Result<Vec<AuthSessionRecord>>>,
    },
    ExportLogoutTokens {
        reply: mpsc::Sender<Result<Vec<OidcLogoutTokenRecord>>>,
    },
}

pub(super) fn execute(
    command: SessionCommand,
    url: &str,
    create_schema: bool,
    client: &mut Client,
) {
    match command {
        SessionCommand::Create {
            record,
            replace_id_hash,
            max_concurrent,
            now,
            reply,
        } => {
            let result = postgres_with_retry(url, create_schema, client, |client| {
                session::create(
                    client,
                    &record,
                    replace_id_hash.as_deref(),
                    max_concurrent,
                    now,
                )
            });
            let _ = reply.send(result);
        }
        SessionCommand::Lookup {
            id_hash,
            now,
            idle_timeout_seconds,
            reply,
        } => {
            let result = postgres_with_retry(url, create_schema, client, |client| {
                session::lookup(client, &id_hash, now, idle_timeout_seconds)
            });
            let _ = reply.send(result);
        }
        SessionCommand::Revoke {
            id_hash,
            now,
            reply,
        } => {
            let result = postgres_with_retry(url, create_schema, client, |client| {
                session::revoke(client, &id_hash, now)
            });
            let _ = reply.send(result);
        }
        SessionCommand::RevokeFamily {
            id_hash,
            now,
            reply,
        } => {
            let result = postgres_with_retry(url, create_schema, client, |client| {
                session::revoke_family_by_id(client, &id_hash, now)
            });
            let _ = reply.send(result);
        }
        SessionCommand::ConsumeOidcLogout {
            token,
            provider_session_id,
            subject,
            now,
            reply,
        } => {
            let result = postgres_with_retry(url, create_schema, client, |client| {
                session::consume_oidc_logout(
                    client,
                    &token,
                    provider_session_id.as_deref(),
                    subject.as_deref(),
                    now,
                )
            });
            let _ = reply.send(result);
        }
        SessionCommand::ExportSessions { reply } => {
            let result = postgres_with_retry(url, create_schema, client, session::export_sessions);
            let _ = reply.send(result);
        }
        SessionCommand::ExportLogoutTokens { reply } => {
            let result =
                postgres_with_retry(url, create_schema, client, session::export_logout_tokens);
            let _ = reply.send(result);
        }
    }
}

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
