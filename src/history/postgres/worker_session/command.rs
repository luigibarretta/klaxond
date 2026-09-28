use super::super::{postgres_with_retry, session};
use crate::history::{AuthSessionRecord, OidcLogoutResult, OidcLogoutTokenRecord};
use anyhow::Result;
use postgres::Client;
use std::sync::mpsc;

pub(in crate::history::postgres) enum SessionCommand {
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
    LookupRotationSuccessor {
        predecessor_hash: String,
        successor_hash: String,
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

#[derive(Clone, Copy)]
enum SessionDomain {
    Access,
    Revoke,
    Export,
}

impl SessionCommand {
    fn domain(&self) -> SessionDomain {
        match self {
            Self::Create { .. } | Self::Lookup { .. } | Self::LookupRotationSuccessor { .. } => {
                SessionDomain::Access
            }
            Self::Revoke { .. } | Self::RevokeFamily { .. } | Self::ConsumeOidcLogout { .. } => {
                SessionDomain::Revoke
            }
            Self::ExportSessions { .. } | Self::ExportLogoutTokens { .. } => SessionDomain::Export,
        }
    }
}

pub(in crate::history::postgres) fn execute(
    command: SessionCommand,
    url: &str,
    create_schema: bool,
    client: &mut Client,
) {
    match command.domain() {
        SessionDomain::Access => execute_access(command, url, create_schema, client),
        SessionDomain::Revoke => execute_revoke(command, url, create_schema, client),
        SessionDomain::Export => execute_export(command, url, create_schema, client),
    }
}

fn execute_access(command: SessionCommand, url: &str, create_schema: bool, client: &mut Client) {
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
        SessionCommand::LookupRotationSuccessor {
            predecessor_hash,
            successor_hash,
            now,
            idle_timeout_seconds,
            reply,
        } => {
            let result = postgres_with_retry(url, create_schema, client, |client| {
                session::lookup_rotation_successor(
                    client,
                    &predecessor_hash,
                    &successor_hash,
                    now,
                    idle_timeout_seconds,
                )
            });
            let _ = reply.send(result);
        }
        _ => unreachable!("session access command domain mismatch"),
    }
}

fn execute_revoke(command: SessionCommand, url: &str, create_schema: bool, client: &mut Client) {
    match command {
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
        _ => unreachable!("session revoke command domain mismatch"),
    }
}

fn execute_export(command: SessionCommand, url: &str, create_schema: bool, client: &mut Client) {
    match command {
        SessionCommand::ExportSessions { reply } => {
            let result = postgres_with_retry(url, create_schema, client, session::export_sessions);
            let _ = reply.send(result);
        }
        SessionCommand::ExportLogoutTokens { reply } => {
            let result =
                postgres_with_retry(url, create_schema, client, session::export_logout_tokens);
            let _ = reply.send(result);
        }
        _ => unreachable!("session export command domain mismatch"),
    }
}
