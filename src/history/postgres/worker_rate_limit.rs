use super::{PostgresCommand, PostgresWorker, postgres_with_retry, rate_limit};
use crate::history::AuthRateLimitRecord;
use anyhow::{Context, Result};
use postgres::Client;
use std::sync::mpsc;

pub(super) enum RateLimitCommand {
    Limited {
        key_hash: String,
        now: i64,
        reply: mpsc::Sender<Result<bool>>,
    },
    RecordFailure {
        key_hash: String,
        now: i64,
        reply: mpsc::Sender<Result<bool>>,
    },
    Clear {
        key_hash: String,
        reply: mpsc::Sender<Result<()>>,
    },
    Export {
        reply: mpsc::Sender<Result<Vec<AuthRateLimitRecord>>>,
    },
}

pub(super) fn execute(
    command: RateLimitCommand,
    url: &str,
    create_schema: bool,
    client: &mut Client,
) {
    match command {
        RateLimitCommand::Limited {
            key_hash,
            now,
            reply,
        } => send(
            reply,
            postgres_with_retry(url, create_schema, client, |client| {
                rate_limit::limited(client, &key_hash, now)
            }),
        ),
        RateLimitCommand::RecordFailure {
            key_hash,
            now,
            reply,
        } => send(
            reply,
            postgres_with_retry(url, create_schema, client, |client| {
                rate_limit::record_failure(client, &key_hash, now)
            }),
        ),
        RateLimitCommand::Clear { key_hash, reply } => send(
            reply,
            postgres_with_retry(url, create_schema, client, |client| {
                rate_limit::clear(client, &key_hash)
            }),
        ),
        RateLimitCommand::Export { reply } => send(
            reply,
            postgres_with_retry(url, create_schema, client, rate_limit::export_all),
        ),
    }
}

impl PostgresWorker {
    pub(in crate::history) fn auth_rate_limited(&self, key_hash: &str, now: i64) -> Result<bool> {
        self.rate_limit_request(
            |reply| RateLimitCommand::Limited {
                key_hash: key_hash.to_string(),
                now,
                reply,
            },
            "rate-limit check",
        )
    }

    pub(in crate::history) fn record_auth_failure(&self, key_hash: &str, now: i64) -> Result<bool> {
        self.rate_limit_request(
            |reply| RateLimitCommand::RecordFailure {
                key_hash: key_hash.to_string(),
                now,
                reply,
            },
            "rate-limit failure",
        )
    }

    pub(in crate::history) fn clear_auth_failures(&self, key_hash: &str) -> Result<()> {
        self.rate_limit_request(
            |reply| RateLimitCommand::Clear {
                key_hash: key_hash.to_string(),
                reply,
            },
            "rate-limit clear",
        )
    }

    pub(in crate::history) fn export_auth_rate_limits(&self) -> Result<Vec<AuthRateLimitRecord>> {
        self.rate_limit_request(
            |reply| RateLimitCommand::Export { reply },
            "rate-limit export",
        )
    }

    fn rate_limit_request<T>(
        &self,
        command: impl FnOnce(mpsc::Sender<Result<T>>) -> RateLimitCommand,
        operation: &str,
    ) -> Result<T> {
        let (reply, result) = mpsc::channel();
        self.tx
            .send(PostgresCommand::RateLimit(command(reply)))
            .with_context(|| format!("send postgres history {operation} request"))?;
        result
            .recv()
            .with_context(|| format!("receive postgres history {operation} response"))?
    }
}

fn send<T>(reply: mpsc::Sender<Result<T>>, result: Result<T>) {
    let _ = reply.send(result);
}
