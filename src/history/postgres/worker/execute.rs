use super::command::CommandDomain;
use super::{PostgresCommand, WorkerContext};
use crate::history::postgres::{emergency, worker_rate_limit, worker_session};

impl WorkerContext {
    pub(super) fn execute(&mut self, command: PostgresCommand) {
        match command.domain() {
            CommandDomain::Delivery => self.execute_delivery(command),
            CommandDomain::Repeat => self.execute_repeat(command),
            CommandDomain::Auth => self.execute_auth(command),
            CommandDomain::EmergencyRegistration => self.execute_emergency_registration(command),
            CommandDomain::EmergencyAttempt => self.execute_emergency_attempt(command),
            CommandDomain::EmergencyTerminal => self.execute_emergency_terminal(command),
            CommandDomain::EmergencyState => self.execute_emergency_state(command),
            CommandDomain::Session => self.execute_session(command),
            CommandDomain::RateLimit => self.execute_rate_limit(command),
        }
    }

    fn execute_delivery(&mut self, command: PostgresCommand) {
        match command {
            PostgresCommand::Record { entry, reply } => self.record(entry, reply),
            PostgresCommand::Page { query, reply } => self.page(query, reply),
            PostgresCommand::Activity {
                hours,
                since,
                until,
                reply,
            } => self.activity(hours, since, until, reply),
            PostgresCommand::ExportAll { reply } => self.export_all(reply),
            _ => unreachable!("delivery command domain mismatch"),
        }
    }

    fn execute_repeat(&mut self, command: PostgresCommand) {
        match command {
            PostgresCommand::ReserveRepeat { candidate, reply } => {
                self.reserve_repeat(candidate, reply);
            }
            PostgresCommand::CompleteRepeat {
                fingerprint,
                reservation_token,
                delivered_at,
                reply,
            } => self.complete_repeat(fingerprint, reservation_token, delivered_at, reply),
            PostgresCommand::RecentRepeatSuppressions { limit, reply } => {
                self.recent_suppressions(limit, reply);
            }
            PostgresCommand::ExportRepeatStates { reply } => self.export_repeat_states(reply),
            PostgresCommand::ImportRepeatState { state, reply } => {
                self.import_repeat_state(state, reply);
            }
            _ => unreachable!("repeat command domain mismatch"),
        }
    }

    fn execute_auth(&mut self, command: PostgresCommand) {
        let PostgresCommand::ImportAuthState { state, reply } = command else {
            unreachable!("auth command domain mismatch");
        };
        self.import_auth_state(state, reply);
    }

    fn execute_emergency_registration(&mut self, command: PostgresCommand) {
        match command {
            PostgresCommand::EmergencyRegister { candidate, reply } => {
                let result = self.with_retry(|client| emergency::register(client, &candidate));
                let _ = reply.send(result);
            }
            PostgresCommand::EmergencyMaterializePolicySnapshot {
                policy_id,
                policy_name,
                snapshot_json,
                reply,
            } => {
                let result = self.with_retry(|client| {
                    emergency::materialize_policy_snapshot(
                        client,
                        &policy_id,
                        &policy_name,
                        &snapshot_json,
                    )
                });
                let _ = reply.send(result);
            }
            _ => unreachable!("emergency registration command domain mismatch"),
        }
    }

    fn execute_emergency_attempt(&mut self, command: PostgresCommand) {
        match command {
            PostgresCommand::EmergencyInitialAttempt { attempt, reply } => {
                let result =
                    self.with_retry(|client| emergency::record_initial_attempt(client, &attempt));
                let _ = reply.send(result);
            }
            PostgresCommand::EmergencyReserve {
                now,
                lease_until,
                token,
                reply,
            } => {
                let result = self
                    .with_retry(|client| emergency::reserve_due(client, now, lease_until, &token));
                let _ = reply.send(result);
            }
            PostgresCommand::EmergencyAdjustLease {
                receipt,
                token,
                lease_until,
                reply,
            } => {
                let result = self.with_retry(|client| {
                    emergency::adjust_lease(client, &receipt, &token, lease_until)
                });
                let _ = reply.send(result);
            }
            PostgresCommand::EmergencyComplete { attempt, reply } => {
                let result =
                    self.with_retry(|client| emergency::complete_attempt(client, &attempt));
                let _ = reply.send(result);
            }
            _ => unreachable!("emergency attempt command domain mismatch"),
        }
    }

    fn execute_emergency_terminal(&mut self, command: PostgresCommand) {
        match command {
            PostgresCommand::EmergencyTerminalize {
                receipt,
                state,
                actor,
                now,
                reply,
            } => {
                let result = self.with_retry(|client| {
                    emergency::terminalize(client, &receipt, &state, &actor, now)
                });
                let _ = reply.send(result);
            }
            PostgresCommand::EmergencyTerminalizeFingerprint {
                fingerprint,
                state,
                actor,
                now,
                reply,
            } => {
                let result = self.with_retry(|client| {
                    emergency::terminalize_fingerprint(client, &fingerprint, &state, &actor, now)
                });
                let _ = reply.send(result);
            }
            PostgresCommand::EmergencyExpire { now, limit, reply } => {
                let result = self.with_retry(|client| emergency::expire_due(client, now, limit));
                let _ = reply.send(result);
            }
            PostgresCommand::EmergencyRetry {
                receipt,
                now,
                reply,
            } => {
                let result = self.with_retry(|client| emergency::retry_now(client, &receipt, now));
                let _ = reply.send(result);
            }
            _ => unreachable!("emergency terminal command domain mismatch"),
        }
    }

    fn execute_emergency_state(&mut self, command: PostgresCommand) {
        match command {
            PostgresCommand::EmergencyGet { receipt, reply } => {
                let result = self.with_retry(|client| emergency::get(client, &receipt));
                let _ = reply.send(result);
            }
            PostgresCommand::EmergencyPage {
                state,
                limit,
                reply,
            } => {
                let result =
                    self.with_retry(|client| emergency::page(client, state.as_deref(), limit));
                let _ = reply.send(result);
            }
            PostgresCommand::EmergencyExport { reply } => {
                let result = self.with_retry(emergency::export_all);
                let _ = reply.send(result);
            }
            PostgresCommand::EmergencyImport { incident, reply } => {
                let result = self.with_retry(|client| emergency::import(client, &incident));
                let _ = reply.send(result);
            }
            PostgresCommand::EmergencyStats { now, reply } => {
                let result = self.with_retry(|client| emergency::active_stats(client, now));
                let _ = reply.send(result);
            }
            _ => unreachable!("emergency state command domain mismatch"),
        }
    }

    fn execute_session(&mut self, command: PostgresCommand) {
        let PostgresCommand::Session(command) = command else {
            unreachable!("session command domain mismatch");
        };
        worker_session::execute(command, &self.url, self.create_schema, &mut self.client);
    }

    fn execute_rate_limit(&mut self, command: PostgresCommand) {
        let PostgresCommand::RateLimit(command) = command else {
            unreachable!("rate-limit command domain mismatch");
        };
        worker_rate_limit::execute(command, &self.url, self.create_schema, &mut self.client);
    }
}
