use super::connect_postgres;
use anyhow::{Context, Result, bail};
use postgres::Client;
use std::sync::mpsc;
use std::thread;

mod command;
mod execute;
mod operations;

pub(super) use command::PostgresCommand;

pub(super) struct WorkerContext {
    url: String,
    retention: usize,
    create_schema: bool,
    client: Client,
}

pub(super) fn spawn(
    url: String,
    retention: usize,
    create_schema: bool,
) -> Result<mpsc::Sender<PostgresCommand>> {
    let (tx, rx) = mpsc::channel();
    let (ready_tx, ready_rx) = mpsc::channel();
    thread::Builder::new()
        .name("klaxond-history-postgres".to_string())
        .spawn(move || run(url, retention, create_schema, rx, ready_tx))
        .context("spawn postgres history worker")?;
    match ready_rx.recv() {
        Ok(Ok(())) => Ok(tx),
        Ok(Err(err)) => Err(err),
        Err(err) => bail!("postgres history worker failed to start: {err}"),
    }
}

fn run(
    url: String,
    retention: usize,
    create_schema: bool,
    commands: mpsc::Receiver<PostgresCommand>,
    ready: mpsc::Sender<Result<()>>,
) {
    let client = match connect_postgres(&url, create_schema) {
        Ok(client) => client,
        Err(err) => {
            let _ = ready.send(Err(err));
            return;
        }
    };
    if ready.send(Ok(())).is_err() {
        return;
    }
    let mut context = WorkerContext {
        url,
        retention,
        create_schema,
        client,
    };
    for command in commands {
        context.execute(command);
    }
}
