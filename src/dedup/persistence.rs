use crate::state::{AppState, DedupItem};
use std::fs::{self, OpenOptions};
use std::io::Write;

pub(super) fn pending_path(state: &AppState, source: &str) -> std::path::PathBuf {
    state
        .paths
        .dedup_pending_dir
        .join(format!("pending_{source}.jsonl"))
}

pub(super) fn persist_item(state: &AppState, source: &str, item: &DedupItem) {
    let _ = fs::create_dir_all(&state.paths.dedup_pending_dir);
    let path = pending_path(state, source);
    match OpenOptions::new().create(true).append(true).open(path) {
        Ok(mut f) => {
            let _ = writeln!(f, "{}", serde_json::to_string(item).unwrap_or_default());
        }
        Err(err) => tracing::warn!("dedup: failed to persist {} item: {}", source, err),
    }
}

pub(super) fn clear_persisted(state: &AppState, source: &str) {
    let _ = fs::remove_file(pending_path(state, source));
}
