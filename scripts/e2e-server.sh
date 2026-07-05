#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DATA="$ROOT/.e2e-data"

rm -rf "$DATA"
mkdir -p "$DATA"

cat >"$DATA/ntfy-topics.json" <<'JSON'
{
  "topics": [
    {"name": "info-topic", "token": "tk_info", "handles": ["info"]},
    {"name": "warning-topic", "token": "tk_warn", "handles": ["warning"]},
    {"name": "critical-topic", "token": "tk_crit", "handles": ["critical"]}
  ]
}
JSON

cd "$ROOT"
PORT=18181 \
KLAXOND_CONFIG="$DATA/klaxond.toml" \
RENDER_CONFIG_PATH="$DATA/render-config.json" \
NTFY_TOPICS_PATH="$DATA/ntfy-topics.json" \
DEDUP_CONFIG_PATH="$DATA/dedup-config.json" \
DEDUP_PENDING_DIR="$DATA/dedup_pending" \
AUTH_CONFIG_PATH="$DATA/auth-config.json" \
AUTH_SESSION_KEY_PATH="$DATA/auth-session.key" \
KLAXOND_BACKUP_DIR="$DATA/backups" \
KLAXOND_SQLITE_PATH="$DATA/klaxond.db" \
KLAXOND_HISTORY_BACKEND="sqlite" \
KLAXOND_INGEST_SECRET_GRAFANA="e2e-secret" \
NTFY_URL="http://127.0.0.1:9" \
cargo run --quiet
