# Klaxon

> Notification bridge for homelab alerting — turns Grafana Alertmanager and Beszel webhooks into clean ntfy pushes, with built-in cascade fallback (ntfy → Telegram → SMTP), declarative inhibition rules, and a single-page admin UI.

```
┌──────────────┐   ┌────────┐                            ┌──────────────────────────┐
│ Alertmanager │ ──┤        ├──→  POST /webhook/<sev> ──→│                          │
└──────────────┘   │ klaxon │                            │   render → cascade tiers │
┌──────────────┐   │        │                            │   1. ntfy       (5s)     │
│   Beszel     │ ──┤        ├──→  POST /beszel/<sev>  ──→│   2. Telegram   (8s)     │
└──────────────┘   └────────┘                            │   3. Gmail SMTP (10s)    │
                                                         └──────────────────────────┘
```

## Why

Grafana's webhook contact-point and Beszel's webhook channel both POST JSON that ntfy can't render legibly on its own. Klaxon parses both formats, builds a clean ntfy push with title/emoji/tags/priority/action-buttons, and — if ntfy is down — falls back to Telegram and then SMTP, so an alert never silently disappears.

A small admin UI lets you watch deliveries in real time, edit channel routing without restarts, manage inhibition rules, and preview how an alert will look on the phone before you ship a new rule.

## Features

- **Two webhook formats**: `/webhook/<sev>` (Grafana Alertmanager-shape) and `/beszel/<sev>` (Beszel-shape).
- **3-tier cascade fallback** — ntfy → Telegram → SMTP. Always on for Beszel, gated for Grafana.
- **Rich ntfy push rendering**: severity emoji in title (RFC 2047 base64-encoded for non-ASCII), priority + tag mapping, up to 2 action buttons via `component` label → dashboard URL.
- **In-memory inhibition** safety net (Alertmanager owns the canonical layer if you're using it).
- **TOML bootstrap config** (`klaxon.toml`) — defines cascade tiers, render mappings, inhibition rules. Auto-bootstrapped on first run from the bundled default.
- **Admin UI** (vanilla HTML+JS, zero build) at `/ui/`: channel health, active inhibitions, recent deliveries, render config CRUD with deep-link test, visual ntfy push preview, cascade tier editor, channel routing config.
- **Python stdlib only** — no pip install needed. Runs in `python:3.13-alpine`.

## Quick start

```bash
git clone https://github.com/your-org/klaxon.git
cd klaxon
cp .env.example .env
# edit .env to fill the secrets: NTFY_TOKEN_*, TELEGRAM_BOT_TOKEN, SMTP_USER/PASSWORD
docker compose up -d
```

Open `http://localhost:8181/ui/` to access the admin UI. Edit channel URLs/topics from the Routing tab; secrets stay in your `.env`.

## Endpoints

### Webhook ingress (machine-to-machine)

| Method | Path | Source |
|---|---|---|
| `POST` | `/webhook/<severity>` | Alertmanager / Grafana |
| `POST` | `/beszel/<severity>` | Beszel UI webhook channel |

`<severity>` is one of `info`, `warning`, `critical`.

### Health + UI

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/healthz` | Plain `OK`, for Docker `HEALTHCHECK` |
| `GET` | `/` / `/ui/` | Static admin UI |

### Admin API (consumed by UI)

| Method | Path | Returns / Effect |
|---|---|---|
| `GET` | `/api/status` | Cascade flag + channel reachability |
| `GET` | `/api/inhibitions` | Active in-memory suppressions with TTL |
| `GET` | `/api/deliveries` | Rolling buffer of the last 50 deliveries |
| `GET` | `/api/render-config` | `component → [label, url]` mapping |
| `POST` | `/api/render-config` | Replace mapping (persists to `/data/render-config.json`) |
| `GET` | `/api/cascade-config` | Cascade tier list + default-enabled flag |
| `POST` | `/api/cascade-config` | Update tiers (persists to `/data/klaxon.toml`) |
| `GET` | `/api/channel-config` | ntfy URL + topics, Telegram chat_id, SMTP host/port/from/to. Secrets shown as configured/missing badges only. |
| `POST` | `/api/channel-config` | Update non-secret channel fields (persists to `/data/klaxon.toml`) |
| `POST` | `/api/render-preview` | Body `{severity, payload}` → returns ntfy headers + body without sending |
| `POST` | `/api/test/<sev>` | Fire a synthetic alert through the cascade |
| `POST` | `/api/cascade/toggle` | Body `{enabled: bool}` or empty (flip) — runtime override of CASCADE_ENABLED |

## Configuration

### Secrets — env-only

These are **never** written to the TOML file. Mount them via your secrets manager / `.env`:

| Var | Required for |
|---|---|
| `NTFY_TOKEN_INFO`, `NTFY_TOKEN_WARN`, `NTFY_TOKEN_CRIT` | ntfy tier delivery |
| `TELEGRAM_BOT_TOKEN` | Telegram tier (also requires chat_id from TOML or env) |
| `SMTP_USER`, `SMTP_PASSWORD` | SMTP tier |

### Routing + policy — `klaxon.toml`

Bootstrapped on first run from the bundled default. Editable on disk or from the admin UI (Routing / Cascade / Render config tabs).

```toml
[ntfy]
url = "https://ntfy.example.com"

[ntfy.topics]
info     = "your-info-topic-id"
warning  = "your-warning-topic-id"
critical = "your-critical-topic-id"

[telegram]
chat_id = "your-chat-id"

[smtp]
host = "smtp.example.com"
port = 587
from_addr = "klaxon@example.com"
to_addr   = "oncall@example.com"

[cascade]
default_enabled_for_webhook = false   # /beszel/* always uses cascade

[[cascade.tiers]]
name = "ntfy"
timeout_seconds = 5

[[cascade.tiers]]
name = "telegram"
timeout_seconds = 8

[[cascade.tiers]]
name = "smtp"
timeout_seconds = 10

[render]
grafana_base = "https://grafana.example.com"

[render.severity_emoji]
info     = "ℹ️"
warning  = "⚠️"
critical = "🚨"

[render.severity_priority]
info     = "default"
warning  = "high"
critical = "urgent"

[render.component_dashboards]
host    = ["Logs",    "/d/your-logs-dashboard"]
traefik = ["Traefik", "/d/your-traefik-dashboard"]

[[inhibitions]]
source = "node-down"
match_by = "host"
ttl_seconds = 900

[[inhibitions]]
source = "traefik-down"
match_label = "job"
match_regex = "^blackbox-(https|http).*"
ttl_seconds = 900
```

### Optional env overrides

Anything in TOML can be overridden by an env var. Use this only as a migration aid or when you really want to pin a value at deploy-time.

| Env | Overrides |
|---|---|
| `NTFY_URL` | `[ntfy].url` |
| `TOPIC_INFO` / `TOPIC_WARN` / `TOPIC_CRIT` | `[ntfy.topics].*` |
| `TELEGRAM_CHAT_ID` | `[telegram].chat_id` |
| `SMTP_HOST` / `SMTP_PORT` / `SMTP_FROM` / `SMTP_TO` | `[smtp].*` |
| `GRAFANA_BASE` | `[render].grafana_base` |
| `CASCADE_ENABLED` | `[cascade].default_enabled_for_webhook` |
| `KLAXON_CONFIG` | path to klaxon.toml (default `/data/klaxon.toml`) |
| `PORT` | listen port (default `8181`) |

## Inhibition

`klaxon.toml` defines inhibition rules — when a "source" alert is firing, derivative alerts are silently dropped until the source resolves or the TTL expires.

Recognise sources by the `inhibition_source` label on your Grafana alert rules:

```yaml
# Grafana alert rule example
labels:
  severity: critical
  inhibition_source: node-down   # ← Klaxon picks up this label
```

Three match modes:

- `match_by: <label>` — suppress when target alert has the same value in that label as the source.
- `match_label + match_regex` — suppress when the target label matches the regex.
- `match_all: true` — suppress everything except the source itself.

Klaxon's inhibition is a safety net for direct posts. If you're using Alertmanager as the upstream router, configure inhibition rules there too — that's the canonical layer (declarative, UI silences, audit trail).

## Project layout

```
klaxon/
├── app.py                  backend (Python stdlib only, ~800 lines)
├── static/
│   ├── index.html          admin UI (single page)
│   ├── style.css           dark theme, ~6KB
│   └── app.js              vanilla JS, fetch + DOM (~400 lines)
├── klaxon.default.toml     bundled defaults, copied to /data on first run
├── Dockerfile              builds an image (~50 MB)
├── docker-compose.yml      reference standalone deploy
├── .env.example            secrets/site-specific env vars
├── README.md
├── CHANGELOG.md
└── LICENSE
```

## Development

There's no build step. Edit `app.py` or `static/*` and restart the container. For local development:

```bash
python3 app.py &
curl -s http://127.0.0.1:8181/healthz
curl -s -X POST http://127.0.0.1:8181/webhook/info \
  -H 'Content-Type: application/json' \
  -d '{"status":"firing","commonLabels":{"alertname":"local-test","severity":"info","host":"dev"}}'
```

## License

Apache-2.0 — see [LICENSE](./LICENSE).
