# Klaxond

> Notification bridge for homelab alerting — turns Grafana Alertmanager and Beszel webhooks into clean ntfy pushes, with built-in cascade fallback (ntfy → Telegram → SMTP), declarative inhibition rules, and a single-page admin UI.

```
┌──────────────┐   ┌────────┐                            ┌──────────────────────────┐
│ Alertmanager │ ──┤        ├──→  POST /webhook/<sev> ──→│                          │
└──────────────┘   │ klaxond │                            │   render → cascade tiers │
┌──────────────┐   │        │                            │   1. ntfy       (5s)     │
│   Beszel     │ ──┤        ├──→  POST /beszel/<sev>  ──→│   2. Telegram   (8s)     │
└──────────────┘   └────────┘                            │   3. Gmail SMTP (10s)    │
                                                         └──────────────────────────┘
```

## Why

Grafana's webhook contact-point and Beszel's webhook channel both POST JSON that ntfy can't render legibly on its own. Klaxond parses both formats, builds a clean ntfy push with title/emoji/tags/priority/action-buttons, and — if ntfy is down — falls back to Telegram and then SMTP, so an alert never silently disappears.

A small admin UI lets you watch deliveries in real time, edit channel routing without restarts, manage inhibition rules, and preview how an alert will look on the phone before you ship a new rule.

## Features

- **Multiple webhook formats**: Grafana Alertmanager, Beszel, Healthchecks, WUD, Authentik, Shelfmark, Prowlarr and Decypharr.
- **3-tier cascade fallback** — ntfy → Telegram → SMTP. Always on for Beszel, gated for Grafana.
- **Rich ntfy push rendering**: severity emoji in title (RFC 2047 base64-encoded for non-ASCII), priority + tag mapping, up to 2 action buttons via `component` label → dashboard URL.
- **In-memory inhibition** safety net (Alertmanager owns the canonical layer if you're using it).
- **Full settings export/import**: TOML plus sidecar JSON files, import preview, automatic pre-restore backup and validated restore.
- **Authentication**: local Argon2id username/password login, LDAP, magic links, optional TOTP/MFA, OIDC, trusted proxy, passkeys, API keys and PATs with granular scopes plus read-only viewer support.
- **Operational diagnostics**: audit log, backend/frontend log search, setup checklist, notification test matrix and policy simulator.
- **Persistent delivery history**: SQLite by default under `/data`, with optional PostgreSQL for shared multi-backend history and a built-in migration command.
- **TOML bootstrap config** (`klaxond.toml`) — defines cascade tiers, delivery policies, render mappings, inhibition rules and schedules. Auto-bootstrapped on first run from the bundled default.
- **Admin UI** (vanilla HTML+JS, zero build) at `/`: channel health, active inhibitions, recent deliveries, logs, audit, import/export, render config CRUD, visual ntfy push preview, cascade tier editor, channel routing config and auth management.
- **Prometheus/Grafana ready**: `/metrics` exposes runtime counters/gauges, with importable Grafana dashboard and Prometheus/VictoriaMetrics scrape examples under `docs/`.
- **Documented API contract**: `docs/openapi.yaml` is bundled and served at `/openapi.yaml` and `/api/openapi.yaml`; Swagger UI is available at `/api/docs`, `/api/swagger` and `/api/swagger-ui`.
- **Rust backend** — single `klaxond` binary built with Cargo, served from a small Alpine runtime image.

## Quick start

```bash
git clone https://github.com/your-org/klaxond.git
cd klaxond
cp .env.example .env
# edit .env to fill the secrets: NTFY_TOKEN_*, TELEGRAM_BOT_TOKEN, SMTP_USER/PASSWORD
docker compose up -d
```

Open `http://localhost:8181/` to access the admin UI. Edit channel URLs/topics from the Routing tab; secrets stay in your `.env`.

### Public legal and accessibility pages

klaxond ships public informational pages that remain reachable even when the
admin UI is protected by SSO, Basic auth, LDAP, magic links, trusted proxy auth, passkeys, API keys
or PATs. Replace `localhost:8181` with your own self-hosted origin:

- [Privacy notice](http://localhost:8181/legal/privacy)
- [Accessibility statement](http://localhost:8181/legal/accessibility)
- [Terms of use](http://localhost:8181/legal/terms)
- [Cookie notice](http://localhost:8181/legal/cookies)
- [Legal notice and contacts](http://localhost:8181/legal/notice)

The same links are shown in the app footer and on the local login/signed-out
screen.

### Authentication and browser safety

The admin UI supports local username/password login backed by Argon2id,
LDAP, optional TOTP/MFA, OIDC, trusted proxy headers, passkeys, magic links, API keys and PATs. Browser
sessions receive a CSRF token and every same-origin mutation must send it back.
Sensitive browser actions also require a short local reauthentication window
when using local username/password or LDAP login. Machine clients should use scoped
Bearer tokens or explicit Basic auth headers; those paths are not gated by
browser CSRF/sudo prompts.

### API contract

The canonical API contract is [`docs/openapi.yaml`](docs/openapi.yaml). The
running backend serves the same document publicly at `/openapi.yaml` and
`/api/openapi.yaml`, including auth schemes, CSRF/reauth behavior, paginated
logs/audit parameters, config import/export, passkeys, TOTP and token scopes.
The self-hosted Swagger UI follows the project convention and is available at
`/api/docs`, `/api/swagger` and `/api/swagger-ui`. The legacy `/swagger` alias
is still served for backwards compatibility.

## Endpoints

This section is an operator summary. Use the OpenAPI document above for the
complete route list, schemas, auth requirements and response contracts.

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
| `GET` | `/metrics` | Prometheus metrics |
| `GET` | `/openapi.yaml` / `/api/openapi.yaml` | Canonical OpenAPI contract |
| `GET` | `/api/docs` / `/api/swagger` / `/api/swagger-ui` | Swagger UI for the OpenAPI contract |
| `GET` | `/` / `/status` / other root-level page routes | Static admin UI |

### Admin API summary (consumed by UI)

| Method | Path | Returns / Effect |
|---|---|---|
| `GET` | `/api/status` | Cascade flag + channel reachability |
| `GET` | `/api/setup-status` | Setup/readiness checklist |
| `GET` | `/api/channel-test-matrix` | Dry-run channel connectivity matrix; sends no notification |
| `GET` | `/api/inhibitions` | Active in-memory suppressions with TTL |
| `GET` | `/api/deliveries` | Persistent delivery history; add `limit`/`offset` for the paginated shape |
| `GET` | `/api/logs` | Runtime/backend/frontend log buffer with keyword, level and pagination filters |
| `GET` | `/api/audit` | Security/configuration audit ring buffer with keyword and pagination filters |
| `GET` | `/api/auth/me` | Current authenticated user, auth mode, scopes and browser CSRF token |
| `GET` | `/api/auth/login` | Public login page and OIDC start flow |
| `GET` | `/api/auth/methods` | Public auth method availability using the shared method names |
| `GET` | `/api/auth/password-policy` | Shared Argon2id password policy limits consumed by the UI |
| `POST` | `/api/auth/local/login` | Local username/password login; accepts optional TOTP code |
| `POST` | `/api/auth/reauth` | Refresh the short reauthentication window for sensitive local-session actions |
| `POST` | `/api/auth/totp/setup/start` | Generate a one-time TOTP setup secret and otpauth URI |
| `POST` | `/api/auth/totp/setup/confirm` | Enable local TOTP after validating the current code |
| `POST` | `/api/auth/totp/disable` | Disable local TOTP |
| `GET` | `/api/config/backup` | Download current `klaxond.toml` |
| `GET` | `/api/config/export` | Admin-only full settings bundle: TOML, sidecars, auth sidecars and runtime-derived secrets |
| `GET` | `/api/config/backups` | List automatic config backups |
| `POST` | `/api/config/import-preview` | Validate and compare a TOML/full bundle before restore |
| `POST` | `/api/config/restore` | Restore a TOML/full bundle after automatic pre-restore backup |
| `GET` | `/api/render-config` | `component → [label, url]` mapping |
| `POST` | `/api/render-config` | Replace mapping (persists to `/data/render-config.json`) |
| `GET` | `/api/cascade-config` | Cascade tier list + default-enabled flag |
| `POST` | `/api/cascade-config` | Update tiers (persists to `/data/klaxond.toml`) |
| `GET` | `/api/channel-config` | ntfy URL + topics, Telegram chat_id, SMTP host/port/from/to. Secrets shown as configured/missing badges only. |
| `POST` | `/api/channel-config` | Update non-secret channel fields (persists to `/data/klaxond.toml`) |
| `POST` | `/api/render-preview` | Body `{severity, payload}` → returns ntfy headers + body without sending |
| `POST` | `/api/policy-simulate` | Dry-run inhibition, delivery policy and dedup decisions |
| `POST` | `/api/test/<sev>` | Fire a synthetic alert through the cascade |
| `POST` | `/api/cascade/toggle` | Body `{enabled: bool}` or empty (flip) — runtime override of CASCADE_ENABLED |

## Observability

Scrape `GET /metrics` with Prometheus-compatible collectors. Ready-to-copy
examples are available for both Prometheus and VictoriaMetrics vmagent:

- [`docs/prometheus-scrape.example.yml`](docs/prometheus-scrape.example.yml)
- [`docs/victoriametrics-scrape.example.yml`](docs/victoriametrics-scrape.example.yml)

The endpoint includes:

- `klaxond_info{version=...}`
- `klaxond_uptime_seconds`
- `klaxond_deliveries_total{source,severity,channel,ok}`
- `klaxond_suppressions_active`
- `klaxond_suppressions_armed_total{rule}`
- `klaxond_render_errors_total{source}`
- `klaxond_dedup_pending{source}`
- `klaxond_dedup_buffered_total{source}` and `klaxond_dedup_flushed_total{source}`

Import [`docs/grafana-dashboard.json`](docs/grafana-dashboard.json) into Grafana and select your Prometheus datasource.

## Configuration

### Secrets and deploy-time overrides

Secrets can be supplied from compose env vars or saved through the UI into the
TOML/sidecar files. Env vars still win at runtime when both are present, which
keeps deploy-time secret managers authoritative.

| Var | Required for |
|---|---|
| `NTFY_TOKEN_INFO`, `NTFY_TOKEN_WARN`, `NTFY_TOKEN_CRIT` | ntfy tier delivery |
| `TELEGRAM_BOT_TOKEN` | Telegram tier (also requires chat_id from TOML or env) |
| `SMTP_USER`, `SMTP_PASSWORD` | SMTP tier |
| `AUTH_SESSION_SECRET`, `AUTH_OIDC_CLIENT_SECRET`, `AUTH_BASIC_PASSWORD_HASH` | auth bootstrap/secrets |
| `KLAXOND_INGEST_SECRET_<SOURCE>` | inbound webhook shared secrets |

### Delivery history storage

Klaxond stores delivery history persistently. SQLite is the default and writes
to `/data/klaxond.db`, which keeps a normal single-container install simple. Use
PostgreSQL when several backend instances must share one history database.

```toml
[paths]
history_db = "klaxond.db"

[history]
backend = "sqlite" # sqlite or postgres
postgres_url = ""
retention = 5000
default_limit = 500
```

Compose/env equivalents:

| Env | TOML equivalent |
|---|---|
| `KLAXOND_SQLITE_PATH` | `[paths].history_db` |
| `KLAXOND_HISTORY_BACKEND` | `[history].backend` |
| `KLAXOND_POSTGRES_URL` | `[history].postgres_url` |
| `KLAXOND_HISTORY_RETENTION` | `[history].retention` |
| `KLAXOND_HISTORY_DEFAULT_LIMIT` | `[history].default_limit` |

`docker-compose.yml` and `docker-compose.split.yml` include an optional
`postgres` profile for operators who want a managed PostgreSQL sidecar. For an
external database, set `KLAXOND_HISTORY_BACKEND=postgres` and
`KLAXOND_POSTGRES_URL=postgres://user:password@host:5432/dbname`. The sidecar
profile requires `KLAXOND_POSTGRES_PASSWORD`; its default published bind is
local-only (`127.0.0.1:55432`) so it is not exposed on every host interface by
accident.

Migrate delivery history between backends with the bundled CLI:

```bash
# SQLite -> PostgreSQL
klaxond history-migrate \
  --from sqlite --from-url /data/klaxond.db \
  --to postgres --to-url postgres://klaxond:password@postgres-host:5432/klaxond

# PostgreSQL -> SQLite
klaxond history-migrate \
  --from postgres --from-url postgres://klaxond:password@postgres-host:5432/klaxond \
  --to sqlite --to-url /data/klaxond.db
```

### Routing + policy — `klaxond.toml`

Bootstrapped on first run from the bundled default. Editable on disk or from the admin UI (Routing / Cascade / Render config tabs).

```toml
[ntfy]
url = "https://ntfy.example.com"

[ntfy.topics]
info     = "your-info-topic-id"
warning  = "your-warning-topic-id"
critical = "your-critical-topic-id"

[telegram]
api_base = "https://api.telegram.org"
bot_token = ""
chat_id = "your-chat-id"

[smtp]
host = "smtp.example.com"
port = 587
starttls = true
user = "smtp-user"
password = "smtp-password"
from_addr = "klaxond@example.com"
to_addr   = "oncall@example.com"

[server]
port = 8181
public_url = "https://klaxond.example.com"

[acks]
default_ttl_seconds = 3600

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
grafana_render_base = "https://grafana-renderer.example.com"
grafana_render_token = ""
render_image_ttl = 900

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

### UI / compose parity

Every UI-managed setting has a compose-managed path:

| UI area | Compose-managed source |
|---|---|
| Routing: ntfy URL, Telegram, SMTP | env vars or `/data/klaxond.toml` |
| Routing: ntfy topics and bearer tokens | env vars, `[ntfy.topics]`, or `/data/ntfy-topics.json` |
| Routing: inbound webhook secrets | `KLAXOND_INGEST_SECRET_<SOURCE>` or `[ingest.secrets]` |
| Cascade, delivery policies, inhibitions, schedules | `/data/klaxond.toml` |
| Render runtime settings and dashboard mappings | `/data/klaxond.toml` and `/data/render-config.json` |
| Dedup/grouping | `[dedup]` bootstrap or `/data/dedup-config.json` |
| Auth, API keys/PATs, TOTP, passkeys, LDAP, magic links | `[auth]` bootstrap or `/data/auth-config.json` |
| Delivery history storage | `[history]`, `[paths].history_db`, or `KLAXOND_HISTORY_*` / `KLAXOND_POSTGRES_URL` |
| Runtime paths exposed by compose | `[paths]` in `/data/klaxond.toml` |

The reverse path is the UI **Full export** button. It exports
`klaxond.toml`, `render-config.json`, `ntfy-topics.json`, `dedup-config.json`
and `auth-config.json`; bind-mount those files in compose when you want the
same settings managed declaratively.

Every compose env var that changes application behavior has at least one
TOML or JSON equivalent. `KLAXOND_CONFIG` is the only bootstrap-only exception:
it selects the TOML file itself, so it cannot live inside that same TOML file.

### Optional env overrides

Use env vars when you want compose/secrets-manager values to override TOML or
UI-saved values at runtime.

| Env | Overrides |
|---|---|
| `NTFY_URL` | `[ntfy].url` |
| `TOPIC_INFO` / `TOPIC_WARN` / `TOPIC_CRIT` | `[ntfy.topics].*` |
| `NTFY_TOKEN_INFO` / `NTFY_TOKEN_WARN` / `NTFY_TOKEN_CRIT` | matching single-severity ntfy topic tokens |
| `TELEGRAM_CHAT_ID` / `TELEGRAM_BOT_TOKEN` / `TELEGRAM_API_BASE` | `[telegram].*` |
| `SMTP_HOST` / `SMTP_PORT` / `SMTP_STARTTLS` / `SMTP_USER` / `SMTP_PASSWORD` / `SMTP_FROM` / `SMTP_TO` | `[smtp].*` |
| `GRAFANA_BASE` / `GRAFANA_RENDER_BASE` / `GRAFANA_RENDER_TOKEN` / `RENDER_IMAGE_TTL` | `[render].*` |
| `KLAXOND_PUBLIC_URL` | `[server].public_url` |
| `ACK_DEFAULT_TTL_SECONDS` | `[acks].default_ttl_seconds` |
| `CASCADE_ENABLED` | `[cascade].default_enabled_for_webhook` |
| `PORT` | `[server].port` |
| `AUTH_SESSION_SECRET` | `[auth].session_secret` or `auth-config.json` |
| `AUTH_OIDC_CLIENT_SECRET` / `AUTH_BASIC_PASSWORD_HASH` | `[auth.oidc].client_secret`, `[auth.basic].password_hash`, or `auth-config.json`; LDAP is configured through `[auth.ldap]` or `auth-config.json` |
| `KLAXOND_INGEST_SECRET_<SOURCE>` | `[ingest.secrets].<source>` |
| `RENDER_CONFIG_PATH` / `NTFY_TOPICS_PATH` / `DEDUP_CONFIG_PATH` / `AUTH_CONFIG_PATH` | `[paths].render_config`, `[paths].ntfy_topics`, `[paths].dedup_config`, `[paths].auth_config` |
| `AUTH_SESSION_KEY_PATH` / `KLAXOND_BACKUP_DIR` / `DEDUP_PENDING_DIR` / `BESZEL_DB_PATH` | `[paths].auth_session_key`, `[paths].backup_dir`, `[paths].dedup_pending_dir`, `[paths].beszel_db` |
| `KLAXOND_SQLITE_PATH` / `KLAXOND_HISTORY_BACKEND` / `KLAXOND_POSTGRES_URL` / `KLAXOND_HISTORY_RETENTION` / `KLAXOND_HISTORY_DEFAULT_LIMIT` | `[paths].history_db`, `[history].backend`, `[history].postgres_url`, `[history].retention`, `[history].default_limit` |
| `KLAXOND_CONFIG` | bootstrap-only path to `klaxond.toml` (default `/data/klaxond.toml`) |

### Split frontend / backend / state

The default image is monolithic: the Rust backend also serves the static admin
UI. For multi-host deployments, use `docker-compose.split.yml` instead:

```bash
# first register the external state volume on every backend host.
# For a single-host demo this can be a local volume; for multi-host use a
# volume driver or bind mount backed by shared storage.
docker volume create klaxond-data

# only needed when using the split PostgreSQL profile with the default
# external volume name.
docker volume create klaxond-postgres-data

# backend host
docker compose -f docker-compose.split.yml --profile backend up -d

# frontend host
KLAXOND_BACKEND_URL=http://backend-host:8181 \
docker compose -f docker-compose.split.yml --profile frontend up -d

# state host, optional keeper for an external/shared volume
docker compose -f docker-compose.split.yml --profile db up -d

# optional PostgreSQL history host
KLAXOND_POSTGRES_PASSWORD='<strong-random-password>' \
docker compose -f docker-compose.split.yml --profile postgres up -d
```

The split frontend image is nginx plus the files in `static/`. It serves the UI
and reverse-proxies `/api/*`, webhook endpoints, `/img/*`,
`/healthz`, `/metrics`, OpenAPI, and Swagger routes to `KLAXOND_BACKEND_URL`.
This keeps browser auth and CSRF same-origin even when the frontend and backend
containers run on different machines. When the frontend sits behind a TLS
terminator, forwarded protocol/port headers are preserved for OIDC callback
generation. The frontend container always listens on internal port `8080`; use
`KLAXOND_FRONTEND_BIND` to choose the host-side published address/port.

Klaxond does not require a SQL server: its core state tier is the `/data` file
bundle: `klaxond.toml`, `render-config.json`, `ntfy-topics.json`,
`dedup-config.json`, `auth-config.json`, backups, pending dedup files and the
default SQLite history database. To place that file tier on another host,
expose it as an external Docker volume backed by NFS/Ceph/etc. and set
`KLAXOND_DATA_VOLUME` in `docker-compose.split.yml`. The backend host must mount
the same external volume; the `db` profile exists for operators who want to
provision or keep that state tier separately.

For active/active multi-backend delivery history, prefer the optional
PostgreSQL profile or an external PostgreSQL instance and point all backend
containers at the same `KLAXOND_POSTGRES_URL`.

## Inhibition

`klaxond.toml` defines inhibition rules — when a "source" alert is firing, derivative alerts are silently dropped until the source resolves or the TTL expires.

Recognise sources by the `inhibition_source` label on your Grafana alert rules:

```yaml
# Grafana alert rule example
labels:
  severity: critical
  inhibition_source: node-down   # ← Klaxond picks up this label
```

Three match modes:

- `match_by: <label>` — suppress when target alert has the same value in that label as the source.
- `match_label + match_regex` — suppress when the target label matches the regex.
- `match_all: true` — suppress everything except the source itself.

Klaxond's inhibition is a safety net for direct posts. If you're using Alertmanager as the upstream router, configure inhibition rules there too — that's the canonical layer (declarative, UI silences, audit trail).

## High availability (optional)

Klaxond is single-process and mostly stateless: persistent config/state lives in
the `/data` file bundle, and delivery history lives in SQLite by default or
PostgreSQL when configured. That means HA is a deploy-time decision, not a code
change.

**TL;DR**: mount `/data` from shared storage (NFS, Ceph, etc.), use PostgreSQL
for shared active/active delivery history, and run two containers behind any
TCP/HTTP load balancer with a `/healthz` health check.

### Architecture

```
                  ┌────────────────────────────┐
                  │ klaxond.example.com         │
                  │ Traefik / nginx / haproxy  │
                  │ healthCheck: GET /healthz  │
                  └─────────┬──────────┬───────┘
                            │          │
                  ┌─────────▼──┐  ┌────▼────────┐
                  │ klaxond #1 │  │ klaxond #2  │
                  │ host A     │  │ host B      │
                  └─────────┬──┘  └─┬───────────┘
                            │       │
                            └───┬───┘
                                ▼
                  ┌──────────────────────────┐
                  │ shared /data (NFS/etc.)  │
                  │  ├ klaxond.toml          │
                  │  ├ render-config.json    │
                  │  ├ ntfy-topics.json      │
                  │  ├ dedup-config.json     │
                  │  └ auth-config.json      │
                  └──────────────────────────┘
                                │
                                ▼
                  ┌──────────────────────────┐
                  │ optional PostgreSQL      │
                  │ shared delivery history  │
                  └──────────────────────────┘
```

### What's safe to share between instances

- **`/data/klaxond.toml`** — TOML config (channels, tiers, render rules, inhibitions). Read on startup + on POST `/api/*-config`. File-locked writes on save.
- **`/data/render-config.json`, `ntfy-topics.json`, `dedup-config.json`, `auth-config.json`** — UI-managed sidecars. Same pattern.

These files are written atomically (write-temp-then-rename). With NFS v4 sync mode the cross-instance read-after-write is consistent. Don't use SMB — locking semantics are too loose.

SQLite delivery history is the default for single-backend installs and
active/passive failover. For two or more simultaneously writing backend
instances, configure PostgreSQL so history has one real multi-writer store.

### What's in-memory and NOT shared

| State | Where | Impact of split between instances |
|---|---|---|
| Inhibition deque (recent alert hashes) | RAM, last ~256 entries per instance | Best-effort dedup. The canonical inhibition layer should be Alertmanager — this is a safety net for direct webhook posts. With 2 instances, occasional duplicate inhibition misses. |

### Load balancer config — Traefik example

```yaml
http:
  routers:
    klaxond:
      rule: "Host(`klaxond.example.com`)"
      service: klaxond-ha
      entryPoints: [websecure]

  services:
    klaxond-ha:
      loadBalancer:
        servers:
          - url: "http://10.0.0.1:8181"
          - url: "http://10.0.0.2:8181"
        healthCheck:
          path: /healthz
          interval: 10s
          timeout: 3s
          scheme: http
```

Same pattern with nginx `upstream` or haproxy `backend`. Any TCP/HTTP LB that supports active health checks works.

### Recommended for a homelab: don't enable it

Klaxond is small (~16MB RSS), starts in <1s, and crashes rarely. The realistic "klaxond down" window is upgrades (~10s). For most use cases, single-instance + a meta-alert that probes klaxond's own `/healthz` and posts to ntfy directly **on failure** is a better cost/benefit ratio than HA — see [Self-monitoring](#self-monitoring) below.

### Self-monitoring (klaxond watching itself)

Even with HA, you want a probe that warns when **both** instances are down. The pattern (in any cron/scheduler):

```bash
# /etc/cron.d/klaxond-self-watch — runs every 5 min
*/5 * * * * root curl -fsS https://klaxond.example.com/healthz \
  || curl -fsS -X POST \
       -H "Authorization: Bearer $NTFY_TOKEN" \
       -H "Title: klaxond DOWN — pipeline broken" \
       -H "Priority: urgent" \
       --data "klaxond /healthz failed at $(date)" \
       https://ntfy.example.com/<your-topic>
```

This single push **bypasses klaxond** by design — it's the one alert that has to reach you when klaxond itself is the problem.

## Project layout

```
klaxond/
├── Cargo.toml / Cargo.lock backend crate and locked Rust dependencies
├── src/                    Rust backend modules
│   └── handlers/           HTTP router, ingest, config, auth and observability handlers
├── static/
│   ├── index.html          admin UI (single page)
│   ├── style.css           dark theme, ~6KB
│   ├── table-pager.js      shared finite-table pagination helper
│   ├── app-main.js         native ESM entrypoint
│   ├── app.js              stable ESM facade re-exporting runtime modules
│   ├── app-core.js, app-http.js, app-query.js, app-routing-core.js, app-toast.js shared UI runtime modules
│   └── app-*.js            feature modules for status, auth, logs, routing and editors
├── tests/
│   ├── parity.rs           parser/inhibition parity tests
│   └── e2e/                Playwright smoke tests
├── docs/
│   ├── openapi.yaml                  canonical API contract, also served by the binary
│   ├── grafana-dashboard.json        importable Grafana dashboard example
│   ├── prometheus-scrape.example.yml Prometheus scrape example
│   ├── victoriametrics-scrape.example.yml vmagent/VictoriaMetrics scrape example
│   └── quality-nasa-jpl-warning-profile.md maintainability warning profile
├── .redocly.yaml           Redocly CLI rules for OpenAPI linting
├── klaxond.default.toml     bundled defaults, copied to /data on first run
├── Dockerfile              multi-stage Rust build
├── Dockerfile.frontend     nginx-only split frontend image
├── docker-compose.yml      reference standalone deploy
├── docker-compose.split.yml reference multi-host FE/BE/state deploy
├── deploy/frontend/        nginx template for the split frontend
├── .env.example            secrets/site-specific env vars
├── playwright.config.ts
├── README.md
├── CHANGELOG.md
└── LICENSE
```

## Development

For local development:

```bash
cargo run &
curl -s http://127.0.0.1:8181/healthz
curl -s -X POST 'http://127.0.0.1:8181/webhook/info?dry_run=1' \
  -H 'Content-Type: application/json' \
  -d '{"status":"firing","commonLabels":{"alertname":"local-test","severity":"info","host":"dev"}}'
```

Verification:

```bash
scripts/check-rsa-private-usage.sh
npm run loc:check
npm run nasa:warn
npm run openapi:lint
cargo test
npm run test:e2e
docker buildx build --build-context auth-modules=../auth-modules -t klaxond:local .
```

`npm run nasa:warn` runs a warning-only maintainability profile inspired by
NASA/JPL rules. It reports files over 300 LOC, functions over 60 LOC and
functions with more than 6 parameters, but does not fail by default. The same
warning profile runs in CI. See
[`docs/quality-nasa-jpl-warning-profile.md`](docs/quality-nasa-jpl-warning-profile.md)
for thresholds and environment knobs.

`npm run openapi:lint` runs the pinned Redocly CLI from `package-lock.json`
against [`docs/openapi.yaml`](docs/openapi.yaml) using `.redocly.yaml`.
Redocly CLI 2.x requires Node 20.19+ with npm 10+; the Gitea workflow pins
Node 20.19.0 for that check.
Redocly checks the quality and consistency of the OpenAPI document; it does not
replace backend tests, contract behavior tests, or the custom route/spec coverage
checks in the Rust test suite.

The Redocly config keeps license metadata, 2xx/4xx response completeness and
unused component cleanup as explicit warnings: they stay visible locally and in
CI without blocking changes that only improve the contract incrementally.
Redocly errors still fail the pipeline.

Security checks include an RSA timing-advisory guard. `cargo audit` currently
reports `RUSTSEC-2023-0071` for the transitive RustCrypto `rsa` crate, which has
no fixed release yet. Klaxond accepts that dependency only for public-key
OIDC/WebAuthn verification and does not perform RSA private-key decrypt/sign
operations in the request path. Run:

```bash
cargo audit --ignore RUSTSEC-2023-0071
scripts/check-rsa-private-usage.sh
```

The threat model and review checklist are tracked in
[`docs/security-rsa-risk.md`](docs/security-rsa-risk.md).

## License

Apache-2.0 — see [LICENSE](./LICENSE).

---
> **This repository is the source of truth for klaxond**. Since 2026-06-10,
> deploys clone this repo at the pinned tag and build/deploy the image published
> by the Gitea registry. Release flow: commit here → tag `vX.Y.Z` → CI
> build/push → automatic Semaphore deploy with `klaxond_image_tag`.
