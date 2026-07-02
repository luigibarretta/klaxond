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

- **Two webhook formats**: `/webhook/<sev>` (Grafana Alertmanager-shape) and `/beszel/<sev>` (Beszel-shape).
- **3-tier cascade fallback** — ntfy → Telegram → SMTP. Always on for Beszel, gated for Grafana.
- **Rich ntfy push rendering**: severity emoji in title (RFC 2047 base64-encoded for non-ASCII), priority + tag mapping, up to 2 action buttons via `component` label → dashboard URL.
- **In-memory inhibition** safety net (Alertmanager owns the canonical layer if you're using it).
- **TOML bootstrap config** (`klaxond.toml`) — defines cascade tiers, render mappings, inhibition rules. Auto-bootstrapped on first run from the bundled default.
- **Admin UI** (vanilla HTML+JS, zero build) at `/ui/`: channel health, active inhibitions, recent deliveries, render config CRUD with deep-link test, visual ntfy push preview, cascade tier editor, channel routing config.
- **Rust backend** — single `klaxond` binary built with Cargo, served from a small Alpine runtime image.

## Quick start

```bash
git clone https://github.com/your-org/klaxond.git
cd klaxond
cp .env.example .env
# edit .env to fill the secrets: NTFY_TOKEN_*, TELEGRAM_BOT_TOKEN, SMTP_USER/PASSWORD
docker compose up -d
```

Open `http://localhost:8181/ui/` to access the admin UI. Edit channel URLs/topics from the Routing tab; secrets stay in your `.env`.

### Public legal and accessibility pages

klaxond ships public informational pages that remain reachable even when the
admin UI is protected by SSO, Basic auth, trusted proxy auth, passkeys, API keys
or PATs. Replace `localhost:8181` with your own self-hosted origin:

- [Privacy notice](http://localhost:8181/ui/privacy)
- [Accessibility statement](http://localhost:8181/ui/accessibility)
- [Terms of use](http://localhost:8181/ui/terms)
- [Cookie notice](http://localhost:8181/ui/cookies)
- [Legal notice and contacts](http://localhost:8181/ui/legal)

The same links are shown in the app footer and on the local login/signed-out
screen.

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
| `POST` | `/api/cascade-config` | Update tiers (persists to `/data/klaxond.toml`) |
| `GET` | `/api/channel-config` | ntfy URL + topics, Telegram chat_id, SMTP host/port/from/to. Secrets shown as configured/missing badges only. |
| `POST` | `/api/channel-config` | Update non-secret channel fields (persists to `/data/klaxond.toml`) |
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
chat_id = "your-chat-id"

[smtp]
host = "smtp.example.com"
port = 587
from_addr = "klaxond@example.com"
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
| `KLAXOND_CONFIG` | path to klaxond.toml (default `/data/klaxond.toml`) |
| `PORT` | listen port (default `8181`) |

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

Klaxond is single-process and stateless-ish — most data lives in two files under `/data`. That means HA is a deploy-time decision, not a code change.

**TL;DR**: mount `/data` from shared storage (NFS, Ceph, etc.) and run two containers behind any TCP/HTTP load balancer with a `/healthz` health check.

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
                  │  ├ klaxond.toml           │
                  │  └ render-config.json    │
                  └──────────────────────────┘
```

### What's safe to share between instances

- **`/data/klaxond.toml`** — TOML config (channels, tiers, render rules, inhibitions). Read on startup + on POST `/api/*-config`. File-locked writes on save.
- **`/data/render-config.json`** — render overrides edited via UI. Same pattern.

Both files are written atomically (write-temp-then-rename). With NFS v4 sync mode the cross-instance read-after-write is consistent. Don't use SMB — locking semantics are too loose.

### What's in-memory and NOT shared

| State | Where | Impact of split between instances |
|---|---|---|
| Inhibition deque (recent alert hashes) | RAM, last ~256 entries per instance | Best-effort dedup. The canonical inhibition layer should be Alertmanager — this is a safety net for direct webhook posts. With 2 instances, occasional duplicate inhibition misses. |
| Delivery history (UI "Recent deliveries") | RAM, last ~512 entries per instance | UI shows local history only. If you load-balance round-robin, each instance sees ~half the deliveries — neither has the full picture. Live in Loki/Prometheus for canonical history; klaxond's view is an immediate-debugging aid. |

If you want global delivery history, scrape the klaxond logs into Loki (already free since both instances write to stdout) and query there.

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
├── static/
│   ├── index.html          admin UI (single page)
│   ├── style.css           dark theme, ~6KB
│   └── app.js              vanilla JS, fetch + DOM
├── tests/
│   ├── parity.rs           parser/inhibition parity tests
│   └── e2e/                Playwright smoke tests
├── klaxond.default.toml     bundled defaults, copied to /data on first run
├── Dockerfile              multi-stage Rust build
├── docker-compose.yml      reference standalone deploy
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
cargo test
npm run test:e2e
docker build -t klaxond:local .
```

## License

Apache-2.0 — see [LICENSE](./LICENSE).

---
> **Questo repo È la source of truth di klaxond** (progetto personale,
> 2026-06-10: invertito il modello — prima il sorgente viveva in
> infra-ansible/files/klaxond). Il deploy (`infra-ansible/playbooks/deploy-klaxond.yml`)
> clona QUESTO repo al tag pinnato e builda/deploya l'immagine pubblicata dal
> registry Gitea. Flusso release: commit qui → tag vX.Y.Z → CI build/push →
> deploy automatico via Semaphore con `klaxond_image_tag`.
