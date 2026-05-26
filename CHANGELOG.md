# Klaxon — CHANGELOG

## 0.2.0 — 2026-05-26

### Changed
- **Renamed binary/image/repo from `klaxon` to `klaxond`** (Unix daemon
  convention). Product display name remains "Klaxon". docker-compose.yml,
  container name, image labels and source file headers updated.

### Added
- Gitea Actions workflow `.gitea/workflows/build.yml` for multi-arch
  Docker image build (`linux/amd64` + `linux/arm64`) on `v*` tag push.
  Image pushed to `git.luigibarretta.com/luigibarretta/klaxond:<tag>`
  and `:latest`.

## 0.1.0 — 2026-05-26

First versioned release.

### Features

- HTTP webhook bridge: `/webhook/<sev>` (Grafana Alertmanager-shape JSON) +
  `/beszel/<sev>` (Beszel-shape JSON) on port 8181.
- ntfy push rendering: severity emoji in title (RFC 2047 base64-encoded),
  priority + tag mapping per severity, up to 2 action buttons via
  `component` label.
- Cascade fallback (ntfy → Telegram → SMTP) with per-tier timeouts.
  Always on for `/beszel/*`; gated for `/webhook/*` (default off, since
  Grafana has its own retries).
- In-memory inhibition rules as safety net for direct posts
  (Alertmanager owns the canonical layer).
- TOML bootstrap (`klaxon.toml`) for cascade tiers, render config,
  inhibition rules. Bootstrapped on first run from bundled default.
- Admin UI (vanilla HTML+JS, no framework) at `/ui/` with 6 tabs:
  Status, Inhibitions, Recent deliveries, Render config CRUD, Render
  preview, Send test.
- JSON API endpoints for the UI: `/api/status`, `/api/inhibitions`,
  `/api/deliveries`, `/api/render-config` (GET+POST),
  `/api/render-preview`, `/api/test/<sev>`, `/api/cascade/toggle`.
- Compose-bootstrappable Docker image:
  `docker compose up -d` is enough — no Ansible required.

### Stack

- Python 3.13 stdlib only (no third-party deps).
- Image: `python:3.13-alpine` base, ~50 MB total.
- Persistent state: `/data` (klaxon.toml + render-config.json).
