# Klaxond — CHANGELOG

## 0.13.4 — 2026-07-01

- Aggiunta paginazione reale a `/api/logs` con `limit` + `offset` e metadata
  coerenti per evitare liste log troppo lunghe in UI.
- La pagina Logs ora ha page size, controlli prima/precedente/successiva/ultima
  e range visibile dei risultati.
- Aggiunto widget Status "Log buffer" con righe trattenute, WARN/ERROR nel
  buffer corrente e link diretto ai log.

## 0.13.3 — 2026-06-30

- Aggiunto export completo impostazioni (`/api/config/export`) in formato JSON:
  include `klaxond.toml`, sidecar effettivi `render-config.json`,
  `ntfy-topics.json`, `dedup-config.json`, `auth-config.json` e snapshot
  runtime derivato da env/stack, inclusi i segreti.
- Il restore config accetta anche il bundle JSON completo e ripristina TOML +
  sidecar in modo atomico sotto config lock.
- Aggiunto pulsante UI "Export completo" e copertura e2e del round-trip
  export/restore bundle.

## 0.13.2 — 2026-06-30

- Serializzate le write admin di configurazione con lock in-process e lock file
  cross-process, evitando lost update tra salvataggi concorrenti di TOML/JSON
  runtime.
- Reso il restore TOML coerente con i sidecar JSON di render, dedup, auth e
  ntfy quando il TOML ripristinato contiene quelle sezioni.
- Resi univoci i temp file delle write atomiche e i nomi degli auto-backup anche
  con piu' salvataggi nello stesso secondo.
- Aggiunta base Telegram configurabile per test/parita' (`TELEGRAM_API_BASE`),
  mantenendo il default `https://api.telegram.org` in produzione.
- Aggiunti test con servizi fake locali per ntfy, Telegram, render Grafana e
  SMTP, così le integrazioni delivery vengono verificate senza dipendere da
  endpoint esterni reali.

## 0.13.1 — 2026-06-30

- Rafforzata la redazione dei log esposti da `/api/logs` per coprire anche
  variabili stile `*_TOKEN`, `*_SECRET`, `*_PASSWORD` e simili.
- Resa la ricerca log case-insensitive anche per testo Unicode/non ASCII.
- Evitati panic a catena da lock poisonati nei principali stati runtime
  condivisi (config, metriche, inhibition/ack/schedule, immagini renderizzate).
- Aggiunto test e2e che verifica che `/api/logs` richieda auth admin quando
  l'autenticazione e' attiva.

## 0.13.0 — 2026-06-30

- Aggiunta pagina UI Logs con ricerca keyword, filtro livello, limite risultati
  e auto-refresh, alimentata da un ring buffer in-process agganciato a
  `tracing` via endpoint admin `/api/logs`; token, secret e URL sensibili
  vengono redatti prima di essere esposti.
- Uniformata la gestione errori frontend: le failure dei loader, dei salvataggi
  e delle azioni utente mostrano sempre un toast, mantenendo il messaggio inline
  vicino al form quando presente.

## 0.12.1 — 2026-06-30

- Corretto il callback OIDC del backend Rust: `jsonwebtoken` ora viene
  compilato con provider crypto RustCrypto, evitando panic durante la verifica
  dell'`id_token` e il conseguente loop di redirect dopo login Authentik.
- Reso piu' robusto il flusso auth contro cookie sessione duplicati e
  `return_to` non sicuri o puntati a `/auth/*`, prevenendo ulteriori loop.
- Logout rafforzato: cancella varianti plausibili del cookie sessione per
  Path/Domain, evitando sessioni sticky quando il browser ha cookie duplicati.

## 0.12.0 — 2026-06-29

- Aggiunta UI bilingue inglese/italiano con preferenza persistita nel browser
  (`klaxond.lang`) e fallback alla lingua del browser.
- Aggiunto selettore tema `system` / `light` / `dark` con preferenza persistita
  (`klaxond.themeMode`) e migrazione dal vecchio toggle binario.
- Coperti i nuovi controlli con test E2E Playwright per lingua, persistenza e
  theme mode.

## 0.11.2 — 2026-06-29

- Corretto il probe `/api/status` per SMTP: ora risolve hostname DNS come
  `smtp.gmail.com` invece di accettare solo indirizzi IP numerici. Questo
  elimina il falso `SMTP down` nella UI quando il server SMTP e' raggiungibile.

## 0.11.1 — 2026-06-29

- Corretto l'healthcheck Docker del container Rust: usa `127.0.0.1` invece di
  `localhost`, evitando il probe IPv6 `::1` di BusyBox `wget` mentre klaxond
  ascolta su IPv4.
- Ridotto il grafo di compilazione Rust: feature-minimal per `axum`, `tokio` e
  `chrono`; rimosse dipendenze inutili come `axum-macros`, `multer`,
  `parking_lot`, `oldtime` e `wasm-bindgen`.
- Ottimizzato il Docker build con cache BuildKit per registry/git/target e
  contesto piu' piccolo tramite `.dockerignore`.

## 0.11.0 — 2026-06-29

- Backend portato da Python a Rust mantenendo il contratto HTTP/API esistente:
  webhook, UI admin API, auth Basic/OIDC/trusted-proxy, dedup persistente,
  inhibition/ack/schedule, metriche Prometheus, delivery ntfy/Telegram/SMTP,
  render immagini Grafana e static UI.
- Runtime Docker convertito a multi-stage Rust build con immagine finale Alpine
  e binario `/usr/local/bin/klaxond`; Python non è più usato nel container.
- Aggiunti test di parità Rust (`cargo test`) e smoke E2E Playwright
  (`npm run test:e2e`) con server isolato e `/data` temporanea.

## 0.10.2 — 2026-06-15

- Override immagine per-componente: nuova sezione toml `[render.component_image]`
  (`component = "dashboard_uid:panel_id"`) che decide QUALE pannello rendere per
  l'immagine dell'alert, indipendentemente dalla dashboard del bottone. Default:
  `host = "infra-cluster-overview:10"` → l'immagine degli alert host mostra il
  pannello risorse (load1/RAM%/disk per host) invece del pannello logs Loki a cui
  punta il bottone. Senza override, resta l'auto-detect del primo pannello.

## 0.10.1 — 2026-06-15

- Render dashboard images con **d-solo** (singolo pannello) invece della
  dashboard intera: evita il modale d'annuncio "Grafana Assistant" di Grafana
  13 che copriva il render full-dashboard (l'app-shell carica il popup a ogni
  sessione headless), ed è più leggibile in una push mobile. Il pannello è
  auto-rilevato via API Grafana (primo pannello non-row/text, cached per uid);
  fallback alla dashboard intera se il lookup fallisce.

## 0.10.0 — 2026-06-15

- **Immagini dashboard negli alert**: quando il `component` dell'alert è mappato
  in `[render.component_dashboards]`, klaxond rende quella dashboard a PNG via
  l'API `/render` di Grafana (richiede il sidecar `grafana-image-renderer`),
  la ospita su `/img/<token>.png` (path auth-free, token random) e la allega
  alla push ntfy con l'header `Attach`. Render best-effort: se fallisce, la push
  parte comunque (testo + bottoni). Nuove env: `GRAFANA_RENDER_BASE` (URL
  interno Grafana, distinto da `GRAFANA_BASE` pubblico usato per il bottone),
  `GRAFANA_RENDER_TOKEN` (service-account), `RENDER_IMAGE_TTL` (default 900s).
  Il render usa `var-instance` dall'etichetta `instance` dell'alert.

## 0.9.34 — 2026-06-10

- Nuova sorgente `/pve/<severity>`: webhook del notification-system di
  Proxmox VE (body JSON via helper `{{ json … }}`). Parser dedicato, dedup
  per `type` (es. N errori vzdump → 1 gruppo), labels per inhibition
  (host=node, alertname=pve-<type>), cascade sempre on.

## 0.9.33 — 2026-06-07

**Full rename `klaxon` → `klaxond` (product name + runtime identifiers).** Display name unified to "Klaxond" everywhere, plus the load-bearing identifiers:

- Config file `/data/klaxon.toml` → `/data/klaxond.toml`; env var `KLAXON_CONFIG` → `KLAXOND_CONFIG`, `KLAXON_DEFAULT`/`KLAXON_BACKUP_DIR`/`KLAXON_BACKUP_KEEP` likewise.
- Session cookie `klaxon_session` → `klaxond_session` (existing sessions are invalidated → silent re-login via the 0.9.32 self-healing OIDC callback).
- Backup files `klaxon-*.toml` → `klaxond-*.toml`.
- **Migration**: live `/data/klaxon.toml` + backups renamed on deploy. If you run this elsewhere, `mv /data/klaxon.toml /data/klaxond.toml` (and `backups/klaxon-*.toml`) before starting 0.9.33, else the daemon bootstraps a fresh empty config.
- Fixed `alert-klaxond-down.yml`: recovery action referenced container `klaxon` (never existed; it's `klaxond`) → `docker start/restart/logs` now target `klaxond`.

## 0.9.32 — 2026-06-07

**OIDC callback self-healing.** A long-idle browser tab would land on `/auth/callback` and get a 400 "invalid or expired state" ("sessione scaduta"), dead-ending the user; reloading the root URL then worked. Cause: the session cookie (8h) expires while the tab is idle, and/or a klaxond restart (deploy / WUD auto-update) drops the in-memory `_OIDC_STATE_STORE` (10-min TTL) — so the returning `state` is unknown at callback time.

- `oidc_callback`: unknown/expired `state` now 302-redirects to `/` instead of returning 400. This restarts the Authorization Code flow; with the upstream Authentik SSO session still alive the user is re-logged-in silently. No session is issued on this path, so there is no CSRF exposure in the redirect.
- Missing `code`/`state` params still return 400 (malformed request ≠ expired flow).

## 0.9.24 — 2026-06-03

**Decypharr endpoint.** Add `/decypharr/` to ingest sources. Decypharr (cy01/blackhole, the qBit-emulation bridge to Real-Debrid) emits per-torrent webhooks (`download_start`, `download_complete`, `download_fail`) via Callback URL configured in Settings → Notifications. Klaxond parses these and routes via standard cascade.

- `parse_decypharr_payload`: maps `status` ("success"/"failure"/"error") → severity (info/warning/critical), formats title with event verb + torrent name, body from payload `message` field (Decypharr pre-formats).
- Dedup key: `decypharr:<event>:<hash>` — same torrent retry-burst dedupes; different events for same hash get through.
- Frontend: new sample button in Preview tab, DCY node in Mermaid flow, dedup card with help text.
- Dispatch: `/decypharr/<severity>` POST endpoint, body status overrides URL path severity (same pattern as Shelfmark Apprise `type` field).

## 0.9.6 — 2026-06-01

**Source-agnostic inhibition.** Previously only Grafana/Alertmanager alerts
were subject to inhibition rules; Beszel/HC/WUD/Authentik always notified
regardless of cluster state. As of 0.9.6:

- New `_normalize_labels(source, payload)` projects every webhook to a
  canonical `{host, service, job, alertname, status}` dict.
- `apply_inhibition(source, labels)` runs against ALL five sources.
- Source-alert ARMING (the `inhibition_source` label set on Grafana rules)
  still comes only from Grafana — but EVERY source is now subject to
  existing suppressions.
- New `applies_to = ["grafana", "beszel", …]` field on rules to scope
  suppression. Omitted → applies to all sources.

Default rules updated:
- `node-down` (host offline) → suppresses any alert with matching `host`
  label across ALL sources (Beszel CPU alerts from the offline box are
  now correctly muted, ditto WUD container updates).
- `cluster-wide-restart` → suppresses EVERYTHING from EVERY source.
- `traefik-down` / `authentik-down` → scoped to `applies_to=["grafana"]`
  (blackbox job labels are a Grafana-only concept).

UI:
- Inhibitions tab shows new "Applies to" column.
- Flow Mermaid now routes ALL emitters through INH (no more
  "(grafana only)" caveat).

Live-tested in-prod 2026-06-01: node-down host=svr-01 successfully
suppressed Beszel system=svr-01 while letting svr-02 through;
applies_to=[grafana] correctly scoped traefik-down away from Beszel.

## 0.5.6 — 2026-05-27

### Fixed

- **Telegram: switched from Markdown to HTML parse_mode**. Markdown
  parser rejected messages whose body contained stray underscores
  (e.g. "remote_cache", a normal identifier in alerts) — Telegram
  interpreted them as unclosed italic markers and returned 400 Bad
  Request. HTML mode only requires escaping <, >, & in text — much
  safer for free-form alert bodies. Title is now <b>...</b>,
  severity is <code>...</code>.


## 0.5.5 — 2026-05-27

### Fixed

- **Telegram tier: all action URLs now as inline_keyboard buttons**.
  Previously, only the first action URL was appended as a markdown
  link at the tail of the message text — runbook and dashboard URLs
  beyond the first were dropped silently. Now klaxond posts one
  Telegram inline_keyboard button per action (capped at 5 for safety),
  matching what ntfy already showed. So a critical alert on Telegram
  now has tappable "📖 Runbook" / "📊 Dashboard" / "View rule"
  buttons under the message.

  SMTP tier was already including all actions as text lines
  ("label: url") so no change there.


## 0.5.4 — 2026-05-27

### Added

- **Fallback runbook URLs per source** ([render.fallback_runbooks] in
  klaxon.toml). Sources without a per-alert annotation channel (Beszel,
  Healthchecks) now also get a "📖 Runbook" button — the URL is taken
  from the toml config for the source. Grafana alerts continue to use
  the per-rule annotation.runbook_url (which wins over any fallback).

  Healthchecks supports per-payload override too: include
  "runbook_url" in the JSON body and it overrides the toml fallback
  for that specific check.

  Example klaxon.toml:
    [render.fallback_runbooks]
    beszel       = "https://docs.example.com/runbooks/beszel.md"
    healthchecks = "https://docs.example.com/runbooks/hc-deadman.md"

  When empty (the default), no button is shown for that source.


## 0.5.3 — 2026-05-27

### Added

- **Runbook action button** on Grafana-origin notifications. If the
  alert rule sets `annotations.runbook_url`, klaxond prepends a
  "📖 Runbook" button to the ntfy actions array, before the
  existing component-dashboard button. Tapping the push opens the
  runbook directly. ntfy supports up to 3 action buttons; runbook
  + dashboard + rule URL fit comfortably.

  Convention: link to a markdown file in your docs repo (e.g.
  Gitea or Forgejo with mermaid rendering), or to a wiki page —
  whatever your team uses. klaxond does not parse the runbook;
  it just forwards the URL to ntfy.

  No-op for Beszel and Healthchecks endpoints since those sources
  don't have an annotation system. (HC checks already get a
  "Open in HC" button via the "url" body field.)


## 0.5.2 — 2026-05-27

### Fixed

- **Emoji conflict on RESOLVED**. When an alert resolved, the tag list
  still contained the severity literal (`warning`/`critical`), which ntfy
  auto-rendered as the matching Unicode emoji on the phone. Result:
  title showed ✅ (resolved) while tags showed ⚠️ — visually contradictory.
  All three parsers (Grafana, Beszel, Healthchecks) now drop the severity
  literal from the tag list when status is resolved, keeping only the
  resolved checkmark + component tag.

### Added

- **Structured audit log per delivery** (`audit_log_delivery()`). klaxond
  emits one JSON line per delivery attempt with stable schema (audit,
  source, severity, alertname, component, host, tiers_attempted, ok,
  channel, duration_ms, timestamp). Promtail scrapes klaxond stdout to
  Loki; the new Alert health dashboard plus future ad-hoc "who got what
  when" queries consume this stream.


## 0.5.1 — 2026-05-27

### Fixed

- **Emoji consistency across renderers**. Three small drifts that
  added up to confusing UX:
  1. `severity_tag_prefix` from `klaxon.toml` was loaded but never
     applied at runtime — both Grafana and Beszel renderers used a
     hardcoded dict inline. Setting the TOML field had no effect.
  2. `severity_emoji.resolved` was loaded into ICONS but bypassed —
     the literal "✅" was hardcoded in all three parsers.
  3. The new /healthchecks parser used "⚠️" as fallback emoji while
     /webhook and /beszel used "ℹ️".

  All three parsers (Grafana, Beszel, Healthchecks) now read from
  the same ICONS and TAG_PREFIXES globals, so a single edit to
  klaxon.toml under [render.severity_emoji] / [render.severity_tag_prefix]
  flips the rendering for every source.

- **TAG_PREFIXES global** added next to ICONS/PRIORITIES.
  Defaults: info=information_source, warning=warning,
  critical=rotating_light, resolved=white_check_mark — all
  TOML-overridable.


## 0.5.0 — 2026-05-27

### Added

- **`/healthchecks/<sev>` endpoint** for Healthchecks self-hosted webhook
  channels. Accepts the JSON body
  `{check, status, code, last_ping, tags, url}` (HC's substitution
  placeholders) and renders an alert with the same shape as
  `/webhook/` and `/beszel/`. `status: up|ok|resolved` flips the
  rendering to "✅ HC UP" with low priority; anything else (`down`,
  `fail`) renders as "🚨 HC DOWN" with the severity priority from the
  URL path. Cascade is always-on for this source (HC's native
  webhook retry is single-channel).

- **HA-ready** documentation in README.md: how to deploy klaxon
  behind a load balancer with shared `/data` storage, what state is
  file-backed vs in-memory, and the self-monitoring pattern that
  works whether you run one instance or many. No code changes
  needed — both config files are already atomically written and
  read on every relevant request, so NFS/Ceph just works.


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
