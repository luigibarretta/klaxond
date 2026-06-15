"""
klaxond — converts Grafana webhook JSON or Beszel webhook JSON into
ntfy pushes with proper headers/actions, with optional cascade fallback
(ntfy → Telegram → mail via Gmail SMTP) when the primary channel fails.

Env:
  NTFY_URL          base URL  (default empty — set via env or klaxond.toml)
  NTFY_TOKEN_INFO   bearer token used for the info topic
  NTFY_TOKEN_WARN   bearer token used for the warning topic
  NTFY_TOKEN_CRIT   bearer token used for the critical topic
  TOPIC_INFO        info topic id      (no default — required)
  TOPIC_WARN        warning topic id   (no default — required)
  TOPIC_CRIT        critical topic id  (no default — required)
  PORT              listen port (default 8181)

  CASCADE_ENABLED   when "true", on ntfy failure fall back to Telegram, then
                    SMTP. Always on for /beszel/* (since Beszel itself only
                    knows webhook). For /webhook/* (Grafana) the default is
                    off — Grafana has its own retries/contact points.

  TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID  Tier-2 fallback
  SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASSWORD, SMTP_FROM, SMTP_TO
                                       Tier-3 fallback

Routes:
  GET  /healthz                  → 200 OK
  POST /webhook/<severity>       → Grafana Alertmanager-shape JSON
  POST /beszel/<severity>        → Beszel webhook JSON
  POST /pve/<severity>           → Proxmox VE notification webhook JSON
"""
import base64
import json
import re
import logging
import os
import smtplib
import urllib.parse
import urllib.request
try:
    import tomllib
except ImportError:
    tomllib = None
import signal
import threading
import time as time_mod
from collections import defaultdict
from email.mime.text import MIMEText
from http.server import HTTPServer, BaseHTTPRequestHandler

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("klaxond")

# These get populated by _apply_channel_config() after TOML is loaded.
# Order of precedence: env var > TOML > hardcoded fallback (defined below).
NTFY_URL = ""
# NTFY_TOPICS replaces the old TOPICS/TOKENS dicts (0.7.0+). Each entry:
#   {"name": "topic_id", "token": "tk_...", "handles": ["info", "warning"]}
# Same severity may appear in multiple topics → fan-out (notification sent to
# all matching topics). Severities can be any non-empty string; ICONS /
# PRIORITIES / TAG_PREFIXES fall back to 'info' defaults for unknown ones.
NTFY_TOPICS: list = []
PRIORITIES = {"info": "default", "warning": "high", "critical": "urgent", "resolved": "low"}

ICONS = {"info": "ℹ️", "warning": "⚠️", "critical": "🚨", "resolved": "✅"}
TAG_PREFIXES = {"info": "information_source", "warning": "warning",
                "critical": "rotating_light", "resolved": "white_check_mark"}
FALLBACK_RUNBOOKS = {"beszel": "", "healthchecks": ""}

NTFY_TOPICS_PATH = os.environ.get("NTFY_TOPICS_PATH", "/data/ntfy-topics.json")


def _topics_for_severity(severity: str) -> list:
    """Return all ntfy topics whose `handles` list contains this severity."""
    return [t for t in NTFY_TOPICS if severity in (t.get("handles") or [])]


def _save_ntfy_topics(topics: list) -> None:
    """Persist topics to /data/ntfy-topics.json (atomic write).
    Supersedes TOML + env on next config load."""
    try:
        os.makedirs(os.path.dirname(NTFY_TOPICS_PATH), exist_ok=True)
    except Exception:
        pass
    tmp = NTFY_TOPICS_PATH + ".tmp"
    payload = {"topics": [{"name": str(t["name"]),
                            "token": str(t.get("token", "") or ""),
                            "handles": [str(h) for h in (t.get("handles") or [])]}
                          for t in topics]}
    with open(tmp, "w") as f:
        json.dump(payload, f, indent=2)
    os.replace(tmp, NTFY_TOPICS_PATH)


def _all_known_severities() -> set:
    """Union of severities declared by any topic + built-in display severities.
    Used to validate the URL path /<source>/<severity>."""
    s = set()
    for t in NTFY_TOPICS:
        s.update(t.get("handles") or [])
    # 'resolved' is a display state, not gated by topic mapping → always accept
    s.add("resolved")
    return s

GRAFANA_BASE = os.environ.get("GRAFANA_BASE", "https://grafana.example.com")

# COMPONENT_DASHBOARDS: mapping `component` label → (button_label, url).
# File-backed so it can be edited at runtime from the UI without a redeploy.
# Default is bootstrapped at first read if the file doesn't exist yet.
RENDER_CONFIG_PATH = os.environ.get("RENDER_CONFIG_PATH", "/data/render-config.json")
_DEFAULT_COMPONENT_DASHBOARDS = {
    # Generic placeholders. Edit via the admin UI (Render config tab) or
    # in klaxond.toml. Paths starting with / are appended to GRAFANA_BASE.
    "host":     ["Logs",         "/d/your-logs-dashboard"],
    "traefik":  ["Traefik",      "/d/your-traefik-dashboard"],
}

# ── Alert image rendering (grafana-image-renderer) ──────────────────────────
# When an alert's `component` maps to a dashboard (COMPONENT_DASHBOARDS), klaxond
# renders that dashboard to PNG via Grafana's /render API (requires the
# grafana-image-renderer sidecar) and hosts it at /img/<token>.png so ntfy can
# attach it (Attach header). The render base is INTERNAL (no Authentik) and is
# distinct from GRAFANA_BASE (public, used for the deep-link button). Feature is
# off unless GRAFANA_RENDER_BASE + GRAFANA_RENDER_TOKEN are set.
GRAFANA_RENDER_BASE = os.environ.get("GRAFANA_RENDER_BASE", "").rstrip("/")
GRAFANA_RENDER_TOKEN = os.environ.get("GRAFANA_RENDER_TOKEN", "")
RENDER_IMAGE_TTL = int(os.environ.get("RENDER_IMAGE_TTL", "900"))
_rendered_images = {}            # token -> (png_bytes, expiry_epoch)
_rendered_images_lock = threading.Lock()


def _prune_rendered_images():
    now = time_mod.time()
    with _rendered_images_lock:
        for k in [k for k, (_, exp) in _rendered_images.items() if exp < now]:
            _rendered_images.pop(k, None)


_dashboard_panel_cache = {}     # uid -> first-real-panel id (or None)


def _first_render_panel(uid: str):
    """First non-row/non-text panel id of a dashboard, for a clean d-solo render.
    d-solo renders just the panel iframe (no app shell) — this is what dodges the
    Grafana app-level announcement modals that obscure full-dashboard renders.
    Cached per uid; returns None on any failure (caller falls back to full dash)."""
    if uid in _dashboard_panel_cache:
        return _dashboard_panel_cache[uid]
    pid = None
    try:
        req = urllib.request.Request(f"{GRAFANA_RENDER_BASE}/api/dashboards/uid/{uid}",
                                     headers={"Authorization": f"Bearer {GRAFANA_RENDER_TOKEN}"})
        with urllib.request.urlopen(req, timeout=10) as r:
            dash = json.loads(r.read()).get("dashboard", {})
        skip = {"row", "text", "news", "dashlist", "alertlist"}
        cands = [p for p in dash.get("panels", []) if p.get("type") not in skip and "id" in p]
        if cands:
            pid = sorted(cands, key=lambda p: p["id"])[0]["id"]
    except Exception as e:
        log.warning("render: panel lookup failed for %s: %s", uid, e)
    _dashboard_panel_cache[uid] = pid
    return pid


def render_alert_image(slug: str, instance: str = "", timeout: int = 25):
    """Render a Grafana dashboard's first panel (d-solo — clean, no app-shell
    announcement modals, and tighter for a mobile push) to PNG via the
    image-renderer. Falls back to the full dashboard if panel lookup fails.
    Returns bytes on success else None. Best-effort: never raises."""
    if not (GRAFANA_RENDER_BASE and GRAFANA_RENDER_TOKEN and slug and slug.startswith("/d/")):
        return None
    uid = slug[len("/d/"):].split("/", 1)[0].split("?", 1)[0]
    pid = _first_render_panel(uid)
    if pid is not None:
        q = {"orgId": "1", "theme": "dark", "width": "1000", "height": "500",
             "panelId": str(pid), "from": "now-3h", "to": "now"}
        if instance:
            q["var-instance"] = instance
        url = f"{GRAFANA_RENDER_BASE}/render/d-solo/{uid}/x?{urllib.parse.urlencode(q)}"
    else:
        q = {"orgId": "1", "theme": "dark", "width": "1000", "height": "800",
             "from": "now-3h", "to": "now"}
        if instance:
            q["var-instance"] = instance
        url = f"{GRAFANA_RENDER_BASE}/render{slug}?{urllib.parse.urlencode(q)}"
    try:
        req = urllib.request.Request(url, headers={"Authorization": f"Bearer {GRAFANA_RENDER_TOKEN}"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = r.read()
        if data[:8] == b"\x89PNG\r\n\x1a\n":
            return data
        log.warning("render: non-PNG response for %s (%d bytes)", slug, len(data))
    except Exception as e:
        log.warning("render: failed for %s: %s", slug, e)
    return None


def stash_alert_image(png: bytes) -> str:
    """Store PNG under a random token (auto-expiring); return the token."""
    _prune_rendered_images()
    tok = secrets.token_urlsafe(12)
    with _rendered_images_lock:
        _rendered_images[tok] = (png, time_mod.time() + RENDER_IMAGE_TTL)
    return tok


def _load_render_config(toml_seed: dict = None) -> dict:
    """Read render-config.json from disk; bootstrap with TOML seed if available,
    or in-code defaults otherwise, on first boot.

    `toml_seed` is the [render.component_dashboards] section of klaxond.toml.
    Order of bootstrap precedence on first boot (no render-config.json):
      1. TOML seed (if non-empty)         — operator's deploy-time choice
      2. _DEFAULT_COMPONENT_DASHBOARDS    — hard-coded fallback
    Once render-config.json exists, it is the source of truth (UI edits persist
    there); TOML seed is NOT re-applied to avoid surprising operators who edit
    via UI.
    """
    try:
        with open(RENDER_CONFIG_PATH, "r") as f:
            data = json.load(f)
        return {k: tuple(v) for k, v in data.get("component_dashboards", {}).items()}
    except FileNotFoundError:
        seed = toml_seed if toml_seed else _DEFAULT_COMPONENT_DASHBOARDS
        # Coerce TOML list values to tuples for in-memory use; persist as lists
        cleaned = {k: tuple(v) if isinstance(v, (list, tuple)) else (str(v), "") for k, v in seed.items()}
        _save_render_config(cleaned)
        return cleaned
    except Exception as e:
        log.warning("render-config read failed (%s) — using defaults", e)
        return {k: tuple(v) for k, v in _DEFAULT_COMPONENT_DASHBOARDS.items()}


def _save_render_config(component_dashboards: dict) -> None:
    """Persist the mapping to disk. Atomic write via temp+rename."""
    try:
        os.makedirs(os.path.dirname(RENDER_CONFIG_PATH), exist_ok=True)
    except Exception:
        pass
    tmp = RENDER_CONFIG_PATH + ".tmp"
    payload = {"component_dashboards": {k: list(v) for k, v in component_dashboards.items()}}
    with open(tmp, "w") as f:
        json.dump(payload, f, indent=2)
    os.replace(tmp, RENDER_CONFIG_PATH)


# Defer COMPONENT_DASHBOARDS init until after TOML is loaded so we can use
# the TOML [render.component_dashboards] as bootstrap seed on first boot.
COMPONENT_DASHBOARDS = {}  # populated below, right after TOML_CONFIG init

# ============================================================================
# Dedup config — group multiple inbound events per source into one notification
# within a configurable time window. Disabled by default for all sources except
# WUD (out of the box).
#
# Config schema (per source):
#   enabled          : bool
#   window_s         : int  — flush after N seconds of inactivity
#   strategy         : "none" | "time" | "key"
#                      key = group items sharing the same dedup_key (per source)
#                      time = all items in the window batched together
#                      none = no grouping (delivery immediate, equivalent to disabled)
#   override_critical: bool — if true, also debounce severity=critical
#                      (otherwise critical always delivers immediately).
#
# Persistence:
#   /data/dedup-config.json    — user settings (read by UI tab)
#   /data/dedup_pending/       — pending event queue per source (.jsonl), so
#                                 a klaxond restart doesn't lose buffered events.
#                                 At startup, any pending_*.jsonl is flushed
#                                 immediately (no window wait).
# ============================================================================
DEDUP_CONFIG_PATH = os.environ.get("DEDUP_CONFIG_PATH", "/data/dedup-config.json")
DEDUP_PENDING_DIR = os.environ.get("DEDUP_PENDING_DIR", "/data/dedup_pending")

DEDUP_SOURCES = ("grafana", "beszel", "healthchecks", "wud", "authentik", "shelfmark", "prowlarr", "decypharr")

_DEFAULT_DEDUP_SETTINGS = {
    "grafana":      {"enabled": False, "window_s": 90, "strategy": "key", "override_critical": False},
    "beszel":       {"enabled": False, "window_s": 90, "strategy": "key", "override_critical": False},
    "healthchecks": {"enabled": False, "window_s": 90, "strategy": "key", "override_critical": False},
    "wud":          {"enabled": True,  "window_s": 90, "strategy": "key", "override_critical": False},
    "authentik":    {"enabled": False, "window_s": 60, "strategy": "key", "override_critical": False},
    "shelfmark":    {"enabled": True,  "window_s": 120, "strategy": "key", "override_critical": False},
    "prowlarr":     {"enabled": True,  "window_s": 90,  "strategy": "key", "override_critical": False},
    "decypharr":    {"enabled": True,  "window_s": 60,  "strategy": "key", "override_critical": False},
}


def _load_dedup_settings(toml_seed: dict = None) -> dict:
    """Bootstrap order on first boot (when /data/dedup-config.json missing):
      1. TOML [dedup.<source>] section (if provided)         — deploy-time
      2. _DEFAULT_DEDUP_SETTINGS                              — in-code defaults
    Once dedup-config.json exists, it's the source of truth (UI edits live here).
    """
    try:
        with open(DEDUP_CONFIG_PATH, "r") as f:
            raw = json.load(f)
        out = {}
        for src in DEDUP_SOURCES:
            cur = dict(_DEFAULT_DEDUP_SETTINGS[src])
            cur.update(raw.get(src, {}))
            out[src] = cur
        return out
    except FileNotFoundError:
        seed = {}
        for src in DEDUP_SOURCES:
            cur = dict(_DEFAULT_DEDUP_SETTINGS[src])
            if toml_seed and isinstance(toml_seed.get(src), dict):
                cur.update(toml_seed[src])
            seed[src] = cur
        _save_dedup_settings(seed)
        return seed
    except Exception as e:
        log.warning("dedup-config read failed (%s) — using defaults", e)
        return dict(_DEFAULT_DEDUP_SETTINGS)


def _save_dedup_settings(settings: dict) -> None:
    try:
        os.makedirs(os.path.dirname(DEDUP_CONFIG_PATH), exist_ok=True)
    except Exception:
        pass
    tmp = DEDUP_CONFIG_PATH + ".tmp"
    with open(tmp, "w") as f:
        json.dump(settings, f, indent=2)
    os.replace(tmp, DEDUP_CONFIG_PATH)


# Populated below, right after TOML_CONFIG init (uses [dedup] as seed if present).
DEDUP_SETTINGS = {src: dict(_DEFAULT_DEDUP_SETTINGS[src]) for src in DEDUP_SOURCES}


def _dedup_key(source: str, payload, parts: dict, common_labels: dict) -> str:
    """Compute the grouping key for one inbound event.
    WUD: container image name (so the same image fired on N hosts groups into 1).
    Grafana: alertname (so the same alert on N hosts groups into 1).
    Beszel: container_name from labels (Beszel container metrics).
    Healthchecks: check name from labels.
    Anything missing → fallback to the rendered title (effectively per-alert).
    """
    title_fallback = parts.get("title", "?") if parts else "?"
    try:
        if source == "wud":
            if isinstance(payload, list) and payload:
                payload = payload[0]
            if isinstance(payload, dict):
                img = (payload.get("image") or {}).get("name") or payload.get("name")
                if img:
                    return f"wud:{img}"
        elif source == "grafana":
            an = common_labels.get("alertname") if isinstance(common_labels, dict) else None
            if an:
                return f"grafana:{an}"
        elif source == "beszel":
            cn = (payload.get("container_name") if isinstance(payload, dict) else None) \
                 or common_labels.get("container_name")
            if cn:
                return f"beszel:{cn}"
        elif source == "healthchecks":
            ck = (payload.get("name") if isinstance(payload, dict) else None) \
                 or (payload.get("check", {}) or {}).get("name") if isinstance(payload, dict) else None
            if ck:
                return f"hc:{ck}"
        elif source == "pve":
            if isinstance(payload, dict):
                t = payload.get("type") or ""
                if t:
                    return f"pve:{t}"
        elif source == "authentik":
            # Group by (action, user) so a burst of logins from same user → 1 notif.
            # Mapping output: data.user + data.event (login/login_failed/...)
            data = payload.get("data") if isinstance(payload, dict) else None
            data = data if isinstance(data, dict) else {}
            user = data.get("user", "")
            action = data.get("event") or data.get("status") or ""
            if user or action:
                return f"authentik:{action}:{user}"
        elif source == "shelfmark":
            # Apprise json:// payload — group by (event_type, book_title) so
            # the same book retry-burst dedups to 1.
            if isinstance(payload, dict):
                t = (payload.get("title") or "").strip()
                # Event type lives in either explicit field or the title prefix
                evt = (payload.get("event") or payload.get("type") or "").strip()
                if t or evt:
                    return f"shelfmark:{evt}:{t}"
        elif source == "prowlarr":
            # Prowlarr webhook — group by eventType (Health, HealthRestored,
            # ApplicationUpdate, Test) + first 60 chars del message: stesso
            # health event triggers ripetuti = 1 notif.
            if isinstance(payload, dict):
                evt = (payload.get("eventType") or "").strip()
                msg = ((payload.get("health") or {}).get("message") or
                       payload.get("message") or "").strip()[:60]
                if evt:
                    return f"prowlarr:{evt}:{msg}"
        elif source == "decypharr":
            # Decypharr webhook — group by (event, hash). Stesso torrent che
            # ricicla start/complete è 2 eventi distinti; ma start+start
            # ripetuto sullo stesso hash (retry RD) = 1 notif.
            if isinstance(payload, dict):
                evt = (payload.get("event") or "").strip().lower()
                h = (payload.get("hash") or "").strip().lower()
                if evt or h:
                    return f"decypharr:{evt}:{h}"
    except Exception:
        pass
    return f"{source}:{title_fallback}"


def _render_batch(source: str, severity: str, items: list) -> dict:
    """Render a single aggregated notification from N buffered items."""
    state_emoji = ICONS.get(severity, ICONS["info"])
    src_label = (
        source.upper() if source == "wud"
        else "Shelfmark" if source == "shelfmark"
        else "Prowlarr"  if source == "prowlarr"
        else "Decypharr" if source == "decypharr"
        else source.capitalize()
    )
    n = len(items)

    # Group by key
    groups = defaultdict(list)
    for it in items:
        groups[it.get("dedup_key", "?")].append(it)

    title = f"{state_emoji} {src_label}: {n} grouped event{'s' if n > 1 else ''} ({len(groups)} group{'s' if len(groups) > 1 else ''})"

    lines = []
    for key, gitems in sorted(groups.items(), key=lambda kv: -len(kv[1])):
        first = gitems[0]
        first_title = (first.get("parts") or {}).get("title", "?").split(": ", 1)[-1]
        if len(gitems) == 1:
            lines.append(f"• {first_title}")
        else:
            # Try to extract per-item host where possible
            hosts = []
            for it in gitems:
                lbls = it.get("common_labels") or {}
                pl = it.get("payload") or {}
                h = lbls.get("host") or lbls.get("instance") or (pl.get("watcher") if isinstance(pl, dict) else None)
                if h and h not in hosts:
                    hosts.append(h)
            host_suffix = f" — {len(gitems)} hosts" + (f" ({', '.join(hosts[:5])}{'…' if len(hosts) > 5 else ''})" if hosts else "")
            lines.append(f"• {first_title}{host_suffix}")
    body = "\n".join(lines[:20])
    if len(lines) > 20:
        body += f"\n… +{len(lines) - 20} more"

    tags = [TAG_PREFIXES.get(severity, "bell"), source, "grouped"]
    actions = []  # batch render keeps actions empty; user can drill down in klaxond UI
    priority = PRIORITIES.get(severity, "default")
    return {"title": title, "body": body, "tags": tags, "actions": actions, "priority": priority}


class DedupBuffer:
    """Per-source debouncing queue with disk-backed pending log.

    submit() returns True if the event was buffered (caller does NOT deliver),
    False if it should pass through to immediate delivery.

    On startup, any pending file is immediately flushed (no window wait).
    On SIGTERM, install_signal_handler() flushes all sources.
    """

    def __init__(self, deliver_fn):
        self.deliver_fn = deliver_fn
        self.queues = {src: [] for src in DEDUP_SOURCES}
        self.timers = {src: None for src in DEDUP_SOURCES}
        self.lock = threading.Lock()
        try:
            os.makedirs(DEDUP_PENDING_DIR, exist_ok=True)
        except Exception:
            pass
        self._restore_pending()

    def _pending_path(self, source: str) -> str:
        return os.path.join(DEDUP_PENDING_DIR, f"pending_{source}.jsonl")

    def _persist(self, source: str, item: dict) -> None:
        try:
            with open(self._pending_path(source), "a") as f:
                f.write(json.dumps(item, default=str) + "\n")
        except Exception as e:
            log.warning("dedup: failed to persist %s item: %s", source, e)

    def _clear_persisted(self, source: str) -> None:
        try:
            os.remove(self._pending_path(source))
        except FileNotFoundError:
            pass
        except Exception as e:
            log.warning("dedup: failed to clear pending %s: %s", source, e)

    def _restore_pending(self) -> None:
        """At startup, flush any pending events immediately."""
        for src in DEDUP_SOURCES:
            p = self._pending_path(src)
            if not os.path.exists(p):
                continue
            items = []
            try:
                with open(p, "r") as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            items.append(json.loads(line))
                        except Exception:
                            continue
            except Exception as e:
                log.warning("dedup: restore read failed for %s: %s", src, e)
                continue
            if not items:
                self._clear_persisted(src)
                continue
            log.info("dedup[%s]: restoring %d pending event(s) from disk → flushing immediately", src, len(items))
            self.queues[src] = items
            self._clear_persisted(src)
            self._flush(src)

    def submit(self, source: str, severity: str, payload, parts: dict,
               common_labels: dict, with_cascade: bool) -> bool:
        cfg = DEDUP_SETTINGS.get(source, {})
        if not cfg.get("enabled"):
            return False
        if cfg.get("strategy") == "none":
            return False
        if severity == "critical" and not cfg.get("override_critical"):
            return False
        key = _dedup_key(source, payload, parts, common_labels)
        item = {
            "ts": time_mod.time(),
            "source": source,
            "severity": severity,
            "payload": payload,
            "parts": parts,
            "common_labels": common_labels,
            "with_cascade": with_cascade,
            "dedup_key": key,
        }
        with self.lock:
            self.queues[source].append(item)
            self._persist(source, item)
            if self.timers[source] is None:
                window = int(cfg.get("window_s", 90))
                t = threading.Timer(window, self._flush, args=[source])
                t.daemon = True
                self.timers[source] = t
                t.start()
                log.info("dedup[%s]: opened %ds window, key=%s", source, window, key)
            else:
                log.info("dedup[%s]: appended to window (key=%s, queue=%d)",
                         source, key, len(self.queues[source]))
        return True

    def _flush(self, source: str) -> None:
        with self.lock:
            items = list(self.queues[source])
            self.queues[source] = []
            if self.timers[source] is not None:
                self.timers[source] = None
            self._clear_persisted(source)
        if not items:
            return
        # Severity: take highest from the buffered items
        sev_rank = {"info": 0, "warning": 1, "critical": 2}
        severity = max((it.get("severity", "info") for it in items),
                       key=lambda s: sev_rank.get(s, 0))
        # Single-item case: deliver the original parts as-is (no batching cosmetics)
        if len(items) == 1:
            it = items[0]
            parts = it.get("parts") or {}
            ok, channel = self.deliver_fn(severity, parts, it.get("with_cascade", True),
                                          labels=it.get("common_labels") or {},
                                          source=source)
            log.info("dedup[%s]: flushed 1 event → %s via %s", source, "OK" if ok else "FAIL", channel)
            return
        # Multi-item: render aggregated
        parts = _render_batch(source, severity, items)
        ok, channel = self.deliver_fn(severity, parts, True,
                                      labels=items[0].get("common_labels") or {},
                                      source=source)
        log.info("dedup[%s]: flushed %d events → %s via %s",
                 source, len(items), "OK" if ok else "FAIL", channel)

    def flush_all_blocking(self, timeout_per_source: float = 5.0) -> None:
        """Called from signal handler before exit."""
        for src in DEDUP_SOURCES:
            with self.lock:
                t = self.timers[src]
                pending = len(self.queues[src])
            if pending == 0:
                continue
            log.info("dedup[%s]: SIGTERM flush (%d pending)", src, pending)
            if t is not None:
                t.cancel()
            self._flush(src)


# ============================================================================
# Auth — pluggable authentication for UI + admin API
# ============================================================================
# Modes:
#   none           : no auth (default; webhook endpoints already public)
#   basic          : HTTP Basic Auth (single user, bcrypt hash)
#   oidc           : OIDC Authorization Code flow (Authentik, Keycloak,
#                    Authelia, Google, generic via issuer discovery)
#   trusted-proxy  : honor X-Forwarded-User header from upstream reverse
#                    proxy (e.g. Traefik + Authentik forwardAuth). klaxond
#                    itself does no auth; restricted by CIDR allowlist on
#                    request peer addr to prevent header spoofing from
#                    untrusted networks.
#
# Webhook endpoints (/webhook/, /beszel/, /healthchecks/, /wud/) are ALWAYS
# auth-free regardless of mode (emitters like WUD/Beszel can't OIDC). UI and
# /api/* are gated when mode != none.
#
# Bootstrap precedence:
#   1. /data/auth-config.json (UI-saved)
#   2. TOML [auth] section
#   3. In-code defaults (mode=none)
# Env overrides for secrets:
#   AUTH_OIDC_CLIENT_SECRET   (never persisted to file)
#   AUTH_BASIC_PASSWORD_HASH  (bcrypt hash; use 'python -c "import bcrypt; print(bcrypt.hashpw(b\"PASSWORD\", bcrypt.gensalt()).decode())"' to compute)
#   AUTH_SESSION_SECRET       (HMAC key for session cookie; auto-generated if missing)
# ============================================================================
import hmac
import hashlib
import secrets
import ipaddress
try:
    import bcrypt
    _BCRYPT_OK = True
except ImportError:
    _BCRYPT_OK = False
try:
    import jwt as pyjwt  # PyJWT
    from jwt import PyJWKClient
    _JWT_OK = True
except ImportError:
    _JWT_OK = False

AUTH_CONFIG_PATH = os.environ.get("AUTH_CONFIG_PATH", "/data/auth-config.json")
AUTH_SESSION_KEY_PATH = os.environ.get("AUTH_SESSION_KEY_PATH", "/data/auth-session.key")
AUTH_SESSION_COOKIE = "klaxond_session"

_DEFAULT_AUTH = {
    "mode": "none",  # none | basic | oidc | trusted-proxy
    "session_timeout_hours": 8,
    "basic": {
        # password_hash NEVER stored here in TOML; only via env AUTH_BASIC_PASSWORD_HASH
        # or written here at runtime from /api/auth-config POST (then persisted in JSON).
        "username": "",
        "password_hash": "",
        "realm": "klaxond",
    },
    "oidc": {
        "provider":         "authentik",  # cosmetic preset name
        "issuer":           "",   # e.g. https://idp.example.com/application/o/klaxond/
        "client_id":        "",
        "client_secret":    "",   # may be overridden by env AUTH_OIDC_CLIENT_SECRET
        "scopes":           "openid profile email",
        "required_group":   "",   # optional: claim 'groups' must contain this value
        "redirect_path":    "/auth/callback",  # appended to the request Host
    },
    "trusted_proxy": {
        "user_header":      "X-Forwarded-User",
        "email_header":     "X-Forwarded-Email",
        "groups_header":    "X-Forwarded-Groups",
        "trusted_cidrs":    ["127.0.0.1/32", "192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12"],
    },
}


def _load_auth_config(toml_seed: dict = None) -> dict:
    try:
        with open(AUTH_CONFIG_PATH, "r") as f:
            raw = json.load(f)
        # Deep-merge with defaults so new fields are present
        out = json.loads(json.dumps(_DEFAULT_AUTH))  # deep copy
        for k, v in raw.items():
            if isinstance(v, dict) and isinstance(out.get(k), dict):
                out[k].update(v)
            else:
                out[k] = v
        return out
    except FileNotFoundError:
        out = json.loads(json.dumps(_DEFAULT_AUTH))
        if toml_seed and isinstance(toml_seed, dict):
            for k, v in toml_seed.items():
                if isinstance(v, dict) and isinstance(out.get(k), dict):
                    out[k].update(v)
                else:
                    out[k] = v
        # Env override for OIDC client secret
        sec = os.environ.get("AUTH_OIDC_CLIENT_SECRET")
        if sec:
            out.setdefault("oidc", {})["client_secret"] = sec
        # Env override for basic password hash
        hsh = os.environ.get("AUTH_BASIC_PASSWORD_HASH")
        if hsh:
            out.setdefault("basic", {})["password_hash"] = hsh
        _save_auth_config(out)
        return out
    except Exception as e:
        log.warning("auth-config read failed (%s) — using defaults", e)
        return json.loads(json.dumps(_DEFAULT_AUTH))


def _save_auth_config(cfg: dict) -> None:
    try:
        os.makedirs(os.path.dirname(AUTH_CONFIG_PATH), exist_ok=True)
    except Exception:
        pass
    tmp = AUTH_CONFIG_PATH + ".tmp"
    with open(tmp, "w") as f:
        json.dump(cfg, f, indent=2)
    os.replace(tmp, AUTH_CONFIG_PATH)


def _load_or_create_session_key() -> bytes:
    """HMAC key for session cookie signing. Persisted across restarts so old
    cookies remain valid; env AUTH_SESSION_SECRET overrides (rotate by changing
    env + restart, invalidates all sessions)."""
    env = os.environ.get("AUTH_SESSION_SECRET")
    if env:
        return env.encode("utf-8")
    try:
        with open(AUTH_SESSION_KEY_PATH, "rb") as f:
            return f.read()
    except FileNotFoundError:
        key = secrets.token_bytes(32)
        try:
            os.makedirs(os.path.dirname(AUTH_SESSION_KEY_PATH), exist_ok=True)
        except Exception:
            pass
        with open(AUTH_SESSION_KEY_PATH, "wb") as f:
            f.write(key)
        os.chmod(AUTH_SESSION_KEY_PATH, 0o600)
        return key


# ----- OIDC helpers ---------------------------------------------------------
class _OIDCCache:
    """In-memory cache for OIDC discovery doc + JWKS."""
    def __init__(self):
        self._discovery = {}     # issuer -> dict
        self._jwks_client = {}   # issuer -> PyJWKClient

    def discovery(self, issuer: str) -> dict:
        if issuer in self._discovery:
            return self._discovery[issuer]
        url = issuer.rstrip("/") + "/.well-known/openid-configuration"
        with urllib.request.urlopen(url, timeout=10) as r:
            doc = json.loads(r.read().decode())
        self._discovery[issuer] = doc
        return doc

    def jwks(self, issuer: str) -> "PyJWKClient":
        if issuer in self._jwks_client:
            return self._jwks_client[issuer]
        if not _JWT_OK:
            raise RuntimeError("PyJWT not installed")
        d = self.discovery(issuer)
        jwks_uri = d.get("jwks_uri")
        if not jwks_uri:
            raise RuntimeError("issuer discovery missing jwks_uri")
        c = PyJWKClient(jwks_uri)
        self._jwks_client[issuer] = c
        return c


_OIDC_CACHE = _OIDCCache()
_OIDC_STATE_STORE = {}     # state -> (created_ts, return_to) — short-lived
_OIDC_STATE_TTL = 600      # 10 minutes


class AuthManager:
    """Verify request → session_user dict or None (anonymous).
    Mode-driven: none/basic/oidc/trusted-proxy.
    Webhook endpoints are always public regardless of mode.
    """
    PUBLIC_PATH_PREFIXES = (
        "/webhook/", "/beszel/", "/healthchecks/", "/wud/", "/authentik/", "/shelfmark/", "/prowlarr/", "/decypharr/", "/pve/",
        "/healthz", "/metrics",  # Prometheus scrape — no auth (LAN-only firewalled)
        "/api/ack/",             # ack/snooze from ntfy push — JWT-style token is the auth
        "/img/",                 # rendered alert images for ntfy Attach — random token is the auth
        "/auth/login", "/auth/callback", "/auth/logout",
        "/static/", "/favicon.ico",  # login page assets
    )

    def __init__(self):
        self.session_key = _load_or_create_session_key()

    def is_public(self, path: str) -> bool:
        return any(path == p or path.startswith(p) for p in self.PUBLIC_PATH_PREFIXES)

    def sign_session(self, payload: dict) -> str:
        """Returns a cookie value: <b64payload>.<b64sig>"""
        body = json.dumps(payload, separators=(",", ":"), default=str).encode()
        b = base64.urlsafe_b64encode(body).decode().rstrip("=")
        sig = hmac.new(self.session_key, b.encode(), hashlib.sha256).hexdigest()
        return f"{b}.{sig}"

    def verify_session(self, cookie_value: str) -> dict | None:
        try:
            b, sig = cookie_value.split(".", 1)
            expected = hmac.new(self.session_key, b.encode(), hashlib.sha256).hexdigest()
            if not hmac.compare_digest(sig, expected):
                return None
            # Pad base64 properly
            pad = "=" * (-len(b) % 4)
            body = base64.urlsafe_b64decode(b + pad)
            payload = json.loads(body.decode())
            if payload.get("exp", 0) < time_mod.time():
                return None
            return payload
        except Exception:
            return None

    def authenticate(self, handler) -> dict | None:
        """Returns user dict (subject/email/groups) if authenticated, else None.
        Sends 401/302 if not authenticated and the path is non-public."""
        cfg = AUTH_CONFIG
        mode = cfg.get("mode", "none")
        if mode == "none":
            return {"sub": "anonymous", "mode": "none"}

        # Session cookie (any mode that uses sessions)
        cookies = handler.headers.get("Cookie", "")
        sess_value = None
        for c in cookies.split(";"):
            c = c.strip()
            if c.startswith(AUTH_SESSION_COOKIE + "="):
                sess_value = c[len(AUTH_SESSION_COOKIE) + 1:]
                break
        if sess_value:
            user = self.verify_session(sess_value)
            if user:
                return user

        if mode == "basic":
            auth = handler.headers.get("Authorization", "")
            if auth.startswith("Basic "):
                try:
                    decoded = base64.b64decode(auth[6:]).decode()
                    user, pwd = decoded.split(":", 1)
                    if self._check_basic(user, pwd):
                        # Set session cookie so subsequent requests don't need re-auth
                        return self._issue_session(handler, {"sub": user, "mode": "basic"})
                except Exception:
                    pass
            handler.send_response(401)
            handler.send_header("WWW-Authenticate", f'Basic realm="{cfg.get("basic",{}).get("realm","klaxond")}"')
            handler.end_headers()
            return None

        if mode == "trusted-proxy":
            tp = cfg.get("trusted_proxy", {})
            peer_ip = handler.client_address[0]
            if not self._cidr_match(peer_ip, tp.get("trusted_cidrs", [])):
                handler.send_response(403); handler.end_headers()
                handler.wfile.write(b"untrusted peer (trusted-proxy mode)")
                return None
            uh = tp.get("user_header", "X-Forwarded-User")
            user_val = handler.headers.get(uh)
            if not user_val:
                handler.send_response(401); handler.end_headers()
                handler.wfile.write(f"missing {uh} header".encode())
                return None
            return {
                "sub":    user_val,
                "email":  handler.headers.get(tp.get("email_header", "X-Forwarded-Email")) or "",
                "groups": (handler.headers.get(tp.get("groups_header", "X-Forwarded-Groups")) or "").split(","),
                "mode":   "trusted-proxy",
            }

        if mode == "oidc":
            # No session cookie → redirect to /auth/login (saving the original path)
            ret = handler.path
            handler.send_response(302)
            handler.send_header("Location", f"/auth/login?return_to={urllib.parse.quote(ret)}")
            handler.end_headers()
            return None

        return None

    # --- helpers -----------------------------------------------------------
    def _check_basic(self, user: str, pwd: str) -> bool:
        cfg = AUTH_CONFIG.get("basic", {})
        if not _BCRYPT_OK:
            log.error("bcrypt not installed but basic auth requested")
            return False
        if cfg.get("username") != user:
            return False
        h = cfg.get("password_hash", "")
        if not h:
            return False
        try:
            return bcrypt.checkpw(pwd.encode(), h.encode())
        except Exception:
            return False

    def _cidr_match(self, ip: str, cidrs: list) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
            for c in cidrs:
                if addr in ipaddress.ip_network(c, strict=False):
                    return True
        except Exception:
            pass
        return False

    def _issue_session(self, handler, user_payload: dict) -> dict:
        cfg = AUTH_CONFIG
        ttl_h = int(cfg.get("session_timeout_hours", 8))
        user_payload = dict(user_payload)
        user_payload["exp"] = int(time_mod.time() + ttl_h * 3600)
        cookie_val = self.sign_session(user_payload)
        # Cookie is set on subsequent successful auth response — we add the
        # Set-Cookie header pre-end_headers by storing into the handler.
        handler._pending_set_cookie = (
            f"{AUTH_SESSION_COOKIE}={cookie_val}; "
            f"HttpOnly; Path=/; SameSite=Lax; Max-Age={ttl_h * 3600}"
        )
        return user_payload

    # --- OIDC flow ---------------------------------------------------------
    def oidc_login_redirect(self, handler) -> None:
        """GET /auth/login — start OIDC flow"""
        cfg = AUTH_CONFIG.get("oidc", {})
        issuer = cfg.get("issuer", "").rstrip("/")
        if not issuer or not cfg.get("client_id"):
            handler.send_response(500); handler.end_headers()
            handler.wfile.write(b"OIDC not configured (set issuer + client_id in Auth tab)")
            return
        try:
            d = _OIDC_CACHE.discovery(issuer)
        except Exception as e:
            handler.send_response(502); handler.end_headers()
            handler.wfile.write(f"OIDC discovery failed: {e}".encode())
            return
        # Parse return_to from query
        q = urllib.parse.urlparse(handler.path).query
        params = urllib.parse.parse_qs(q)
        return_to = params.get("return_to", ["/"])[0]
        # Build redirect_uri from Host header
        host = handler.headers.get("Host", "")
        scheme = "https" if handler.headers.get("X-Forwarded-Proto", "https") == "https" else "http"
        redirect_uri = f"{scheme}://{host}{cfg.get('redirect_path', '/auth/callback')}"
        state = secrets.token_urlsafe(24)
        _OIDC_STATE_STORE[state] = (time_mod.time(), return_to)
        # Cleanup old states
        cutoff = time_mod.time() - _OIDC_STATE_TTL
        for k in list(_OIDC_STATE_STORE.keys()):
            if _OIDC_STATE_STORE[k][0] < cutoff:
                _OIDC_STATE_STORE.pop(k, None)
        # Build authorize URL
        auth_url = d["authorization_endpoint"]
        qp = {
            "response_type": "code",
            "client_id":     cfg["client_id"],
            "redirect_uri":  redirect_uri,
            "scope":         cfg.get("scopes", "openid profile email"),
            "state":         state,
        }
        full = auth_url + ("&" if "?" in auth_url else "?") + urllib.parse.urlencode(qp)
        handler.send_response(302)
        handler.send_header("Location", full)
        handler.end_headers()

    def oidc_callback(self, handler) -> None:
        """GET /auth/callback?code=...&state=..."""
        cfg = AUTH_CONFIG.get("oidc", {})
        issuer = cfg.get("issuer", "").rstrip("/")
        q = urllib.parse.urlparse(handler.path).query
        params = urllib.parse.parse_qs(q)
        code = params.get("code", [None])[0]
        state = params.get("state", [None])[0]
        if not code or not state:
            handler.send_response(400); handler.end_headers()
            handler.wfile.write(b"missing code or state"); return
        if state not in _OIDC_STATE_STORE:
            # Unknown/expired state: the login flow was interrupted — the
            # session cookie expired while the tab sat idle, or klaxond
            # restarted (deploy / WUD auto-update) and lost the in-memory
            # _OIDC_STATE_STORE. Don't dead-end on a 400 ("session expired");
            # restart the flow from /. With the Authentik SSO session still
            # alive upstream this re-logs the user in silently. No session is
            # issued at this point, so the redirect carries no CSRF exposure.
            handler.send_response(302)
            handler.send_header("Location", "/")
            handler.end_headers(); return
        _, return_to = _OIDC_STATE_STORE.pop(state)
        try:
            d = _OIDC_CACHE.discovery(issuer)
        except Exception as e:
            handler.send_response(502); handler.end_headers()
            handler.wfile.write(f"OIDC discovery failed: {e}".encode()); return
        host = handler.headers.get("Host", "")
        scheme = "https" if handler.headers.get("X-Forwarded-Proto", "https") == "https" else "http"
        redirect_uri = f"{scheme}://{host}{cfg.get('redirect_path', '/auth/callback')}"
        # Exchange code for tokens
        token_body = urllib.parse.urlencode({
            "grant_type":    "authorization_code",
            "code":          code,
            "redirect_uri":  redirect_uri,
            "client_id":     cfg["client_id"],
            "client_secret": cfg.get("client_secret", ""),
        }).encode()
        req = urllib.request.Request(
            d["token_endpoint"],
            data=token_body,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                tokens = json.loads(r.read().decode())
        except urllib.error.HTTPError as e:
            body = e.read().decode()
            handler.send_response(502); handler.end_headers()
            handler.wfile.write(f"token exchange failed: {e.code} {body[:200]}".encode())
            return
        except Exception as e:
            handler.send_response(502); handler.end_headers()
            handler.wfile.write(f"token exchange failed: {e}".encode())
            return
        id_token = tokens.get("id_token")
        if not id_token:
            handler.send_response(502); handler.end_headers()
            handler.wfile.write(b"no id_token in response"); return
        # Verify id_token signature against JWKS
        try:
            jwks_client = _OIDC_CACHE.jwks(issuer)
            signing_key = jwks_client.get_signing_key_from_jwt(id_token).key
            claims = pyjwt.decode(
                id_token, signing_key,
                algorithms=["RS256", "RS384", "RS512", "ES256", "ES384"],
                audience=cfg["client_id"],
                issuer=d.get("issuer", issuer),
            )
        except Exception as e:
            handler.send_response(401); handler.end_headers()
            handler.wfile.write(f"id_token verify failed: {e}".encode()); return
        # Optional group check
        req_group = cfg.get("required_group", "").strip()
        if req_group:
            groups = claims.get("groups", []) or []
            if req_group not in groups:
                handler.send_response(403); handler.end_headers()
                handler.wfile.write(f"required_group '{req_group}' not in user claims".encode())
                return
        user_payload = {
            "sub":    claims.get("sub", ""),
            "email":  claims.get("email", ""),
            "name":   claims.get("name", "") or claims.get("preferred_username", ""),
            "groups": claims.get("groups", []),
            "mode":   "oidc",
        }
        ttl_h = int(AUTH_CONFIG.get("session_timeout_hours", 8))
        user_payload["exp"] = int(time_mod.time() + ttl_h * 3600)
        cookie_val = self.sign_session(user_payload)
        handler.send_response(302)
        handler.send_header("Location", return_to or "/")
        handler.send_header("Set-Cookie",
            f"{AUTH_SESSION_COOKIE}={cookie_val}; HttpOnly; Path=/; SameSite=Lax; Max-Age={ttl_h * 3600}")
        handler.end_headers()

    def logout(self, handler) -> None:
        handler.send_response(302)
        handler.send_header("Location", "/")
        handler.send_header("Set-Cookie",
            f"{AUTH_SESSION_COOKIE}=; HttpOnly; Path=/; SameSite=Lax; Max-Age=0")
        handler.end_headers()


# Auth instances populated after TOML loads (uses [auth] as seed on first boot).
AUTH_CONFIG = {}
AUTH_MANAGER = None  # type: AuthManager


# ============================================================================
# Bootstrap config (TOML) — cascading rules + render rules + inhibition rules.
# Loaded from KLAXOND_CONFIG (default /data/klaxond.toml). If missing on first
# boot, bootstrapped from the bundled klaxond.default.toml shipped in the
# image. After bootstrap, the file is read-write and can be edited via UI.
# ============================================================================
KLAXOND_CONFIG = os.environ.get("KLAXOND_CONFIG", "/data/klaxond.toml")
KLAXOND_DEFAULT = "/app/klaxond.default.toml"


def _bootstrap_config_if_missing():
    if os.path.exists(KLAXOND_CONFIG):
        return
    try:
        os.makedirs(os.path.dirname(KLAXOND_CONFIG), exist_ok=True)
    except Exception:
        pass
    if os.path.exists(KLAXOND_DEFAULT):
        import shutil
        shutil.copy(KLAXOND_DEFAULT, KLAXOND_CONFIG)
        log.info("klaxond.toml bootstrapped from %s", KLAXOND_DEFAULT)
    else:
        log.warning("klaxond.toml missing and no default at %s — running with hard-coded defaults", KLAXOND_DEFAULT)


def _load_toml_config() -> dict:
    if tomllib is None:
        log.warning("tomllib not available (Python <3.11) — using hard-coded defaults")
        return {}
    _bootstrap_config_if_missing()
    try:
        with open(KLAXOND_CONFIG, "rb") as f:
            cfg = tomllib.load(f)
        log.info("loaded klaxond.toml from %s", KLAXOND_CONFIG)
        return cfg
    except FileNotFoundError:
        return {}
    except Exception as e:
        log.error("klaxond.toml parse failed: %s — using hard-coded defaults", e)
        return {}


def _save_toml_config(cfg: dict) -> None:
    """Atomic TOML save. Python stdlib has no tomli_w, so we serialise by hand
    for the known shape (cascade.tiers, render.*, inhibitions[])."""
    lines = []
    cascade = cfg.get("cascade", {})
    lines.append("[cascade]")
    lines.append(f'default_enabled_for_webhook = {str(bool(cascade.get("default_enabled_for_webhook", False))).lower()}')
    lines.append("")
    for tier in cascade.get("tiers", []):
        lines.append("[[cascade.tiers]]")
        lines.append(f'name = "{tier["name"]}"')
        lines.append(f'timeout_seconds = {int(tier.get("timeout_seconds", 5))}')
        lines.append("")
    render = cfg.get("render", {})
    ntfy = cfg.get("ntfy", {})
    if ntfy:
        lines.append("[ntfy]")
        if ntfy.get("url"):
            lines.append(f'url = "{ntfy["url"]}"')
        lines.append("")
        topics = ntfy.get("topics", {})
        if topics:
            lines.append("[ntfy.topics]")
            for k in ("info", "warning", "critical"):
                if k in topics:
                    lines.append(f'{k} = "{topics[k]}"')
            lines.append("")
    tg = cfg.get("telegram", {})
    if tg:
        lines.append("[telegram]")
        if "chat_id" in tg:
            lines.append(f'chat_id = "{tg["chat_id"]}"')
        lines.append("")
    smtp = cfg.get("smtp", {})
    if smtp:
        lines.append("[smtp]")
        if smtp.get("host"):
            lines.append(f'host = "{smtp["host"]}"')
        if smtp.get("port"):
            lines.append(f'port = {int(smtp["port"])}')
        if smtp.get("from_addr"):
            lines.append(f'from_addr = "{smtp["from_addr"]}"')
        if smtp.get("to_addr"):
            lines.append(f'to_addr = "{smtp["to_addr"]}"')
        lines.append("")
    lines.append("[render]")
    if render.get("grafana_base"):
        lines.append(f'grafana_base = "{render["grafana_base"]}"')
    lines.append("")
    for sub in ("severity_emoji", "severity_priority", "severity_tag_prefix"):
        d = render.get(sub, {})
        if d:
            lines.append(f"[render.{sub}]")
            for k, v in d.items():
                lines.append(f'{k} = "{v}"')
            lines.append("")
    cd = render.get("component_dashboards", {})
    if cd:
        lines.append("[render.component_dashboards]")
        for k, v in cd.items():
            label, url = v[0], v[1]
            lines.append(f'{k} = ["{label}", "{url}"]')
        lines.append("")
    delivery = cfg.get("delivery", {})
    if delivery:
        lines.append("[delivery]")
        if delivery.get("default_policy"):
            lines.append(f'default_policy = "{delivery["default_policy"]}"')
        lines.append("")
        for p in delivery.get("policies", []) or []:
            lines.append("[[delivery.policies]]")
            lines.append(f'name = "{p["name"]}"')
            lines.append(f'mode = "{p.get("mode","cascade")}"')
            tier_strs = []
            for t in p.get("tiers", []) or []:
                tier_strs.append('{{ name = "{0}", timeout_seconds = {1} }}'.format(t["name"], int(t.get("timeout_seconds", 5))))
            lines.append("tiers = [" + ", ".join(tier_strs) + "]")
            lines.append("")
        for r in delivery.get("rules", []) or []:
            lines.append("[[delivery.rules]]")
            lines.append(f'policy = "{r["policy"]}"')
            for k, v in (r.get("match", {}) or {}).items():
                lines.append(f'match.{k} = "{v}"')
            lines.append("")
    for inh in cfg.get("inhibitions", []):
        lines.append("[[inhibitions]]")
        lines.append(f'source = "{inh["source"]}"')
        if "match_by" in inh:
            lines.append(f'match_by = "{inh["match_by"]}"')
        if "match_label" in inh:
            lines.append(f'match_label = "{inh["match_label"]}"')
            lines.append(f'match_regex = "{inh["match_regex"]}"')
        if inh.get("match_all"):
            lines.append("match_all = true")
        if inh.get("applies_to"):
            quoted = ", ".join(f'"{s}"' for s in inh["applies_to"])
            lines.append(f'applies_to = [{quoted}]')
        lines.append(f'ttl_seconds = {int(inh.get("ttl_seconds", 900))}')
        lines.append("")
    ingest_secrets = ((cfg.get("ingest") or {}).get("secrets") or {})
    if ingest_secrets:
        lines.append("[ingest.secrets]")
        for k, v in ingest_secrets.items():
            if v:
                lines.append(f'{k} = "{v}"')
        lines.append("")
    for s in cfg.get("schedules", []) or []:
        if not isinstance(s, dict): continue
        lines.append("[[schedules]]")
        lines.append(f'name = "{s.get("name","")}"')
        lines.append(f'cron = "{s.get("cron","")}"')
        lines.append(f'duration_minutes = {int(s.get("duration_minutes", 30))}')
        if s.get("applies_to"):
            quoted = ", ".join(f'"{x}"' for x in s["applies_to"])
            lines.append(f'applies_to = [{quoted}]')
        m = s.get("match") or {}
        if m:
            # Dotted-key form keeps the match dict nested inside this
            # [[schedules]] item without needing a separate table header.
            for k, v in m.items():
                lines.append(f'match.{k} = "{v}"')
        lines.append("")
    tmp = KLAXOND_CONFIG + ".tmp"
    with open(tmp, "w") as f:
        f.write("\n".join(lines))
    # Auto-backup before replacing — keeps last N copies of klaxond.toml
    # under /data/backups/. Cheap insurance against bad edits.
    try:
        _config_auto_backup()
    except Exception as e:
        log.warning("config auto-backup failed (continuing save anyway): %s", e)
    os.replace(tmp, KLAXOND_CONFIG)


# ----------------------------------------------------------------------------
# Inbound webhook authentication (0.9.18+) — per-source shared secret.
#
# Pragmatic design: real-world emitters (Grafana Alertmanager, Beszel,
# Healthchecks, WUD, Authentik) DON'T natively support HMAC body signing.
# But all of them either support an Authorization header or a query
# parameter. So we accept the shared secret three ways, picking the first
# that matches:
#   1) Authorization: Bearer <secret>          (Grafana Alertmanager,
#                                                ntfy, custom curl)
#   2) X-Klaxond-Token: <secret>               (any header-customising client)
#   3) ?token=<secret>                          (last-resort query param)
#
# Secret resolution per source, env wins over TOML so vault overrides
# configurable defaults:
#   - env KLAXOND_INGEST_SECRET_GRAFANA (uppercased source)
#   - TOML [ingest.secrets].<source>
#
# Backward compat: if no secret configured for a source, the legacy
# permissive mode applies (accept all — same as 0.9.17 and earlier).
# ----------------------------------------------------------------------------
def _ingest_secret_for(source: str) -> str:
    env_key = f"KLAXOND_INGEST_SECRET_{source.upper()}"
    env_val = os.environ.get(env_key, "").strip()
    if env_val:
        return env_val
    secrets = (TOML_CONFIG.get("ingest", {}) or {}).get("secrets", {}) or {}
    return str(secrets.get(source, "")).strip()


def _ingest_secret_status() -> dict:
    """Return {source: {configured, source_of_secret}} for the UI."""
    out = {}
    for src in DEDUP_SOURCES:
        env_val = os.environ.get(f"KLAXOND_INGEST_SECRET_{src.upper()}", "").strip()
        toml_val = str(((TOML_CONFIG.get("ingest", {}) or {}).get("secrets", {}) or {}).get(src, "")).strip()
        if env_val:
            out[src] = {"configured": True, "from": "env"}
        elif toml_val:
            out[src] = {"configured": True, "from": "toml"}
        else:
            out[src] = {"configured": False, "from": ""}
    return out


def _verify_ingest_auth(source: str, headers: dict, query: dict) -> tuple[bool, str]:
    """Return (ok, reason). If no secret configured → (True, 'no-secret') = legacy."""
    secret = _ingest_secret_for(source)
    if not secret:
        return True, "no-secret"
    # 1) Authorization: Bearer <secret>
    auth = headers.get("Authorization", "") or headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        token = auth[7:].strip()
        if hmac.compare_digest(token, secret):
            return True, "bearer"
    # 2) X-Klaxond-Token
    xkt = headers.get("X-Klaxond-Token", "") or headers.get("x-klaxond-token", "")
    if xkt and hmac.compare_digest(xkt.strip(), secret):
        return True, "x-klaxond-token"
    # 3) ?token=<secret>
    qtok = (query.get("token") or [""])[0]
    if qtok and hmac.compare_digest(qtok, secret):
        return True, "query"
    return False, "secret-required-but-missing-or-mismatch"


KLAXOND_BACKUP_DIR = os.environ.get("KLAXOND_BACKUP_DIR", "/data/backups")
KLAXOND_BACKUP_KEEP = 10

def _config_auto_backup() -> str | None:
    """Copy current klaxond.toml to /data/backups/klaxond-YYYYMMDD-HHMMSS.toml.
    Prunes to KLAXOND_BACKUP_KEEP newest. Returns the backup path, or None
    if the source doesn't exist yet (first boot, before bootstrap)."""
    if not os.path.exists(KLAXOND_CONFIG):
        return None
    os.makedirs(KLAXOND_BACKUP_DIR, exist_ok=True)
    import shutil, datetime
    stamp = datetime.datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    dest = os.path.join(KLAXOND_BACKUP_DIR, f"klaxond-{stamp}.toml")
    shutil.copy2(KLAXOND_CONFIG, dest)
    # Prune oldest beyond KLAXOND_BACKUP_KEEP
    try:
        files = sorted(
            (f for f in os.listdir(KLAXOND_BACKUP_DIR)
             if f.startswith("klaxond-") and f.endswith(".toml")),
            reverse=True
        )
        for stale in files[KLAXOND_BACKUP_KEEP:]:
            os.unlink(os.path.join(KLAXOND_BACKUP_DIR, stale))
    except Exception as e:
        log.warning("backup prune failed: %s", e)
    return dest


def _list_config_backups() -> list:
    """Return [{name, size, mtime_iso}, …] sorted newest-first."""
    out = []
    if not os.path.isdir(KLAXOND_BACKUP_DIR):
        return out
    import datetime
    for n in os.listdir(KLAXOND_BACKUP_DIR):
        if not (n.startswith("klaxond-") and n.endswith(".toml")):
            continue
        p = os.path.join(KLAXOND_BACKUP_DIR, n)
        try:
            st = os.stat(p)
            out.append({
                "name": n,
                "size": st.st_size,
                "mtime_iso": datetime.datetime.utcfromtimestamp(st.st_mtime).isoformat() + "Z",
            })
        except Exception:
            continue
    out.sort(key=lambda r: r["mtime_iso"], reverse=True)
    return out


# Loaded at startup; refreshed on /api/config POST.
TOML_CONFIG = _load_toml_config()

# Now that TOML is loaded, bootstrap render-config from [render.component_dashboards]
# of klaxond.toml on first boot (when /data/render-config.json doesn't exist).
_render_seed = (TOML_CONFIG.get("render", {}) or {}).get("component_dashboards", {}) or {}
COMPONENT_DASHBOARDS = _load_render_config(toml_seed=_render_seed)

# Same pattern for dedup settings: [dedup.<source>] in TOML seeds the JSON file
# on first boot. Once /data/dedup-config.json exists, it's the source of truth.
_dedup_seed = TOML_CONFIG.get("dedup", {}) or {}
DEDUP_SETTINGS = _load_dedup_settings(toml_seed=_dedup_seed)

# Auth — same bootstrap pattern: [auth] in TOML seeds /data/auth-config.json
# on first boot. Once auth-config.json exists, that's the source of truth
# (the Authentication tab edits it).
_auth_seed = TOML_CONFIG.get("auth", {}) or {}
AUTH_CONFIG = _load_auth_config(toml_seed=_auth_seed)
AUTH_MANAGER = AuthManager()
log.info("auth mode = %s", AUTH_CONFIG.get("mode"))

# ============================================================================
# Apply TOML config overrides (if klaxond.toml provided non-empty sections)
# ============================================================================
def _apply_toml_overrides():
    global PRIORITIES, ICONS, TAG_PREFIXES, COMPONENT_DASHBOARDS, INHIBITION_RULES, GRAFANA_BASE, FALLBACK_RUNBOOKS, SCHEDULES
    render = TOML_CONFIG.get("render", {})
    if render.get("severity_priority"):
        PRIORITIES = dict(render["severity_priority"])
    if render.get("severity_emoji"):
        ICONS = dict(render["severity_emoji"])
    if render.get("severity_tag_prefix"):
        TAG_PREFIXES = dict(render["severity_tag_prefix"])
    if render.get("fallback_runbooks"):
        FALLBACK_RUNBOOKS = {**FALLBACK_RUNBOOKS, **render["fallback_runbooks"]}
    if render.get("component_dashboards"):
        COMPONENT_DASHBOARDS = {k: tuple(v) for k, v in render["component_dashboards"].items()}
    if render.get("grafana_base"):
        GRAFANA_BASE = render["grafana_base"]
    inh = TOML_CONFIG.get("inhibitions")
    if inh:
        rebuilt = []
        for r in inh:
            entry = {"source": r["source"], "ttl_seconds": int(r.get("ttl_seconds", 900))}
            if "match_by" in r:
                entry["match_by"] = r["match_by"]
            if "match_label" in r and "match_regex" in r:
                entry["match_label_regex"] = (r["match_label"], r["match_regex"])
            if r.get("match_all"):
                entry["match_all"] = True
            if r.get("applies_to"):
                # Defensive cast: TOML reads as list[str]; ignore non-string entries.
                entry["applies_to"] = [str(s) for s in r["applies_to"] if isinstance(s, str)]
            rebuilt.append(entry)
        INHIBITION_RULES = rebuilt
    # Schedules (0.9.19+) — list of {name, cron, duration_minutes, match, applies_to}
    scheds = TOML_CONFIG.get("schedules", []) or []
    rebuilt_s = []
    for s in scheds:
        if not isinstance(s, dict): continue
        name = str(s.get("name", "")).strip()
        cron = str(s.get("cron", "")).strip()
        if not name or not cron: continue
        try:
            duration = max(1, int(s.get("duration_minutes", 30)))
        except Exception:
            duration = 30
        match = s.get("match") or {}
        if not isinstance(match, dict): match = {}
        applies = s.get("applies_to") or []
        if not isinstance(applies, list): applies = []
        rebuilt_s.append({
            "name": name, "cron": cron, "duration_minutes": duration,
            "match": {str(k): str(v) for k, v in match.items()},
            "applies_to": [str(x) for x in applies if isinstance(x, str)],
        })
    SCHEDULES = rebuilt_s


def _apply_channel_config():
    """Populate NTFY_URL/NTFY_TOPICS/TG_*/SMTP_* from TOML first, then let env
    overrides take precedence. Called once at startup; can be re-called
    after the user edits values via the UI.

    NTFY_TOPICS bootstrap order (first that produces ≥1 entry wins):
      1. /data/ntfy-topics.json   (UI-saved runtime state)        — Fase B
      2. TOML [[ntfy.topics]]     (new array format, 0.7.0+)
      3. TOML [ntfy.topics] dict  (legacy 3-severity dict format) + env tokens
      4. Env-only fallback        (NTFY_TOKEN_*, TOPIC_*)
    """
    global NTFY_URL, NTFY_TOPICS, TG_CHAT, SMTP_HOST, SMTP_PORT, SMTP_FROM, SMTP_TO
    ntfy_cfg = TOML_CONFIG.get("ntfy", {}) or {}
    NTFY_URL = (os.environ.get("NTFY_URL") or ntfy_cfg.get("url") or "").rstrip("/")

    # Try /data/ntfy-topics.json (Fase B — UI write). For Fase A this is read-only.
    new_topics = None
    try:
        if os.path.exists(NTFY_TOPICS_PATH):
            with open(NTFY_TOPICS_PATH) as f:
                jp = json.load(f)
            if isinstance(jp, dict) and isinstance(jp.get("topics"), list):
                new_topics = jp["topics"]
    except Exception as e:
        log.warning("ntfy-topics.json read failed (%s) — falling back to TOML/env", e)

    # Try TOML [[ntfy.topics]] array format (0.7.0+)
    if new_topics is None:
        toml_topics = ntfy_cfg.get("topics", None)
        if isinstance(toml_topics, list) and toml_topics:
            new_topics = [dict(t) for t in toml_topics]
        elif isinstance(toml_topics, dict) and toml_topics:
            # Legacy 3-severity dict format → upgrade in-memory
            new_topics = [
                {"name": toml_topics.get("info", ""),     "token": "", "handles": ["info"]},
                {"name": toml_topics.get("warning", ""),  "token": "", "handles": ["warning"]},
                {"name": toml_topics.get("critical", ""), "token": "", "handles": ["critical"]},
            ]

    # Env-only fallback (no TOML config at all)
    if new_topics is None:
        new_topics = [
            {"name": os.environ.get("TOPIC_INFO", ""),  "token": "", "handles": ["info"]},
            {"name": os.environ.get("TOPIC_WARN", ""),  "token": "", "handles": ["warning"]},
            {"name": os.environ.get("TOPIC_CRIT", ""),  "token": "", "handles": ["critical"]},
        ]

    # Env override for TOPIC_* names (per-severity convenience), and tokens are
    # ALWAYS env-driven for the 3 default severities for backward-compat.
    env_overrides_name = {
        "info":     os.environ.get("TOPIC_INFO", ""),
        "warning":  os.environ.get("TOPIC_WARN", ""),
        "critical": os.environ.get("TOPIC_CRIT", ""),
    }
    env_overrides_token = {
        "info":     os.environ.get("NTFY_TOKEN_INFO", ""),
        "warning":  os.environ.get("NTFY_TOKEN_WARN", ""),
        "critical": os.environ.get("NTFY_TOKEN_CRIT", ""),
    }
    for t in new_topics:
        # If this topic exclusively handles one of the 3 default severities,
        # and the corresponding env vars are set, use them (back-compat).
        handles = t.get("handles") or []
        if len(handles) == 1 and handles[0] in env_overrides_name:
            sev = handles[0]
            if env_overrides_name[sev]:
                t["name"] = env_overrides_name[sev]
            if env_overrides_token[sev] and not t.get("token"):
                t["token"] = env_overrides_token[sev]
        # Ensure required fields exist
        t.setdefault("token", "")
        t.setdefault("handles", [])

    # Filter out topics with no name (incomplete config) — keep them but
    # they won't fire. Logging tells operator if topics are missing.
    NTFY_TOPICS = [t for t in new_topics if t.get("name")]
    log.info("ntfy: %d topic(s) loaded, severities routed: %s",
             len(NTFY_TOPICS),
             sorted(_all_known_severities() - {"resolved"}))
    tg_cfg = TOML_CONFIG.get("telegram", {}) or {}
    TG_CHAT = os.environ.get("TELEGRAM_CHAT_ID") or tg_cfg.get("chat_id", "")
    smtp_cfg = TOML_CONFIG.get("smtp", {}) or {}
    SMTP_HOST = os.environ.get("SMTP_HOST") or smtp_cfg.get("host", "")
    try:
        SMTP_PORT = int(os.environ.get("SMTP_PORT") or smtp_cfg.get("port", 587))
    except Exception:
        SMTP_PORT = 587
    SMTP_FROM = os.environ.get("SMTP_FROM") or smtp_cfg.get("from_addr", "") or SMTP_USER
    SMTP_TO   = os.environ.get("SMTP_TO")   or smtp_cfg.get("to_addr", "")


_apply_toml_overrides()
# Scheduler thread spawn is moved to the bottom of the file (after
# _scheduler_thread is defined). See "Spawn the maintenance-window
# scheduler" near the signal handler setup.



# Cascade fallback config (token/password env-only; other values TOML+env).
CASCADE_ENABLED = os.environ.get("CASCADE_ENABLED", "false").lower() == "true"
TG_TOKEN  = os.environ.get("TELEGRAM_BOT_TOKEN", "")   # SECRET (env-only)
TG_CHAT   = ""                                           # filled by _apply_channel_config
SMTP_HOST = ""
SMTP_PORT = 587
SMTP_USER = os.environ.get("SMTP_USER", "")            # SECRET (env-only)
SMTP_PASS = os.environ.get("SMTP_PASSWORD", "")        # SECRET (env-only)
SMTP_FROM = ""
SMTP_TO   = ""

# Now apply TOML channel config (overrides the empty defaults above; env still wins)
_apply_channel_config()


# ============================================================================
# Runtime state (rolling delivery log + admin toggle for cascade)
# ============================================================================
import collections

_DELIVERY_LOG_MAX = 50
_delivery_log = collections.deque(maxlen=_DELIVERY_LOG_MAX)

# ----------------------------------------------------------------------------
# Prometheus-style counters (0.9.17+). Plain dict-of-counters, escape labels
# via _esc_label(), exposition via /metrics (no external client lib). Counters
# survive container lifetime; reset on restart (acceptable — Loki audit log
# is the durable archive).
# ----------------------------------------------------------------------------
_KLAXOND_VERSION = "0.10.1"
_metrics_lock = threading.Lock()
_METRICS_START_TS = time_mod.time()
_metric_counters: dict[str, int] = {}
_metric_gauges: dict[str, float] = {}

def _esc_label(v: str) -> str:
    # Escape per Prometheus exposition: backslash, double-quote, newline
    return str(v).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")

def _metric_inc(name: str, labels: dict | None = None, by: int = 1) -> None:
    key = name + "|" + (",".join(f"{k}={_esc_label(v)}" for k, v in sorted((labels or {}).items())) if labels else "")
    with _metrics_lock:
        _metric_counters[key] = _metric_counters.get(key, 0) + by

def _metric_set_gauge(name: str, value: float, labels: dict | None = None) -> None:
    key = name + "|" + (",".join(f"{k}={_esc_label(v)}" for k, v in sorted((labels or {}).items())) if labels else "")
    with _metrics_lock:
        _metric_gauges[key] = value

def _render_metrics_exposition() -> str:
    """Build a Prometheus 0.0.4 text-exposition response body."""
    lines = []
    lines.append("# HELP klaxond_info Static info (version, etc).")
    lines.append("# TYPE klaxond_info gauge")
    lines.append(f'klaxond_info{{version="{_esc_label(_KLAXOND_VERSION)}"}} 1')
    lines.append("# HELP klaxond_uptime_seconds Seconds since klaxond started.")
    lines.append("# TYPE klaxond_uptime_seconds counter")
    lines.append(f"klaxond_uptime_seconds {int(time_mod.time() - _METRICS_START_TS)}")

    # Refresh derived gauges from live state right before emitting
    try:
        _metric_set_gauge("klaxond_suppressions_active", len(_suppressions))
    except Exception:
        pass
    try:
        for src in DEDUP_SOURCES:
            try:
                with DEDUP_BUFFER.lock:
                    pending = len(DEDUP_BUFFER.queues.get(src, []))
                _metric_set_gauge("klaxond_dedup_pending", pending, {"source": src})
            except Exception:
                pass
    except Exception:
        pass

    # Group counters/gauges by metric name for HELP/TYPE headers
    with _metrics_lock:
        snapshot_counters = dict(_metric_counters)
        snapshot_gauges = dict(_metric_gauges)

    def _emit(samples: dict, kind: str, helps: dict[str, str]):
        by_name: dict[str, list[tuple[str, float]]] = {}
        for key, val in samples.items():
            name, _, label_str = key.partition("|")
            by_name.setdefault(name, []).append((label_str, val))
        for name, rows in sorted(by_name.items()):
            lines.append(f"# HELP {name} {helps.get(name, '(no description)')}")
            lines.append(f"# TYPE {name} {kind}")
            for label_str, val in rows:
                label_render = "{" + ",".join(
                    f'{k}="{v}"' for k, v in (kv.split("=", 1) for kv in label_str.split(",") if "=" in kv)
                ) + "}" if label_str else ""
                lines.append(f"{name}{label_render} {val}")

    _emit(snapshot_counters, "counter", {
        "klaxond_deliveries_total":   "Cumulative deliveries (or attempts) per source/severity/channel/ok.",
        "klaxond_suppressions_armed_total": "Inhibition source-alerts that armed a suppression.",
        "klaxond_render_errors_total": "Render-time exceptions per source.",
        "klaxond_dedup_buffered_total": "Events queued in the dedup buffer per source.",
        "klaxond_dedup_flushed_total": "Events flushed from the dedup buffer per source.",
    })
    _emit(snapshot_gauges, "gauge", {
        "klaxond_suppressions_active": "Currently-armed in-memory suppressions.",
        "klaxond_dedup_pending":       "Events pending in the dedup buffer per source.",
    })

    return "\n".join(lines) + "\n"
_log_lock = threading.Lock()

# Runtime override for CASCADE_ENABLED — flipped via /api/cascade/toggle
_cascade_runtime_enabled = CASCADE_ENABLED


def _log_delivery(source: str, severity: str, title: str, channel: str, suppressed_by: str = "") -> None:
    with _log_lock:
        _delivery_log.append({
            "ts": time_mod.time(),
            "source": source,
            "severity": severity,
            "title": title,
            "channel": channel,
            "suppressed_by": suppressed_by,
        })


def _recent_deliveries() -> list:
    with _log_lock:
        return list(_delivery_log)


def _check_channel_reachability() -> dict:
    """Light, cached-by-call probes to each delivery tier. Returns
    dict {ntfy:bool, telegram:bool, smtp:bool}."""
    out = {"ntfy": False, "telegram": False, "smtp": False}
    # ntfy: HEAD on the public push URL
    try:
        req = urllib.request.Request(NTFY_URL + "/v1/health", method="GET")
        with urllib.request.urlopen(req, timeout=3) as r:
            out["ntfy"] = 200 <= r.status < 400
    except Exception:
        pass
    # Telegram: GET getMe (no message sent)
    if TG_TOKEN:
        try:
            with urllib.request.urlopen(
                f"https://api.telegram.org/bot{TG_TOKEN}/getMe", timeout=4
            ) as r:
                out["telegram"] = 200 <= r.status < 400
        except Exception:
            pass
    # SMTP: try a 25-port-style banner check (just TCP connect to host:port)
    if SMTP_HOST:
        try:
            import socket
            with socket.create_connection((SMTP_HOST, SMTP_PORT), timeout=4):
                out["smtp"] = True
        except Exception:
            pass
    return out

# ============================================================================
# Inhibition (Alertmanager-style suppression — homegrown, in-memory)
# ----------------------------------------------------------------------------
# When a "source" alert fires (e.g. node-down for host X), suppress derivative
# alerts that share the same label value for a TTL. Saves the user from being
# paged 6x when 1 host going offline cascades into postgres-down +
# restart-loop + smartctl-can't-scrape etc.
#
# Rules below are evaluated *in order*; the first matching source wins. A
# source alert is identified by the `inhibition_source` label set on its
# Grafana rule definition (in manage-grafana-dashboards.yml).
# ============================================================================
#
# Each rule may set `applies_to` = list of source names ("grafana", "beszel",
# "healthchecks", "wud", "authentik"). If omitted → applies to ALL sources
# (cross-source suppression — e.g. node-down suppresses Beszel/HC alerts
# from the same host too, not just Grafana alerts). The matching key
# (`match_by` / `match_label_regex`) lookups happen against the NORMALIZED
# label dict produced by _normalize_labels(), which exposes `host`, `service`,
# `job`, `alertname` uniformly across all sources.
INHIBITION_RULES = [
    # node-down (host offline) → suppress everything with same `host` label,
    # regardless of source (Grafana cascade alerts AND Beszel/HC/WUD from
    # the same host all become noise when the box is offline).
    {"source": "node-down",
     "match_by": "host",                # suppress alerts whose label[host] == source's host
     "ttl_seconds": 900},
    # traefik-down → suppress all blackbox HTTP/HTTPS e2e probes (everything
    # behind Traefik will fail until it's back). Blackbox is a Grafana-only
    # concept; other sources don't have a `job=blackbox-*` label.
    {"source": "traefik-down",
     "match_label_regex": ("job", r"^blackbox-(https|http).*"),
     "applies_to": ["grafana"],
     "ttl_seconds": 900},
    # authentik-down → suppress alerts on services gated by forwardAuth.
    # We don't have an explicit "auth-gated" label, so use a conservative
    # match: blackbox-https-public probes (which all chain through Authentik
    # at the public e2e layer). Grafana-only by construction.
    {"source": "authentik-down",
     "match_label_regex": ("job", r"^blackbox-https.*"),
     "applies_to": ["grafana"],
     "ttl_seconds": 900},
    # cluster-wide-restart → suppress EVERYTHING from EVERY source for 30min.
    # Half the cluster rebooting is going to fire dozens of derivative
    # alerts while services come back; mute them en masse.
    {"source": "cluster-wide-restart",
     "match_all": True,
     "ttl_seconds": 1800},
]

# Active suppressions: list of dicts
#   {"rule_idx": <int>, "anchor": <str|None>, "expiry": <float epoch>}
# `anchor` = the label value matched (e.g. host=server-01) used to scope
# the suppression to a specific host. None for match_all rules.
_suppressions: list = []
_supp_lock = threading.Lock()


def _cleanup_expired() -> None:
    now = time_mod.time()
    with _supp_lock:
        _suppressions[:] = [s for s in _suppressions if s["expiry"] > now]


def _alert_is_source(labels: dict) -> int | None:
    """If `labels` belong to a source alert, return the rule index it matches.
    Otherwise return None."""
    source = labels.get("inhibition_source")
    if not source:
        return None
    for idx, rule in enumerate(INHIBITION_RULES):
        if rule["source"] == source:
            return idx
    return None


def _register_suppression(rule_idx: int, labels: dict, resolved: bool) -> None:
    """Add or remove a suppression entry based on whether the source is
    firing or resolved."""
    rule = INHIBITION_RULES[rule_idx]
    anchor = None
    if "match_by" in rule:
        anchor = labels.get(rule["match_by"], "")
        if not anchor:
            log.warning("source %s missing match label %s — skip register",
                        rule["source"], rule["match_by"])
            return
    expiry = time_mod.time() + rule["ttl_seconds"]
    with _supp_lock:
        # Remove any existing entry for this rule+anchor (re-fire extends TTL)
        _suppressions[:] = [s for s in _suppressions
                            if not (s["rule_idx"] == rule_idx and s["anchor"] == anchor)]
        if not resolved:
            _suppressions.append({"rule_idx": rule_idx, "anchor": anchor, "expiry": expiry})
            log.info("inhibition armed: rule=%s anchor=%s ttl=%ds",
                     rule["source"], anchor or "*", rule["ttl_seconds"])
            try: _metric_inc("klaxond_suppressions_armed_total", {"rule": rule["source"]})
            except Exception: pass
        else:
            log.info("inhibition cleared: rule=%s anchor=%s",
                     rule["source"], anchor or "*")


def _normalize_labels(source: str, payload) -> dict:
    """Project a per-source webhook payload to a canonical label dict so
    inhibition rules (keyed on host/service/job/alertname) can match
    uniformly across all 5 sources. Returns at least {"source": source}.

    Keys produced where applicable: host, service, job, alertname,
    inhibition_source, status (raw — 'firing' or 'resolved'-ish).
    """
    out = {"source": source, "status": "firing"}

    if source == "grafana":
        common = (payload.get("commonLabels") or {}) if isinstance(payload, dict) else {}
        # Pass through commonLabels verbatim (host/job/alertname/etc all
        # already in there) + alias instance→host if host missing.
        for k, v in common.items():
            out[k] = v
        if "host" not in out and out.get("instance"):
            out["host"] = out["instance"]
        out["status"] = (payload.get("status") if isinstance(payload, dict) else None) or "firing"
        return out

    if source == "beszel":
        if isinstance(payload, dict):
            host = payload.get("system") or payload.get("host")
            if host: out["host"] = host
            alert = payload.get("alert") or payload.get("name")
            if alert: out["alertname"] = alert
            status = (payload.get("status") or "").lower()
            if status in ("resolved", "ok", "back to normal"):
                out["status"] = "resolved"
        out["job"] = "beszel"
        return out

    if source == "healthchecks":
        if isinstance(payload, dict):
            check = payload.get("check") or payload.get("name")
            if check: out["alertname"] = check
            # HC channel template carries `tags` as a space-separated string;
            # honour host=… / service=… conventions if present.
            tags_str = payload.get("tags") or ""
            if isinstance(tags_str, str):
                for tok in tags_str.split():
                    if "=" in tok:
                        k, v = tok.split("=", 1)
                        k = k.strip().lower()
                        if k in ("host", "service") and v:
                            out[k] = v
            status = (payload.get("status") or "").lower()
            if status in ("up", "ok", "resolved"):
                out["status"] = "resolved"
        out["job"] = "healthchecks"
        return out

    if source == "wud":
        if isinstance(payload, dict):
            host = payload.get("watcher") or payload.get("host")
            if host: out["host"] = host
            name = payload.get("name")
            if name:
                out["service"] = name
                out["alertname"] = "container-update"
        elif isinstance(payload, list) and payload:
            # Batch fires don't have a single host; use first container's
            # watcher as best-effort (caller can still match_all rules).
            first = payload[0] if isinstance(payload[0], dict) else {}
            host = first.get("watcher") or first.get("host")
            if host: out["host"] = host
            out["alertname"] = "container-update-batch"
        out["job"] = "wud"
        return out

    if source == "authentik":
        if isinstance(payload, dict):
            data = payload.get("data") or {}
            host = data.get("host") or data.get("client_ip")
            if host: out["host"] = host
        out["job"] = "authentik"
        return out

    if source == "shelfmark":
        if isinstance(payload, dict):
            evt = payload.get("event") or payload.get("type") or ""
            out["alertname"] = f"shelfmark-{evt}" if evt else "shelfmark"
            # Apprise json:// puts requester/user in payload extra fields
            user = payload.get("user") or (payload.get("data") or {}).get("user")
            if user: out["host"] = str(user)
        out["job"] = "shelfmark"
        return out

    if source == "prowlarr":
        if isinstance(payload, dict):
            evt = (payload.get("eventType") or "").strip()
            out["alertname"] = f"prowlarr-{evt}" if evt else "prowlarr"
            instance = payload.get("instanceName") or "prowlarr"
            out["host"] = str(instance)
        out["job"] = "prowlarr"
        return out

    if source == "decypharr":
        if isinstance(payload, dict):
            evt = (payload.get("event") or "").strip()
            out["alertname"] = f"decypharr-{evt}" if evt else "decypharr"
            debrid = payload.get("debrid") or "decypharr"
            out["host"] = str(debrid)
        out["job"] = "decypharr"
        return out

    if source == "pve":
        if isinstance(payload, dict):
            out["host"] = str(payload.get("node") or "pve")
            ntype = str(payload.get("type") or "")
            out["alertname"] = f"pve-{ntype}" if ntype else "pve-notification"
            out["service"] = ntype
        out["job"] = "pve"
        return out

    return out


def _is_suppressed(labels: dict, source: str) -> str | None:
    """If `labels` describe an alert that should be suppressed, return the
    name of the source rule. Else None.

    Rules with `applies_to` set restrict matching to those source names; an
    unset/empty `applies_to` means the rule applies to ALL sources.
    """
    _cleanup_expired()
    with _supp_lock:
        active = list(_suppressions)
    # Don't suppress the source alert itself even if cluster-wide-restart is on
    own_source = labels.get("inhibition_source", "")
    for supp in active:
        rule = INHIBITION_RULES[supp["rule_idx"]]
        if rule["source"] == own_source:
            return None
        applies_to = rule.get("applies_to")
        if applies_to and source not in applies_to:
            continue
        if rule.get("match_all"):
            return rule["source"]
        if "match_by" in rule:
            target_val = labels.get(rule["match_by"], "")
            if target_val and target_val == supp["anchor"]:
                return rule["source"]
        if "match_label_regex" in rule:
            label_name, pattern = rule["match_label_regex"]
            target_val = labels.get(label_name, "")
            if target_val and re.match(pattern, target_val):
                return rule["source"]
    return None


# ============================================================================
# Ack / snooze from ntfy push (0.9.20+)
# ----------------------------------------------------------------------------
# Each ntfy notification gets an extra action button "Snooze 1h" pointing at
# /api/ack/<token>. The token is a small HMAC-signed payload (no JWT lib —
# stdlib base64 + hmac is sufficient for a short-lived single-purpose token).
# Tapping the button → GET /api/ack/<token> → registers an ack-suppression
# keyed on alertname for the requested TTL.
#
# Token format:  base64url(payload).sig
#   payload = JSON {"a": alertname, "t": ttl_sec, "e": exp_unix}
#   sig     = hmac_sha256(session_key, base64url_payload).hexdigest()
# Token never holds a secret value — it's purely a binding "this user
# tapped this button at time T for alertname A". Replay within validity
# is acceptable (just re-extends the suppression).
#
# Ack suppressions are checked in apply_inhibition BEFORE the scheduled-mute
# and inhibition-rules checks, so an explicit user ack takes precedence.
# ============================================================================
KLAXOND_PUBLIC_URL = os.environ.get("KLAXOND_PUBLIC_URL", "https://klaxond.luigibarretta.com")
_ack_suppressions: dict[str, float] = {}   # alertname → expiry_ts
_ack_lock = threading.Lock()
ACK_DEFAULT_TTL = int(os.environ.get("ACK_DEFAULT_TTL_SECONDS", "3600"))  # 1h


def _ack_sign(alertname: str, ttl_sec: int) -> str:
    """Build a base64url(payload).sig token. payload includes expiry so
    a stolen token can't outlive its window."""
    import base64 as _b64
    exp = int(time_mod.time() + ttl_sec)
    payload = json.dumps({"a": alertname, "t": ttl_sec, "e": exp},
                         separators=(",", ":"))
    b = _b64.urlsafe_b64encode(payload.encode()).decode().rstrip("=")
    key = AUTH_MANAGER.session_key if "AUTH_MANAGER" in globals() else b"klaxond-fallback-key"
    sig = hmac.new(key, b.encode(), hashlib.sha256).hexdigest()
    return f"{b}.{sig}"


def _ack_verify(token: str) -> tuple[str | None, str]:
    """Returns (alertname, reason). alertname is None if the token is invalid
    or expired; reason is a human-readable string."""
    import base64 as _b64
    try:
        b, sig = token.split(".", 1)
    except Exception:
        return None, "malformed"
    key = AUTH_MANAGER.session_key if "AUTH_MANAGER" in globals() else b"klaxond-fallback-key"
    expected = hmac.new(key, b.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, expected):
        return None, "bad-signature"
    try:
        pad = "=" * (-len(b) % 4)
        body = _b64.urlsafe_b64decode(b + pad).decode("utf-8")
        payload = json.loads(body)
    except Exception:
        return None, "bad-payload"
    if not isinstance(payload.get("e"), int) or payload["e"] < time_mod.time():
        return None, "expired"
    alertname = str(payload.get("a") or "").strip()
    if not alertname:
        return None, "no-alertname"
    return alertname, "ok"


def _register_ack_suppression(alertname: str, ttl_sec: int) -> None:
    with _ack_lock:
        _ack_suppressions[alertname] = time_mod.time() + ttl_sec
    log.info("ack-suppression armed: alertname=%s ttl=%ds", alertname, ttl_sec)


def _ack_match(labels: dict) -> str | None:
    """If the alert's alertname is in an active ack-suppression, return it."""
    name = labels.get("alertname", "")
    if not name:
        return None
    now = time_mod.time()
    with _ack_lock:
        exp = _ack_suppressions.get(name)
        if exp is not None and exp > now:
            return name
        if exp is not None:
            del _ack_suppressions[name]  # expired
    return None


def ack_status_snapshot() -> list:
    """For /api/acks display in the UI."""
    out = []
    now = time_mod.time()
    with _ack_lock:
        for name, exp in list(_ack_suppressions.items()):
            if exp <= now:
                continue
            out.append({"alertname": name, "expires_in_seconds": int(exp - now)})
    out.sort(key=lambda r: r["expires_in_seconds"])
    return out


# ============================================================================
# Maintenance windows / scheduled silences (0.9.19+)
# ----------------------------------------------------------------------------
# Per-rule cron + duration: while inside the window AND the alert's labels
# match the rule's match-dict, the alert is suppressed with channel
# "scheduled-mute" in the deliveries ring buffer for visibility. Cron parsing
# is stdlib-only (minimal 5-field), no external deps.
#
# Use cases:
#   - Sunday 04:30, duration 30min, match {component=storage}: silence the
#     storage alerts during the weekly backup window.
#   - Daily 22:00-06:00, match {severity=info}: night-mute info-level alerts.
# ============================================================================

def _cron_field_matches(field: str, value: int, lo: int, hi: int) -> bool:
    """Evaluate a single cron field against an integer value.
    Supports: '*', '*/N', 'a-b', 'a,b,c', single value, and a-b/N steps."""
    if field == "*" or field == "":
        return True
    for token in field.split(","):
        token = token.strip()
        step = 1
        if "/" in token:
            base, step_s = token.split("/", 1)
            try: step = int(step_s)
            except Exception: return False
            token = base
        if token == "*":
            rng = range(lo, hi + 1, step)
        elif "-" in token:
            try:
                a, b = token.split("-", 1)
                a, b = int(a), int(b)
            except Exception: return False
            rng = range(a, b + 1, step)
        else:
            try: v = int(token)
            except Exception: return False
            if value == v: return True
            continue
        if value in rng: return True
    return False


def _cron_matches(cron: str, now_dt) -> bool:
    """5-field cron: minute hour dom month dow.
    Returns True if `now_dt` (a datetime) matches all 5 fields.

    Cron-style DOW vs DOM: per POSIX, if BOTH are restricted (neither '*'),
    the trigger fires when EITHER matches. We implement the common case
    (most rules use either DOM or DOW restricted, not both); we OR them.
    """
    parts = cron.strip().split()
    if len(parts) != 5:
        return False
    minute, hour, dom, month, dow = parts
    if not _cron_field_matches(minute, now_dt.minute, 0, 59): return False
    if not _cron_field_matches(hour,   now_dt.hour,   0, 23): return False
    if not _cron_field_matches(month,  now_dt.month,  1, 12): return False
    # dom uses 1-31; dow uses 0=Sunday .. 6=Saturday (Python weekday() is
    # 0=Monday .. 6=Sunday → adjust)
    py_weekday = now_dt.weekday()
    cron_dow = (py_weekday + 1) % 7    # Mon=0 → 1, Sun=6 → 0
    dom_restricted = dom != "*"
    dow_restricted = dow != "*"
    if dom_restricted and dow_restricted:
        return _cron_field_matches(dom, now_dt.day, 1, 31) or \
               _cron_field_matches(dow, cron_dow, 0, 7)  # allow 7 too (Sun alias)
    if dom_restricted:
        return _cron_field_matches(dom, now_dt.day, 1, 31)
    if dow_restricted:
        return _cron_field_matches(dow, cron_dow, 0, 7)
    return True  # both '*' → fire every minute


# In-memory schedule list (rebuilt on TOML reload).
SCHEDULES: list = []          # list of {name, cron, duration_minutes, match: {label: val}, applies_to: [src]}
_active_mutes: dict = {}      # name → expiry_ts (set when a window is entered)
_sched_lock = threading.Lock()


def _scheduler_tick():
    """Called every ~60s. For each schedule whose cron matches NOW, set its
    expiry to now+duration. Prune expired entries from _active_mutes."""
    import datetime as _dt
    now = _dt.datetime.now()
    now_ts = time_mod.time()
    with _sched_lock:
        # 1) Prune expired
        for name, expiry in list(_active_mutes.items()):
            if expiry <= now_ts:
                del _active_mutes[name]
                log.info("schedule '%s' expired", name)
        # 2) Activate matching cron windows
        for s in SCHEDULES:
            name = s.get("name") or "?"
            cron = s.get("cron") or ""
            try:
                if _cron_matches(cron, now):
                    duration = int(s.get("duration_minutes", 30))
                    new_expiry = now_ts + duration * 60
                    cur = _active_mutes.get(name, 0)
                    if new_expiry > cur:
                        _active_mutes[name] = new_expiry
                        if cur == 0:
                            log.info("schedule '%s' ARMED (cron=%s duration=%dm)",
                                     name, cron, duration)
            except Exception as e:
                log.warning("scheduler tick failed for '%s': %s", name, e)


def _scheduler_thread():
    """Background thread: tick the scheduler once per minute, aligned to
    the start of each clock-minute (so a cron with minute=30 fires roughly
    at HH:30:00 give or take a second)."""
    import time as _t
    while True:
        try:
            _scheduler_tick()
        except Exception as e:
            log.error("scheduler_thread tick crashed: %s", e)
        # Sleep until ~5s after the next minute boundary
        now = _t.time()
        sleep_s = 60 - (now % 60) + 5
        _t.sleep(sleep_s)


def _scheduled_mute_match(labels: dict, source: str) -> str | None:
    """Return the schedule name if labels match an active mute window."""
    if not _active_mutes:
        return None
    with _sched_lock:
        active_names = set(_active_mutes.keys())
    for s in SCHEDULES:
        if s.get("name") not in active_names:
            continue
        applies = s.get("applies_to") or []
        if applies and source not in applies:
            continue
        m = s.get("match") or {}
        ok = True
        for k, v in m.items():
            if labels.get(k, "") != v:
                ok = False; break
        if ok:
            return s["name"]
    return None


def scheduler_status() -> dict:
    """Snapshot for /api/schedules — list of all schedules + active windows."""
    now_ts = time_mod.time()
    with _sched_lock:
        active = {n: int(e - now_ts) for n, e in _active_mutes.items() if e > now_ts}
    return {
        "schedules": [dict(s) for s in SCHEDULES],
        "active_mutes": active,   # name → seconds remaining
    }


def apply_inhibition(source: str, labels: dict, *, dry_run: bool = False) -> tuple[bool, str]:
    """Source-agnostic inhibition. Takes normalized labels (see
    _normalize_labels) plus the originating source name.

    Source-alert detection (the thing that ARMS suppression) still only fires
    for Grafana, because the `inhibition_source` label is set inside Grafana
    rule definitions — it's the human-curated marker for "this alert should
    suppress others". Non-Grafana sources never ARM new suppressions, but
    they ARE subject to existing ones (the whole point of going agnostic).

    dry_run=True: skip _register_suppression entirely (read-only — used by
    the /webhook/?dry_run=1 ingest path so tests don't mutate live state).

    Returns (should_send, reason).
    """
    if source == "grafana":
        source_idx = _alert_is_source(labels)
        if source_idx is not None:
            if not dry_run:
                _register_suppression(source_idx, labels, resolved=(labels.get("status") == "resolved"))
            return True, "source"

    # User ack-snooze — checked first because it's the most explicit signal
    # ("I tapped Snooze on my phone" overrides rules + windows).
    ack = _ack_match(labels)
    if ack:
        return False, f"ack-snoozed-{ack}"

    # Scheduled mute (maintenance window) — checked before inhibition rules
    # so the reason in the deliveries log clearly identifies maintenance vs.
    # source-anchored suppression.
    sched = _scheduled_mute_match(labels, source)
    if sched:
        return False, f"scheduled-mute-{sched}"

    suppressed_by = _is_suppressed(labels, source)
    if suppressed_by:
        return False, f"inhibited-by-{suppressed_by}"

    return True, "ok"


def inhibition_status() -> list:
    """Return a snapshot of current suppressions, for /healthz?inhibition=1
    and the Inhibitions tab."""
    _cleanup_expired()
    now = time_mod.time()
    with _supp_lock:
        out = []
        for s in _suppressions:
            rule = INHIBITION_RULES[s["rule_idx"]]
            applies_to = rule.get("applies_to") or ["*"]
            out.append({
                "source": rule["source"],
                "anchor": s["anchor"] or "*",
                "applies_to": applies_to,
                "expires_in_seconds": int(s["expiry"] - now),
            })
        return out




# Beszel SQLite — mounted read-only at /beszel_data/data.db (deploy-klaxond.yml).
# Used to enrich Grafana alert bodies with top container consumers on the
# affected host (e.g., 'Swap > 80%' → top 3 by RAM).
BESZEL_DB_PATH = os.environ.get("BESZEL_DB_PATH", "/beszel_data/data.db")

# Regex patterns → enrichment kind. When alertname matches, klaxond queries
# Beszel and appends top-3 to body. Keep patterns broad: alertname conventions
# vary (swap-high-host, ram-pressure-host, memory-high, ...).
# kind values:
#   mem  → top container by RAM (Beszel container.m field, MB)
#   cpu  → top container by CPU% (Beszel container.c field)
#   net  → top container by net throughput (Beszel container.b = [tx,rx])
#   disk → top filesystem by usage% (Beszel system.efs + main d/du/dp,
#          host-level — Beszel non traccia disk per-container)
ENRICHMENT_PATTERNS = [
    (re.compile(r"(swap|ram|memory).*(high|pressure|exhausted|used|usage|above|averaged|\d+(\.\d+)?\s*%)", re.I), "mem"),
    (re.compile(r"(cpu|load(avg)?|load[\s_-]aver)", re.I), "cpu"),
    (re.compile(r"network.*(high|saturation|bandwidth|saturated|\d+(\.\d+)?\s*%)", re.I), "net"),
    (re.compile(r"(disk|filesystem|fs|root|/pool|/dev/sd).*(full|high|low|usage|above|\d+(\.\d+)?\s*%)", re.I), "disk"),
    # WAN/internet — culprit di solito su nas-01 (download) ma può essere
    # chiunque saturi upstream → GLOBAL scan, no host-specific.
    (re.compile(r"(internet|wan|icmp|blackbox).*(latency|slow|saturat|degrad|p\d+|loss)", re.I), "wan"),
]


def _beszel_open():
    """Open Beszel DB read-only + immutable (no WAL/SHM access). Returns None if absent."""
    if not os.path.exists(BESZEL_DB_PATH):
        return None
    try:
        import sqlite3
        return sqlite3.connect(f"file:{BESZEL_DB_PATH}?mode=ro&immutable=1", uri=True, timeout=2)
    except Exception as e:
        log.warning("beszel DB open failed: %s", e)
        return None


def _beszel_system_id(conn, host: str):
    row = conn.execute(
        "SELECT id FROM systems WHERE name = ? OR name LIKE ? LIMIT 1",
        (host, f"%{host}%"),
    ).fetchone()
    return row[0] if row else None


def _beszel_top_containers(host: str, by: str = "mem", n: int = 3):
    """Top-N containers for given host. `by` ∈ {mem, cpu, net}.
    Returns list of (name, value, unit). [] if unavailable."""
    if not host:
        return []
    conn = _beszel_open()
    if conn is None:
        return []
    try:
        system_id = _beszel_system_id(conn, host)
        if not system_id:
            return []
        row = conn.execute(
            "SELECT stats FROM container_stats WHERE system = ? "
            "ORDER BY created DESC LIMIT 1",
            (system_id,),
        ).fetchone()
        if not row:
            return []
        stats = json.loads(row[0])
        if by == "net":
            # b = [tx_bytes_per_s, rx_bytes_per_s]; usiamo sum come throughput
            def netval(s):
                b = s.get("b") or [0, 0]
                return (b[0] if len(b) > 0 else 0) + (b[1] if len(b) > 1 else 0)
            ranked = sorted(stats, key=netval, reverse=True)[:n]
            # Bytes/s → kB/s formatting
            return [(s.get("n", "?"), netval(s) / 1024, "kB/s") for s in ranked]
        else:
            key = "m" if by == "mem" else "c"
            unit = "MB" if by == "mem" else "%"
            ranked = sorted(stats, key=lambda x: x.get(key, 0), reverse=True)[:n]
            return [(s.get("n", "?"), s.get(key, 0), unit) for s in ranked]
    except Exception as e:
        log.warning("beszel container enrichment failed: %s", e)
        return []
    finally:
        try: conn.close()
        except Exception: pass


def _beszel_top_containers_global(by: str = "net", n: int = 5):
    """Scan ALL Beszel-monitored systems, rank containers globally.
    Used for WAN alerts where culprit can be on any host (typically the
    big downloader, like nas-01 with Decypharr/RD streams).
    Returns list of (host, name, value, unit)."""
    conn = _beszel_open()
    if conn is None:
        return []
    try:
        systems = {r[0]: r[1] for r in conn.execute("SELECT id, name FROM systems").fetchall()}
        if not systems:
            return []
        all_items = []
        for sys_id, host_name in systems.items():
            row = conn.execute(
                "SELECT stats FROM container_stats WHERE system = ? "
                "ORDER BY created DESC LIMIT 1",
                (sys_id,),
            ).fetchone()
            if not row:
                continue
            stats = json.loads(row[0])
            if by == "net":
                def netval(s):
                    b = s.get("b") or [0, 0]
                    return (b[0] if len(b) > 0 else 0) + (b[1] if len(b) > 1 else 0)
                for s in stats:
                    all_items.append((host_name, s.get("n","?"), netval(s) / 1024, "kB/s"))
            else:
                key = "m" if by == "mem" else "c"
                unit = "MB" if by == "mem" else "%"
                for s in stats:
                    all_items.append((host_name, s.get("n","?"), s.get(key, 0), unit))
        all_items.sort(key=lambda x: x[2], reverse=True)
        return all_items[:n]
    except Exception as e:
        log.warning("beszel global enrichment failed: %s", e)
        return []
    finally:
        try: conn.close()
        except Exception: pass


def _beszel_top_filesystems(host: str, n: int = 5):
    """Top-N filesystems on host by usage%. Beszel non traccia disk
    per-container, quindi mostriamo host-level fs breakdown.
    Returns list of (mount_name, used_gb, total_gb, used_pct, '')."""
    if not host:
        return []
    conn = _beszel_open()
    if conn is None:
        return []
    try:
        system_id = _beszel_system_id(conn, host)
        if not system_id:
            return []
        row = conn.execute(
            "SELECT stats FROM system_stats WHERE system = ? "
            "ORDER BY created DESC LIMIT 1",
            (system_id,),
        ).fetchone()
        if not row:
            return []
        stats = json.loads(row[0])
        items = []
        # Main disk (top-level d/du/dp)
        if stats.get("d") and stats.get("du") is not None:
            d, du = stats["d"], stats["du"]
            dp = stats.get("dp") or (du / d * 100 if d > 0 else 0)
            items.append(("root", du, d, dp))
        # Extra filesystems
        efs = stats.get("efs") or {}
        for name, fs in efs.items():
            d, du = fs.get("d", 0), fs.get("du", 0)
            dp = (du / d * 100) if d > 0 else 0
            items.append((name, du, d, dp))
        # Sort by usage % desc
        items.sort(key=lambda x: x[3], reverse=True)
        return [(name, used, total, pct, "") for name, used, total, pct in items[:n]]
    except Exception as e:
        log.warning("beszel filesystem enrichment failed: %s", e)
        return []
    finally:
        try: conn.close()
        except Exception: pass


def _enrich_grafana_body(alertname: str, host: str, body: str = "") -> str:
    """Return extra body text to append to alert, or empty string.
    Match attempt:
      1. alertname against ENRICHMENT_PATTERNS
      2. body text against same patterns (catches OMV/proxy alerts where
         alertname è generico tipo "OMV system mail (nas-01)" e il vero
         signal "CPU averaged 80%" è nel body)
    """
    haystack = (alertname or "") + " " + (body or "")
    for pattern, kind in ENRICHMENT_PATTERNS:
        if pattern.search(haystack):
            if kind == "wan":
                # WAN alert: scan global cluster, mostra top 5 culprits
                items = _beszel_top_containers_global(by="net", n=5)
                if not items:
                    return ""
                lines = ["\nTop network consumers (cluster-wide):"]
                for h, name, val, unit in items:
                    h_short = h.replace("it1-prd-", "")
                    lines.append(f"  • {name:20s} @ {h_short:8s} {val:>7.1f}{unit}")
                return "\n".join(lines)
            # Other kinds need host
            if not host:
                return ""
            if kind == "disk":
                items = _beszel_top_filesystems(host, n=5)
                if not items:
                    return ""
                lines = [f"\nFilesystem usage ({host}):"]
                for name, used, total, pct, _ in items:
                    lines.append(f"  • {name:15s} {used:>7.1f}G / {total:>7.1f}G  ({pct:>5.1f}%)")
                return "\n".join(lines)
            else:
                top = _beszel_top_containers(host, by=kind, n=3)
                if not top:
                    return ""
                labels = {"mem": "RAM", "cpu": "CPU", "net": "network"}
                label = labels.get(kind, kind.upper())
                lines = [f"\nTop {label} consumers ({host}):"]
                for name, val, unit in top:
                    lines.append(f"  • {name:25s} {val:>7.1f}{unit}")
                return "\n".join(lines)
    return ""


def parse_grafana_payload(payload: dict, severity: str) -> dict:
    """Return {title, body, tags, actions, priority} from a Grafana
    Alertmanager-style webhook body."""
    status = payload.get("status", "firing")
    alerts = payload.get("alerts", [])
    common_labels = payload.get("commonLabels", {})
    common_annot  = payload.get("commonAnnotations", {})

    alertname = common_labels.get("alertname", "Grafana alert")
    component = common_labels.get("component", "")
    host      = common_labels.get("host") or common_labels.get("instance") or ""
    # Fallback host extraction se labels mancanti (es. OMV proxy alerts):
    # cerca pattern "nas-01" / "it1-prd-X" in component, alertname, summary.
    if not host:
        if re.match(r"^(it1-prd-)?[a-z]+-\d+$", component):
            host = component if component.startswith("it1-prd-") else f"it1-prd-{component}"
    if not host:
        summary = (payload.get("commonAnnotations") or {}).get("summary") or ""
        m = re.search(r"\b(it1-prd-[a-z]+-\d+|[a-z]+-\d+)\b", alertname + " " + summary)
        if m:
            h = m.group(1)
            host = h if h.startswith("it1-prd-") else f"it1-prd-{h}"

    state_emoji = ICONS["resolved"] if status == "resolved" else ICONS.get(severity, ICONS["info"])
    # Source prefix for consistency with Beszel/HC/WUD/Authentik titles
    # (each says "Beszel:" / "HC X:" / "WUD:" — Grafana didn't, audit-fixed
    # in 0.9.21 so the user can identify the source at a glance in mixed
    # notification queues).
    title = f"{state_emoji} Grafana: {alertname}"
    if host:
        title += f" — {host}"

    summary = common_annot.get("summary", "")
    description = common_annot.get("description", "")
    body_parts = []
    if status == "resolved":
        body_parts.append(f"Status: RESOLVED")
    if summary:
        body_parts.append(summary)
    if description and description != summary:
        body_parts.append(description)
    affected = []
    for a in alerts[:5]:
        lbls = a.get("labels", {})
        h = lbls.get("host") or lbls.get("instance") or lbls.get("container_name")
        if h and h not in affected:
            affected.append(h)
    if len(affected) > 1 or (affected and affected[0] != host):
        body_parts.append(f"Affected: {', '.join(affected)}")
    body = "\n".join(body_parts) or "(no body)"

    # Enrichment: per alert mem/cpu/net/disk → query Beszel SQLite per top
    # consumers su host. Match su alertname + body (cattura anche OMV
    # system mail e altri proxied dove signal è nel body, non in alertname).
    if status != "resolved":
        enrichment = _enrich_grafana_body(alertname, host, body)
        if enrichment:
            body += enrichment

    # Always include an explicit "grafana" source tag (0.9.21+ uniformity
    # audit fix) — Beszel/HC/WUD/Authentik already do this; previously only
    # the variable `component` label was used.
    # When resolved, drop the severity literal from tag list — ntfy auto-renders
    # 'warning'/'critical'/'info' as Unicode emoji, which would conflict with
    # the ✅ resolved emoji in the title and confuse the user.
    if status == "resolved":
        tags = [TAG_PREFIXES.get("resolved", "white_check_mark"), "grafana", component or "homelab"]
    else:
        tags = [TAG_PREFIXES.get(severity, "bell"), severity, "grafana", component or "homelab"]

    actions = []
    # 1st button: runbook (if the alert rule sets annotations.runbook_url)
    # — fronted because clicking the push usually means "show me what to do".
    runbook_url = common_annot.get("runbook_url", "")
    if runbook_url:
        actions.append(("view", "📖 Runbook", runbook_url))
    # 2nd button: component dashboard (where to see the state in Grafana)
    if component in COMPONENT_DASHBOARDS:
        label, slug = COMPONENT_DASHBOARDS[component]
        actions.append(("view", f"📊 {label}", f"{GRAFANA_BASE}{slug}"))
    rule_url = ""
    if alerts:
        rule_url = alerts[0].get("generatorURL", "")
    if not rule_url:
        rule_url = payload.get("externalURL", "")
    if rule_url:
        actions.append(("view", "View rule", rule_url))

    priority = PRIORITIES.get(severity, "default")
    if status == "resolved":
        priority = "low"

    return {"title": title, "body": body, "tags": tags, "actions": actions, "priority": priority,
            "_alertname": alertname,
            # Image rendering hints (deliver() renders the mapped dashboard to PNG
            # and attaches it to the push). slug = the component's dashboard;
            # instance = the alert's instance label (→ var-instance on render).
            "_render_slug": (COMPONENT_DASHBOARDS.get(component, (None, None))[1]
                             if component in COMPONENT_DASHBOARDS else None),
            "_render_instance": common_labels.get("instance", "") if isinstance(common_labels, dict) else "",
            # Resolved events don't need a snooze button — by definition the
            # condition is gone, so suppressing future occurrences would just
            # delay seeing it the next time it fires.
            "_skip_snooze": (status == "resolved")}


def parse_beszel_payload(payload: dict, severity: str) -> dict:
    """Beszel webhook is fully template-customisable in the UI. Convention:
    configure Beszel with a JSON body of the form
       { "alert": "...", "system": "...", "value": "...", "threshold": "...",
         "status": "triggered|resolved", "url": "<beszel deep link>" }
    Any of these keys may be absent — we fall back gracefully."""
    alert    = payload.get("alert") or payload.get("name") or "Beszel alert"
    system   = payload.get("system") or payload.get("host") or ""
    value    = payload.get("value", "")
    threshold = payload.get("threshold", "")
    status   = payload.get("status", "triggered").lower()
    url      = payload.get("url", "")

    is_resolved = status in ("resolved", "ok", "back to normal")
    state_emoji = ICONS["resolved"] if is_resolved else ICONS.get(severity, ICONS["info"])
    title = f"{state_emoji} Beszel: {alert}"
    if system:
        title += f" — {system}"

    body_parts = []
    if is_resolved:
        body_parts.append("Status: RESOLVED")
    if value != "" and threshold != "":
        body_parts.append(f"value={value} (threshold={threshold})")
    elif value != "":
        body_parts.append(f"value={value}")
    body = "\n".join(body_parts) or alert

    if is_resolved:
        tags = [TAG_PREFIXES.get("resolved", "white_check_mark"), "beszel"]
    else:
        tags = [TAG_PREFIXES.get(severity, "bell"), severity, "beszel"]

    actions = []
    if FALLBACK_RUNBOOKS.get("beszel"):
        actions.append(("view", "📖 Runbook", FALLBACK_RUNBOOKS["beszel"]))
    actions.append(("view", "📊 Beszel UI", url))

    priority = PRIORITIES.get(severity, "default")
    if is_resolved:
        priority = "low"

    return {"title": title, "body": body, "tags": tags, "actions": actions, "priority": priority,
            "_alertname": alert, "_skip_snooze": is_resolved}


def parse_healthchecks_payload(payload: dict, severity: str) -> dict:
    """Healthchecks self-hosted webhook. HC supports placeholder substitution
    in the body before POST, so we configure the channel to send JSON:
       { "check": "...", "status": "up|down|fail|...", "code": "...",
         "last_ping": "...", "tags": "...", "url": "<HC details page>" }
    The `status` field drives resolved-vs-firing styling; everything else
    is decorative."""
    check     = payload.get("check") or payload.get("name") or "healthcheck"
    status    = (payload.get("status") or "down").lower()
    code      = payload.get("code", "")
    last_ping = payload.get("last_ping", "")
    raw_tags  = payload.get("tags", "")
    url       = payload.get("url", "")

    is_resolved = status in ("up", "ok", "resolved")
    state_emoji = ICONS["resolved"] if is_resolved else ICONS.get(severity, ICONS["info"])
    # Title preserves HC's own terminology (UP/DOWN) since that matches the
    # HC UI users navigate when investigating. Body normalises to RESOLVED
    # so it lines up with Grafana/Beszel in mixed notification streams
    # (0.9.21 uniformity audit fix).
    state_word_title = "UP" if is_resolved else "DOWN"
    state_word_body  = "RESOLVED" if is_resolved else "DOWN"
    title = f"{state_emoji} HC {state_word_title}: {check}"

    body_parts = [f"Status: {state_word_body}"]
    if last_ping:
        body_parts.append(f"Last ping: {last_ping}")
    if code:
        body_parts.append(f"Code: {code}")
    if raw_tags:
        body_parts.append(f"Tags: {raw_tags}")
    body = "\n".join(body_parts)

    if is_resolved:
        tags = [TAG_PREFIXES.get("resolved", "white_check_mark"), "healthchecks"]
    else:
        tags = [TAG_PREFIXES.get(severity, "bell"), severity, "healthchecks"]

    # 1st: runbook (per-payload override > per-source fallback)
    rb = payload.get("runbook_url") or FALLBACK_RUNBOOKS.get("healthchecks") or ""
    actions = []
    if rb:
        actions.append(("view", "📖 Runbook", rb))
    # 2nd: HC check details page (deep-link)
    if url:
        actions.append(("view", "📊 Open in HC", url))
    else:
        actions.append(("view", "📊 Open Healthchecks", "https://hc.luigibarretta.com/projects/"))

    priority = PRIORITIES.get(severity, "default")
    if is_resolved:
        priority = "low"

    return {"title": title, "body": body, "tags": tags, "actions": actions, "priority": priority,
            "_alertname": check, "_skip_snooze": is_resolved}



def parse_pve_payload(payload: dict, severity: str) -> dict:
    """Proxmox VE notification-system webhook target (PVE 8.3+/9).

    Il target webhook su pve POSTa un JSON minimale costruito col helper
    handlebars {{ json … }} (escaping sicuro di quote/newline):
       { "title": "...", "message": "...", "severity": "...",
         "node": "...", "type": "vzdump" }
    La severity nel body è quella pve (info|notice|warning|error|unknown);
    quella che guida i topic klaxond è il path (/pve/<sev>) — il mapping lo
    decidono i matcher su pve (warning→warning, error+unknown→critical).
    """
    if not isinstance(payload, dict):
        payload = {}
    title_raw = str(payload.get("title") or "Proxmox notification").strip()
    message = str(payload.get("message") or "").strip()
    node = str(payload.get("node") or "pve").strip() or "pve"
    pve_sev = str(payload.get("severity") or "").lower()
    ntype = str(payload.get("type") or "").strip()

    emoji = ICONS.get(severity, ICONS["info"])
    title = f"{emoji} PVE {node}: {title_raw}"

    body_parts = []
    if ntype:
        body_parts.append(f"Type: {ntype}")
    if pve_sev and pve_sev != severity:
        body_parts.append(f"PVE severity: {pve_sev}")
    if message:
        # i messaggi vzdump di errore possono essere lunghi — tronca, il
        # dettaglio completo sta nel task log di pve
        body_parts.append(message if len(message) <= 1500 else message[:1500] + " …[troncato]")
    body = "\n".join(body_parts) or title_raw

    tags = [TAG_PREFIXES.get(severity, "bell"), severity, "pve"]
    actions = []
    rb = FALLBACK_RUNBOOKS.get("pve") or ""
    if rb:
        actions.append(("view", "📖 Runbook", rb))
    actions.append(("view", "🖥 Open Proxmox", "https://proxmox.luigibarretta.com/"))

    return {"title": title, "body": body, "tags": tags, "actions": actions,
            "priority": PRIORITIES.get(severity, "default"),
            "_alertname": f"pve-{ntype}" if ntype else "pve-notification"}


def parse_wud_payload(payload, severity: str) -> dict:
    """WUD (What's Up Docker) HTTP trigger payload.

    WUD HTTP trigger has TWO possible body shapes:

    1) Raw container JSON (WUD's actual HTTP trigger behavior — `simpletitle`/
       `simplebody` settings are IGNORED for the http channel; see
       Http.js:sendHttpRequest which does options.data = container):
       {
         "name": "grafana", "watcher": "local",
         "image": {"name": "grafana/grafana", "tag": {"value": "12.4.2"}},
         "updateKind": {"kind": "tag", "localValue": "12.4.2",
                         "remoteValue": "13.1.0", "semverDiff": "major"},
         "result": {"link": "..."}, ...
       }
       (or an ARRAY of these for batch fires)

    2) {title, body} — legacy manual format from curl tests / synthetic POSTs.

    Optional extra keys honored on both shapes:
      - runbook_url    : per-payload runbook (falls back to FALLBACK_RUNBOOKS['wud'])
      - wud_url        : deep-link to WUD UI

    WUD has no native multi-channel/retry, so cascade is always on.
    """
    state_emoji = ICONS.get(severity, ICONS["info"])

    # Batch shape: array of container objects → summarize
    if isinstance(payload, list):
        containers = payload
        count = len(containers)
        title_raw = f"{count} container update{'s' if count != 1 else ''} available"
        lines = []
        for c in containers[:10]:
            n = c.get("name", "?")
            uk = c.get("updateKind") or {}
            local = uk.get("localValue") or "?"
            remote = uk.get("remoteValue") or "?"
            kind = uk.get("kind") or "tag"
            semv = uk.get("semverDiff")
            sv = f" ({semv})" if semv else ""
            lines.append(f"• {n}: {kind} {local} ⇒ {remote}{sv}")
        if count > 10:
            lines.append(f"… +{count - 10} more")
        body_raw = "\n".join(lines)
        # Extra keys not available on lists; skip runbook/wud_url overrides
        payload_extras = {}
    elif isinstance(payload, dict) and "name" in payload and "updateKind" in payload:
        # Single container JSON (WUD native HTTP trigger body)
        name = payload.get("name", "?")
        watcher = payload.get("watcher") or "local"
        uk = payload.get("updateKind") or {}
        local = uk.get("localValue") or "?"
        remote = uk.get("remoteValue") or "?"
        kind = uk.get("kind") or "tag"
        semv = uk.get("semverDiff")
        sv = f" ({semv})" if semv else ""
        link = (payload.get("result") or {}).get("link") or ""
        title_raw = f"Update available for {name} on {watcher}"
        body_raw = f"{name}: {kind} {local} ⇒ {remote}{sv}"
        if link:
            body_raw += f"\n{link}"
        payload_extras = payload
    else:
        # Legacy {title, body} shape (manual tests, synthetic POSTs)
        title_raw = (payload.get("title") if isinstance(payload, dict) else None) or "Container update available"
        body_raw = (payload.get("body") if isinstance(payload, dict) else None) or "Container update detected — see WUD UI for details."
        payload_extras = payload if isinstance(payload, dict) else {}

    title = f"{state_emoji} WUD: {title_raw}"
    body = body_raw

    # First tag = severity emoji (matches Beszel/HC pattern for uniform
    # severity-at-a-glance). 'package' kept as second tag so ntfy still
    # renders the 📦 alongside the severity. Pre-0.9.21 had 'package' as
    # the leading tag which made WUD pushes visually distinct from other
    # info-level notifications.
    tags = [TAG_PREFIXES.get(severity, "bell"), severity, "package", "wud", "container-update"]

    actions = []
    rb = payload_extras.get("runbook_url") or FALLBACK_RUNBOOKS.get("wud") or ""
    if rb:
        actions.append(("view", "📖 Runbook", rb))
    wud_url = payload_extras.get("wud_url") or "http://192.168.50.110:3033/"
    actions.append(("view", "📦 Open WUD", wud_url))

    priority = PRIORITIES.get(severity, "default")

    return {"title": title, "body": body, "tags": tags, "actions": actions, "priority": priority,
            # WUD updates don't benefit from snooze — they fire once per
            # detected update, not continuously, so suppressing wouldn't
            # change the next batch's behaviour.
            "_skip_snooze": True}


def parse_authentik_payload(payload: dict, severity: str) -> dict:
    """Authentik notification webhook payload (from ntfy-body-mapping property mapping).

    The mapping outputs an ntfy-native shape dict:
      {
        "topic":    "<ntfy topic>",          # we ignore (klaxond routes via NTFY_TOPICS)
        "title":    "🔐 Authentication SUCCESS - <user>",
        "message":  "<plain text body>",
        "data":     {"severity": "info"|"critical", "auth_method": ..., ...},
        "tags":     ["authentik", "login", "success"|"failed", ...],
        "priority": 3|5,                      # ntfy priority scale
        "click":    "<URL of the service>",   # primary click target
        "actions":  [{"action":"view","label":"...","url":"..."}, ...],
      }

    Severity preference: body.data.severity > URL path severity (so a single
    Authentik transport can route both info + critical correctly).
    """
    # Severity override from body
    body_sev = ((payload.get("data") or {}).get("severity") or "").strip().lower()
    if body_sev and body_sev in _all_known_severities():
        severity = body_sev

    title_raw = str(payload.get("title") or "Authentik notification")
    body_raw  = str(payload.get("message") or "")

    # Klaxond convention: emoji + source-tag prefix in title (mirrors other sources).
    # Authentik mapping already includes a leading icon (🔐/🚨), so we add a
    # severity emoji prefix + "Authentik:" source prefix (0.9.21 uniformity
    # audit fix) and keep the mapping's title intact afterwards.
    state_emoji = ICONS.get(severity, ICONS["info"])
    title = f"{state_emoji} Authentik: {title_raw}"

    # Tags: keep what the mapping produced + add severity prefix (for ntfy display)
    tags = list(payload.get("tags") or [])
    sev_tag = TAG_PREFIXES.get(severity)
    if sev_tag and sev_tag not in tags:
        tags.insert(0, sev_tag)
    if "authentik" not in tags:
        tags.append("authentik")

    # Actions: convert {action, label, url} → klaxond's tuple format (kind, label, target)
    actions = []
    click = payload.get("click")
    if click:
        actions.append(("view", "Open Authentik", click))
    for a in (payload.get("actions") or [])[:3]:
        if isinstance(a, dict) and a.get("url") and a.get("label"):
            actions.append(("view", str(a["label"]), str(a["url"])))
    actions = actions[:3]  # cap to 3 (ntfy max)

    # Priority: prefer klaxond's per-severity table; fall back to mapping value
    priority = PRIORITIES.get(severity, "default")

    return {"title": title, "body": body_raw, "tags": tags,
            "actions": actions, "priority": priority,
            # Authentik events (login successes/failures, MFA enrol, etc.) are
            # discrete identity events, not recurring alarms. A snooze button
            # would be semantically odd.
            "_skip_snooze": True}


def parse_prowlarr_payload(payload: dict, severity: str) -> dict:
    """Prowlarr webhook payload.

    *arr family (Prowlarr/Sonarr/Radarr/Readarr) usano webhook format custom
    Servarr. Eventi tipici:
      - Test                  → {eventType:"Test", instanceName:"Prowlarr"}
      - Health                → {eventType:"Health", health:{type, message, wikiUrl}}
      - HealthRestored        → {eventType:"HealthRestored", health:{...}}
      - ApplicationUpdate     → {eventType:"ApplicationUpdate", previousVersion, newVersion}

    Severity mapping:
      Test, HealthRestored, ApplicationUpdate → info
      Health(type=warning)                    → warning
      Health(type=error)                      → critical
    URL path severity è il fallback se nessun match.
    """
    evt = (payload.get("eventType") or "Unknown").strip()
    instance = payload.get("instanceName") or "Prowlarr"
    app_url = payload.get("applicationUrl") or "https://prowlarr.luigibarretta.com"

    # Prowlarr payload shape varia: a volte i Health field sono nested in
    # `health: {type, message, wikiUrl}`, a volte direttamente top-level
    # (`type`, `message`, `wikiUrl` su payload root). Cerchiamo entrambi.
    health = payload.get("health") or {}
    health_type = (
        health.get("type") or payload.get("type") or payload.get("level") or ""
    ).strip().lower()
    health_message = health.get("message") or payload.get("message") or ""
    health_wiki    = health.get("wikiUrl") or payload.get("wikiUrl") or ""

    if evt == "Health":
        if health_type == "warning":
            severity = "warning"
        elif health_type in ("error", "critical"):
            severity = "critical"
    elif evt in ("HealthRestored", "Test", "ApplicationUpdate"):
        severity = "info"

    # Build title and body based on event type
    state_emoji = ICONS.get(severity, ICONS["info"])
    if evt == "Health":
        title_raw = "Health issue"
        body_raw = health_message or "Unknown health issue"
        wiki = health_wiki
    elif evt == "HealthRestored":
        title_raw = "Health restored"
        body_raw = health_message or "All health issues resolved"
        wiki = ""
    elif evt == "ApplicationUpdate":
        prev = payload.get("previousVersion") or "?"
        new  = payload.get("newVersion") or "?"
        title_raw = "Application updated"
        body_raw  = f"{instance} {prev} → {new}"
        wiki = ""
    elif evt == "Test":
        title_raw = "Test notification"
        body_raw  = "Klaxond webhook test successful"
        wiki = ""
    else:
        title_raw = evt
        body_raw  = str(payload.get("message") or "")
        wiki = ""

    title = f"{state_emoji} Prowlarr: {title_raw}"

    tags = [TAG_PREFIXES.get(severity, "bell"), severity, "prowlarr"]
    if evt == "Health":          tags.append("health")
    elif evt == "ApplicationUpdate": tags.append("update")
    elif evt == "Test":          tags.append("test")

    actions = [("view", "Open Prowlarr", app_url)]
    if wiki:
        actions.append(("view", "Wiki", wiki))

    priority = PRIORITIES.get(severity, "default")

    return {"title": title, "body": body_raw, "tags": tags,
            "actions": actions, "priority": priority,
            # Prowlarr events sono health/update discrete, no recurrence → no snooze
            "_skip_snooze": True}


def parse_shelfmark_payload(payload: dict, severity: str) -> dict:
    """Shelfmark notification webhook payload (Apprise json:// shape).

    Shelfmark uses Apprise for notifications. The json:// scheme sends:
      {
        "version": "1.0",
        "title": "Subject line",
        "message": "Body text",
        "type": "info" | "success" | "warning" | "failure"
      }
    Optionally Shelfmark may add 'event', 'user', 'book_title' depending on
    Custom Payload settings in UI.

    Severity preference: body.type → URL path severity (last fallback).
    Mapping:
        info     → info
        success  → info
        warning  → warning
        failure  → critical
    """
    # Severity override from Apprise 'type' field
    body_type = (payload.get("type") if isinstance(payload, dict) else None)
    if body_type:
        type_to_sev = {"info": "info", "success": "info",
                       "warning": "warning", "failure": "critical"}
        mapped = type_to_sev.get(str(body_type).lower())
        if mapped and mapped in _all_known_severities():
            severity = mapped

    title_raw = str(payload.get("title") or "Shelfmark notification")
    body_raw  = str(payload.get("message") or "")

    state_emoji = ICONS.get(severity, ICONS["info"])
    title = f"{state_emoji} Shelfmark: {title_raw}"

    # Tags
    tags = [TAG_PREFIXES.get(severity, "bell"), severity, "shelfmark", "book"]
    sev_tag = TAG_PREFIXES.get(severity)
    if sev_tag and sev_tag not in tags:
        tags.insert(0, sev_tag)

    # Actions: deep-link a Shelfmark UI if possible
    actions = [("view", "Open Shelfmark", "https://bookdl.luigibarretta.com")]

    priority = PRIORITIES.get(severity, "default")

    return {"title": title, "body": body_raw, "tags": tags,
            "actions": actions, "priority": priority,
            # Shelfmark events (download done/failed, request approved) are
            # discrete file-level events — no ricorrenza periodica → no snooze.
            "_skip_snooze": True}


def parse_decypharr_payload(payload: dict, severity: str) -> dict:
    """Decypharr (cy01/blackhole) webhook payload.

    Schema osservato (Callback URL → JSON POST):
      {
        "hash": "<infohash>",
        "name": "<torrent name>",
        "status": "success" | "failure" | "error",
        "event": "download_start" | "download_complete" | "download_fail",
        "debrid": "realdebrid" | "alldebrid" | ...,
        "content_path": "/downloads/...",
        "message": "<human readable>"
      }

    Severity mapping (status field has priority over URL path):
      success → info
      failure → warning
      error   → critical
    """
    if not isinstance(payload, dict):
        payload = {}

    status = str(payload.get("status") or "").strip().lower()
    status_to_sev = {"success": "info", "failure": "warning", "error": "critical"}
    mapped = status_to_sev.get(status)
    if mapped and mapped in _all_known_severities():
        severity = mapped

    event = str(payload.get("event") or "").strip().lower()
    name = str(payload.get("name") or "<unknown>").strip() or "<unknown>"
    debrid = str(payload.get("debrid") or "").strip()
    content_path = str(payload.get("content_path") or "").strip()
    msg = str(payload.get("message") or "").strip()

    event_human = {
        "download_start":    "Download started",
        "download_complete": "Download completed",
        "download_fail":     "Download failed",
        "download_failed":   "Download failed",
        "download_error":    "Download error",
    }.get(event, event.replace("_", " ").capitalize() if event else "Event")

    state_emoji = ICONS.get(severity, ICONS["info"])
    title_raw = f"{event_human}: {name}"
    title = f"{state_emoji} Decypharr: {title_raw}"

    if msg:
        body = msg
    else:
        bp = [f"{event_human}: {name}"]
        if content_path:
            bp.append(f"-> {content_path}")
        body = "\n".join(bp)
    if debrid and debrid.lower() not in body.lower():
        body = f"{body}\n[backend: {debrid}]"

    tags = [TAG_PREFIXES.get(severity, "bell"), severity, "decypharr", "download"]
    sev_tag = TAG_PREFIXES.get(severity)
    if sev_tag and sev_tag not in tags:
        tags.insert(0, sev_tag)

    actions = [("view", "Open Decypharr", "https://decypharr.luigibarretta.com")]

    priority = PRIORITIES.get(severity, "default")

    return {"title": title, "body": body, "tags": tags,
            "actions": actions, "priority": priority,
            # Decypharr per-torrent events (start/complete/fail) sono discreti
            # file-level — no ricorrenza periodica → no snooze.
            "_skip_snooze": True}


def _strip_non_ascii(text: str) -> str:
    """Strip Unicode chars > 0x7F. ntfy headers are Latin-1 only — emoji
    in action labels (📖 Runbook) cause urllib to raise. We keep emoji in
    title (RFC 2047 base64-encoded) and in Telegram inline_keyboard (JSON
    body, supports UTF-8), but Action labels must be ASCII-safe."""
    return "".join(c if ord(c) < 128 else "" for c in text).strip()

def post_to_ntfy(severity: str, parts: dict, timeout: int = 5) -> bool:
    """Fan-out: POST to ALL topics that declare this severity in handles[].
    Returns True if at least one succeeded. If no topic handles this severity,
    returns False (caller falls through to next cascade tier)."""
    topics = _topics_for_severity(severity)
    if not topics:
        log.warning("ntfy: no topic handles severity '%s' — skipping", severity)
        return False
    title_b64 = base64.b64encode(parts["title"].encode("utf-8")).decode("ascii")
    encoded_title = f"=?UTF-8?B?{title_b64}?="
    # Build the actions list. The renderer-supplied actions go first (max 2),
    # then we append a "Snooze 1h" action automatically when there's a real
    # alertname to suppress on (skip dry-runs, skip resolved). ntfy caps at 3.
    actions = list(parts.get("actions") or [])[:2]
    alertname = (parts.get("_alertname") or "").strip()
    if not alertname:
        # Fall back: derive from title — strip emoji, strip leading severity.
        # Renderers should populate _alertname explicitly; this is best-effort.
        t = parts.get("title", "")
        if " — " in t:
            t = t.split(" — ", 1)[0]
        alertname = "".join(c for c in t if ord(c) > 0x7F or c.isalnum() or c in "-_./ ").strip()
    if alertname and not parts.get("_skip_snooze"):
        try:
            tok = _ack_sign(alertname, ACK_DEFAULT_TTL)
            actions.append(("view", "Snooze 1h", f"{KLAXOND_PUBLIC_URL}/api/ack/{tok}"))
        except Exception as e:
            log.warning("ntfy: ack-token sign failed (continuing without snooze button): %s", e)
    actions_header = None
    if actions:
        actions_header = "; ".join(
            f"{kind}, {_strip_non_ascii(label)}, {target}" for kind, label, target in actions[:3]
        )
    any_ok = False
    for t in topics:
        token = t.get("token") or ""
        if not token:
            log.warning("ntfy: topic '%s' has no token — skipping", t.get("name"))
            continue
        url = f"{NTFY_URL}/{t['name']}"
        headers = {
            "Authorization": f"Bearer {token}",
            "Title": encoded_title,
            "Tags": ",".join(parts["tags"]),
            "Priority": parts["priority"],
        }
        if actions_header:
            headers["Actions"] = actions_header
        # Attach the rendered dashboard PNG (ntfy fetches the URL client-side).
        if parts.get("_attach_url"):
            headers["Attach"] = parts["_attach_url"]
        req = urllib.request.Request(url, data=parts["body"].encode("utf-8"),
                                     headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                ok = 200 <= resp.status < 300
                any_ok = any_ok or ok
        except Exception as e:
            log.warning("ntfy POST to %s failed: %s", t.get("name"), e)
    return any_ok


def post_to_telegram(severity: str, parts: dict, timeout: int = 8) -> bool:
    if not TG_TOKEN or not TG_CHAT:
        return False
    # HTML parse_mode is more robust than Markdown — only <, >, & need
    # escaping in text. Markdown italic on stray underscores (e.g. body
    # contains "remote_cache") causes 400 Bad Request from Telegram.
    def _esc(t: str) -> str:
        return t.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    msg = f"<b>{_esc(parts['title'])}</b>\nseverity: <code>{_esc(severity)}</code>\n\n{_esc(parts['body'])}"

    # Build an inline_keyboard with one button per action URL.
    payload = {
        "chat_id": TG_CHAT,
        "parse_mode": "HTML",
        "text": msg,
        "disable_web_page_preview": "true",
    }
    if parts.get("actions"):
        payload["reply_markup"] = json.dumps({
            "inline_keyboard": [
                [{"text": label, "url": target}]
                for _, label, target in parts["actions"][:5]  # cap safety
                if target  # skip empty URLs
            ]
        })

    data = urllib.parse.urlencode(payload).encode("utf-8")
    url = f"https://api.telegram.org/bot{TG_TOKEN}/sendMessage"
    try:
        with urllib.request.urlopen(url, data=data, timeout=timeout) as resp:
            return 200 <= resp.status < 300
    except Exception as e:
        log.warning("telegram POST failed: %s", e)
        return False


def post_to_smtp(severity: str, parts: dict, timeout: int = 10) -> bool:
    if not SMTP_HOST or not SMTP_USER or not SMTP_PASS or not SMTP_TO:
        return False
    try:
        body_text = f"{parts['body']}\n\nseverity: {severity}\n"
        if parts.get("actions"):
            body_text += "\n" + "\n".join(f"{label}: {target}"
                                          for _, label, target in parts["actions"])
        msg = MIMEText(body_text, "plain", "utf-8")
        msg["Subject"] = f"[{severity}] {parts['title']}"
        msg["From"] = SMTP_FROM
        msg["To"] = SMTP_TO
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=timeout) as s:
            s.starttls()
            s.login(SMTP_USER, SMTP_PASS)
            s.sendmail(SMTP_FROM, [SMTP_TO], msg.as_string())
        return True
    except Exception as e:
        log.warning("smtp send failed: %s", e)
        return False


# Default tiers if TOML config is missing.
_DEFAULT_TIERS = [
    {"name": "ntfy",     "timeout_seconds": 5},
    {"name": "telegram", "timeout_seconds": 8},
    {"name": "smtp",     "timeout_seconds": 10},
]

_TIER_FUNCS = {
    "ntfy":     post_to_ntfy,
    "telegram": post_to_telegram,
    "smtp":     post_to_smtp,
}


def _legacy_cascade_policy() -> dict:
    """Build a synthetic policy from the legacy [cascade] block so that
    default_policy = 'cascade' Just Works without duplicating the
    tier list."""
    return {
        "name": "cascade",
        "mode": "cascade",
        "tiers": TOML_CONFIG.get("cascade", {}).get("tiers") or _DEFAULT_TIERS,
    }


def _resolve_policy(name: str) -> dict | None:
    if name == "cascade":
        return _legacy_cascade_policy()
    for p in TOML_CONFIG.get("delivery", {}).get("policies", []):
        if p.get("name") == name:
            return p
    return None


def _matcher_matches(matcher: dict, labels: dict) -> bool:
    """Each k/v in matcher must hold for labels (exact, or regex if value starts with 're:')."""
    for k, v in matcher.items():
        actual = labels.get(k, "")
        if isinstance(v, str) and v.startswith("re:"):
            try:
                if not re.search(v[3:], actual):
                    return False
            except re.error:
                return False
        else:
            if actual != v:
                return False
    return True


def _pick_policy(labels: dict) -> tuple[dict, str]:
    """First rule whose `match` is a subset-AND match wins. Falls back to
    default_policy. Returns (policy_dict, reason_str)."""
    delivery = TOML_CONFIG.get("delivery", {}) or {}
    for i, rule in enumerate(delivery.get("rules", []) or []):
        m = rule.get("match", {}) or {}
        if _matcher_matches(m, labels):
            pol = _resolve_policy(rule.get("policy", ""))
            if pol:
                return pol, f"rule#{i+1}→{pol['name']}"
    default = delivery.get("default_policy", "cascade")
    pol = _resolve_policy(default)
    if pol:
        return pol, f"default→{default}"
    # Hard fallback: synthetic legacy cascade so we never silently drop alerts.
    return _legacy_cascade_policy(), "fallback→legacy"



def audit_log_delivery(severity: str, parts: dict, labels: dict, source: str,
                       tiers_attempted: list, ok: bool, channel: str,
                       started_at: float, ended_at: float) -> None:
    """Emit one structured JSON line per delivery attempt.
    Promtail scrapes klaxond's stdout into Loki; the JSON is parsed there
    with a json|line_format pipeline to power the Alert health dashboard
    and ad-hoc 'who got what, when' queries.

    Schema kept stable on purpose. Add keys only — never remove or rename.
    """
    try:
        record = {
            "audit": "delivery",
            "source": source,                    # grafana | beszel | healthchecks
            "severity": severity,
            "alertname": labels.get("alertname", parts.get("title","")[:120]),
            "component": labels.get("component", ""),
            "host": labels.get("host", labels.get("instance_name", "")),
            "title": parts.get("title","")[:200],
            "tiers_attempted": tiers_attempted,  # ["ntfy","telegram"] etc.
            "ok": ok,
            "channel": channel,                  # final delivery channel, or "all-failed"
            "duration_ms": int((ended_at - started_at) * 1000),
            "timestamp": int(ended_at * 1000),
        }
        log.info("AUDIT %s", json.dumps(record, separators=(",", ":"), default=str))
    except Exception as e:  # never let audit break delivery
        log.warning("audit_log_delivery failed: %s", e)
    # Prometheus counter — one inc per delivery attempt outcome
    try:
        _metric_inc("klaxond_deliveries_total", {
            "source": source, "severity": severity,
            "channel": channel, "ok": "1" if ok else "0",
        })
    except Exception:
        pass


def deliver(severity: str, parts: dict, with_cascade: bool, labels: dict = None, source: str = "unknown") -> tuple[bool, str]:
    """Pick a policy from delivery.rules based on alert labels, then walk
    its tiers in cascade or broadcast mode. `with_cascade` is honoured only
    for cascade-mode policies on /webhook/* (legacy behaviour).

    Returns (ok, channel_used). For broadcast mode, channel_used is a
    "+"-joined list of tiers that succeeded.
    """
    labels = labels or {}
    labels = {**labels, "severity": severity}
    policy, reason = _pick_policy(labels)
    tiers = policy.get("tiers") or _DEFAULT_TIERS
    mode = policy.get("mode", "cascade")
    log.info("policy picked: %s (mode=%s, %d tiers)", reason, mode, len(tiers))

    # Render the mapped dashboard to PNG once (best-effort) and expose it at
    # /img/<token>.png; tiers that support attachments (ntfy) will reference it.
    if GRAFANA_RENDER_BASE and parts.get("_render_slug") and not parts.get("_attach_url"):
        png = render_alert_image(parts["_render_slug"], parts.get("_render_instance", ""))
        if png:
            tok = stash_alert_image(png)
            parts["_attach_url"] = f"{KLAXOND_PUBLIC_URL}/img/{tok}.png"
            log.info("render: attached dashboard image (%d bytes) for %s → %s",
                     len(png), parts.get("_render_slug"), parts["_attach_url"])

    import time as _time
    started_at = _time.time()
    tiers_attempted = []

    def _audit(ok: bool, channel: str):
        audit_log_delivery(severity, parts, labels, source, tiers_attempted, ok, channel, started_at, _time.time())

    if mode == "broadcast":
        succeeded = []
        for t in tiers:
            fn = _TIER_FUNCS.get(t["name"])
            if not fn:
                continue
            tiers_attempted.append(t["name"])
            if fn(severity, parts, timeout=int(t.get("timeout_seconds", 10))):
                succeeded.append(t["name"])
        if succeeded:
            _audit(True, "+".join(succeeded))
            return True, "+".join(succeeded)
        _audit(False, "broadcast-all-failed")
        return False, "broadcast-all-failed"

    # cascade
    if not tiers:
        _audit(False, "no-tiers")
        return False, "no-tiers"
    first = tiers[0]
    fn = _TIER_FUNCS.get(first["name"])
    tiers_attempted.append(first["name"])
    if fn and fn(severity, parts, timeout=int(first.get("timeout_seconds", 5))):
        _audit(True, first["name"])
        return True, first["name"]
    if not with_cascade:
        _audit(False, f"{first['name']}-failed")
        return False, f"{first['name']}-failed"
    for tier in tiers[1:]:
        fn = _TIER_FUNCS.get(tier["name"])
        if not fn:
            continue
        tiers_attempted.append(tier["name"])
        if fn(severity, parts, timeout=int(tier.get("timeout_seconds", 10))):
            log.info("cascade delivered via %s: %s", tier["name"], parts["title"])
            _audit(True, tier["name"])
            return True, tier["name"]
    log.error("ALL channels failed: %s", parts["title"])
    _audit(False, "all-failed")
    return False, "all-failed"


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        log.info("%s - %s", self.address_string(), fmt % args)

    def end_headers(self):
        # Inject pending Set-Cookie (from AuthManager._issue_session)
        pc = getattr(self, "_pending_set_cookie", None)
        if pc:
            self.send_header("Set-Cookie", pc)
            self._pending_set_cookie = None
        BaseHTTPRequestHandler.end_headers(self)

    def _require_auth(self) -> bool:
        """Returns True if request is authorized (or public path), False if AuthManager
        already wrote a 401/403/302 response and the caller must return immediately."""
        if AUTH_MANAGER.is_public(self.path):
            return True
        user = AUTH_MANAGER.authenticate(self)
        if user is None:
            return False
        self._authed_user = user
        return True

    def do_GET(self):
        # Special-case OIDC routes before auth gating
        if self.path.startswith("/auth/login"):
            return AUTH_MANAGER.oidc_login_redirect(self)
        if self.path.startswith("/auth/callback"):
            return AUTH_MANAGER.oidc_callback(self)
        if self.path.startswith("/auth/logout"):
            return AUTH_MANAGER.logout(self)
        if self.path == "/auth/me":
            user = AUTH_MANAGER.authenticate(self) if AUTH_CONFIG.get("mode") != "none" else {"sub": "anonymous", "mode": "none"}
            if user is None: return
            return self._send_json(user)

        # All other paths: enforce auth (webhook paths return True via is_public)
        if not self._require_auth(): return

        if self.path == "/healthz":
            self.send_response(200); self.end_headers(); self.wfile.write(b"OK")
        elif self.path == "/metrics":
            body = _render_metrics_exposition().encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers(); self.wfile.write(body)
        elif self.path.startswith("/img/"):
            # Rendered alert dashboard PNG, referenced by ntfy Attach. Random
            # token = the auth (auth-free path); auto-expires from memory.
            tok = self.path[len("/img/"):].split("?", 1)[0]
            if tok.endswith(".png"):
                tok = tok[:-4]
            _prune_rendered_images()
            with _rendered_images_lock:
                entry = _rendered_images.get(tok)
            if not entry:
                self.send_response(404); self.end_headers(); return
            png = entry[0]
            self.send_response(200)
            self.send_header("Content-Type", "image/png")
            self.send_header("Content-Length", str(len(png)))
            self.send_header("Cache-Control", "private, max-age=900")
            self.end_headers(); self.wfile.write(png)
        elif self.path in ("/", "/ui", "/ui/"):
            self.send_response(302); self.send_header("Location", "/ui/index.html"); self.end_headers()
        elif self.path.startswith("/ui/"):
            self._serve_static(self.path[len("/ui/"):])
        elif self.path == "/inhibitions" or self.path == "/api/inhibitions":
            self._send_json(inhibition_status())
        elif self.path == "/api/config/backup":
            # Stream the current klaxond.toml as attachment for manual backup.
            try:
                with open(KLAXOND_CONFIG, "rb") as f: body = f.read()
                import datetime
                stamp = datetime.datetime.utcnow().strftime("%Y%m%d-%H%M%S")
                self.send_response(200)
                self.send_header("Content-Type", "application/toml")
                self.send_header("Content-Disposition", f'attachment; filename="klaxond-{stamp}.toml"')
                self.send_header("Content-Length", str(len(body)))
                self.end_headers(); self.wfile.write(body)
            except FileNotFoundError:
                self.send_response(404); self.end_headers()
                self.wfile.write(b"klaxond.toml not found")
        elif self.path == "/api/config/backups":
            # List existing on-disk auto-backups (sorted newest-first).
            self._send_json({
                "backups": _list_config_backups(),
                "keep_max": KLAXOND_BACKUP_KEEP,
                "dir": KLAXOND_BACKUP_DIR,
            })
        elif self.path == "/api/ingest-auth":
            # Per-source secret status (configured / unset / from env-or-toml).
            # Values themselves never returned — only presence.
            self._send_json({
                "sources": _ingest_secret_status(),
                "auth_methods_accepted": [
                    "Authorization: Bearer <secret>",
                    "X-Klaxond-Token: <secret>",
                    "?token=<secret> query param",
                ],
                "note": "Legacy permissive mode (no auth required) is in effect when a source has no secret configured.",
            })
        elif self.path == "/api/schedules":
            self._send_json(scheduler_status())
        elif self.path.startswith("/api/ack/"):
            # Token-gated ack/snooze endpoint reached via ntfy push action.
            # No OIDC required — the signed token IS the credential.
            token = self.path[len("/api/ack/"):].split("?")[0].strip()
            alertname, reason = _ack_verify(token)
            if not alertname:
                self.send_response(400)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.end_headers()
                self.wfile.write(f"<html><body><h2>Ack rejected</h2><p>{reason}</p></body></html>".encode())
                return
            _register_ack_suppression(alertname, ACK_DEFAULT_TTL)
            mins = ACK_DEFAULT_TTL // 60
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(
                f"<html><body style='font-family:system-ui,sans-serif;padding:2em;max-width:480px;margin:auto'>"
                f"<h2 style='color:#22c55e'>✓ Snooze armed</h2>"
                f"<p>Alerts with <code style='background:#eee;padding:0.1em 0.4em;border-radius:3px'>alertname={alertname}</code> are silenced for the next <b>{mins} minutes</b>.</p>"
                f"<p style='color:#666;font-size:0.9em'>This page can be closed. The snooze auto-expires; you'll get the next occurrence when the condition recurs.</p>"
                f"</body></html>".encode()
            )
        elif self.path == "/api/acks":
            self._send_json(ack_status_snapshot())
        elif self.path == "/api/inhibition-rules":
            # Flat shape for UI consumption: match_label_regex tuple → flat
            # match_label + match_regex keys (mirrors TOML on-disk shape).
            rules_out = []
            for r in INHIBITION_RULES:
                row = {"source": r["source"], "ttl_seconds": int(r.get("ttl_seconds", 900))}
                if "match_by" in r:
                    row["match_by"] = r["match_by"]
                if "match_label_regex" in r:
                    row["match_label"], row["match_regex"] = r["match_label_regex"]
                if r.get("match_all"):
                    row["match_all"] = True
                row["applies_to"] = list(r.get("applies_to") or [])
                rules_out.append(row)
            self._send_json({
                "rules": rules_out,
                "available_sources": list(DEDUP_SOURCES),
            })
        elif self.path == "/api/status":
            self._send_json({
                "cascade_enabled_runtime": _cascade_runtime_enabled,
                "cascade_enabled_default": CASCADE_ENABLED,
                "channels": _check_channel_reachability(),
                "ntfy_url": NTFY_URL,
                "smtp_host": SMTP_HOST,
                "telegram_configured": bool(TG_TOKEN and TG_CHAT),
            })
        elif self.path == "/api/deliveries":
            self._send_json(_recent_deliveries())
        elif self.path == "/api/render-config":
            self._send_json({"component_dashboards": {k: list(v) for k, v in COMPONENT_DASHBOARDS.items()},
                             "grafana_base": GRAFANA_BASE})
        elif self.path == "/api/cascade-config":
            tiers = TOML_CONFIG.get("cascade", {}).get("tiers") or _DEFAULT_TIERS
            default_enabled = TOML_CONFIG.get("cascade", {}).get("default_enabled_for_webhook", CASCADE_ENABLED)
            self._send_json({"tiers": tiers, "default_enabled_for_webhook": default_enabled, "runtime_enabled": _cascade_runtime_enabled})
        elif self.path == "/api/auth-config":
            # Strip secrets from public response
            redacted = json.loads(json.dumps(AUTH_CONFIG))
            if redacted.get("basic", {}).get("password_hash"):
                redacted["basic"]["password_hash"] = "***SET***"
            if redacted.get("oidc", {}).get("client_secret"):
                redacted["oidc"]["client_secret"] = "***SET***"
            self._send_json({
                "settings": redacted,
                "available_modes": ["none", "basic", "oidc", "trusted-proxy"],
                "bcrypt_available": _BCRYPT_OK,
                "jwt_available": _JWT_OK,
                "current_user": getattr(self, "_authed_user", {"sub": "anonymous", "mode": "none"}),
            })
        elif self.path == "/api/ntfy-topics":
            # Return all topics + their handles. Tokens redacted to ***SET***
            # if present, empty string otherwise.
            redacted = []
            for t in NTFY_TOPICS:
                r = {"name": t.get("name", ""), "handles": list(t.get("handles") or [])}
                r["token"] = "***SET***" if (t.get("token") or "") else ""
                redacted.append(r)
            known = sorted(_all_known_severities())
            # Detect orphan severities (no topic handles them); 'resolved' is always covered
            orphans = []  # in Fase A nothing is orphan (severities derived from topics) — but custom URL severities could be
            self._send_json({
                "topics":   redacted,
                "ntfy_url": NTFY_URL,
                "known_severities": known,
                "orphans":  orphans,
                "writeable": True,
                "persisted_at": NTFY_TOPICS_PATH,
                "note": "Edits saved to /data/ntfy-topics.json supersede TOML + env vars. Delete the file + restart to re-bootstrap from env.",
            })
        elif self.path == "/api/dedup-config":
            # Return current per-source dedup settings + counts of currently-pending events.
            pending_counts = {}
            for src in DEDUP_SOURCES:
                with DEDUP_BUFFER.lock:
                    pending_counts[src] = len(DEDUP_BUFFER.queues[src])
            self._send_json({
                "sources": list(DEDUP_SOURCES),
                "settings": DEDUP_SETTINGS,
                "pending_counts": pending_counts,
                "defaults": _DEFAULT_DEDUP_SETTINGS,
            })
        elif self.path == "/api/delivery-config":
            delivery = TOML_CONFIG.get("delivery", {}) or {}
            self._send_json({
                "default_policy": delivery.get("default_policy", "cascade"),
                "policies": delivery.get("policies", []) or [],
                "rules":    delivery.get("rules", []) or [],
                "available_tiers": list(_TIER_FUNCS.keys()),
                "legacy_cascade_tiers": TOML_CONFIG.get("cascade", {}).get("tiers") or _DEFAULT_TIERS,
            })
        elif self.path == "/api/channel-config":
            # Build a per-severity legacy view from NTFY_TOPICS for backward-compat
            # in the existing Channel-config UI tab. The richer per-topic view is
            # served by /api/ntfy-topics (0.7.0+, used by the dedicated section).
            legacy_topics = {}
            legacy_tokens = {}
            for sev in ("info", "warning", "critical"):
                matches = _topics_for_severity(sev)
                legacy_topics[sev] = matches[0]["name"] if matches else ""
                legacy_tokens[sev] = bool(matches and matches[0].get("token"))
            self._send_json({
                "ntfy": {
                    "url": NTFY_URL,
                    "topics": legacy_topics,
                    "url_from_env": bool(os.environ.get("NTFY_URL")),
                    "topics_from_env": {
                        "info":     bool(os.environ.get("TOPIC_INFO")),
                        "warning":  bool(os.environ.get("TOPIC_WARN")),
                        "critical": bool(os.environ.get("TOPIC_CRIT")),
                    },
                    "tokens_configured": legacy_tokens,
                },
                "telegram": {
                    "chat_id": TG_CHAT,
                    "chat_id_from_env": bool(os.environ.get("TELEGRAM_CHAT_ID")),
                    "bot_token_configured": bool(TG_TOKEN),
                },
                "smtp": {
                    "host": SMTP_HOST,
                    "port": SMTP_PORT,
                    "from_addr": SMTP_FROM,
                    "to_addr": SMTP_TO,
                    "host_from_env": bool(os.environ.get("SMTP_HOST")),
                    "user_configured": bool(SMTP_USER),
                    "password_configured": bool(SMTP_PASS),
                },
            })
        else:
            self.send_response(404); self.end_headers()

    def _send_json(self, obj):
        body = json.dumps(obj, indent=2).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers(); self.wfile.write(body)

    def _serve_static(self, rel):
        # Safe path resolution under /app/static
        safe = os.path.normpath("/" + rel).lstrip("/")
        full = os.path.join("/app/static", safe)
        if not full.startswith("/app/static") or not os.path.isfile(full):
            self.send_response(404); self.end_headers(); return
        mime = "text/html"
        if full.endswith(".css"):  mime = "text/css"
        elif full.endswith(".js"): mime = "application/javascript"
        elif full.endswith(".svg"): mime = "image/svg+xml"
        with open(full, "rb") as f: data = f.read()
        self.send_response(200)
        self.send_header("Content-Type", mime + "; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        # Vendored 3rd-party libs (mermaid etc.) are large + immutable per release →
        # allow caching. Our own app.js/css/html change frequently → no-store.
        if "mermaid" in os.path.basename(full).lower() or "vendor" in full:
            self.send_header("Cache-Control", "public, max-age=86400, immutable")
        else:
            self.send_header("Cache-Control", "no-store")
        self.end_headers(); self.wfile.write(data)

    def do_POST(self):
        # Gate ALL writes behind auth (webhook endpoints are still public via PUBLIC_PATH_PREFIXES)
        if not self._require_auth(): return

        # ---- admin/UI endpoints ----
        if self.path == "/api/auth-config":
            return self._handle_auth_config_update()
        if self.path.startswith("/api/test/"):
            return self._handle_api_test()
        if self.path == "/api/cascade/toggle":
            return self._handle_cascade_toggle()
        if self.path == "/api/render-config":
            return self._handle_render_config_update()
        if self.path == "/api/cascade-config":
            return self._handle_cascade_config_update()
        if self.path == "/api/channel-config":
            return self._handle_channel_config_update()
        if self.path == "/api/delivery-config":
            return self._handle_delivery_config_update()
        if self.path == "/api/render-preview":
            return self._handle_render_preview()
        if self.path == "/api/dedup-config":
            return self._handle_dedup_config_update()
        if self.path == "/api/ntfy-topics":
            return self._handle_ntfy_topics_update()
        if self.path == "/api/inhibition-rules":
            return self._handle_inhibition_rules_update()
        if self.path == "/api/config/restore":
            return self._handle_config_restore()
        if self.path == "/api/ingest-auth":
            return self._handle_ingest_auth_update()
        if self.path == "/api/schedules":
            return self._handle_schedules_update()
        if self.path == "/api/acks/clear":
            return self._handle_ack_clear()
        if self.path == "/api/inhibitions/clear":
            return self._handle_inhibition_clear()
        if self.path == "/api/inhibition-rules/test":
            return self._handle_inhibition_rules_test()

        # ---- alert ingestion ----
        # Parse out query string from the path so it doesn't pollute the
        # severity match. Dry-run can be requested via:
        #   1) ?dry_run=1 on the URL                                 (curl-friendly)
        #   2) "_klaxond_dry_run": true inside the JSON payload      (programmatic)
        parsed_url = urllib.parse.urlparse(self.path)
        url_path = parsed_url.path
        qs = urllib.parse.parse_qs(parsed_url.query)
        dry_run_qs = qs.get("dry_run", ["0"])[0].lower() in ("1", "true", "yes", "on")

        if url_path.startswith("/webhook/"):
            source = "grafana"
        elif url_path.startswith("/beszel/"):
            source = "beszel"
        elif url_path.startswith("/healthchecks/"):
            source = "healthchecks"
        elif url_path.startswith("/wud/"):
            source = "wud"
        elif url_path.startswith("/authentik/"):
            source = "authentik"
        elif url_path.startswith("/shelfmark/"):
            source = "shelfmark"
        elif url_path.startswith("/prowlarr/"):
            source = "prowlarr"
        elif url_path.startswith("/decypharr/"):
            source = "decypharr"
        elif url_path.startswith("/pve/"):
            source = "pve"
        else:
            self.send_response(404); self.end_headers(); return

        severity = url_path.split("/")[-1].lower()
        if severity not in _all_known_severities():
            self.send_response(400); self.end_headers()
            self.wfile.write(f"unknown severity {severity} (no topic handles it)".encode()); return

        # Webhook auth (0.9.18+) — per-source shared secret if configured.
        # No-op for sources without a configured secret (legacy permissive).
        auth_ok, auth_reason = _verify_ingest_auth(source, dict(self.headers), qs)
        if not auth_ok:
            log.warning("[%s/%s] webhook auth rejected: %s (from %s)",
                        source, severity, auth_reason, self.client_address[0] if self.client_address else "?")
            self.send_response(401); self.end_headers()
            self.wfile.write(b"unauthorized (per-source secret required)"); return

        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length)
        try:
            payload = json.loads(raw) if raw else {}
        except Exception as e:
            log.error("invalid JSON: %s", e)
            self.send_response(400); self.end_headers(); return

        dry_run = dry_run_qs or bool(isinstance(payload, dict) and payload.get("_klaxond_dry_run"))

        # Inhibition: source-agnostic from 0.9.6. Normalize payload to a
        # canonical {host,service,job,alertname,…} dict and run rules against
        # it. Source-alerts (the ones with `inhibition_source` label set in
        # Grafana) still come ONLY from Grafana — they're what ARMS new
        # suppressions. Non-Grafana sources never arm, but they are subject
        # to existing suppressions (e.g. Beszel CPU alert from host=svr-01 is
        # muted while node-down for that host is active).
        # dry_run=True → apply_inhibition skips _register_suppression so
        # synthetic tests don't pollute live state.
        norm_labels = _normalize_labels(source, payload)
        should_send, reason = apply_inhibition(source, norm_labels, dry_run=dry_run)
        if not should_send:
            title = norm_labels.get("alertname") or norm_labels.get("host") or "alert"
            log.info("[%s/%s%s] SUPPRESSED: %s (%s)", source, severity,
                     " DRY-RUN" if dry_run else "", title, reason)
            # Distinguish ack/scheduled-mute/inhibition in the channel field.
            if reason.startswith("ack-snoozed-"):
                suppressed_by = reason[len("ack-snoozed-"):]
                ch = "dry-run-ack-snoozed" if dry_run else "ack-snoozed"
            elif reason.startswith("scheduled-mute-"):
                suppressed_by = reason[len("scheduled-mute-"):]
                ch = "dry-run-scheduled-mute" if dry_run else "scheduled-mute"
            elif reason.startswith("inhibited-by-"):
                suppressed_by = reason[len("inhibited-by-"):]
                ch = "dry-run-suppressed" if dry_run else "suppressed"
            else:
                suppressed_by = reason
                ch = "dry-run-suppressed" if dry_run else "suppressed"
            _log_delivery(source, severity, title, channel=ch, suppressed_by=suppressed_by)
            if dry_run:
                return self._send_json({
                    "dry_run": True, "would_send": False,
                    "reason": reason, "suppressed_by": suppressed_by, "title": title,
                })
            self.send_response(200)
            self.end_headers()
            self.wfile.write(f"suppressed by {reason}".encode())
            return

        if source == "grafana":
            parts = parse_grafana_payload(payload, severity)
            with_cascade = CASCADE_ENABLED
        elif source == "beszel":
            parts = parse_beszel_payload(payload, severity)
            # Beszel has no native retries/multi-channel, so the cascade is
            # always on for /beszel/* regardless of CASCADE_ENABLED.
            with_cascade = True
        elif source == "healthchecks":
            parts = parse_healthchecks_payload(payload, severity)
            # HC sends 3 channels separately if we didn't centralize here.
            # Through klaxond it gets the same cascade as Beszel — always on
            # so the missing-ping signal reaches us via tier-2/3 if ntfy
            # fails. (HC itself has retry but not multi-channel-with-fallback.)
            with_cascade = True
        elif source == "pve":
            parts = parse_pve_payload(payload, severity)
            # Il notification-system di pve logga gli errori di consegna ma
            # non ha fallback multi-canale → cascade sempre on.
            with_cascade = True
        elif source == "wud":
            parts = parse_wud_payload(payload, severity)
            # WUD HTTP trigger has no retry/multi-channel native, cascade always on
            with_cascade = True
        elif source == "authentik":
            parts = parse_authentik_payload(payload, severity)
            # parse_authentik_payload may override severity from body.data.severity
            # → recompute it so cascade + dedup see the corrected value
            body_sev = ((payload.get("data") or {}).get("severity") or "").strip().lower()
            if body_sev and body_sev in _all_known_severities():
                severity = body_sev
            with_cascade = True
        elif source == "shelfmark":
            parts = parse_shelfmark_payload(payload, severity)
            # parse_shelfmark_payload may override severity from body.type
            # (Apprise "type": success|info|warning|failure)
            body_type = str(payload.get("type", "")).lower() if isinstance(payload, dict) else ""
            type_to_sev = {"info": "info", "success": "info",
                           "warning": "warning", "failure": "critical"}
            mapped = type_to_sev.get(body_type)
            if mapped and mapped in _all_known_severities():
                severity = mapped
            # Shelfmark sends webhook synchronously durante download/request
            # processing — no native retry, cascade always on per consegna.
            with_cascade = True
        elif source == "prowlarr":
            parts = parse_prowlarr_payload(payload, severity)
            # parse_prowlarr_payload may override severity based on eventType
            # (Health.type → warning/critical; Test/HealthRestored/AppUpdate → info)
            evt = (payload.get("eventType") or "").strip() if isinstance(payload, dict) else ""
            ht  = ((payload.get("health") or {}).get("type") or "").strip().lower() if isinstance(payload, dict) else ""
            if evt == "Health":
                if ht == "warning": severity = "warning"
                elif ht in ("error","critical"): severity = "critical"
            elif evt in ("HealthRestored","Test","ApplicationUpdate"):
                severity = "info"
            # Prowlarr webhook ha retry minimal nativo, cascade attiva per
            # garantire consegna anche se ntfy giù.
            with_cascade = True
        else:  # source == "decypharr"
            parts = parse_decypharr_payload(payload, severity)
            # parse_decypharr_payload may override severity from body.status
            # (success → info, failure → warning, error → critical)
            body_status = str(payload.get("status", "")).lower() if isinstance(payload, dict) else ""
            status_to_sev = {"success": "info", "failure": "warning", "error": "critical"}
            mapped = status_to_sev.get(body_status)
            if mapped and mapped in _all_known_severities():
                severity = mapped
            # Decypharr webhook is fire-and-forget, no native retry → cascade
            # always on per garantire consegna anche se ntfy giù.
            with_cascade = True

        log.info("[%s/%s%s] %s", source, severity, " DRY-RUN" if dry_run else "", parts["title"])
        commonLabels = payload.get("commonLabels", {}) if source == "grafana" else {}

        # Dry-run short-circuit: skip dedup buffer + deliver(). Log to ring
        # buffer with channel='dry-run' so the test is visible in Recent
        # deliveries (clearly tagged, won't be mistaken for a real delivery).
        if dry_run:
            _log_delivery(source, severity, parts["title"], channel="dry-run", suppressed_by="")
            return self._send_json({
                "dry_run": True, "would_send": True, "reason": reason,
                "source": source, "severity": severity,
                "with_cascade": with_cascade,
                "parsed": {
                    "title": parts["title"], "body": parts["body"],
                    "tags": parts["tags"], "actions": parts["actions"],
                    "priority": parts["priority"],
                },
            })

        # Dedup buffering: if enabled for this source + severity, queue and return
        # 202 Accepted (caller knows it's been accepted but not delivered immediately).
        if DEDUP_BUFFER.submit(source, severity, payload, parts, commonLabels, with_cascade):
            self.send_response(202)
            self.end_headers()
            self.wfile.write(f"buffered (dedup window)".encode())
            return

        ok, channel = deliver(severity, parts, with_cascade, labels=commonLabels, source=source)
        if ok:
            self.send_response(200)
            self.end_headers()
            self.wfile.write(f"delivered via {channel}".encode())
        else:
            self.send_response(502)
            self.end_headers()
            self.wfile.write(f"all channels failed ({channel})".encode())



    def _handle_api_test(self):
        severity = self.path.split("/")[-1].lower()
        if severity not in _all_known_severities():
            self.send_response(400); self.end_headers(); return
        length = int(self.headers.get("Content-Length", "0"))
        try:
            payload = json.loads(self.rfile.read(length)) if length else {}
        except Exception:
            payload = {}
        title = payload.get("title", f"klaxond test [{severity}]")
        body  = payload.get("body",  "Synthetic alert from /api/test endpoint")
        component = payload.get("component", "").strip()
        host      = payload.get("host", "").strip()

        if component or host:
            # Build a Grafana-shape payload to exercise the real render
            # pipeline (action button lookup, host suffix in title, tags
            # from labels).
            fake = {
                "status": "firing",
                "commonLabels": {
                    "alertname": title,
                    "severity": severity,
                    "component": component,
                    "host": host,
                },
                "commonAnnotations": {"summary": body},
                "alerts": [{
                    "labels": {"alertname": title, "host": host, "component": component},
                    "annotations": {"summary": body},
                    "generatorURL": "",
                }],
            }
            parts = parse_grafana_payload(fake, severity)
        else:
            parts = {"title": title, "body": body, "tags": [severity, "test"],
                     "actions": [], "priority": PRIORITIES.get(severity, "default")}

        global _cascade_runtime_enabled
        test_labels = {"component": component, "host": host} if (component or host) else {}
        ok, channel = deliver(severity, parts, _cascade_runtime_enabled, labels=test_labels)
        _log_delivery("api-test", severity, parts["title"], channel if ok else "all-failed")
        self._send_json({"ok": ok, "channel": channel, "title": parts["title"]})

    def _handle_cascade_toggle(self):
        global _cascade_runtime_enabled
        length = int(self.headers.get("Content-Length", "0"))
        try:
            payload = json.loads(self.rfile.read(length)) if length else {}
        except Exception:
            payload = {}
        if "enabled" in payload:
            _cascade_runtime_enabled = bool(payload["enabled"])
        else:
            _cascade_runtime_enabled = not _cascade_runtime_enabled
        log.info("cascade runtime toggled → %s", _cascade_runtime_enabled)
        self._send_json({"cascade_enabled_runtime": _cascade_runtime_enabled})

    def _handle_ntfy_topics_update(self):
        """POST /api/ntfy-topics — replace the entire topics list, persist to
        /data/ntfy-topics.json, reload runtime via _apply_channel_config().

        Body shape: {"topics": [{"name":"...", "token":"...", "handles":["info"]}, ...]}
        Token value "***SET***" means "keep existing" (don't overwrite redacted).
        Token "" (empty string) means "clear it" (env will repopulate at next reload
        if the legacy env vars are still set for that severity).
        """
        global NTFY_TOPICS
        length = int(self.headers.get("Content-Length", "0"))
        try:
            payload = json.loads(self.rfile.read(length)) if length else {}
        except Exception as e:
            self.send_response(400); self.end_headers()
            self.wfile.write(f"bad json: {e}".encode()); return
        incoming = payload.get("topics") if isinstance(payload, dict) else None
        if not isinstance(incoming, list):
            self.send_response(400); self.end_headers()
            self.wfile.write(b"missing 'topics' list"); return

        # Build existing tokens map for "keep" semantics
        existing_by_name = {t["name"]: (t.get("token") or "") for t in NTFY_TOPICS}

        cleaned = []
        seen_names = set()
        errors = []
        for idx, t in enumerate(incoming):
            if not isinstance(t, dict):
                errors.append(f"topic[{idx}]: not an object")
                continue
            name = str(t.get("name", "")).strip()
            if not name:
                errors.append(f"topic[{idx}]: empty name")
                continue
            if name in seen_names:
                errors.append(f"topic[{idx}]: duplicate name '{name}'")
                continue
            seen_names.add(name)
            handles = t.get("handles", [])
            if not isinstance(handles, list):
                errors.append(f"topic[{idx}] '{name}': handles must be a list")
                continue
            handles = [str(h).strip().lower() for h in handles if str(h).strip()]
            if not handles:
                errors.append(f"topic[{idx}] '{name}': handles is empty")
                continue
            tok_in = t.get("token", "")
            if tok_in == "***SET***":
                tok_final = existing_by_name.get(name, "")
            else:
                tok_final = str(tok_in or "")
            cleaned.append({"name": name, "token": tok_final, "handles": handles})

        if errors:
            self.send_response(400); self.end_headers()
            self.wfile.write(("validation errors:\n  - " + "\n  - ".join(errors)).encode())
            return
        if not cleaned:
            self.send_response(400); self.end_headers()
            self.wfile.write(b"need at least one valid topic"); return

        try:
            _save_ntfy_topics(cleaned)
            # Force reload from disk (clears env-override path since file exists)
            _apply_channel_config()
            log.info("ntfy-topics updated via UI: %d topic(s), severities=%s",
                     len(NTFY_TOPICS),
                     sorted(_all_known_severities() - {"resolved"}))
            # Return redacted view (same shape as GET)
            redacted = [{"name": t["name"],
                         "token": "***SET***" if (t.get("token") or "") else "",
                         "handles": list(t.get("handles") or [])}
                        for t in NTFY_TOPICS]
            self._send_json({"ok": True, "topics": redacted,
                             "known_severities": sorted(_all_known_severities()),
                             "persisted_at": NTFY_TOPICS_PATH})
        except Exception as e:
            log.error("ntfy-topics save failed: %s", e)
            self.send_response(500); self.end_headers()
            self.wfile.write(str(e).encode())

    def _handle_dedup_config_update(self):
        global DEDUP_SETTINGS
        length = int(self.headers.get("Content-Length", "0"))
        try:
            payload = json.loads(self.rfile.read(length)) if length else {}
        except Exception as e:
            self.send_response(400); self.end_headers()
            self.wfile.write(f"bad json: {e}".encode()); return
        new = payload.get("settings") if isinstance(payload, dict) else None
        if not isinstance(new, dict):
            self.send_response(400); self.end_headers()
            self.wfile.write(b"missing 'settings' object"); return
        cleaned = {}
        valid_strategies = {"none", "time", "key"}
        for src in DEDUP_SOURCES:
            base = dict(_DEFAULT_DEDUP_SETTINGS[src])
            incoming = new.get(src, {})
            if not isinstance(incoming, dict):
                cleaned[src] = base; continue
            base["enabled"] = bool(incoming.get("enabled", base["enabled"]))
            try:
                ws = int(incoming.get("window_s", base["window_s"]))
                base["window_s"] = max(5, min(ws, 3600))  # clamp 5s..1h
            except Exception:
                pass
            strat = str(incoming.get("strategy", base["strategy"]))
            if strat in valid_strategies:
                base["strategy"] = strat
            base["override_critical"] = bool(incoming.get("override_critical", base["override_critical"]))
            cleaned[src] = base
        try:
            _save_dedup_settings(cleaned)
            DEDUP_SETTINGS = cleaned
            log.info("dedup config updated: %s", {s: cleaned[s]["enabled"] for s in DEDUP_SOURCES})
            self._send_json({"ok": True, "settings": cleaned})
        except Exception as e:
            log.error("dedup config save failed: %s", e)
            self.send_response(500); self.end_headers()
            self.wfile.write(str(e).encode())

    def _handle_auth_config_update(self):
        global AUTH_CONFIG
        length = int(self.headers.get("Content-Length", "0"))
        try:
            payload = json.loads(self.rfile.read(length)) if length else {}
        except Exception as e:
            self.send_response(400); self.end_headers()
            self.wfile.write(f"bad json: {e}".encode()); return
        incoming = payload.get("settings") if isinstance(payload, dict) else None
        if not isinstance(incoming, dict):
            self.send_response(400); self.end_headers()
            self.wfile.write(b"missing 'settings' object"); return
        # Validate mode
        valid_modes = {"none", "basic", "oidc", "trusted-proxy"}
        mode = incoming.get("mode", AUTH_CONFIG.get("mode", "none"))
        if mode not in valid_modes:
            self.send_response(400); self.end_headers()
            self.wfile.write(f"invalid mode (must be one of {valid_modes})".encode()); return

        # Build new config — deep-merge so we don't drop fields the UI didn't send
        new_cfg = json.loads(json.dumps(AUTH_CONFIG))
        new_cfg["mode"] = mode
        if "session_timeout_hours" in incoming:
            try:
                new_cfg["session_timeout_hours"] = max(1, min(int(incoming["session_timeout_hours"]), 720))
            except Exception:
                pass

        # Basic auth: if a fresh password is provided in plaintext, bcrypt-hash it
        b_in = incoming.get("basic", {}) or {}
        if isinstance(b_in, dict):
            b = new_cfg.setdefault("basic", {})
            if "username" in b_in:
                b["username"] = str(b_in["username"])
            if "realm" in b_in:
                b["realm"] = str(b_in["realm"])
            if b_in.get("password"):  # plaintext (one-time, from UI)
                if not _BCRYPT_OK:
                    self.send_response(500); self.end_headers()
                    self.wfile.write(b"bcrypt not installed in image"); return
                b["password_hash"] = bcrypt.hashpw(str(b_in["password"]).encode(), bcrypt.gensalt()).decode()
            elif "password_hash" in b_in and b_in["password_hash"] not in ("***SET***", ""):
                b["password_hash"] = str(b_in["password_hash"])

        # OIDC: secrets handled carefully (don't accept "***SET***" placeholder)
        o_in = incoming.get("oidc", {}) or {}
        if isinstance(o_in, dict):
            o = new_cfg.setdefault("oidc", {})
            for k in ("provider", "issuer", "client_id", "scopes", "required_group", "redirect_path"):
                if k in o_in:
                    o[k] = str(o_in[k])
            cs = o_in.get("client_secret")
            if cs and cs != "***SET***":
                o["client_secret"] = str(cs)

        # Trusted proxy
        tp_in = incoming.get("trusted_proxy", {}) or {}
        if isinstance(tp_in, dict):
            tp = new_cfg.setdefault("trusted_proxy", {})
            for k in ("user_header", "email_header", "groups_header"):
                if k in tp_in:
                    tp[k] = str(tp_in[k])
            if isinstance(tp_in.get("trusted_cidrs"), list):
                cleaned_cidrs = []
                for c in tp_in["trusted_cidrs"]:
                    try:
                        ipaddress.ip_network(str(c), strict=False)
                        cleaned_cidrs.append(str(c))
                    except Exception:
                        continue
                tp["trusted_cidrs"] = cleaned_cidrs

        try:
            _save_auth_config(new_cfg)
            AUTH_CONFIG = new_cfg
            # Invalidate OIDC discovery cache so a new issuer is picked up
            _OIDC_CACHE._discovery.clear()
            _OIDC_CACHE._jwks_client.clear()
            log.info("auth config updated: mode=%s", new_cfg["mode"])
            # Return redacted
            redacted = json.loads(json.dumps(new_cfg))
            if redacted.get("basic", {}).get("password_hash"):
                redacted["basic"]["password_hash"] = "***SET***"
            if redacted.get("oidc", {}).get("client_secret"):
                redacted["oidc"]["client_secret"] = "***SET***"
            self._send_json({"ok": True, "settings": redacted})
        except Exception as e:
            log.error("auth config save failed: %s", e)
            self.send_response(500); self.end_headers()
            self.wfile.write(str(e).encode())

    def _handle_render_config_update(self):
        global COMPONENT_DASHBOARDS
        length = int(self.headers.get("Content-Length", "0"))
        try:
            payload = json.loads(self.rfile.read(length)) if length else {}
        except Exception as e:
            self.send_response(400); self.end_headers()
            self.wfile.write(f"bad json: {e}".encode()); return
        new = payload.get("component_dashboards", {})
        # Validate shape: {component_key: [label, url]}
        cleaned = {}
        for k, v in new.items():
            if not isinstance(k, str) or not k:
                continue
            if not isinstance(v, list) or len(v) != 2:
                continue
            label, url = str(v[0]), str(v[1])
            if label and url:
                cleaned[k] = (label, url)
        try:
            _save_render_config(cleaned)
            COMPONENT_DASHBOARDS = cleaned
            log.info("render config updated: %d mappings", len(cleaned))
            self._send_json({"ok": True, "count": len(cleaned)})
        except Exception as e:
            log.error("render config save failed: %s", e)
            self.send_response(500); self.end_headers()
            self.wfile.write(str(e).encode())

    def _handle_inhibition_rules_update(self):
        """Replace INHIBITION_RULES wholesale from a UI-submitted list.

        Body shape: {"rules": [<rule>, …]} where each rule is:
          {source: str, ttl_seconds: int, applies_to: [<source>, …],
           match_by?: str, match_label?: str, match_regex?: str,
           match_all?: bool}
        Exactly one of match_by / match_label+match_regex / match_all is
        required. Empty applies_to means "all sources".

        Side effect: any active suppressions are cleared, because their
        rule_idx references would be stale after the list is replaced.
        Suppressions will re-arm naturally the next time a source alert
        fires.
        """
        global INHIBITION_RULES, TOML_CONFIG
        length = int(self.headers.get("Content-Length", "0"))
        try:
            payload = json.loads(self.rfile.read(length)) if length else {}
        except Exception as e:
            self.send_response(400); self.end_headers()
            self.wfile.write(f"bad json: {e}".encode()); return
        new_rules = payload.get("rules", [])
        if not isinstance(new_rules, list):
            self.send_response(400); self.end_headers()
            self.wfile.write(b"rules must be a list"); return

        valid_sources = set(DEDUP_SOURCES)
        cleaned_internal = []   # in-memory shape (match_label_regex tuple)
        cleaned_toml = []       # TOML shape (match_label + match_regex flat)
        errors = []
        for i, r in enumerate(new_rules):
            if not isinstance(r, dict):
                errors.append(f"rule[{i}]: not an object")
                continue
            src = str(r.get("source") or "").strip()
            if not src:
                errors.append(f"rule[{i}]: source is required")
                continue
            try:
                ttl = int(r.get("ttl_seconds", 900))
            except Exception:
                ttl = 900
            ttl = max(30, min(86400, ttl))   # 30s..24h

            # Exactly one match type
            match_types = sum(bool(r.get(k)) for k in ("match_by", "match_all")) + \
                          (1 if (r.get("match_label") and r.get("match_regex")) else 0)
            if match_types == 0:
                errors.append(f"rule[{i}] ({src}): one of match_by / match_label+match_regex / match_all is required")
                continue
            if match_types > 1:
                errors.append(f"rule[{i}] ({src}): only one match type may be set")
                continue

            internal = {"source": src, "ttl_seconds": ttl}
            toml_row = {"source": src, "ttl_seconds": ttl}
            if r.get("match_by"):
                internal["match_by"] = str(r["match_by"]).strip()
                toml_row["match_by"] = internal["match_by"]
            elif r.get("match_label") and r.get("match_regex"):
                lbl = str(r["match_label"]).strip()
                rx = str(r["match_regex"]).strip()
                try:
                    re.compile(rx)
                except Exception as e:
                    errors.append(f"rule[{i}] ({src}): invalid regex: {e}")
                    continue
                internal["match_label_regex"] = (lbl, rx)
                toml_row["match_label"] = lbl
                toml_row["match_regex"] = rx
            else:   # match_all
                internal["match_all"] = True
                toml_row["match_all"] = True

            applies_to = r.get("applies_to") or []
            if applies_to:
                if not isinstance(applies_to, list):
                    errors.append(f"rule[{i}] ({src}): applies_to must be a list")
                    continue
                filtered = [s for s in applies_to if isinstance(s, str) and s in valid_sources]
                if filtered:
                    internal["applies_to"] = filtered
                    toml_row["applies_to"] = filtered
            cleaned_internal.append(internal)
            cleaned_toml.append(toml_row)

        if errors:
            self.send_response(400); self.end_headers()
            self.wfile.write(("\n".join(errors)).encode()); return

        # Update TOML on disk first; if that fails we don't touch in-memory.
        TOML_CONFIG["inhibitions"] = cleaned_toml
        try:
            _save_toml_config(TOML_CONFIG)
        except Exception as e:
            log.error("inhibition rules save failed: %s", e)
            self.send_response(500); self.end_headers()
            self.wfile.write(str(e).encode()); return

        # Swap in-memory rules + invalidate active suppressions (rule_idx-keyed).
        INHIBITION_RULES = cleaned_internal
        with _supp_lock:
            cleared = len(_suppressions)
            _suppressions[:] = []
        log.info("inhibition rules updated: %d rule(s), cleared %d active suppression(s)",
                 len(cleaned_internal), cleared)
        self._send_json({"ok": True, "count": len(cleaned_internal),
                         "cleared_suppressions": cleared})

    def _handle_inhibition_clear(self):
        """Force-clear active suppressions.

        Body shape:
          {} or {"all": true}          → clear ALL active suppressions
          {"source": "X", "anchor": "Y"} → clear specific (anchor may be "*"
                                            for match_all rules; "" matches
                                            stored anchor=None)

        Idempotent — clearing a non-existent suppression is not an error.
        Suppressions naturally re-arm on the next source alert.
        """
        length = int(self.headers.get("Content-Length", "0"))
        try:
            payload = json.loads(self.rfile.read(length)) if length else {}
        except Exception as e:
            self.send_response(400); self.end_headers()
            self.wfile.write(f"bad json: {e}".encode()); return
        clear_all = (not payload) or bool(payload.get("all"))
        target_source = str(payload.get("source") or "").strip()
        target_anchor = payload.get("anchor")
        if target_anchor == "*":
            target_anchor = None
        with _supp_lock:
            before = len(_suppressions)
            if clear_all:
                _suppressions[:] = []
            else:
                if not target_source:
                    self.send_response(400); self.end_headers()
                    self.wfile.write(b"source is required (or pass {'all': true})"); return
                kept = []
                for s in _suppressions:
                    rule = INHIBITION_RULES[s["rule_idx"]]
                    matches = (rule["source"] == target_source and
                               (target_anchor is None or s["anchor"] == target_anchor))
                    if not matches:
                        kept.append(s)
                _suppressions[:] = kept
            after = len(_suppressions)
        cleared = before - after
        log.info("inhibitions cleared via UI: %d suppression(s) (all=%s, source=%s, anchor=%s)",
                 cleared, clear_all, target_source or "*", target_anchor or "*")
        self._send_json({"ok": True, "cleared": cleared, "remaining": after})

    def _handle_inhibition_rules_test(self):
        """Dry-run an alert against the current rule set + active suppressions.

        Body: {"source": "<grafana|beszel|…>", "labels": {<labels>}}
        Returns: {
          would_send: bool,
          reason: str,                # "ok" | "source" | "inhibited-by-<rule>"
          matched_rule: str | null,   # rule.source name if a match was found
          would_arm_suppression: bool,# true if this would register a new suppression
          considered_rules: [<rule.source>, …],   # rules that COULD apply to this source
        }

        Does NOT modify state — pure read-only simulation. Useful for
        iterating on regex/match_by while you have a real label set to test.
        """
        length = int(self.headers.get("Content-Length", "0"))
        try:
            payload = json.loads(self.rfile.read(length)) if length else {}
        except Exception as e:
            self.send_response(400); self.end_headers()
            self.wfile.write(f"bad json: {e}".encode()); return
        source = str(payload.get("source") or "").strip().lower()
        labels = payload.get("labels") or {}
        if not source:
            self.send_response(400); self.end_headers()
            self.wfile.write(b"source is required"); return
        if not isinstance(labels, dict):
            self.send_response(400); self.end_headers()
            self.wfile.write(b"labels must be an object"); return

        # Match against active state — same code path as apply_inhibition
        # except we DO NOT register new suppressions or call _log_delivery.
        considered = []
        for r in INHIBITION_RULES:
            applies_to = r.get("applies_to")
            if not applies_to or source in applies_to:
                considered.append(r["source"])

        would_arm = False
        if source == "grafana":
            arm_idx = _alert_is_source(labels)
            if arm_idx is not None:
                would_arm = True

        # Read-only suppression check (don't mutate _suppressions)
        suppressed_by = _is_suppressed(labels, source)
        if would_arm:
            reason, would_send = "source", True
            matched = INHIBITION_RULES[arm_idx]["source"]
        elif suppressed_by:
            reason, would_send = f"inhibited-by-{suppressed_by}", False
            matched = suppressed_by
        else:
            reason, would_send = "ok", True
            matched = None

        self._send_json({
            "would_send": would_send,
            "reason": reason,
            "matched_rule": matched,
            "would_arm_suppression": would_arm,
            "considered_rules": considered,
        })

    def _handle_ingest_auth_update(self):
        """Set/clear per-source ingest secret.

        Body: {"source": "<grafana|beszel|…>", "action": "set|generate|clear", "secret": "<optional>"}
          - set     → requires `secret` in body (the literal string)
          - generate → server picks a random 32-byte hex; returns it ONCE
          - clear   → removes secret (returns to legacy permissive mode for that source)

        Persisted to klaxond.toml [ingest.secrets]. Env-set secrets are
        unaffected (env wins; the UI shows the source as 'env').
        """
        global TOML_CONFIG
        length = int(self.headers.get("Content-Length", "0"))
        try:
            body = json.loads(self.rfile.read(length)) if length else {}
        except Exception as e:
            self.send_response(400); self.end_headers()
            self.wfile.write(f"bad json: {e}".encode()); return
        src = str(body.get("source", "")).strip().lower()
        action = str(body.get("action", "")).strip().lower()
        if src not in DEDUP_SOURCES:
            self.send_response(400); self.end_headers()
            self.wfile.write(f"source must be one of {list(DEDUP_SOURCES)}".encode()); return
        if action not in ("set", "generate", "clear"):
            self.send_response(400); self.end_headers()
            self.wfile.write(b"action must be one of: set, generate, clear"); return

        TOML_CONFIG.setdefault("ingest", {}).setdefault("secrets", {})
        new_secret = None
        if action == "clear":
            TOML_CONFIG["ingest"]["secrets"].pop(src, None)
        elif action == "generate":
            import secrets as _sec
            new_secret = _sec.token_hex(32)
            TOML_CONFIG["ingest"]["secrets"][src] = new_secret
        else:  # set
            sec = str(body.get("secret", "")).strip()
            if not sec or len(sec) < 16:
                self.send_response(400); self.end_headers()
                self.wfile.write(b"secret missing or shorter than 16 chars"); return
            TOML_CONFIG["ingest"]["secrets"][src] = sec
            new_secret = sec
        try:
            _save_toml_config(TOML_CONFIG)
        except Exception as e:
            log.error("ingest-auth save failed: %s", e)
            self.send_response(500); self.end_headers()
            self.wfile.write(str(e).encode()); return
        log.info("ingest-auth %s for source=%s (env override: %s)",
                 action, src, "yes" if os.environ.get(f"KLAXOND_INGEST_SECRET_{src.upper()}") else "no")
        # Only return the secret value on `set`/`generate`. Never echo on clear.
        resp = {"ok": True, "source": src, "action": action}
        if new_secret and action == "generate":
            resp["secret"] = new_secret  # shown to user ONCE; UI must capture
        self._send_json(resp)

    def _handle_ack_clear(self):
        """Force-clear ack-snoozes. Body: {} → clear all; {"alertname": X} → clear one."""
        length = int(self.headers.get("Content-Length", "0"))
        try:
            body = json.loads(self.rfile.read(length)) if length else {}
        except Exception as e:
            self.send_response(400); self.end_headers()
            self.wfile.write(f"bad json: {e}".encode()); return
        target = str(body.get("alertname") or "").strip()
        with _ack_lock:
            before = len(_ack_suppressions)
            if not target:
                _ack_suppressions.clear()
            else:
                _ack_suppressions.pop(target, None)
            after = len(_ack_suppressions)
        cleared = before - after
        log.info("ack-suppressions cleared via UI: %d (target=%s)", cleared, target or "*")
        self._send_json({"ok": True, "cleared": cleared, "remaining": after})

    def _handle_schedules_update(self):
        """Replace SCHEDULES wholesale. Body: {"schedules": [<sched>, …]}
        Each sched: {name, cron, duration_minutes, match: {label:val}, applies_to: [src]}
        Cron validated by attempting _cron_matches against now (parse only,
        not match result).
        """
        global TOML_CONFIG, SCHEDULES
        length = int(self.headers.get("Content-Length", "0"))
        try:
            body = json.loads(self.rfile.read(length)) if length else {}
        except Exception as e:
            self.send_response(400); self.end_headers()
            self.wfile.write(f"bad json: {e}".encode()); return
        in_list = body.get("schedules", [])
        if not isinstance(in_list, list):
            self.send_response(400); self.end_headers()
            self.wfile.write(b"schedules must be a list"); return
        errors = []
        cleaned_internal = []
        cleaned_toml = []
        valid_sources = set(DEDUP_SOURCES)
        import datetime as _dt
        now = _dt.datetime.now()
        for i, s in enumerate(in_list):
            if not isinstance(s, dict):
                errors.append(f"schedule[{i}]: not an object"); continue
            name = str(s.get("name", "")).strip()
            if not name:
                errors.append(f"schedule[{i}]: name required"); continue
            cron = str(s.get("cron", "")).strip()
            if len(cron.split()) != 5:
                errors.append(f"schedule[{i}] ({name}): cron must have 5 fields"); continue
            try:
                _cron_matches(cron, now)  # parse-validate (result irrelevant)
            except Exception as e:
                errors.append(f"schedule[{i}] ({name}): cron invalid: {e}"); continue
            try:
                duration = int(s.get("duration_minutes", 30))
            except Exception:
                duration = 30
            if duration < 1 or duration > 24*60:
                errors.append(f"schedule[{i}] ({name}): duration_minutes must be 1..1440"); continue
            applies = s.get("applies_to") or []
            applies = [x for x in applies if isinstance(x, str) and x in valid_sources]
            match = s.get("match") or {}
            if not isinstance(match, dict):
                errors.append(f"schedule[{i}] ({name}): match must be a dict"); continue
            match_clean = {str(k): str(v) for k, v in match.items() if v}
            entry = {"name": name, "cron": cron, "duration_minutes": duration,
                     "match": match_clean, "applies_to": applies}
            cleaned_internal.append(entry)
            cleaned_toml.append(entry)
        if errors:
            self.send_response(400); self.end_headers()
            self.wfile.write(("\n".join(errors)).encode()); return
        TOML_CONFIG["schedules"] = cleaned_toml
        try:
            _save_toml_config(TOML_CONFIG)
        except Exception as e:
            log.error("schedules save failed: %s", e)
            self.send_response(500); self.end_headers()
            self.wfile.write(str(e).encode()); return
        with _sched_lock:
            SCHEDULES = cleaned_internal
            # Drop _active_mutes for schedules that no longer exist
            names = {s["name"] for s in cleaned_internal}
            for n in list(_active_mutes.keys()):
                if n not in names:
                    del _active_mutes[n]
        log.info("schedules updated: %d schedule(s)", len(cleaned_internal))
        self._send_json({"ok": True, "count": len(cleaned_internal)})

    def _handle_config_restore(self):
        """Accept a full klaxond.toml body and atomically replace the current one.
        Validation: parseable as TOML + must contain at least a [cascade] or
        [delivery] section (sanity check — empty configs aren't useful).
        Auto-backup of the current file happens BEFORE write via the regular
        _save_toml_config path? No — restore writes raw bytes, so we backup
        explicitly here.
        Side effect: rebuilds in-memory TOML_CONFIG and re-applies overrides.
        """
        global TOML_CONFIG
        length = int(self.headers.get("Content-Length", "0"))
        if length <= 0 or length > 1_000_000:  # 1 MB cap
            self.send_response(400); self.end_headers()
            self.wfile.write(b"empty or oversized body"); return
        raw = self.rfile.read(length)
        # Parse to validate
        if tomllib is None:
            self.send_response(500); self.end_headers()
            self.wfile.write(b"tomllib unavailable in runtime"); return
        try:
            parsed = tomllib.loads(raw.decode("utf-8"))
        except Exception as e:
            self.send_response(400); self.end_headers()
            self.wfile.write(f"invalid TOML: {e}".encode()); return
        # Sanity check: at minimum cascade or delivery or render section
        if not any(k in parsed for k in ("cascade", "delivery", "render", "ntfy", "auth")):
            self.send_response(400); self.end_headers()
            self.wfile.write(b"no recognised top-level sections; refusing as likely empty"); return
        # Backup current + atomic replace
        try:
            backup = _config_auto_backup()
        except Exception as e:
            log.warning("pre-restore backup failed (continuing anyway): %s", e)
            backup = None
        tmp = KLAXOND_CONFIG + ".restore.tmp"
        try:
            with open(tmp, "wb") as f: f.write(raw)
            os.replace(tmp, KLAXOND_CONFIG)
        except Exception as e:
            if os.path.exists(tmp):
                try: os.unlink(tmp)
                except Exception: pass
            self.send_response(500); self.end_headers()
            self.wfile.write(f"write failed: {e}".encode()); return
        # Reload in-memory state
        try:
            TOML_CONFIG = _load_toml_config()
            _apply_toml_overrides()
            _apply_channel_config()
        except Exception as e:
            log.error("post-restore reload failed: %s — config on disk is the new one but in-memory is stale; restart the container", e)
        log.info("config restored from upload (%d bytes), pre-restore backup at %s", length, backup or "<none>")
        self._send_json({"ok": True, "bytes_written": length, "pre_restore_backup": backup})

    def _handle_cascade_config_update(self):
        global TOML_CONFIG
        length = int(self.headers.get("Content-Length", "0"))
        try:
            payload = json.loads(self.rfile.read(length)) if length else {}
        except Exception as e:
            self.send_response(400); self.end_headers()
            self.wfile.write(f"bad json: {e}".encode()); return
        new_tiers = payload.get("tiers", [])
        if not isinstance(new_tiers, list) or not new_tiers:
            self.send_response(400); self.end_headers()
            self.wfile.write(b"tiers must be a non-empty list"); return
        cleaned = []
        for t in new_tiers:
            name = t.get("name", "").lower()
            if name not in _TIER_FUNCS:
                continue
            try:
                to = int(t.get("timeout_seconds", 5))
            except Exception:
                to = 5
            cleaned.append({"name": name, "timeout_seconds": max(1, min(60, to))})
        if not cleaned:
            self.send_response(400); self.end_headers()
            self.wfile.write(b"no valid tiers"); return
        # Update TOML_CONFIG in memory + persist to file
        TOML_CONFIG.setdefault("cascade", {})["tiers"] = cleaned
        if "default_enabled_for_webhook" in payload:
            TOML_CONFIG["cascade"]["default_enabled_for_webhook"] = bool(payload["default_enabled_for_webhook"])
        try:
            _save_toml_config(TOML_CONFIG)
            log.info("cascade tiers updated: %s", [t["name"] for t in cleaned])
            self._send_json({"ok": True, "tiers": cleaned})
        except Exception as e:
            log.error("cascade save failed: %s", e)
            self.send_response(500); self.end_headers()
            self.wfile.write(str(e).encode())

    def _handle_render_preview(self):
        length = int(self.headers.get("Content-Length", "0"))
        try:
            payload = json.loads(self.rfile.read(length)) if length else {}
        except Exception:
            self.send_response(400); self.end_headers(); return
        severity = payload.get("severity", "warning")
        sample = payload.get("payload", {})
        if "alerts" in sample or "commonLabels" in sample:
            parts = parse_grafana_payload(sample, severity)
        elif "check" in sample and "status" in sample:
            parts = parse_healthchecks_payload(sample, severity)
        elif "title" in sample and "body" in sample and "alert" not in sample:
            parts = parse_wud_payload(sample, severity)
        else:
            parts = parse_beszel_payload(sample, severity)
        # Build the ntfy headers that WOULD be sent (without actually sending).
        # On fan-out (multiple topics for same severity) we show the FIRST topic
        # in the preview — the full list is shown in the dedicated ntfy-topics tab.
        title_b64 = base64.b64encode(parts["title"].encode("utf-8")).decode("ascii")
        _preview_topics = _topics_for_severity(severity)
        _preview_url = f"{NTFY_URL}/{_preview_topics[0]['name']}" if _preview_topics else f"{NTFY_URL}/(no topic handles '{severity}')"
        ntfy_preview = {
            "url": _preview_url,
            "headers": {
                "Title (raw)":  parts["title"],
                "Title (RFC2047)": f"=?UTF-8?B?{title_b64}?=",
                "Tags": ",".join(parts["tags"]),
                "Priority": parts["priority"],
                "Actions": "; ".join(f"{kind}, {label}, {target}" for kind, label, target in (parts.get("actions") or [])),
            },
            "body": parts["body"],
        }
        self._send_json(ntfy_preview)




    def _handle_delivery_config_update(self):
        global TOML_CONFIG
        length = int(self.headers.get("Content-Length", "0"))
        try:
            payload = json.loads(self.rfile.read(length)) if length else {}
        except Exception as e:
            self.send_response(400); self.end_headers()
            self.wfile.write(f"bad json: {e}".encode()); return
        # Sanitize
        delivery = TOML_CONFIG.setdefault("delivery", {})
        if "default_policy" in payload:
            delivery["default_policy"] = str(payload["default_policy"])
        if "policies" in payload and isinstance(payload["policies"], list):
            clean_policies = []
            for p in payload["policies"]:
                name = str(p.get("name", "")).strip()
                mode = p.get("mode", "cascade")
                if mode not in ("cascade", "broadcast"):
                    mode = "cascade"
                tiers = []
                for t in p.get("tiers", []) or []:
                    if t.get("name") in _TIER_FUNCS:
                        try:
                            to = int(t.get("timeout_seconds", 5))
                        except Exception:
                            to = 5
                        tiers.append({"name": t["name"], "timeout_seconds": max(1, min(60, to))})
                if name and tiers:
                    clean_policies.append({"name": name, "mode": mode, "tiers": tiers})
            delivery["policies"] = clean_policies
        if "rules" in payload and isinstance(payload["rules"], list):
            clean_rules = []
            for r in payload["rules"]:
                m = r.get("match", {}) or {}
                # Only string values, drop empty
                m = {str(k): str(v) for k, v in m.items() if isinstance(v, (str, int)) and str(v)}
                pol = str(r.get("policy", "")).strip()
                if pol:
                    clean_rules.append({"match": m, "policy": pol})
            delivery["rules"] = clean_rules
        try:
            _save_toml_config(TOML_CONFIG)
            log.info("delivery-config updated via UI: %d policies, %d rules",
                     len(delivery.get("policies", [])), len(delivery.get("rules", [])))
            self._send_json({"ok": True})
        except Exception as e:
            log.error("delivery-config save failed: %s", e)
            self.send_response(500); self.end_headers()
            self.wfile.write(str(e).encode())

    def _handle_channel_config_update(self):
        """Update non-secret channel fields in klaxond.toml. Tokens/passwords
        are env-only and NOT touched here."""
        global TOML_CONFIG
        length = int(self.headers.get("Content-Length", "0"))
        try:
            payload = json.loads(self.rfile.read(length)) if length else {}
        except Exception as e:
            self.send_response(400); self.end_headers()
            self.wfile.write(f"bad json: {e}".encode()); return
        # Update TOML structure
        if "ntfy" in payload:
            n = payload["ntfy"]
            TOML_CONFIG.setdefault("ntfy", {})
            if "url" in n:
                TOML_CONFIG["ntfy"]["url"] = str(n["url"]).rstrip("/")
            if "topics" in n:
                TOML_CONFIG["ntfy"].setdefault("topics", {})
                for k in ("info", "warning", "critical"):
                    if k in n["topics"]:
                        TOML_CONFIG["ntfy"]["topics"][k] = str(n["topics"][k])
        if "telegram" in payload:
            t = payload["telegram"]
            TOML_CONFIG.setdefault("telegram", {})
            if "chat_id" in t:
                TOML_CONFIG["telegram"]["chat_id"] = str(t["chat_id"])
        if "smtp" in payload:
            sm = payload["smtp"]
            TOML_CONFIG.setdefault("smtp", {})
            for k in ("host", "from_addr", "to_addr"):
                if k in sm:
                    TOML_CONFIG["smtp"][k] = str(sm[k])
            if "port" in sm:
                try:
                    TOML_CONFIG["smtp"]["port"] = int(sm["port"])
                except Exception:
                    pass
        try:
            _save_toml_config(TOML_CONFIG)
            _apply_channel_config()  # re-apply so runtime reflects new values immediately
            log.info("channel-config updated via UI")
            self._send_json({"ok": True})
        except Exception as e:
            log.error("channel-config save failed: %s", e)
            self.send_response(500); self.end_headers()
            self.wfile.write(str(e).encode())

# DedupBuffer is instantiated once `deliver()` is defined. We do it at module
# import time after both `deliver` and the DEDUP_SETTINGS dict are ready
# (the class is declared above; the instance must come AFTER deliver).
DEDUP_BUFFER = DedupBuffer(deliver_fn=lambda *a, **kw: deliver(*a, **kw))


def _shutdown_handler(signum, frame):
    log.info("received signal %d → flushing dedup buffer before exit", signum)
    try:
        DEDUP_BUFFER.flush_all_blocking()
    except Exception as e:
        log.warning("dedup flush on shutdown failed: %s", e)
    # Re-raise SIGTERM behavior (exit)
    raise SystemExit(0)


signal.signal(signal.SIGTERM, _shutdown_handler)
signal.signal(signal.SIGINT, _shutdown_handler)


# Spawn the maintenance-window scheduler (0.9.19+). One thread, ticks every
# ~60s aligned to clock minute. Cron evaluation is cheap so this is fine.
# Lives near the end of the module so _scheduler_thread is already defined.
threading.Thread(target=_scheduler_thread, name="klaxond-scheduler", daemon=True).start()


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8181"))
    log.info("klaxond listening on :%d  (cascade_enabled=%s, dedup_sources_enabled=%s)",
             port, CASCADE_ENABLED,
             [s for s, c in DEDUP_SETTINGS.items() if c.get("enabled")])
    HTTPServer(("0.0.0.0", port), Handler).serve_forever()
