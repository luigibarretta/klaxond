"""
klaxond — converts Grafana webhook JSON or Beszel webhook JSON into
ntfy pushes with proper headers/actions, with optional cascade fallback
(ntfy → Telegram → mail via Gmail SMTP) when the primary channel fails.

Env:
  NTFY_URL          base URL  (default empty — set via env or klaxon.toml)
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
    # in klaxon.toml. Paths starting with / are appended to GRAFANA_BASE.
    "host":     ["Logs",         "/d/your-logs-dashboard"],
    "traefik":  ["Traefik",      "/d/your-traefik-dashboard"],
}


def _load_render_config(toml_seed: dict = None) -> dict:
    """Read render-config.json from disk; bootstrap with TOML seed if available,
    or in-code defaults otherwise, on first boot.

    `toml_seed` is the [render.component_dashboards] section of klaxon.toml.
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

DEDUP_SOURCES = ("grafana", "beszel", "healthchecks", "wud")

_DEFAULT_DEDUP_SETTINGS = {
    "grafana":      {"enabled": False, "window_s": 90, "strategy": "key", "override_critical": False},
    "beszel":       {"enabled": False, "window_s": 90, "strategy": "key", "override_critical": False},
    "healthchecks": {"enabled": False, "window_s": 90, "strategy": "key", "override_critical": False},
    "wud":          {"enabled": True,  "window_s": 90, "strategy": "key", "override_critical": False},
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
    except Exception:
        pass
    return f"{source}:{title_fallback}"


def _render_batch(source: str, severity: str, items: list) -> dict:
    """Render a single aggregated notification from N buffered items."""
    state_emoji = ICONS.get(severity, ICONS["info"])
    src_label = source.upper() if source == "wud" else source.capitalize()
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
AUTH_SESSION_COOKIE = "klaxon_session"

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
        "/webhook/", "/beszel/", "/healthchecks/", "/wud/",
        "/healthz",
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
            handler.send_response(400); handler.end_headers()
            handler.wfile.write(b"invalid or expired state"); return
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
# Loaded from KLAXON_CONFIG (default /data/klaxon.toml). If missing on first
# boot, bootstrapped from the bundled klaxond.default.toml shipped in the
# image. After bootstrap, the file is read-write and can be edited via UI.
# ============================================================================
KLAXON_CONFIG = os.environ.get("KLAXON_CONFIG", "/data/klaxon.toml")
KLAXON_DEFAULT = "/app/klaxond.default.toml"


def _bootstrap_config_if_missing():
    if os.path.exists(KLAXON_CONFIG):
        return
    try:
        os.makedirs(os.path.dirname(KLAXON_CONFIG), exist_ok=True)
    except Exception:
        pass
    if os.path.exists(KLAXON_DEFAULT):
        import shutil
        shutil.copy(KLAXON_DEFAULT, KLAXON_CONFIG)
        log.info("klaxon.toml bootstrapped from %s", KLAXON_DEFAULT)
    else:
        log.warning("klaxon.toml missing and no default at %s — running with hard-coded defaults", KLAXON_DEFAULT)


def _load_toml_config() -> dict:
    if tomllib is None:
        log.warning("tomllib not available (Python <3.11) — using hard-coded defaults")
        return {}
    _bootstrap_config_if_missing()
    try:
        with open(KLAXON_CONFIG, "rb") as f:
            cfg = tomllib.load(f)
        log.info("loaded klaxon.toml from %s", KLAXON_CONFIG)
        return cfg
    except FileNotFoundError:
        return {}
    except Exception as e:
        log.error("klaxon.toml parse failed: %s — using hard-coded defaults", e)
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
        lines.append(f'ttl_seconds = {int(inh.get("ttl_seconds", 900))}')
        lines.append("")
    tmp = KLAXON_CONFIG + ".tmp"
    with open(tmp, "w") as f:
        f.write("\n".join(lines))
    os.replace(tmp, KLAXON_CONFIG)


# Loaded at startup; refreshed on /api/config POST.
TOML_CONFIG = _load_toml_config()

# Now that TOML is loaded, bootstrap render-config from [render.component_dashboards]
# of klaxon.toml on first boot (when /data/render-config.json doesn't exist).
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
# Apply TOML config overrides (if klaxon.toml provided non-empty sections)
# ============================================================================
def _apply_toml_overrides():
    global PRIORITIES, ICONS, TAG_PREFIXES, COMPONENT_DASHBOARDS, INHIBITION_RULES, GRAFANA_BASE, FALLBACK_RUNBOOKS
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
            rebuilt.append(entry)
        INHIBITION_RULES = rebuilt


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
INHIBITION_RULES = [
    # node-down (host offline) → suppress everything with same `host` label
    {"source": "node-down",
     "match_by": "host",                # suppress alerts whose label[host] == source's host
     "ttl_seconds": 900},
    # traefik-down → suppress all blackbox HTTP/HTTPS e2e probes (everything
    # behind Traefik will fail until it's back)
    {"source": "traefik-down",
     "match_label_regex": ("job", r"^blackbox-(https|http).*"),
     "ttl_seconds": 900},
    # authentik-down → suppress alerts on services gated by forwardAuth.
    # We don't have an explicit "auth-gated" label, so use a conservative
    # match: blackbox-https-public probes (which all chain through Authentik
    # at the public e2e layer).
    {"source": "authentik-down",
     "match_label_regex": ("job", r"^blackbox-https.*"),
     "ttl_seconds": 900},
    # cluster-wide-restart → suppress EVERYTHING except itself for 30min.
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
        else:
            log.info("inhibition cleared: rule=%s anchor=%s",
                     rule["source"], anchor or "*")


def _is_suppressed(labels: dict) -> str | None:
    """If `labels` describe an alert that should be suppressed, return the
    name of the source rule. Else None."""
    _cleanup_expired()
    with _supp_lock:
        active = list(_suppressions)
    # Don't suppress the source alert itself even if cluster-wide-restart is on
    own_source = labels.get("inhibition_source", "")
    for supp in active:
        rule = INHIBITION_RULES[supp["rule_idx"]]
        if rule["source"] == own_source:
            return None
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


def apply_inhibition(payload: dict, severity: str) -> tuple[bool, str]:
    """Examine a Grafana webhook payload. For each alert in payload['alerts'],
    update suppression state if it's a source alert, or check if it should be
    suppressed. Returns (should_send, reason).
    
    Decision is based on commonLabels for grouped payloads. Resolved source
    alerts clear their suppression."""
    common = payload.get("commonLabels", {}) or {}
    status = payload.get("status", "firing")

    # Update suppression state from source alerts
    source_idx = _alert_is_source(common)
    if source_idx is not None:
        _register_suppression(source_idx, common, resolved=(status == "resolved"))
        # Source alerts always go through (we want to be notified that
        # node-down is firing/resolved)
        return True, "source"

    # Check if this alert is suppressed
    suppressed_by = _is_suppressed(common)
    if suppressed_by:
        return False, f"inhibited-by-{suppressed_by}"

    return True, "ok"


def inhibition_status() -> list:
    """Return a snapshot of current suppressions, for /healthz?inhibition=1."""
    _cleanup_expired()
    now = time_mod.time()
    with _supp_lock:
        return [{
            "source": INHIBITION_RULES[s["rule_idx"]]["source"],
            "anchor": s["anchor"] or "*",
            "expires_in_seconds": int(s["expiry"] - now),
        } for s in _suppressions]




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

    state_emoji = ICONS["resolved"] if status == "resolved" else ICONS.get(severity, ICONS["info"])
    title = f"{state_emoji} {alertname}"
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

    # When resolved, drop the severity literal from tag list — ntfy auto-renders
    # 'warning'/'critical'/'info' as Unicode emoji, which would conflict with
    # the ✅ resolved emoji in the title and confuse the user.
    if status == "resolved":
        tags = [TAG_PREFIXES.get("resolved", "white_check_mark"), component or "homelab"]
    else:
        tags = [TAG_PREFIXES.get(severity, "bell"), severity, component or "homelab"]

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

    return {"title": title, "body": body, "tags": tags, "actions": actions, "priority": priority}


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

    return {"title": title, "body": body, "tags": tags, "actions": actions, "priority": priority}


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
    state_word = "UP" if is_resolved else "DOWN"
    title = f"{state_emoji} HC {state_word}: {check}"

    body_parts = [f"Status: {state_word}"]
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

    return {"title": title, "body": body, "tags": tags, "actions": actions, "priority": priority}



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

    tags = [TAG_PREFIXES.get(severity, "package"), "wud", "container-update"]

    actions = []
    rb = payload_extras.get("runbook_url") or FALLBACK_RUNBOOKS.get("wud") or ""
    if rb:
        actions.append(("view", "📖 Runbook", rb))
    wud_url = payload_extras.get("wud_url") or "http://192.168.50.110:3033/"
    actions.append(("view", "📦 Open WUD", wud_url))

    priority = PRIORITIES.get(severity, "default")

    return {"title": title, "body": body, "tags": tags, "actions": actions, "priority": priority}



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
    actions_header = None
    if parts.get("actions"):
        actions_header = "; ".join(
            f"{kind}, {_strip_non_ascii(label)}, {target}" for kind, label, target in parts["actions"][:3]
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
        elif self.path in ("/", "/ui", "/ui/"):
            self.send_response(302); self.send_header("Location", "/ui/index.html"); self.end_headers()
        elif self.path.startswith("/ui/"):
            self._serve_static(self.path[len("/ui/"):])
        elif self.path == "/inhibitions" or self.path == "/api/inhibitions":
            self._send_json(inhibition_status())
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

        # ---- alert ingestion ----
        if self.path.startswith("/webhook/"):
            source = "grafana"
        elif self.path.startswith("/beszel/"):
            source = "beszel"
        elif self.path.startswith("/healthchecks/"):
            source = "healthchecks"
        elif self.path.startswith("/wud/"):
            source = "wud"
        else:
            self.send_response(404); self.end_headers(); return

        severity = self.path.split("/")[-1].lower()
        if severity not in _all_known_severities():
            self.send_response(400); self.end_headers()
            self.wfile.write(f"unknown severity {severity} (no topic handles it)".encode()); return

        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length)
        try:
            payload = json.loads(raw) if raw else {}
        except Exception as e:
            log.error("invalid JSON: %s", e)
            self.send_response(400); self.end_headers(); return

        # Inhibition: only applied to Grafana alerts. Beszel events are
        # host metrics, independent of cluster state, so they always notify.
        if source == "grafana":
            should_send, reason = apply_inhibition(payload, severity)
            if not should_send:
                title = payload.get("commonLabels", {}).get("alertname", "alert")
                log.info("[grafana/%s] SUPPRESSED: %s (%s)", severity, title, reason)
                self.send_response(200)
                self.end_headers()
                self.wfile.write(f"suppressed by {reason}".encode())
                return
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
        else:  # source == "wud"
            parts = parse_wud_payload(payload, severity)
            # WUD HTTP trigger has no retry/multi-channel native, cascade always on
            with_cascade = True

        log.info("[%s/%s] %s", source, severity, parts["title"])
        commonLabels = payload.get("commonLabels", {}) if source == "grafana" else {}

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
        """Update non-secret channel fields in klaxon.toml. Tokens/passwords
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


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8181"))
    log.info("klaxond listening on :%d  (cascade_enabled=%s, dedup_sources_enabled=%s)",
             port, CASCADE_ENABLED,
             [s for s, c in DEDUP_SETTINGS.items() if c.get("enabled")])
    HTTPServer(("0.0.0.0", port), Handler).serve_forever()
