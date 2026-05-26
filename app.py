"""
webhook bridge — converts Grafana webhook JSON or Beszel webhook JSON into
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
import threading
import time as time_mod
from email.mime.text import MIMEText
from http.server import HTTPServer, BaseHTTPRequestHandler

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("bridge")

# These get populated by _apply_channel_config() after TOML is loaded.
# Order of precedence: env var > TOML > hardcoded fallback (defined below).
NTFY_URL = ""
TOPICS   = {"info": "", "warning": "", "critical": ""}
TOKENS   = {"info": "", "warning": "", "critical": ""}
PRIORITIES = {"info": "default", "warning": "high", "critical": "urgent"}

ICONS = {"info": "ℹ️", "warning": "⚠️", "critical": "🚨"}

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


def _load_render_config() -> dict:
    """Read render-config.json from disk; bootstrap with defaults if missing."""
    try:
        with open(RENDER_CONFIG_PATH, "r") as f:
            data = json.load(f)
        # Coerce list values back into tuples for downstream code
        return {k: tuple(v) for k, v in data.get("component_dashboards", {}).items()}
    except FileNotFoundError:
        _save_render_config(_DEFAULT_COMPONENT_DASHBOARDS)
        return {k: tuple(v) for k, v in _DEFAULT_COMPONENT_DASHBOARDS.items()}
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


COMPONENT_DASHBOARDS = _load_render_config()

# ============================================================================
# Bootstrap config (TOML) — cascading rules + render rules + inhibition rules.
# Loaded from KLAXON_CONFIG (default /data/klaxon.toml). If missing on first
# boot, bootstrapped from the bundled klaxon.default.toml shipped in the
# image. After bootstrap, the file is read-write and can be edited via UI.
# ============================================================================
KLAXON_CONFIG = os.environ.get("KLAXON_CONFIG", "/data/klaxon.toml")
KLAXON_DEFAULT = "/app/klaxon.default.toml"


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

# ============================================================================
# Apply TOML config overrides (if klaxon.toml provided non-empty sections)
# ============================================================================
def _apply_toml_overrides():
    global PRIORITIES, ICONS, COMPONENT_DASHBOARDS, INHIBITION_RULES, GRAFANA_BASE
    render = TOML_CONFIG.get("render", {})
    if render.get("severity_priority"):
        PRIORITIES = dict(render["severity_priority"])
    if render.get("severity_emoji"):
        ICONS = dict(render["severity_emoji"])
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
    """Populate NTFY_URL/TOPICS/TG_*/SMTP_* from TOML first, then let env
    overrides take precedence. Called once at startup; can be re-called
    after the user edits values via the UI."""
    global NTFY_URL, TOPICS, TOKENS, TG_CHAT, SMTP_HOST, SMTP_PORT, SMTP_FROM, SMTP_TO
    ntfy_cfg = TOML_CONFIG.get("ntfy", {}) or {}
    NTFY_URL = (os.environ.get("NTFY_URL") or ntfy_cfg.get("url") or "").rstrip("/")
    toml_topics = ntfy_cfg.get("topics", {}) or {}
    TOPICS = {
        "info":     os.environ.get("TOPIC_INFO")  or toml_topics.get("info", ""),
        "warning":  os.environ.get("TOPIC_WARN")  or toml_topics.get("warning", ""),
        "critical": os.environ.get("TOPIC_CRIT")  or toml_topics.get("critical", ""),
    }
    # Tokens are SECRET → env-only.
    TOKENS = {
        "info":     os.environ.get("NTFY_TOKEN_INFO", ""),
        "warning":  os.environ.get("NTFY_TOKEN_WARN", ""),
        "critical": os.environ.get("NTFY_TOKEN_CRIT", ""),
    }
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

    state_emoji = "✅" if status == "resolved" else ICONS.get(severity, "ℹ️")
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

    tags = [severity, component or "homelab"]
    if status == "resolved":
        tags = ["white_check_mark"] + tags
    else:
        tags = [{"critical": "rotating_light", "warning": "warning", "info": "information_source"}.get(severity, "bell")] + tags

    actions = []
    if component in COMPONENT_DASHBOARDS:
        label, slug = COMPONENT_DASHBOARDS[component]
        actions.append(("view", f"Open {label}", f"{GRAFANA_BASE}{slug}"))
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
    state_emoji = "✅" if is_resolved else ICONS.get(severity, "ℹ️")
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

    tags = [severity, "beszel"]
    if is_resolved:
        tags = ["white_check_mark"] + tags
    else:
        tags = [{"critical": "rotating_light", "warning": "warning", "info": "information_source"}.get(severity, "bell")] + tags

    actions = [("view", "Beszel UI", url)]

    priority = PRIORITIES.get(severity, "default")
    if is_resolved:
        priority = "low"

    return {"title": title, "body": body, "tags": tags, "actions": actions, "priority": priority}


def post_to_ntfy(severity: str, parts: dict, timeout: int = 5) -> bool:
    topic = TOPICS[severity]
    token = TOKENS[severity]
    if not token:
        return False
    url = f"{NTFY_URL}/{topic}"
    title_b64 = base64.b64encode(parts["title"].encode("utf-8")).decode("ascii")
    encoded_title = f"=?UTF-8?B?{title_b64}?="
    headers = {
        "Authorization": f"Bearer {token}",
        "Title": encoded_title,
        "Tags": ",".join(parts["tags"]),
        "Priority": parts["priority"],
    }
    if parts.get("actions"):
        headers["Actions"] = "; ".join(
            f"{kind}, {label}, {target}" for kind, label, target in parts["actions"][:3]
        )
    req = urllib.request.Request(url, data=parts["body"].encode("utf-8"),
                                 headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return 200 <= resp.status < 300
    except Exception as e:
        log.warning("ntfy POST failed: %s", e)
        return False


def post_to_telegram(severity: str, parts: dict, timeout: int = 8) -> bool:
    if not TG_TOKEN or not TG_CHAT:
        return False
    emoji = ICONS.get(severity, "")
    msg = f"{emoji} *{parts['title']}*\nseverity: `{severity}`\n\n{parts['body']}"
    if parts.get("actions"):
        # include first action URL as a tail link
        kind, label, target = parts["actions"][0]
        msg += f"\n\n[{label}]({target})"
    data = urllib.parse.urlencode({
        "chat_id": TG_CHAT,
        "parse_mode": "Markdown",
        "text": msg,
        "disable_web_page_preview": "true",
    }).encode("utf-8")
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


def deliver(severity: str, parts: dict, with_cascade: bool) -> tuple[bool, str]:
    """Walk the configured cascade tier list. The first tier is always tried;
    the rest are only tried when with_cascade is True (always True for
    /beszel/*). Returns (ok, channel_used)."""
    tiers = TOML_CONFIG.get("cascade", {}).get("tiers") or _DEFAULT_TIERS
    if not tiers:
        log.error("no cascade tiers configured")
        return False, "no-tiers"
    # First tier always
    first = tiers[0]
    fn = _TIER_FUNCS.get(first["name"])
    if fn and fn(severity, parts, timeout=int(first.get("timeout_seconds", 5))):
        return True, first["name"]
    if not with_cascade:
        return False, f"{first['name']}-failed"
    for tier in tiers[1:]:
        fn = _TIER_FUNCS.get(tier["name"])
        if not fn:
            log.warning("unknown cascade tier %s — skipping", tier["name"])
            continue
        if fn(severity, parts, timeout=int(tier.get("timeout_seconds", 10))):
            log.info("cascade delivered via %s: %s", tier["name"], parts["title"])
            return True, tier["name"]
    log.error("ALL channels failed: %s", parts["title"])
    return False, "all-failed"


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        log.info("%s - %s", self.address_string(), fmt % args)

    def do_GET(self):
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
        elif self.path == "/api/channel-config":
            self._send_json({
                "ntfy": {
                    "url": NTFY_URL,
                    "topics": dict(TOPICS),
                    "url_from_env": bool(os.environ.get("NTFY_URL")),
                    "topics_from_env": {
                        "info":     bool(os.environ.get("TOPIC_INFO")),
                        "warning":  bool(os.environ.get("TOPIC_WARN")),
                        "critical": bool(os.environ.get("TOPIC_CRIT")),
                    },
                    "tokens_configured": {sev: bool(tok) for sev, tok in TOKENS.items()},
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
        self.send_header("Cache-Control", "no-store")
        self.end_headers(); self.wfile.write(data)

    def do_POST(self):
        # ---- admin/UI endpoints ----
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
        if self.path == "/api/render-preview":
            return self._handle_render_preview()

        # ---- alert ingestion ----
        if self.path.startswith("/webhook/"):
            source = "grafana"
        elif self.path.startswith("/beszel/"):
            source = "beszel"
        else:
            self.send_response(404); self.end_headers(); return

        severity = self.path.split("/")[-1].lower()
        if severity not in TOPICS:
            self.send_response(400); self.end_headers()
            self.wfile.write(f"unknown severity {severity}".encode()); return

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
        else:
            parts = parse_beszel_payload(payload, severity)
            # Beszel has no native retries/multi-channel, so the cascade is
            # always on for /beszel/* regardless of CASCADE_ENABLED.
            with_cascade = True

        log.info("[%s/%s] %s", source, severity, parts["title"])
        ok, channel = deliver(severity, parts, with_cascade)
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
        if severity not in TOPICS:
            self.send_response(400); self.end_headers(); return
        length = int(self.headers.get("Content-Length", "0"))
        try:
            payload = json.loads(self.rfile.read(length)) if length else {}
        except Exception:
            payload = {}
        title = payload.get("title", f"Klaxon test [{severity}]")
        body  = payload.get("body",  "Synthetic alert from /api/test endpoint")
        parts = {"title": title, "body": body, "tags": [severity, "test"],
                 "actions": [], "priority": PRIORITIES.get(severity, "default")}
        global _cascade_runtime_enabled
        ok, channel = deliver(severity, parts, _cascade_runtime_enabled)
        _log_delivery("api-test", severity, title, channel if ok else "all-failed")
        self._send_json({"ok": ok, "channel": channel, "title": title})

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
        else:
            parts = parse_beszel_payload(sample, severity)
        # Build the ntfy headers that WOULD be sent (without actually sending)
        title_b64 = base64.b64encode(parts["title"].encode("utf-8")).decode("ascii")
        ntfy_preview = {
            "url": f"{NTFY_URL}/{TOPICS[severity]}",
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

if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8181"))
    log.info("bridge listening on :%d  (cascade_enabled=%s)", port, CASCADE_ENABLED)
    HTTPServer(("0.0.0.0", port), Handler).serve_forever()
