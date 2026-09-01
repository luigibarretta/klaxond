import {
  $, $$, J, SEARCH_DEBOUNCE_MS, apiFetch, applyTablePager, debounce, dirtyTabs, errorText,
  escapeHtml, fetchError, fetchOk, getAuthPasswordPolicy, getCurrentUser, isAbortError, isPublicInfoPage,
  markTabDirty, notifyError, notifyResponseError, notifySuccess, notifyValidationError, onReady,
  queryGet, refreshTablePagers, setAuthPasswordPolicy, setCurrentUser, setInlineStatus, setLocalTotpEnabled,
  showTableRowPage, syncTabFromPath, tr, updateAllTabAccessibleLabels, updatePublicLoginLinksText,
  updateTabAccessibleLabel,
} from "./app.js";
import { loadConfigBackups } from "./app-config-backups.js";
export { loadConfigBackups } from "./app-config-backups.js";

// ---- Status ----
export async function loadStatus(opts = {}) {
  try {
    const s = await queryGet("status", "/api/status", { force: opts.force });
    const setCh = (id, configured, up, detail) => {
      const card = $("#" + id);
      const dot = card.querySelector(".dot");
      const state = !configured ? "unknown" : up ? "up" : "down";
      dot.className = `dot ${state}`;
      dot.title = !configured
        ? tr("channel.state_not_configured")
        : up ? tr("channel.reachable") : tr("channel.unreachable");
      // Add a textual status next to the dot (accessibility — color alone
      // isn't enough for colorblind users + screen readers).
      let statusText = card.querySelector(".ch-status-text");
      if (!statusText) {
        statusText = document.createElement("small");
        statusText.className = "ch-status-text";
        statusText.style.marginLeft = "6px";
        dot.insertAdjacentElement("afterend", statusText);
      }
      statusText.textContent = !configured
        ? tr("channel.state_not_configured")
        : up ? tr("channel.up") : tr("channel.down");
      statusText.style.color = !configured ? "var(--muted)" : up ? "var(--green)" : "var(--red)";
      card.querySelector(".ch-url").textContent = detail || "";
    };
    const configured = s.channel_configured || {
      ntfy: Boolean(s.ntfy_url),
      telegram: Boolean(s.telegram_configured),
      smtp: Boolean(s.smtp_host),
    };
    const channelDetail = (value, isConfigured) => [
      value,
      isConfigured ? "" : tr("channel.not_configured"),
    ].filter(Boolean).join(" · ");
    setCh("ch-ntfy", configured.ntfy, s.channels.ntfy, channelDetail(s.ntfy_url, configured.ntfy));
    setCh("ch-telegram", configured.telegram, s.channels.telegram, channelDetail(configured.telegram ? tr("channel.bot_configured") : "", configured.telegram));
    setCh("ch-smtp", configured.smtp, s.channels.smtp, channelDetail(s.smtp_host, configured.smtp));
    updateAppVersion(s.version);
    $("#cas-default").textContent = s.cascade_enabled_default;
    $("#cas-runtime").textContent = s.cascade_enabled_runtime;
    updateStatusLogWidget(s.logs || {});
  } catch (e) { fetchError("status", e); }
  loadStatusActivity();
}

function updateStatusLogWidget(logs) {
  const retained = Number.isFinite(logs.retained) ? logs.retained : 0;
  const capacity = Number.isFinite(logs.capacity) ? logs.capacity : 0;
  const warn = Number.isFinite(logs.warn) ? logs.warn : 0;
  const error = Number.isFinite(logs.error) ? logs.error : 0;
  const retainedEl = $("#stat-log-retained");
  if (retainedEl) retainedEl.textContent = capacity ? `${retained}/${capacity}` : String(retained);
  const severityEl = $("#stat-log-severity");
  if (severityEl) {
    const newest = logs.newest_timestamp ? new Date(logs.newest_timestamp).toLocaleString() : tr("status.no_activity");
    severityEl.innerHTML = `${escapeHtml(tr("status.warn_error", { warn, error }))}<br>${escapeHtml(tr("status.latest_log", { time: newest }))}`;
  }
  const noisy = warn + error;
  setTabBadge("logs", noisy, error > 0 ? "crit" : noisy > 0 ? "warn" : "");
}

import { updateAppVersion } from "./app-status-version.js";

// Update the small count chip next to a tab label.
// kind: '' (neutral) | 'warn' (yellow) | 'crit' (red). count=0 hides the badge.
export function setTabBadge(tabId, count, kind = "") {
  const tab = document.querySelector(`.tab[data-tab="${tabId}"]`);
  if (!tab) return;
  let badge = tab.querySelector(".tab-badge");
  if (!count || count <= 0) {
    if (badge) badge.remove();
    updateTabAccessibleLabel(tab);
    return;
  }
  if (!badge) {
    badge = document.createElement("span");
    badge.className = "tab-badge";
    tab.appendChild(badge);
  }
  badge.className = "tab-badge" + (kind ? " " + kind : "");
  badge.textContent = count > 99 ? "99+" : String(count);
  updateTabAccessibleLabel(tab);
}

function displayUserName(user = {}) {
  return user.name || user.email || user.sub || "anonymous";
}

function isReadOnlyViewer(user = {}) {
  const groups = Array.isArray(user.groups) ? user.groups : [];
  if (groups.some(g => ["viewer", "klaxond-viewer", "klaxond:viewer", "viewer:*"].includes(g))) return true;
  if ((user.mode === "pat" || user.mode === "api-key") && groups.length) {
    return groups.every(scope => String(scope).endsWith(":read") || scope === "viewer:*" || scope === "admin:read");
  }
  return false;
}

export function applyReadOnlyViewerMode(user = {}) {
  const readOnly = isReadOnlyViewer(user);
  document.body.classList.toggle("viewer-readonly", readOnly);
  document.body.setAttribute("data-viewer-readonly-label", tr("auth.viewer_readonly"));
  document.querySelector("main")?.setAttribute("data-viewer-readonly-label", tr("auth.viewer_readonly"));
  const writeSelectors = [
    "#btn-cascade-toggle", "#cfg-import-apply", "#inhib-add", "#inhib-save", "#inhib-clear-all",
    "#sched-add", "#sched-save", "#btn-rc-add", "#btn-rc-save", "#ntfy-topic-add",
    "#ntfy-topics-save", "#btn-routing-save", "#btn-cas-add", "#btn-cas-save",
    "#btn-pol-add", "#btn-rule-add", "#btn-delivery-save", "[data-dedup-save]", "[data-auth-save]",
    "#token-create", "#passkey-register", "#totp-start", "#totp-enable", "#totp-disable", "#btn-preview", "#inhib-test-run", "#btn-test-fire",
    "button.danger", "[data-clear-suppression]", "[data-clear-ack]", "[data-del]", "[data-revoke]", "[data-passkey-del]", "button[data-act]", "button[data-emergency-action]"
  ];
  document.querySelectorAll(writeSelectors.join(",")).forEach(el => {
    const dirtyTab = el.dataset.enableWhenDirty;
    el.disabled = readOnly || Boolean(dirtyTab && !dirtyTabs.has(dirtyTab));
    if (readOnly) el.title = tr("auth.viewer_readonly");
  });
}
window.applyReadOnlyViewerMode = applyReadOnlyViewerMode;

export function updateCurrentUserUI(user = {}) {
  const current = setCurrentUser(user || { sub: "anonymous", mode: "none", groups: [] });
  const name = displayUserName(user);
  const mode = user.mode || "none";
  const readOnly = isReadOnlyViewer(user);
  const initials = name
    .split(/[\s@._-]+/)
    .filter(Boolean)
    .slice(0, 2)
    .map(part => part[0])
    .join("")
    .toUpperCase() || "?";
  const nameEl = $("#sidebar-user-name");
  const modeEl = $("#sidebar-user-mode");
  const avatar = $("#sidebar-avatar");
  if (nameEl) nameEl.textContent = name;
  if (modeEl) modeEl.textContent = readOnly ? `mode=${mode} · viewer` : `mode=${mode}`;
  if (avatar) avatar.textContent = initials;
  const authUser = $("#auth-current-user");
  if (authUser) authUser.textContent = `${user.sub || "?"} (mode=${mode})`;
  applyReadOnlyViewerMode(user);
}

export async function loadCurrentUser() {
  try {
    updateCurrentUserUI(await J("/api/auth/me"));
  } catch (e) {
    updateCurrentUserUI({ sub: "anonymous", mode: "none" });
  }
}

(function setupSidebar() {
  const media = window.matchMedia?.("(max-width: 760px)");
  const savedDesktopState = () => {
    try {
      const saved = localStorage.getItem("klaxond.sidebarCollapsed");
      if (saved === "1" || saved === "0") return saved === "1";
    } catch (e) {}
    return false;
  };
  const setCollapsed = (collapsed, persist = false) => {
    document.body.classList.toggle("sidebar-collapsed", collapsed);
    const toggle = $("#sidebar-toggle");
    toggle?.setAttribute("aria-expanded", String(!collapsed));
    if (persist && !media?.matches) {
      try { localStorage.setItem("klaxond.sidebarCollapsed", collapsed ? "1" : "0"); } catch (e) {}
    }
  };
  setCollapsed(media?.matches ? true : savedDesktopState());
  onReady(() => {
    const toggle = $("#sidebar-toggle");
    toggle?.setAttribute("aria-controls", "sidebar");
    toggle?.addEventListener("click", () => {
      const next = !document.body.classList.contains("sidebar-collapsed");
      setCollapsed(next, true);
    });
    document.querySelectorAll(".tab").forEach(tab => {
      tab.addEventListener("click", () => {
        if (media?.matches) setCollapsed(true);
      });
    });
    document.addEventListener("keydown", event => {
      if (event.key !== "Escape" || !media?.matches || document.body.classList.contains("sidebar-collapsed")) return;
      setCollapsed(true);
      toggle?.focus();
    });
    const handleViewportChange = event => setCollapsed(event.matches ? true : savedDesktopState());
    if (media?.addEventListener) media.addEventListener("change", handleViewportChange);
    else media?.addListener?.(handleViewportChange);
  });
})();

function normalizeDeliveries(payload) {
  if (Array.isArray(payload)) return payload;
  if (Array.isArray(payload?.entries)) return payload.entries;
  return [];
}

export async function fetchDeliveries(limit = 0, opts = {}) {
  const suffix = limit ? `?limit=${encodeURIComponent(limit)}` : "";
  return normalizeDeliveries(await queryGet(opts.scope || `deliveries:${limit || "all"}`, `/api/deliveries${suffix}`, {
    cancelPrevious: false,
    force: opts.force,
  }));
}

export function deliveryTsSeconds(item) {
  const raw = Number(item?.ts ?? item?.timestamp ?? 0);
  return raw > 1000000000000 ? raw / 1000 : raw;
}

// Aggregate 24h activity from persisted delivery history.
// Also updates the tab badges (deliveries24h / suppressions / dedup-pending).
export async function loadStatusActivity() {
  // Deliveries: fetch persisted history + count last 24h
  try {
    const items = await fetchDeliveries(10000);
    const cutoff = Date.now() / 1000 - 24 * 3600;
    const recent = (items || []).filter(it => deliveryTsSeconds(it) >= cutoff);
    const bySource = {};
    for (const it of recent) {
      const k = it.source || "?";
      bySource[k] = (bySource[k] || 0) + 1;
    }
    $("#stat-deliv-total").textContent = recent.length;
    const parts = Object.entries(bySource).sort((a,b) => b[1]-a[1])
                  .map(([k,v]) => `${k}: ${v}`);
    $("#stat-deliv-breakdown").innerHTML = parts.length
      ? tr("status.by_source") + " " + parts.map(p => `<code>${escapeHtml(p)}</code>`).join(" · ")
      : `${tr("status.by_source")} <span class='muted'>${escapeHtml(tr("status.no_activity"))}</span>`;
    setTabBadge("deliveries", recent.length);
  } catch (e) {
    $("#stat-deliv-total").textContent = "?";
    $("#stat-deliv-breakdown").textContent = tr("status.deliveries_unreachable");
    fetchError("status-activity-deliveries", e);
  }
  // Active suppressions count
  try {
    const inhib = await queryGet("status-inhibitions", "/api/inhibitions", { cancelPrevious: false });
    const n = (inhib || []).length;
    $("#stat-suppr-count").textContent = n;
    setTabBadge("inhibitions", n, n > 0 ? "warn" : "");
  } catch (e) { $("#stat-suppr-count").textContent = "?"; fetchError("status-activity-inhibitions", e); }
  // Dedup pending count (sum across all sources)
  try {
    const d = await queryGet("status-dedup", "/api/dedup-config", { cancelPrevious: false });
    const pc = d.pending_counts || {};
    const total = Object.values(pc).reduce((a, b) => a + (b || 0), 0);
    $("#stat-dedup-count").textContent = total;
    setTabBadge("grouping", total, total > 0 ? "warn" : "");
  } catch (e) { $("#stat-dedup-count").textContent = "?"; fetchError("status-activity-dedup", e); }
  // Refresh config backup list (also belongs to the Status pane)
  loadConfigBackups();
}

$("#btn-cascade-toggle").addEventListener("click", async () => {
  try {
    await J("/api/cascade/toggle", { method: "POST", body: "{}" });
    notifySuccess(tr("cascade.runtime_toggled"), { durationMs: 3000 });
    loadStatus({ force: true });
  } catch (e) {
    notifyError("cascade-toggle", e);
  }
});
