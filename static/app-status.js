import {
  $, $$, APP_META, J, SEARCH_DEBOUNCE_MS, apiFetch, applyTablePager, debounce, errorText,
  escapeHtml, fetchError, fetchOk, getAuthPasswordPolicy, getCurrentUser, isAbortError, isPublicInfoPage,
  markTabDirty, notifyError, notifyResponseError, notifySuccess, notifyValidationError, onReady,
  queryGet, refreshTablePagers, setAuthPasswordPolicy, setCurrentUser, setInlineStatus, setLocalTotpEnabled,
  showTableRowPage, syncTabFromPath, tr, updateAllTabAccessibleLabels, updatePublicLoginLinksText,
  updateTabAccessibleLabel,
} from "./app.js";

// ---- Status ----
export async function loadStatus(opts = {}) {
  try {
    const s = await queryGet("status", "/api/status", { force: opts.force });
    const setCh = (id, up, url) => {
      const card = $("#" + id);
      const dot = card.querySelector(".dot");
      dot.className = "dot " + (up ? "up" : "down");
      dot.title = up ? tr("channel.reachable") : tr("channel.unreachable");
      // Add a textual status next to the dot (accessibility — color alone
      // isn't enough for colorblind users + screen readers).
      let statusText = card.querySelector(".ch-status-text");
      if (!statusText) {
        statusText = document.createElement("small");
        statusText.className = "ch-status-text";
        statusText.style.marginLeft = "6px";
        dot.insertAdjacentElement("afterend", statusText);
      }
      statusText.textContent = up ? tr("channel.up") : tr("channel.down");
      statusText.style.color = up ? "var(--green)" : "var(--red)";
      card.querySelector(".ch-url").textContent = url || "";
    };
    setCh("ch-ntfy", s.channels.ntfy, s.ntfy_url);
    setCh("ch-telegram", s.channels.telegram, s.telegram_configured ? tr("channel.bot_configured") : tr("channel.not_configured"));
    setCh("ch-smtp", s.channels.smtp, s.smtp_host ? `${s.smtp_host}` : tr("channel.not_configured"));
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

const VERSION_EASTER_EGG_CLICKS = 7;
let _appVersion = "";
let _versionEggClicks = 0;
let _versionEggTimer = null;
let _versionEggLastFocus = null;

const VERSION_EASTER_EGGS = {
  "0": {
    title: "bootstrap signal",
    lines: [
      "cascade path: armed",
      "inhibition matrix: warm",
      "dedup buffer: quiet",
      "renderer: standing by"
    ]
  }
};

function majorVersion(version) {
  const match = String(version || "").match(/^v?(\d+)/);
  return match ? match[1] : "0";
}

function fallbackEasterEggForMajor(major) {
  const variants = [
    ["signal window", ["routes aligned", "alerts normalized", "channels watching", "operator calm"]],
    ["relay chamber", ["webhooks primed", "policies loaded", "tokens scoped", "handoff clean"]],
    ["control plane", ["guards awake", "logs retained", "config sealed", "status green"]]
  ];
  const seed = Array.from(String(major)).reduce((acc, ch) => acc + ch.charCodeAt(0), 0);
  const chosen = variants[seed % variants.length];
  return { title: chosen[0], lines: chosen[1] };
}

function easterEggForMajor(major) {
  return VERSION_EASTER_EGGS[major] || fallbackEasterEggForMajor(major);
}

function updateAppVersion(version) {
  if (!version) return;
  _appVersion = String(version).replace(/^v/, "");
  const footerVersion = $("#footer-version");
  if (!footerVersion) return;
  footerVersion.textContent = `v${_appVersion}`;
  footerVersion.dataset.version = _appVersion;
  footerVersion.dataset.major = majorVersion(_appVersion);
  footerVersion.setAttribute("role", "button");
  footerVersion.setAttribute("tabindex", "0");
  footerVersion.setAttribute("aria-label", `klaxond v${_appVersion}`);
}

updateAppVersion(APP_META.version);

function showVersionEasterEgg() {
  const major = majorVersion(_appVersion || $("#footer-version")?.textContent || "0");
  const egg = easterEggForMajor(major);
  const panel = $("#version-easter-egg");
  if (!panel) return;
  _versionEggLastFocus = document.activeElement instanceof HTMLElement ? document.activeElement : null;
  $("#version-egg-major").textContent = `major v${major}`;
  $("#version-egg-title").textContent = egg.title;
  $("#version-egg-body").textContent = egg.lines.join("\n");
  panel.dataset.major = major;
  panel.classList.remove("hidden");
  requestAnimationFrame(() => $("#version-egg-close")?.focus());
}

function closeVersionEasterEgg() {
  const panel = $("#version-easter-egg");
  if (!panel || panel.classList.contains("hidden")) return;
  panel.classList.add("hidden");
  if (_versionEggLastFocus && document.contains(_versionEggLastFocus)) {
    _versionEggLastFocus.focus();
  }
}

function countVersionClick() {
  clearTimeout(_versionEggTimer);
  _versionEggClicks += 1;
  if (_versionEggClicks >= VERSION_EASTER_EGG_CLICKS) {
    _versionEggClicks = 0;
    showVersionEasterEgg();
    return;
  }
  _versionEggTimer = setTimeout(() => { _versionEggClicks = 0; }, 2500);
}

function setupVersionEasterEgg() {
  const footerVersion = $("#footer-version");
  if (!footerVersion) return;
  updateAppVersion(footerVersion.textContent || "0");
  footerVersion.addEventListener("click", countVersionClick);
  footerVersion.addEventListener("keydown", e => {
    if (e.key !== "Enter" && e.key !== " ") return;
    e.preventDefault();
    countVersionClick();
  });
  $("#version-egg-close")?.addEventListener("click", closeVersionEasterEgg);
  document.addEventListener("keydown", e => {
    if (e.key === "Escape") closeVersionEasterEgg();
  });
}

onReady(setupVersionEasterEgg);

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
    "#btn-pol-add", "#btn-rule-add", "#btn-delivery-save", "#dedup-save", "#auth-save",
    "#token-create", "#passkey-register", "#totp-start", "#totp-enable", "#totp-disable", "#btn-preview", "#inhib-test-run", "#btn-test-fire",
    "button.danger", "[data-clear-suppression]", "[data-clear-ack]", "[data-del]", "[data-revoke]", "[data-passkey-del]", "button[data-act]"
  ];
  document.querySelectorAll(writeSelectors.join(",")).forEach(el => {
    el.disabled = readOnly;
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
  const collapsed = (() => {
    try {
      const saved = localStorage.getItem("klaxond.sidebarCollapsed");
      if (saved === "1" || saved === "0") return saved === "1";
    } catch (e) {}
    return window.matchMedia?.("(max-width: 760px)")?.matches || false;
  })();
  document.body.classList.toggle("sidebar-collapsed", collapsed);
  onReady(() => {
    $("#sidebar-toggle")?.addEventListener("click", () => {
      const next = !document.body.classList.contains("sidebar-collapsed");
      document.body.classList.toggle("sidebar-collapsed", next);
      try { localStorage.setItem("klaxond.sidebarCollapsed", next ? "1" : "0"); } catch (e) {}
    });
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

function deliveryTsSeconds(item) {
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


// ---- Config backup / restore ----
export async function loadConfigBackups() {
  const ul = $("#cfg-backup-list"); if (!ul) return;
  try {
    const r = await queryGet("config-backups", "/api/config/backups");
    if (r.dir) $("#cfg-backup-dir").textContent = r.dir;
    if (r.keep_max) $("#cfg-backup-keep").textContent = r.keep_max;
    const items = r.backups || [];
    if (!items.length) { ul.innerHTML = `<li>${escapeHtml(tr("status.no_backups"))}</li>`; return; }
    ul.innerHTML = items.slice(0, 10).map(b => {
      const kb = Math.round(b.size / 1024);
      return `<li><code>${escapeHtml(b.name)}</code> · ${kb} KB · ${escapeHtml(b.mtime_iso)}</li>`;
    }).join("");
  } catch (e) {
    ul.innerHTML = `<li class='muted'>${escapeHtml(tr("status.backups_unavailable", { message: errorText(e) }))}</li>`;
    fetchError("config-backups", e);
  }
}

let _pendingConfigImport = null;

function clearConfigImportPreview(opts = {}) {
  _pendingConfigImport = null;
  const box = $("#cfg-import-preview");
  if (box) {
    box.classList.add("hidden");
    box.innerHTML = "";
  }
  $("#cfg-import-apply") && ($("#cfg-import-apply").hidden = true);
  $("#cfg-import-clear") && ($("#cfg-import-clear").hidden = true);
  if (!opts.keepStatus) setInlineStatus("#cfg-restore-status", "");
}

function renderConfigImportPreview(file, preview) {
  const box = $("#cfg-import-preview");
  if (!box) return;
  const warnings = (preview.warnings || []).map(w => `<li>${escapeHtml(w)}</li>`).join("");
  box.classList.remove("hidden");
  box.innerHTML = `
    <strong>${escapeHtml(tr("config.import_preview_title", { name: file.name }))}</strong>
    <div class="import-preview-grid">
      <span>${escapeHtml(tr("config.import_kind"))}</span><code>${escapeHtml(preview.source_kind || "")}</code>
      <span>${escapeHtml(tr("config.import_changed"))}</span><code>${escapeHtml((preview.changed_files || []).join(", ") || tr("status.none"))}</code>
      <span>${escapeHtml(tr("config.import_unchanged"))}</span><code>${escapeHtml((preview.unchanged_files || []).join(", ") || tr("status.none"))}</code>
      <span>${escapeHtml(tr("config.import_restore"))}</span><code>${escapeHtml((preview.would_restore || []).join(", ") || tr("status.none"))}</code>
    </div>
    ${warnings ? `<ul class="muted">${warnings}</ul>` : ""}`;
  $("#cfg-import-apply") && ($("#cfg-import-apply").hidden = false);
  $("#cfg-import-clear") && ($("#cfg-import-clear").hidden = false);
}

async function previewConfigImportFile(file) {
  const status = $("#cfg-restore-status");
  clearConfigImportPreview();
  setInlineStatus(status, tr("config.previewing"));
  const raw = await file.text();
  const isJson = raw.trimStart().startsWith("{");
  const res = await apiFetch("/api/config/import-preview", {
    method: "POST",
    headers: {"Content-Type": isJson ? "application/json" : "application/toml"},
    body: raw,
  });
  if (!res.ok) {
    const txt = await res.text();
    notifyResponseError("config-import-preview", res, txt.slice(0, 300), status);
    return;
  }
  const preview = await res.json();
  _pendingConfigImport = { file, raw, contentType: isJson ? "application/json" : "application/toml", preview };
  renderConfigImportPreview(file, preview);
  setInlineStatus(status, tr("config.preview_ready"));
}

async function applyConfigImport() {
  const pending = _pendingConfigImport;
  const status = $("#cfg-restore-status");
  if (!pending) return;
  if (!confirm(tr("config.restore_confirm", { name: pending.file.name, size: pending.file.size }))) return;
  setInlineStatus(status, tr("status.uploading"));
  try {
    const res = await apiFetch("/api/config/restore", {
      method: "POST",
      headers: {"Content-Type": pending.contentType},
      body: pending.raw,
    });
    if (!res.ok) {
      const txt = await res.text();
      notifyResponseError("config-restore", res, txt.slice(0, 300), status);
      return;
    }
    const j = await res.json();
    notifySuccess(tr("config.restored_toast"), {
      status,
      inlineText: tr("status.restored", { bytes: j.bytes_written, backup: j.pre_restore_backup || tr("status.none") }),
      durationMs: 6000,
    });
    clearConfigImportPreview({ keepStatus: true });
    loadConfigBackups();
  } catch (err) {
    notifyError("config-restore", err, { status, inlineText: "❌ " + errorText(err) });
  }
}

// Download is a plain anchor href — the browser handles content-disposition.
onReady(() => {
  const dl = document.getElementById("cfg-backup-download");
  if (dl) dl.href = "/api/config/backup";
  const full = document.getElementById("cfg-full-export-download");
  if (full) full.href = "/api/config/export";
  $("#cfg-import-apply")?.addEventListener("click", applyConfigImport);
  $("#cfg-import-clear")?.addEventListener("click", clearConfigImportPreview);

  const fileInput = document.getElementById("cfg-restore-file");
  if (fileInput) fileInput.addEventListener("change", async e => {
    const f = e.target.files[0]; if (!f) return;
    try {
      await previewConfigImportFile(f);
    } catch (err) {
      notifyError("config-import-preview", err, { status: "#cfg-restore-status", inlineText: "❌ " + errorText(err) });
    } finally {
      e.target.value = "";
    }
  });
});
