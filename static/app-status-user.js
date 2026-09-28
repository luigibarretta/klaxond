import {
  $,
  $$,
  J,
  SEARCH_DEBOUNCE_MS,
  apiFetch,
  applyTablePager,
  debounce,
  dirtyTabs,
  errorText,
  escapeHtml,
  fetchError,
  fetchOk,
  getAuthPasswordPolicy,
  getCurrentUser,
  isAbortError,
  isPublicInfoPage,
  markTabDirty,
  notifyError,
  notifyResponseError,
  notifySuccess,
  notifyValidationError,
  queryGet,
  refreshTablePagers,
  setAuthPasswordPolicy,
  setCurrentUser,
  setInlineStatus,
  setLocalTotpEnabled,
  showTableRowPage,
  syncTabFromPath,
  tr,
  updateAllTabAccessibleLabels,
  updatePublicLoginLinksText,
  updateTabAccessibleLabel,
} from "./app.js";
import { loadStatus } from "./app-status.js";
import { updateAppVersion } from "./app-status-version.js";
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
  if (
    groups.some((g) =>
      ["viewer", "klaxond-viewer", "klaxond:viewer", "viewer:*"].includes(g),
    )
  )
    return true;
  if ((user.mode === "pat" || user.mode === "api-key") && groups.length) {
    return groups.every(
      (scope) =>
        String(scope).endsWith(":read") ||
        scope === "viewer:*" ||
        scope === "admin:read",
    );
  }
  return false;
}
export function applyReadOnlyViewerMode(user = {}) {
  const readOnly = isReadOnlyViewer(user);
  document.body.classList.toggle("viewer-readonly", readOnly);
  document.body.setAttribute(
    "data-viewer-readonly-label",
    tr("auth.viewer_readonly"),
  );
  document
    .querySelector("main")
    ?.setAttribute("data-viewer-readonly-label", tr("auth.viewer_readonly"));
  const writeSelectors = [
    "#btn-cascade-toggle",
    "#cfg-import-apply",
    "#inhib-add",
    "#inhib-save",
    "#inhib-clear-all",
    "#sched-add",
    "#sched-save",
    "#btn-rc-add",
    "#btn-rc-save",
    "#ntfy-topic-add",
    "#ntfy-topics-save",
    "#btn-routing-save",
    "#routing-save-all",
    "#routing-discard",
    "#btn-cas-add",
    "#btn-cas-save",
    "#btn-pol-add",
    "#btn-rule-add",
    "#btn-delivery-save",
    "[data-dedup-save]",
    "[data-auth-save]",
    "#token-create",
    "#passkey-register",
    "#totp-start",
    "#totp-enable",
    "#totp-disable",
    "#btn-preview",
    "#inhib-test-run",
    "#btn-test-fire",
    "button.danger",
    "[data-clear-suppression]",
    "[data-clear-ack]",
    "[data-del]",
    "[data-revoke]",
    "[data-passkey-del]",
    "button[data-act]",
    "button[data-emergency-action]",
  ];
  document.querySelectorAll(writeSelectors.join(",")).forEach((el) => {
    const dirtyTab = el.dataset.enableWhenDirty;
    el.disabled = readOnly || Boolean(dirtyTab && !dirtyTabs.has(dirtyTab));
    if (readOnly) el.title = tr("auth.viewer_readonly");
  });
  document.dispatchEvent(new CustomEvent("klaxond:readonlychange"));
}
window.applyReadOnlyViewerMode = applyReadOnlyViewerMode;
export function updateCurrentUserUI(user = {}) {
  const current = setCurrentUser(
    user || { sub: "anonymous", mode: "none", groups: [] },
  );
  const name = displayUserName(user);
  const mode = user.mode || "none";
  const readOnly = isReadOnlyViewer(user);
  const initials =
    name
      .split(/[\s@._-]+/)
      .filter(Boolean)
      .slice(0, 2)
      .map((part) => part[0])
      .join("")
      .toUpperCase() || "?";
  const nameEl = $("#sidebar-user-name");
  const modeEl = $("#sidebar-user-mode");
  const avatar = $("#sidebar-avatar");
  if (nameEl) nameEl.textContent = name;
  if (modeEl)
    modeEl.textContent = readOnly ? `mode=${mode} · viewer` : `mode=${mode}`;
  if (avatar) avatar.textContent = initials;
  const authUser = $("#auth-current-user");
  if (authUser) {
    const email = user.email && user.email !== name ? ` · ${user.email}` : "";
    authUser.textContent = `${name}${email}`;
  }
  const authSub = $("#auth-current-sub");
  if (authSub) authSub.textContent = `${user.sub || "?"} · ${mode}`;
  applyReadOnlyViewerMode(user);
}
export async function loadCurrentUser() {
  try {
    updateCurrentUserUI(await J("/api/auth/me"));
  } catch (e) {
    updateCurrentUserUI({ sub: "anonymous", mode: "none" });
  }
}
function normalizeDeliveries(payload) {
  if (Array.isArray(payload)) return payload;
  if (Array.isArray(payload?.entries)) return payload.entries;
  return [];
}
export async function fetchDeliveries(limit = 0, opts = {}) {
  const suffix = limit ? `?limit=${encodeURIComponent(limit)}` : "";
  return normalizeDeliveries(
    await queryGet(
      opts.scope || `deliveries:${limit || "all"}`,
      `/api/deliveries${suffix}`,
      { cancelPrevious: false, force: opts.force },
    ),
  );
}
export async function fetchDeliveryActivity(hours = 24, opts = {}) {
  const boundedHours = Math.max(1, Math.min(Number(hours) || 24, 168));
  return queryGet(
    opts.scope || `delivery-activity:${boundedHours}`,
    `/api/status/activity?hours=${boundedHours}`,
    { cancelPrevious: false, force: opts.force },
  );
}
export function deliveryTsSeconds(item) {
  const raw = Number(item?.ts ?? item?.timestamp ?? 0);
  return raw > 1e12 ? raw / 1e3 : raw;
}
export async function loadStatusActivity() {
  try {
    const activity = await fetchDeliveryActivity(24, {
      scope: "status-delivery-activity",
    });
    const total = Number(activity.total || activity.window_total || 0);
    const bySource = activity.by_source || {};
    const byChannel = activity.by_channel || {};
    $("#stat-deliv-total").textContent = total;
    const parts = Object.entries(bySource)
      .sort((a, b) => b[1] - a[1])
      .map(([k, v]) => `${k}: ${v}`);
    $("#stat-deliv-breakdown").innerHTML = parts.length
      ? tr("status.by_source") +
        " " +
        parts.map((p) => `<code>${escapeHtml(p)}</code>`).join(" · ")
      : `${tr("status.by_source")} <span class='muted'>${escapeHtml(tr("status.no_activity"))}</span>`;
    setTabBadge("deliveries", total);
    const failed = Object.entries(byChannel)
      .filter(([channel]) => channel.includes("failed"))
      .reduce((sum, [, count]) => sum + Number(count || 0), 0);
    $("#status-failed-24h").textContent = String(failed);
    $("#status-suppressed-24h").textContent = String(activity.suppressed || 0);
  } catch (e) {
    $("#stat-deliv-total").textContent = "?";
    $("#stat-deliv-breakdown").textContent = tr(
      "status.deliveries_unreachable",
    );
    $("#status-failed-24h").textContent = "—";
    $("#status-suppressed-24h").textContent = "—";
    fetchError("status-activity-deliveries", e);
  }
  try {
    const inhib = await queryGet("status-inhibitions", "/api/inhibitions", {
      cancelPrevious: false,
    });
    const n = (inhib || []).length;
    $("#stat-suppr-count").textContent = n;
    setTabBadge("inhibitions", n, n > 0 ? "warn" : "");
  } catch (e) {
    $("#stat-suppr-count").textContent = "?";
    fetchError("status-activity-inhibitions", e);
  }
  try {
    const d = await queryGet("status-dedup", "/api/dedup-config", {
      cancelPrevious: false,
    });
    const pc = d.pending_counts || {};
    const total = Object.values(pc).reduce((a, b) => a + (b || 0), 0);
    $("#stat-dedup-count").textContent = total;
    setTabBadge("grouping", total, total > 0 ? "warn" : "");
  } catch (e) {
    $("#stat-dedup-count").textContent = "?";
    fetchError("status-activity-dedup", e);
  }
}
$("#btn-cascade-toggle").addEventListener("click", async () => {
  try {
    await J("/api/cascade/toggle", { method: "POST", body: "{}" });
    notifySuccess(tr("cascade.runtime_toggled"), { durationMs: 3e3 });
    loadStatus({ force: true });
  } catch (e) {
    notifyError("cascade-toggle", e);
  }
});
