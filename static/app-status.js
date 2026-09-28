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
import { loadConfigBackups } from "./app-config-backups.js";
import { updateAppVersion } from "./app-status-version.js";
export { loadConfigBackups } from "./app-config-backups.js";
function setChannelStatus(channelStates, id, configured, up, detail) {
  channelStates[id.replace(/^ch-/, "")] = { configured: configured, up: up };
  const card = $("#" + id);
  const dot = card.querySelector(".dot");
  const state = !configured ? "unknown" : up ? "up" : "down";
  dot.className = `dot ${state}`;
  dot.title = !configured
    ? tr("channel.state_not_configured")
    : up
      ? tr("channel.reachable")
      : tr("channel.unreachable");
  let statusText = card.querySelector(".ch-status-text");
  if (!statusText) {
    statusText = document.createElement("small");
    statusText.className = "ch-status-text";
    statusText.style.marginLeft = "6px";
    dot.insertAdjacentElement("afterend", statusText);
  }
  statusText.textContent = !configured
    ? tr("channel.state_not_configured")
    : up
      ? tr("channel.up")
      : tr("channel.down");
  statusText.style.color = !configured
    ? "var(--muted)"
    : up
      ? "var(--green)"
      : "var(--red)";
  card.querySelector(".ch-url").textContent = detail || "";
}

export async function loadStatus(opts = {}) {
  setOperationalSummaryLoading();
  try {
    const s = await queryGet("status", "/api/status", { force: opts.force });
    const channelStates = {};
    const configured = s.channel_configured || {
      ntfy: Boolean(s.ntfy_url),
      telegram: Boolean(s.telegram_configured),
      smtp: Boolean(s.smtp_host),
    };
    const channelDetail = (value, isConfigured) =>
      [value, isConfigured ? "" : tr("channel.not_configured")]
        .filter(Boolean)
        .join(" · ");
    setChannelStatus(
      channelStates,
      "ch-ntfy",
      configured.ntfy,
      s.channels.ntfy,
      channelDetail(s.ntfy_url, configured.ntfy),
    );
    setChannelStatus(
      channelStates,
      "ch-telegram",
      configured.telegram,
      s.channels.telegram,
      channelDetail(
        configured.telegram ? tr("channel.bot_configured") : "",
        configured.telegram,
      ),
    );
    setChannelStatus(
      channelStates,
      "ch-smtp",
      configured.smtp,
      s.channels.smtp,
      channelDetail(s.smtp_host, configured.smtp),
    );
    updateOperationalSummary(s, channelStates);
    updateAppVersion(s.version);
    renderCascadeRuntimeState(s.cascade_enabled_default, s.cascade_enabled_runtime);
    updateStatusLogWidget(s.logs || {});
  } catch (e) {
    setOperationalSummaryUnavailable(e);
    fetchError("status", e);
  }
  loadStatusActivity();
}

function renderCascadeRuntimeState(defaultEnabled, runtimeEnabled) {
  const defaultState = $("#cas-runtime-default");
  const runtimeState = $("#cas-runtime");
  const toggle = $("#btn-cascade-toggle");
  if (defaultState) defaultState.textContent = tr(defaultEnabled ? "common.on" : "common.off");
  if (runtimeState) runtimeState.textContent = tr(runtimeEnabled ? "common.on" : "common.off");
  for (const [element, enabled] of [[defaultState, defaultEnabled], [runtimeState, runtimeEnabled]]) {
    element?.classList.toggle("state-on", !!enabled);
    element?.classList.toggle("state-off", !enabled);
  }
  if (toggle) {
    toggle.textContent = tr(runtimeEnabled ? "delivery.runtime_disable" : "delivery.runtime_enable");
    toggle.setAttribute("aria-pressed", runtimeEnabled ? "true" : "false");
  }
}
function setOperationalSummaryLoading() {
  const summary = $("#operational-summary");
  if (!summary) return;
  summary.dataset.state = "loading";
  summary.querySelector(".operational-summary-icon").textContent = "…";
  $("#operational-summary-title").textContent = tr("status.checking");
  $("#operational-summary-detail").textContent = "";
}
function setOperationalSummaryUnavailable(error) {
  const summary = $("#operational-summary");
  if (!summary) return;
  summary.dataset.state = "unknown";
  summary.querySelector(".operational-summary-icon").textContent = "?";
  $("#operational-summary-title").textContent = tr(
    "status.channel_state_unknown",
  );
  $("#operational-summary-detail").textContent = tr(
    "status.channel_state_unknown_detail",
    { message: errorText(error) },
  );
  $("#status-active-emergencies").textContent = "—";
}
function updateOperationalSummary(status, channelStates) {
  const summary = $("#operational-summary");
  if (!summary) return;
  const configured = Object.entries(channelStates).filter(
    ([, state]) => state.configured,
  );
  const reachable = configured.filter(([, state]) => state.up);
  const unavailable = configured
    .filter(([, state]) => !state.up)
    .map(([name]) => name);
  const emergencyStorageOk = status.emergency?.storage_ok !== false;
  let state = "healthy";
  let title = tr("status.channels_reachable");
  let detail = tr("status.delivery_healthy_detail", {
    count: reachable.length,
  });
  if (!configured.length || !emergencyStorageOk || !reachable.length) {
    state = "action";
    title = tr("status.delivery_action_required");
    detail = !configured.length
      ? tr("status.no_channels_configured")
      : !emergencyStorageOk
        ? tr("status.emergency_storage_unavailable")
        : tr("status.no_channels_reachable");
  } else if (unavailable.length) {
    state = "degraded";
    title = tr("status.delivery_degraded");
    detail = tr("status.channels_unavailable", {
      channels: unavailable.join(", "),
    });
  }
  summary.dataset.state = state;
  const icon = summary.querySelector(".operational-summary-icon");
  if (icon)
    icon.textContent =
      state === "healthy" ? "✓" : state === "degraded" ? "!" : "×";
  $("#operational-summary-title").textContent = title;
  $("#operational-summary-detail").textContent = detail;
  $("#status-active-emergencies").textContent = String(
    status.emergency?.active || 0,
  );
}
function updateStatusLogWidget(logs) {
  const retained = Number.isFinite(logs.retained) ? logs.retained : 0;
  const capacity = Number.isFinite(logs.capacity) ? logs.capacity : 0;
  const warn = Number.isFinite(logs.warn) ? logs.warn : 0;
  const error = Number.isFinite(logs.error) ? logs.error : 0;
  const retainedEl = $("#stat-log-retained");
  if (retainedEl)
    retainedEl.textContent = capacity
      ? `${retained}/${capacity}`
      : String(retained);
  const severityEl = $("#stat-log-severity");
  if (severityEl) {
    const newest = logs.newest_timestamp
      ? new Date(logs.newest_timestamp).toLocaleString()
      : tr("status.no_activity");
    severityEl.innerHTML = `${escapeHtml(tr("status.warn_error", { warn: warn, error: error }))}<br>${escapeHtml(tr("status.latest_log", { time: newest }))}`;
  }
  const noisy = warn + error;
  setTabBadge("logs", noisy, error > 0 ? "crit" : noisy > 0 ? "warn" : "");
}
import { loadStatusActivity, setTabBadge } from "./app-status-user.js";
export { applyReadOnlyViewerMode, fetchDeliveryActivity, fetchDeliveries, deliveryTsSeconds, loadCurrentUser, loadStatusActivity, setTabBadge, updateCurrentUserUI } from "./app-status-user.js";
