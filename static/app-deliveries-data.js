import {
  $,
  J,
  SEARCH_DEBOUNCE_MS,
  debounce,
  escapeHtml,
  fetchError,
  isAbortError,
  notifyError,
  notifySuccess,
  notifyValidationError,
  onReady,
  queryGet,
  tr,
} from "./app.js";
import { acknowledgeEmergencyReceipt } from "./app-emergency-actions.js";
let deliveryRenderer = () => {};
import { deliveryState } from "./app-deliveries-state.js";
export function deliveryPageSize() {
  const raw = parseInt(
    document.querySelector("[data-deliv-page-size]")?.value || "25",
    10,
  );
  return [25, 50, 100].includes(raw) ? raw : 25;
}
export function currentDeliveryFilters() {
  return {
    query: ($("#deliv-filter")?.value || "").trim(),
    severity: $("#deliv-severity")?.value || "",
    channel: $("#deliv-channel")?.value || "",
    includeSuppressed: $("#deliv-show-suppressed")?.checked !== false,
  };
}
export function syncSuppressedFilterControls() {
  const channel = $("#deliv-channel");
  const checkbox = $("#deliv-show-suppressed");
  if (!channel || !checkbox) return;
  const suppressedOnly = channel.value === "__suppressed__";
  if (suppressedOnly) checkbox.checked = true;
  checkbox.disabled = suppressedOnly;
}
export function deliveryQueryParams({
  limit: limit = deliveryPageSize(),
  offset: offset = deliveryState.page.offset,
  filters: filters = currentDeliveryFilters(),
} = {}) {
  const params = new URLSearchParams({
    limit: String(limit),
    offset: String(Math.max(0, offset)),
  });
  if (filters.query) params.set("q", filters.query);
  if (filters.severity) params.set("severity", filters.severity);
  if (filters.channel === "__suppressed__") {
    params.set("suppressed", "only");
  } else {
    if (filters.channel) params.set("channel", filters.channel);
    if (!filters.includeSuppressed) params.set("suppressed", "exclude");
  }
  return params;
}
async function loadDeliveryStorageEstimate(opts = {}) {
  try {
    const activity = await queryGet(
      "deliveries-storage",
      "/api/status/activity?hours=24",
      { force: opts.force, cancelPrevious: false },
    );
    deliveryState.approximateBytes = Number(activity.approximate_history_bytes || 0);
    deliveryState.historyTotal = Number(activity.total_history || 0);
    deliveryState.storageAvailable = true;
  } catch (error) {
    deliveryState.approximateBytes = 0;
    deliveryState.historyTotal = 0;
    deliveryState.storageAvailable = false;
    fetchError("deliveries-storage", error);
  }
}
export async function loadDeliv(opts = {}) {
  if (opts.reset) deliveryState.page.offset = 0;
  const params = deliveryQueryParams();
  const requestSeq = ++deliveryState.requestSeq;
  try {
    const payload = await queryGet("deliveries", `/api/deliveries?${params}`, {
      force: opts.force,
    });
    if (requestSeq !== deliveryState.requestSeq) return;
    const entries = Array.isArray(payload) ? payload : payload.entries || [];
    deliveryState.page = {
      entries: entries,
      total: Array.isArray(payload)
        ? entries.length
        : Number(payload.total || 0),
      limit: Array.isArray(payload)
        ? deliveryPageSize()
        : Number(payload.limit || deliveryPageSize()),
      offset: Array.isArray(payload) ? 0 : Number(payload.offset || 0),
    };
    await Promise.all([
      loadDeliveryStorageEstimate(opts),
      queryGet(
        "deliveries-emergencies",
        "/api/emergencies?state=active&limit=500",
        { force: opts.force, cancelPrevious: false },
      )
        .then((emergencyPayload) => {
          deliveryState.activeEmergencyReceipts = new Set(
            (emergencyPayload.incidents || []).map((item) => item.receipt_id),
          );
        })
        .catch((error) => {
          deliveryState.activeEmergencyReceipts = new Set();
          fetchError("deliveries-emergencies", error);
        }),
    ]);
  } catch (e) {
    if (isAbortError(e) || requestSeq !== deliveryState.requestSeq) return;
    fetchError("deliveries", e);
    deliveryState.page = {
      entries: [],
      total: 0,
      limit: deliveryPageSize(),
      offset: 0,
    };
    deliveryState.activeEmergencyReceipts = new Set();
  }
  deliveryRenderer();
}

export function setDeliveryRenderer(renderer) {
  deliveryRenderer = renderer;
}
