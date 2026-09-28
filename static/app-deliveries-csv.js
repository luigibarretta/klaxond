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
const DELIVERY_EXPORT_LIMIT = 1e4;
import { deliveryState } from "./app-deliveries-state.js";
import { currentDeliveryFilters, deliveryQueryParams } from "./app-deliveries-data.js";
function _csvCell(v) {
  const s = String(v == null ? "" : v);
  if (/[",\r\n]/.test(s)) return '"' + s.replace(/"/g, '""') + '"';
  return s;
}
async function fetchExportRows(filters) {
  const params = deliveryQueryParams({
    limit: DELIVERY_EXPORT_LIMIT,
    offset: 0,
    filters: filters,
  });
  const payload = await J(`/api/deliveries?${params}`);
  const exportTotal = Number(payload.total || 0);
  if (exportTotal > DELIVERY_EXPORT_LIMIT) {
    notifyValidationError(
      "deliveries-export",
      tr("deliveries.export_too_large", {
        limit: DELIVERY_EXPORT_LIMIT,
        total: exportTotal,
      }),
    );
    return null;
  }
  const rows = payload.entries || [];
  if (!exportTotal || !rows.length) {
    notifyValidationError("deliveries-export", tr("deliveries.no_rows_export"));
    return null;
  }
  return rows;
}

function downloadCsv(rows) {
  const header = [
    "timestamp_iso", "timestamp_epoch", "source", "severity", "title",
    "channel", "suppressed_by", "emergency_receipt_id",
  ];
  const lines = [header.join(",")];
  for (const row of rows) {
    const iso = new Date((row.ts || 0) * 1e3).toISOString();
    lines.push([
      iso,
      row.ts || "",
      row.source || "",
      row.severity || "",
      row.title || "",
      row.channel || "",
      row.suppressed_by || "",
      row.emergency_receipt_id || "",
    ].map(_csvCell).join(","));
  }
  const blob = new Blob([lines.join("\r\n") + "\r\n"], {
    type: "text/csv;charset=utf-8",
  });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download =
    "klaxond-deliveries-" +
    new Date().toISOString().replace(/[:.]/g, "-") +
    ".csv";
  a.click();
  URL.revokeObjectURL(url);
  return rows.length;
}

export async function exportDeliveriesCsv() {
  const button = $("#deliv-export-csv");
  button.disabled = true;
  button.setAttribute("aria-busy", "true");
  let rows;
  try {
    rows = await fetchExportRows(currentDeliveryFilters());
  } catch (error) {
    notifyError("deliveries-export", error);
    return;
  } finally {
    button.disabled = false;
    button.removeAttribute("aria-busy");
  }
  if (!rows) return;
  downloadCsv(rows);
  notifySuccess(tr("deliveries.exported", { count: rows.length }));
}
