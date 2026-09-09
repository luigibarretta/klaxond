import {
  $, $$, APP_META, J, SEARCH_DEBOUNCE_MS, apiFetch, applyTablePager, debounce, errorText,
  escapeHtml, fetchError, fetchOk, getAuthPasswordPolicy, getCurrentUser, isAbortError, isPublicInfoPage,
  markTabDirty, notifyError, notifyResponseError, notifySuccess, notifyValidationError, onReady,
  queryGet, refreshTablePagers, setAuthPasswordPolicy, setInlineStatus, setLocalTotpEnabled,
  showTableRowPage, syncTabFromPath, tr, updateAllTabAccessibleLabels, updatePublicLoginLinksText,
} from "./app.js";
import { acknowledgeEmergencyReceipt } from "./app-emergency-actions.js";

// ---- Deliveries ----
let _delivCache = [];  // most recent fetch — filter applies client-side without re-fetching
let _delivTotal = 0;
let _activeEmergencyReceipts = new Set();
const _expandedDeliveries = new Set();

export async function loadDeliv(opts = {}) {
  try {
    const payload = await queryGet("deliveries", "/api/deliveries?limit=10000", {
      force: opts.force,
      cancelPrevious: false,
    });
    _delivCache = Array.isArray(payload) ? payload : (payload.entries || []);
    _delivTotal = Array.isArray(payload) ? payload.length : Number(payload.total || _delivCache.length);
    try {
      const emergencyPayload = await queryGet(
        "deliveries-emergencies",
        "/api/emergencies?state=active&limit=500",
        { force: opts.force, cancelPrevious: false },
      );
      _activeEmergencyReceipts = new Set((emergencyPayload.incidents || []).map(item => item.receipt_id));
    } catch (error) {
      _activeEmergencyReceipts = new Set();
      fetchError("deliveries-emergencies", error);
    }
  } catch (e) {
    fetchError("deliveries", e);
    _delivCache = [];
    _delivTotal = 0;
    _activeEmergencyReceipts = new Set();
  }
  renderDeliv();
}

export function renderDeliv(opts = {}) {
  const tb = $("#t-deliv tbody"); if (!tb) return;
  tb.innerHTML = "";
  const total = _delivTotal || (_delivCache || []).length;
  const rows = _filteredDelivRows();
  let shown = rows.length;
  for (const r of rows) {
    const row = document.createElement("tr");
    row.classList.add("deliv-row");
    const t = new Date(r.ts * 1000).toLocaleTimeString();
    let chCell;
    if (r.channel === "suppressed") {
      chCell = `<span class="ch-suppressed">${escapeHtml(tr("deliveries.suppressed_by"))} <code>${escapeHtml(r.suppressed_by || "?")}</code></span>`;
    } else if (r.channel === "dry-run") {
      chCell = `<span class="ch-dry-run">${escapeHtml(tr("deliveries.dry_run"))}</span>`;
    } else if (r.channel === "dry-run-suppressed") {
      chCell = `<span class="ch-suppressed">${escapeHtml(tr("deliveries.dry_run"))} (${escapeHtml(tr("deliveries.would_suppress"))}: <code>${escapeHtml(r.suppressed_by || "?")}</code>)</span>`;
    } else {
      chCell = `<span class="ch-${r.channel}">${escapeHtml(r.channel)}</span>`;
    }
    const key = _deliveryKey(r);
    row.dataset.deliveryKey = key;
    const canAck = r.emergency_receipt_id && _activeEmergencyReceipts.has(r.emergency_receipt_id);
    row.innerHTML = `<td data-label="${escapeHtml(tr("common.time"))}">${t}</td><td data-label="${escapeHtml(tr("common.source"))}">${escapeHtml(r.source)}</td><td data-label="${escapeHtml(tr("common.severity"))}" class="sev-${r.severity}">${escapeHtml(r.severity)}</td><td data-label="${escapeHtml(tr("common.title"))}">${escapeHtml(r.title)}</td><td data-label="${escapeHtml(tr("deliveries.channel_or_suppressed"))}">${chCell}</td><td data-label="${escapeHtml(tr("common.actions"))}"><div class="delivery-actions"><button type="button" class="btn" data-delivery-details aria-expanded="false">${escapeHtml(tr("deliveries.details"))}</button>${canAck ? `<button type="button" class="btn primary" data-delivery-ack="${escapeHtml(r.emergency_receipt_id)}">${escapeHtml(tr("emergency.ack"))}</button>` : ""}</div></td>`;
    row.querySelector("[data-delivery-details]")?.addEventListener("click", event => _toggleDelivExpand(event.currentTarget, row, r));
    row.querySelector("[data-delivery-ack]")?.addEventListener("click", async event => {
      const button = event.currentTarget;
      button.disabled = true;
      if (await acknowledgeEmergencyReceipt(button.dataset.deliveryAck, "delivery-emergency-ack")) {
        await loadDeliv({ force: true });
      } else {
        button.disabled = false;
      }
    });
    tb.appendChild(row);
  }
  const cnt = $("#deliv-count");
  if (cnt) cnt.textContent = total === shown ? tr("deliveries.event_count", { count: total }) : tr("deliveries.event_count_filtered", { shown, total });
  const storage = $("#deliv-storage");
  if (storage) {
    const bytes = new Blob([JSON.stringify(_delivCache)]).size;
    storage.textContent = tr("deliveries.serialized_size", {
      count: _delivCache.length,
      size: _formatBytes(bytes),
    });
  }
  if (!shown && total) {
    tb.innerHTML = `<tr><td colspan="6" class="muted">${escapeHtml(tr("deliveries.no_match"))}</td></tr>`;
  } else if (!shown) {
    tb.innerHTML = `<tr><td colspan="6"><div class="table-empty-state">
      <strong>${escapeHtml(tr("deliveries.empty_title"))}</strong>
      <p class="muted">${escapeHtml(tr("deliveries.empty_desc"))}</p>
      <div class="table-empty-actions">
        <a class="btn primary" href="/test">${escapeHtml(tr("deliveries.empty_test"))}</a>
        <a class="btn" href="/setup">${escapeHtml(tr("deliveries.empty_setup"))}</a>
      </div>
    </div></td></tr>`;
  }
  applyTablePager("t-deliv", { reset: opts.reset });
  tb.querySelectorAll("tr.deliv-row").forEach(row => {
    if (_expandedDeliveries.has(row.dataset.deliveryKey) && row.style.display !== "none") {
      _insertDelivDetail(row.querySelector("[data-delivery-details]"), row, rows.find(item => _deliveryKey(item) === row.dataset.deliveryKey));
    }
  });
}

function _deliveryKey(row) {
  return [row.ts, row.source, row.severity, row.title, row.channel].join("\u0000");
}

function _formatBytes(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KiB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MiB`;
}

function _toggleDelivExpand(button, row, r) {
  const next = row.nextElementSibling;
  if (next && next.classList.contains("deliv-detail")) {
    next.remove();
    row.classList.remove("expanded");
    button.setAttribute("aria-expanded", "false");
    _expandedDeliveries.delete(row.dataset.deliveryKey);
    return;
  }
  _expandedDeliveries.add(row.dataset.deliveryKey);
  _insertDelivDetail(button, row, r);
}

function _insertDelivDetail(button, row, r) {
  if (!r || row.nextElementSibling?.classList.contains("deliv-detail")) return;
  const detail = document.createElement("tr");
  detail.classList.add("deliv-detail");
  const ts = new Date(r.ts * 1000);
  const tsFull = ts.toISOString() + " (" + ts.toLocaleString() + ")";
  const rows = [
    ["timestamp", `<code>${escapeHtml(tsFull)}</code>`],
    ["source",    `<code>${escapeHtml(r.source || "")}</code>`],
    ["severity",  `<code>${escapeHtml(r.severity || "")}</code>`],
    ["title",     `<code>${escapeHtml(r.title || "")}</code>`],
    ["channel",   `<code>${escapeHtml(r.channel || "")}</code>`],
  ];
  if (r.suppressed_by) rows.push(["suppressed_by", `<code>${escapeHtml(r.suppressed_by)}</code>`]);
  if (r.emergency_receipt_id) rows.push(["emergency_receipt_id", `<code>${escapeHtml(r.emergency_receipt_id)}</code>`]);
  const html = rows.map(([k, v]) => `<div class="kv"><span class="kv-k">${k}</span><span class="kv-v">${v}</span></div>`).join("");
  detail.innerHTML = `<td colspan="6" class="deliv-detail-cell">${html}</td>`;
  row.insertAdjacentElement("afterend", detail);
  row.classList.add("expanded");
  button?.setAttribute("aria-expanded", "true");
}

// Re-render (client-side, no fetch) when filter changes
const scheduleDelivRender = debounce(() => renderDeliv({ reset: true }));
onReady(() => {
  $("#deliv-filter")?.addEventListener("input", e => {
    if (!String(e.target?.value || "").trim()) {
      scheduleDelivRender.cancel();
      renderDeliv({ reset: true });
      return;
    }
    scheduleDelivRender();
  });
  $("#deliv-show-suppressed")?.addEventListener("change", () => renderDeliv({ reset: true }));
  $("#deliv-export-csv")?.addEventListener("click", exportDeliveriesCsv);
});

// Apply the same filter as renderDeliv so the CSV matches what the user sees.
function _filteredDelivRows() {
  const filter = ($("#deliv-filter")?.value || "").trim().toLowerCase();
  const showSuppressed = $("#deliv-show-suppressed")?.checked !== false;
  return (_delivCache || []).filter(r => {
    const isSupp = r.channel === "suppressed" || r.channel === "dry-run-suppressed";
    if (isSupp && !showSuppressed) return false;
    if (filter) {
      const hay = `${r.source} ${r.severity} ${r.title} ${r.channel} ${r.suppressed_by || ""}`.toLowerCase();
      if (!hay.includes(filter)) return false;
    }
    return true;
  });
}

// RFC 4180 CSV: wrap in double-quotes if it contains commas/quotes/newlines;
// escape embedded double-quotes by doubling them.
function _csvCell(v) {
  const s = String(v == null ? "" : v);
  if (/[",\r\n]/.test(s)) return '"' + s.replace(/"/g, '""') + '"';
  return s;
}

function exportDeliveriesCsv() {
  const rows = _filteredDelivRows();
  if (!rows.length) { notifyValidationError("deliveries-export", tr("deliveries.no_rows_export")); return; }
  const header = ["timestamp_iso", "timestamp_epoch", "source", "severity", "title", "channel", "suppressed_by", "emergency_receipt_id"];
  const lines = [header.join(",")];
  for (const r of rows) {
    const iso = new Date((r.ts || 0) * 1000).toISOString();
    lines.push([iso, r.ts || "", r.source || "", r.severity || "", r.title || "", r.channel || "", r.suppressed_by || "", r.emergency_receipt_id || ""]
                .map(_csvCell).join(","));
  }
  const blob = new Blob([lines.join("\r\n") + "\r\n"], { type: "text/csv;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = "klaxond-deliveries-" + new Date().toISOString().replace(/[:.]/g, "-") + ".csv";
  a.click();
  URL.revokeObjectURL(url);
  notifySuccess(tr("deliveries.exported", { count: rows.length }));
}

// ---- Backend logs ----
let _logsCache = { entries: [], total: 0, limit: 100, offset: 0 };
let _logsOffset = 0;
let _logsFilterTimer = null;
let _logsAutoTimer = null;
let _logsRequestSeq = 0;

function logsPageSize() {
  const raw = parseInt($("#logs-limit")?.value || "100", 10);
  if (!Number.isFinite(raw)) return 100;
  return Math.max(1, Math.min(raw, 500));
}

export async function loadLogs(opts = {}) {
  clearTimeout(_logsFilterTimer);
  _logsFilterTimer = null;
  if (opts.reset) _logsOffset = 0;
  const params = new URLSearchParams();
  const q = ($("#logs-filter")?.value || "").trim();
  const level = $("#logs-level")?.value || "all";
  const limit = logsPageSize();
  if (q) params.set("q", q);
  if (level && level !== "all") params.set("level", level);
  params.set("limit", String(limit));
  params.set("offset", String(Math.max(0, _logsOffset)));
  const requestSeq = ++_logsRequestSeq;
  try {
    const payload = await queryGet("logs", "/api/logs?" + params.toString(), { force: opts.force });
    if (requestSeq !== _logsRequestSeq) return;
    _logsCache = payload;
    _logsOffset = payload.offset || 0;
    fetchOk("logs");
    renderLogs();
  } catch (e) {
    if (isAbortError(e)) return;
    if (requestSeq !== _logsRequestSeq) return;
    fetchError("logs", e);
    const tb = $("#t-logs tbody");
    if (tb) tb.innerHTML = `<tr><td colspan="4" class="muted">${escapeHtml(tr("common.error"))}: ${escapeHtml(errorText(e))}</td></tr>`;
    const count = $("#logs-count");
    if (count) count.textContent = "";
    updateLogsPager();
  }
}

function renderLogs() {
  const tb = $("#t-logs tbody"); if (!tb) return;
  const entries = _logsCache.entries || [];
  tb.innerHTML = "";
  for (const entry of entries) {
    const row = document.createElement("tr");
    const level = (entry.level || "").toLowerCase();
    const fields = entry.fields && Object.keys(entry.fields).length
      ? "\n" + Object.entries(entry.fields)
          .sort(([a], [b]) => a.localeCompare(b))
          .map(([k, v]) => `${k}=${v}`)
          .join(" ")
      : "";
    const target = entry.line ? `${entry.target}:${entry.line}` : entry.target;
    row.innerHTML = `
      <td class="log-time">${escapeHtml(new Date((entry.ts || 0) * 1000).toLocaleString())}</td>
      <td><span class="log-level ${escapeHtml(level)}">${escapeHtml(entry.level || "")}</span></td>
      <td class="log-target">${escapeHtml(target || "")}</td>
      <td class="log-message">${escapeHtml((entry.message || "") + fields)}</td>`;
    tb.appendChild(row);
  }
  if (!entries.length) {
    tb.innerHTML = `<tr><td colspan="4" class="muted">${escapeHtml(tr("logs.empty"))}</td></tr>`;
  }
  const count = $("#logs-count");
  const total = _logsCache.total || 0;
  const offset = _logsCache.offset || 0;
  const from = entries.length ? offset + 1 : 0;
  const to = entries.length ? offset + entries.length : 0;
  if (count) count.textContent = tr("logs.showing_range", { from, to, total });
  updateLogsPager();
}

function updateLogsPager() {
  const total = _logsCache.total || 0;
  const limit = _logsCache.limit || logsPageSize();
  const offset = _logsCache.offset || 0;
  const pageCount = total ? Math.ceil(total / limit) : 1;
  const page = total ? Math.floor(offset / limit) + 1 : 0;
  const info = $("#logs-page-info");
  if (info) info.textContent = total ? tr("logs.page_info", { page, pages: pageCount }) : tr("logs.page_info_empty");
  const atStart = offset <= 0;
  const atEnd = !total || offset + limit >= total;
  $("#logs-first") && ($("#logs-first").disabled = atStart);
  $("#logs-prev") && ($("#logs-prev").disabled = atStart);
  $("#logs-next") && ($("#logs-next").disabled = atEnd);
  $("#logs-last") && ($("#logs-last").disabled = atEnd);
}

function scheduleLogsLoad() {
  _logsRequestSeq++;
  clearTimeout(_logsFilterTimer);
  const q = ($("#logs-filter")?.value || "").trim();
  if (!q) {
    loadLogs({ reset: true });
    return;
  }
  _logsFilterTimer = setTimeout(() => loadLogs({ reset: true }), SEARCH_DEBOUNCE_MS);
}

function changeLogsPage(direction) {
  const total = _logsCache.total || 0;
  const limit = _logsCache.limit || logsPageSize();
  if (!total) return;
  const lastOffset = Math.floor((total - 1) / limit) * limit;
  if (direction === "first") _logsOffset = 0;
  if (direction === "prev") _logsOffset = Math.max(0, (_logsCache.offset || 0) - limit);
  if (direction === "next") _logsOffset = Math.min(lastOffset, (_logsCache.offset || 0) + limit);
  if (direction === "last") _logsOffset = lastOffset;
  loadLogs();
}

function updateLogsAutorefresh() {
  clearInterval(_logsAutoTimer);
  _logsAutoTimer = null;
  if ($("#logs-autorefresh")?.checked) {
    _logsAutoTimer = setInterval(() => {
      if ($("#tab-logs")?.classList.contains("active")) loadLogs({ force: true });
    }, 5000);
  }
}

document.addEventListener("click", e => {
  if (!e.target.closest?.("#logs-refresh")) return;
  e.preventDefault();
  loadLogs({ force: true });
});

onReady(() => {
  $("#logs-filter")?.addEventListener("input", scheduleLogsLoad);
  $("#logs-level")?.addEventListener("change", () => loadLogs({ reset: true }));
  $("#logs-limit")?.addEventListener("change", () => loadLogs({ reset: true }));
  $("#logs-frontend-filter")?.addEventListener("click", () => {
    $("#logs-filter").value = "klaxond::frontend";
    $("#logs-level").value = "ERROR";
    loadLogs({ reset: true });
  });
  $("#logs-clear-filter")?.addEventListener("click", () => {
    $("#logs-filter").value = "";
    $("#logs-level").value = "all";
    loadLogs({ reset: true });
  });
  $("#logs-first")?.addEventListener("click", () => changeLogsPage("first"));
  $("#logs-prev")?.addEventListener("click", () => changeLogsPage("prev"));
  $("#logs-next")?.addEventListener("click", () => changeLogsPage("next"));
  $("#logs-last")?.addEventListener("click", () => changeLogsPage("last"));
  $("#logs-autorefresh")?.addEventListener("change", updateLogsAutorefresh);
  updateLogsAutorefresh();
});
export { loadAudit } from "./app-audit-log.js";
