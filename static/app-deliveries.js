import {
  $, J, SEARCH_DEBOUNCE_MS, debounce, escapeHtml, fetchError, isAbortError,
  notifyError, notifySuccess, notifyValidationError, onReady, queryGet, tr,
} from "./app.js";
import { acknowledgeEmergencyReceipt } from "./app-emergency-actions.js";

// Delivery history, filters, pagination, export, details, and emergency ACK.
const DELIVERY_EXPORT_LIMIT = 10000;
let _delivPage = { entries: [], total: 0, limit: 25, offset: 0 };
let _delivApproximateBytes = 0;
let _delivHistoryTotal = 0;
let _delivStorageAvailable = false;
let _delivRequestSeq = 0;
let _activeEmergencyReceipts = new Set();
const _expandedDeliveries = new Set();

function deliveryPageSize() {
  const raw = parseInt(document.querySelector("[data-deliv-page-size]")?.value || "25", 10);
  return [25, 50, 100].includes(raw) ? raw : 25;
}

function currentDeliveryFilters() {
  return {
    query: ($("#deliv-filter")?.value || "").trim(),
    severity: $("#deliv-severity")?.value || "",
    channel: $("#deliv-channel")?.value || "",
    includeSuppressed: $("#deliv-show-suppressed")?.checked !== false,
  };
}

function syncSuppressedFilterControls() {
  const channel = $("#deliv-channel");
  const checkbox = $("#deliv-show-suppressed");
  if (!channel || !checkbox) return;
  const suppressedOnly = channel.value === "__suppressed__";
  if (suppressedOnly) checkbox.checked = true;
  checkbox.disabled = suppressedOnly;
}

function deliveryQueryParams({
  limit = deliveryPageSize(),
  offset = _delivPage.offset,
  filters = currentDeliveryFilters(),
} = {}) {
  const params = new URLSearchParams({ limit: String(limit), offset: String(Math.max(0, offset)) });
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
    const activity = await queryGet("deliveries-storage", "/api/status/activity?hours=24", {
      force: opts.force,
      cancelPrevious: false,
    });
    _delivApproximateBytes = Number(activity.approximate_history_bytes || 0);
    _delivHistoryTotal = Number(activity.total_history || 0);
    _delivStorageAvailable = true;
  } catch (error) {
    _delivApproximateBytes = 0;
    _delivHistoryTotal = 0;
    _delivStorageAvailable = false;
    fetchError("deliveries-storage", error);
  }
}

export async function loadDeliv(opts = {}) {
  if (opts.reset) _delivPage.offset = 0;
  const params = deliveryQueryParams();
  const requestSeq = ++_delivRequestSeq;
  try {
    const payload = await queryGet("deliveries", `/api/deliveries?${params}`, { force: opts.force });
    if (requestSeq !== _delivRequestSeq) return;
    const entries = Array.isArray(payload) ? payload : (payload.entries || []);
    _delivPage = {
      entries,
      total: Array.isArray(payload) ? entries.length : Number(payload.total || 0),
      limit: Array.isArray(payload) ? deliveryPageSize() : Number(payload.limit || deliveryPageSize()),
      offset: Array.isArray(payload) ? 0 : Number(payload.offset || 0),
    };
    await Promise.all([
      loadDeliveryStorageEstimate(opts),
      queryGet("deliveries-emergencies", "/api/emergencies?state=active&limit=500", {
        force: opts.force,
        cancelPrevious: false,
      }).then(emergencyPayload => {
        _activeEmergencyReceipts = new Set((emergencyPayload.incidents || []).map(item => item.receipt_id));
      }).catch(error => {
        _activeEmergencyReceipts = new Set();
        fetchError("deliveries-emergencies", error);
      }),
    ]);
  } catch (e) {
    if (isAbortError(e) || requestSeq !== _delivRequestSeq) return;
    fetchError("deliveries", e);
    _delivPage = { entries: [], total: 0, limit: deliveryPageSize(), offset: 0 };
    _activeEmergencyReceipts = new Set();
  }
  renderDeliv();
}

export function renderDeliv() {
  const tb = $("#t-deliv tbody"); if (!tb) return;
  tb.innerHTML = "";
  const total = _delivPage.total || 0;
  const rows = _delivPage.entries || [];
  const shown = rows.length;
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
  const from = shown ? _delivPage.offset + 1 : 0;
  const to = shown ? _delivPage.offset + shown : 0;
  if (cnt) cnt.textContent = total
    ? tr("deliveries.showing_range", { from, to, total })
    : tr("deliveries.event_count", { count: 0 });
  const storage = $("#deliv-storage");
  if (storage) {
    storage.textContent = _delivStorageAvailable
      ? tr("deliveries.approximate_history_size", { count: _delivHistoryTotal, size: _formatBytes(_delivApproximateBytes) })
      : tr("deliveries.page_payload_size", { count: shown, size: _formatBytes(new Blob([JSON.stringify(rows)]).size) });
  }
  if (!shown && total) {
    tb.innerHTML = `<tr><td colspan="6" class="muted">${escapeHtml(tr("deliveries.page_empty"))}</td></tr>`;
  } else if (!shown && _hasDeliveryFilters()) {
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
  tb.querySelectorAll("tr.deliv-row").forEach(row => {
    if (_expandedDeliveries.has(row.dataset.deliveryKey)) {
      _insertDelivDetail(row.querySelector("[data-delivery-details]"), row, rows.find(item => _deliveryKey(item) === row.dataset.deliveryKey));
    }
  });
  updateDeliveriesPager();
}

function _hasDeliveryFilters() {
  return Boolean(
    ($("#deliv-filter")?.value || "").trim()
    || $("#deliv-severity")?.value
    || $("#deliv-channel")?.value
    || $("#deliv-show-suppressed")?.checked === false
  );
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

function updateDeliveriesPager() {
  const total = _delivPage.total || 0;
  const limit = _delivPage.limit || deliveryPageSize();
  const offset = _delivPage.offset || 0;
  const pageCount = total ? Math.ceil(total / limit) : 1;
  const page = total ? Math.floor(offset / limit) + 1 : 0;
  const from = _delivPage.entries.length ? offset + 1 : 0;
  const to = _delivPage.entries.length ? offset + _delivPage.entries.length : 0;
  document.querySelectorAll("[data-deliveries-pager]").forEach(pager => {
    const size = pager.querySelector("[data-deliv-page-size]");
    if (size) size.value = String(limit);
    const range = pager.querySelector("[data-deliv-range]");
    if (range) range.textContent = total ? tr("deliveries.showing_range", { from, to, total }) : tr("deliveries.no_results");
    const info = pager.querySelector("[data-deliv-page-info]");
    if (info) info.textContent = total ? tr("logs.page_info", { page, pages: pageCount }) : tr("logs.page_info_empty");
    pager.querySelectorAll('[data-deliv-page="first"], [data-deliv-page="prev"]').forEach(button => { button.disabled = offset <= 0; });
    pager.querySelectorAll('[data-deliv-page="next"], [data-deliv-page="last"]').forEach(button => { button.disabled = !total || offset + limit >= total; });
  });
}

function changeDeliveriesPage(direction) {
  const total = _delivPage.total || 0;
  const limit = _delivPage.limit || deliveryPageSize();
  if (!total) return;
  const lastOffset = Math.floor((total - 1) / limit) * limit;
  if (direction === "first") _delivPage.offset = 0;
  if (direction === "prev") _delivPage.offset = Math.max(0, _delivPage.offset - limit);
  if (direction === "next") _delivPage.offset = Math.min(lastOffset, _delivPage.offset + limit);
  if (direction === "last") _delivPage.offset = lastOffset;
  loadDeliv();
}

const scheduleDelivLoad = debounce(() => loadDeliv({ reset: true }), SEARCH_DEBOUNCE_MS);
onReady(() => {
  $("#deliv-filter")?.addEventListener("input", e => {
    if (!String(e.target?.value || "").trim()) {
      scheduleDelivLoad.cancel();
      loadDeliv({ reset: true });
      return;
    }
    scheduleDelivLoad();
  });
  $("#deliv-severity")?.addEventListener("change", () => loadDeliv({ reset: true }));
  $("#deliv-channel")?.addEventListener("change", event => {
    syncSuppressedFilterControls();
    loadDeliv({ reset: true });
  });
  $("#deliv-show-suppressed")?.addEventListener("change", event => {
    if (!event.target.checked && $("#deliv-channel")?.value === "__suppressed__") {
      $("#deliv-channel").value = "";
    }
    syncSuppressedFilterControls();
    loadDeliv({ reset: true });
  });
  $("#deliv-export-csv")?.addEventListener("click", exportDeliveriesCsv);
  document.querySelectorAll("[data-deliv-page-size]").forEach(select => {
    select.addEventListener("change", event => {
      document.querySelectorAll("[data-deliv-page-size]").forEach(peer => { peer.value = event.target.value; });
      _delivPage.limit = deliveryPageSize();
      loadDeliv({ reset: true });
    });
  });
  document.querySelectorAll("[data-deliv-page]").forEach(button => {
    button.addEventListener("click", () => changeDeliveriesPage(button.dataset.delivPage));
  });
  syncSuppressedFilterControls();
});

// RFC 4180 CSV: wrap in double-quotes if it contains commas/quotes/newlines;
// escape embedded double-quotes by doubling them.
function _csvCell(v) {
  const s = String(v == null ? "" : v);
  if (/[",\r\n]/.test(s)) return '"' + s.replace(/"/g, '""') + '"';
  return s;
}

async function exportDeliveriesCsv() {
  const button = $("#deliv-export-csv");
  button.disabled = true;
  button.setAttribute("aria-busy", "true");
  let rows = [];
  const filters = currentDeliveryFilters();
  try {
    const params = deliveryQueryParams({ limit: DELIVERY_EXPORT_LIMIT, offset: 0, filters });
    const payload = await J(`/api/deliveries?${params}`);
    const exportTotal = Number(payload.total || 0);
    if (exportTotal > DELIVERY_EXPORT_LIMIT) {
      notifyValidationError("deliveries-export", tr("deliveries.export_too_large", {
        limit: DELIVERY_EXPORT_LIMIT,
        total: exportTotal,
      }));
      return;
    }
    rows = payload.entries || [];
    if (!exportTotal || !rows.length) {
      notifyValidationError("deliveries-export", tr("deliveries.no_rows_export"));
      return;
    }
  } catch (error) {
    notifyError("deliveries-export", error);
    return;
  } finally {
    button.disabled = false;
    button.removeAttribute("aria-busy");
  }
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
