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
import { deliveryState } from "./app-deliveries-state.js";
import {
  deliveryPageSize,
  loadDeliv,
  syncSuppressedFilterControls,
} from "./app-deliveries-data.js";
import { exportDeliveriesCsv } from "./app-deliveries-csv.js";
function renderDeliveryRows(tb, rows) {
  for (const delivery of rows) {
    const row = document.createElement("tr");
    row.classList.add("deliv-row");
    const time = new Date(delivery.ts * 1e3).toLocaleTimeString();
    const channel = delivery.channel;
    const channelCell =
      channel === "suppressed"
        ? `<span class="ch-suppressed">${escapeHtml(tr("deliveries.suppressed_by"))} <code>${escapeHtml(delivery.suppressed_by || "?")}</code></span>`
        : channel === "dry-run"
          ? `<span class="ch-dry-run">${escapeHtml(tr("deliveries.dry_run"))}</span>`
          : channel === "dry-run-suppressed"
            ? `<span class="ch-suppressed">${escapeHtml(tr("deliveries.dry_run"))} (${escapeHtml(tr("deliveries.would_suppress"))}: <code>${escapeHtml(delivery.suppressed_by || "?")}</code>)</span>`
            : `<span class="ch-${channel}">${escapeHtml(channel)}</span>`;
    const key = _deliveryKey(delivery);
    row.dataset.deliveryKey = key;
    const canAck =
      delivery.emergency_receipt_id &&
      deliveryState.activeEmergencyReceipts.has(delivery.emergency_receipt_id);
    row.innerHTML = `<td data-label="${escapeHtml(tr("common.time"))}">${time}</td><td data-label="${escapeHtml(tr("common.source"))}">${escapeHtml(delivery.source)}</td><td data-label="${escapeHtml(tr("common.severity"))}" class="sev-${delivery.severity}">${escapeHtml(delivery.severity)}</td><td data-label="${escapeHtml(tr("common.title"))}">${escapeHtml(delivery.title)}</td><td data-label="${escapeHtml(tr("deliveries.channel_or_suppressed"))}">${channelCell}</td><td data-label="${escapeHtml(tr("common.actions"))}"><div class="delivery-actions"><button type="button" class="btn" data-delivery-details aria-expanded="false">${escapeHtml(tr("deliveries.details"))}</button>${canAck ? `<button type="button" class="btn primary" data-delivery-ack="${escapeHtml(delivery.emergency_receipt_id)}">${escapeHtml(tr("emergency.ack"))}</button>` : ""}</div></td>`;
    row.querySelector("[data-delivery-details]")?.addEventListener("click", (event) =>
      _toggleDelivExpand(event.currentTarget, row, delivery),
    );
    row.querySelector("[data-delivery-ack]")?.addEventListener("click", async (event) => {
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
}

export function renderDeliv() {
  const tb = $("#t-deliv tbody");
  if (!tb) return;
  tb.innerHTML = "";
  const total = deliveryState.page.total || 0;
  const rows = deliveryState.page.entries || [];
  const shown = rows.length;
  renderDeliveryRows(tb, rows);
  const cnt = $("#deliv-count");
  const from = shown ? deliveryState.page.offset + 1 : 0;
  const to = shown ? deliveryState.page.offset + shown : 0;
  if (cnt)
    cnt.textContent = total
      ? tr("deliveries.showing_range", { from: from, to: to, total: total })
      : tr("deliveries.event_count", { count: 0 });
  const storage = $("#deliv-storage");
  if (storage) {
    storage.textContent = deliveryState.storageAvailable
      ? tr("deliveries.approximate_history_size", {
          count: deliveryState.historyTotal,
          size: _formatBytes(deliveryState.approximateBytes),
        })
      : tr("deliveries.page_payload_size", {
          count: shown,
          size: _formatBytes(new Blob([JSON.stringify(rows)]).size),
        });
  }
  if (!shown && total) {
    tb.innerHTML = `<tr><td colspan="6" class="muted">${escapeHtml(tr("deliveries.page_empty"))}</td></tr>`;
  } else if (!shown && _hasDeliveryFilters()) {
    tb.innerHTML = `<tr><td colspan="6" class="muted">${escapeHtml(tr("deliveries.no_match"))}</td></tr>`;
  } else if (!shown) {
    tb.innerHTML = `<tr><td colspan="6"><div class="table-empty-state">\n      <strong>${escapeHtml(tr("deliveries.empty_title"))}</strong>\n      <p class="muted">${escapeHtml(tr("deliveries.empty_desc"))}</p>\n      <div class="table-empty-actions">\n        <a class="btn primary" href="/test">${escapeHtml(tr("deliveries.empty_test"))}</a>\n        <a class="btn" href="/setup">${escapeHtml(tr("deliveries.empty_setup"))}</a>\n      </div>\n    </div></td></tr>`;
  }
  tb.querySelectorAll("tr.deliv-row").forEach((row) => {
    if (deliveryState.expanded.has(row.dataset.deliveryKey)) {
      _insertDelivDetail(
        row.querySelector("[data-delivery-details]"),
        row,
        rows.find((item) => _deliveryKey(item) === row.dataset.deliveryKey),
      );
    }
  });
  updateDeliveriesPager();
}
function _hasDeliveryFilters() {
  return Boolean(
    ($("#deliv-filter")?.value || "").trim() ||
      $("#deliv-severity")?.value ||
      $("#deliv-channel")?.value ||
      $("#deliv-show-suppressed")?.checked === false,
  );
}
function _deliveryKey(row) {
  return [row.ts, row.source, row.severity, row.title, row.channel].join("\0");
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
    deliveryState.expanded.delete(row.dataset.deliveryKey);
    return;
  }
  deliveryState.expanded.add(row.dataset.deliveryKey);
  _insertDelivDetail(button, row, r);
}
function _insertDelivDetail(button, row, r) {
  if (!r || row.nextElementSibling?.classList.contains("deliv-detail")) return;
  const detail = document.createElement("tr");
  detail.classList.add("deliv-detail");
  const ts = new Date(r.ts * 1e3);
  const tsFull = ts.toISOString() + " (" + ts.toLocaleString() + ")";
  const rows = [
    ["timestamp", `<code>${escapeHtml(tsFull)}</code>`],
    ["source", `<code>${escapeHtml(r.source || "")}</code>`],
    ["severity", `<code>${escapeHtml(r.severity || "")}</code>`],
    ["title", `<code>${escapeHtml(r.title || "")}</code>`],
    ["channel", `<code>${escapeHtml(r.channel || "")}</code>`],
  ];
  if (r.suppressed_by)
    rows.push(["suppressed_by", `<code>${escapeHtml(r.suppressed_by)}</code>`]);
  if (r.emergency_receipt_id)
    rows.push([
      "emergency_receipt_id",
      `<code>${escapeHtml(r.emergency_receipt_id)}</code>`,
    ]);
  const html = rows
    .map(
      ([k, v]) =>
        `<div class="kv"><span class="kv-k">${k}</span><span class="kv-v">${v}</span></div>`,
    )
    .join("");
  detail.innerHTML = `<td colspan="6" class="deliv-detail-cell">${html}</td>`;
  row.insertAdjacentElement("afterend", detail);
  row.classList.add("expanded");
  button?.setAttribute("aria-expanded", "true");
}
function updateDeliveriesPager() {
  const total = deliveryState.page.total || 0;
  const limit = deliveryState.page.limit || deliveryPageSize();
  const offset = deliveryState.page.offset || 0;
  const pageCount = total ? Math.ceil(total / limit) : 1;
  const page = total ? Math.floor(offset / limit) + 1 : 0;
  const from = deliveryState.page.entries.length ? offset + 1 : 0;
  const to = deliveryState.page.entries.length ? offset + deliveryState.page.entries.length : 0;
  document.querySelectorAll("[data-deliveries-pager]").forEach((pager) => {
    const size = pager.querySelector("[data-deliv-page-size]");
    if (size) size.value = String(limit);
    const range = pager.querySelector("[data-deliv-range]");
    if (range)
      range.textContent = total
        ? tr("deliveries.showing_range", { from: from, to: to, total: total })
        : tr("deliveries.no_results");
    const info = pager.querySelector("[data-deliv-page-info]");
    if (info)
      info.textContent = total
        ? tr("logs.page_info", { page: page, pages: pageCount })
        : tr("logs.page_info_empty");
    pager
      .querySelectorAll('[data-deliv-page="first"], [data-deliv-page="prev"]')
      .forEach((button) => {
        button.disabled = offset <= 0;
      });
    pager
      .querySelectorAll('[data-deliv-page="next"], [data-deliv-page="last"]')
      .forEach((button) => {
        button.disabled = !total || offset + limit >= total;
      });
  });
}
function changeDeliveriesPage(direction) {
  const total = deliveryState.page.total || 0;
  const limit = deliveryState.page.limit || deliveryPageSize();
  if (!total) return;
  const lastOffset = Math.floor((total - 1) / limit) * limit;
  if (direction === "first") deliveryState.page.offset = 0;
  if (direction === "prev")
    deliveryState.page.offset = Math.max(0, deliveryState.page.offset - limit);
  if (direction === "next")
    deliveryState.page.offset = Math.min(lastOffset, deliveryState.page.offset + limit);
  if (direction === "last") deliveryState.page.offset = lastOffset;
  loadDeliv();
}
const scheduleDelivLoad = debounce(
  () => loadDeliv({ reset: true }),
  SEARCH_DEBOUNCE_MS,
);
onReady(() => {
  $("#deliv-filter")?.addEventListener("input", (e) => {
    if (!String(e.target?.value || "").trim()) {
      scheduleDelivLoad.cancel();
      loadDeliv({ reset: true });
      return;
    }
    scheduleDelivLoad();
  });
  $("#deliv-severity")?.addEventListener("change", () =>
    loadDeliv({ reset: true }),
  );
  $("#deliv-channel")?.addEventListener("change", (event) => {
    syncSuppressedFilterControls();
    loadDeliv({ reset: true });
  });
  $("#deliv-show-suppressed")?.addEventListener("change", (event) => {
    if (
      !event.target.checked &&
      $("#deliv-channel")?.value === "__suppressed__"
    ) {
      $("#deliv-channel").value = "";
    }
    syncSuppressedFilterControls();
    loadDeliv({ reset: true });
  });
  $("#deliv-export-csv")?.addEventListener("click", exportDeliveriesCsv);
  document.querySelectorAll("[data-deliv-page-size]").forEach((select) => {
    select.addEventListener("change", (event) => {
      document.querySelectorAll("[data-deliv-page-size]").forEach((peer) => {
        peer.value = event.target.value;
      });
      deliveryState.page.limit = deliveryPageSize();
      loadDeliv({ reset: true });
    });
  });
  document.querySelectorAll("[data-deliv-page]").forEach((button) => {
    button.addEventListener("click", () =>
      changeDeliveriesPage(button.dataset.delivPage),
    );
  });
  syncSuppressedFilterControls();
});
