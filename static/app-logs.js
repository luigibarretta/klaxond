import {
  $, SEARCH_DEBOUNCE_MS, errorText, escapeHtml, fetchError, fetchOk, isAbortError,
  onReady, queryGet, tr,
} from "./app.js";

let logsPage = { entries: [], total: 0, limit: 100, offset: 0 };
let logsOffset = 0;
let filterTimer = null;
let autoRefreshTimer = null;
let requestSequence = 0;

function pageSize() {
  const raw = parseInt($("#logs-limit")?.value || "100", 10);
  if (!Number.isFinite(raw)) return 100;
  return Math.max(1, Math.min(raw, 500));
}

export async function loadLogs(opts = {}) {
  clearTimeout(filterTimer);
  filterTimer = null;
  if (opts.reset) logsOffset = 0;
  const params = new URLSearchParams();
  const query = ($("#logs-filter")?.value || "").trim();
  const level = $("#logs-level")?.value || "all";
  const limit = pageSize();
  if (query) params.set("q", query);
  if (level && level !== "all") params.set("level", level);
  params.set("limit", String(limit));
  params.set("offset", String(Math.max(0, logsOffset)));
  const sequence = ++requestSequence;
  try {
    const payload = await queryGet("logs", `/api/logs?${params}`, { force: opts.force });
    if (sequence !== requestSequence) return;
    logsPage = payload;
    logsOffset = payload.offset || 0;
    fetchOk("logs");
    renderLogs();
  } catch (error) {
    if (isAbortError(error) || sequence !== requestSequence) return;
    fetchError("logs", error);
    const body = $("#t-logs tbody");
    if (body) body.innerHTML = `<tr><td colspan="4" class="muted">${escapeHtml(tr("common.error"))}: ${escapeHtml(errorText(error))}</td></tr>`;
    const count = $("#logs-count");
    if (count) count.textContent = "";
    updatePager();
  }
}

function renderLogs() {
  const body = $("#t-logs tbody");
  if (!body) return;
  const entries = logsPage.entries || [];
  body.innerHTML = "";
  for (const entry of entries) {
    const row = document.createElement("tr");
    const level = (entry.level || "").toLowerCase();
    const fields = entry.fields && Object.keys(entry.fields).length
      ? "\n" + Object.entries(entry.fields)
          .sort(([a], [b]) => a.localeCompare(b))
          .map(([key, value]) => `${key}=${value}`)
          .join(" ")
      : "";
    const target = entry.line ? `${entry.target}:${entry.line}` : entry.target;
    row.innerHTML = `
      <td class="log-time">${escapeHtml(new Date((entry.ts || 0) * 1000).toLocaleString())}</td>
      <td><span class="log-level ${escapeHtml(level)}">${escapeHtml(entry.level || "")}</span></td>
      <td class="log-target">${escapeHtml(target || "")}</td>
      <td class="log-message">${escapeHtml((entry.message || "") + fields)}</td>`;
    body.appendChild(row);
  }
  if (!entries.length) {
    body.innerHTML = `<tr><td colspan="4" class="muted">${escapeHtml(tr("logs.empty"))}</td></tr>`;
  }
  const total = logsPage.total || 0;
  const offset = logsPage.offset || 0;
  const from = entries.length ? offset + 1 : 0;
  const to = entries.length ? offset + entries.length : 0;
  const count = $("#logs-count");
  if (count) count.textContent = tr("logs.showing_range", { from, to, total });
  updatePager();
}

function updatePager() {
  const total = logsPage.total || 0;
  const limit = logsPage.limit || pageSize();
  const offset = logsPage.offset || 0;
  const pages = total ? Math.ceil(total / limit) : 1;
  const page = total ? Math.floor(offset / limit) + 1 : 0;
  const info = $("#logs-page-info");
  if (info) info.textContent = total ? tr("logs.page_info", { page, pages }) : tr("logs.page_info_empty");
  const atStart = offset <= 0;
  const atEnd = !total || offset + limit >= total;
  if ($("#logs-first")) $("#logs-first").disabled = atStart;
  if ($("#logs-prev")) $("#logs-prev").disabled = atStart;
  if ($("#logs-next")) $("#logs-next").disabled = atEnd;
  if ($("#logs-last")) $("#logs-last").disabled = atEnd;
}

function scheduleLoad() {
  requestSequence++;
  clearTimeout(filterTimer);
  const query = ($("#logs-filter")?.value || "").trim();
  if (!query) {
    loadLogs({ reset: true });
    return;
  }
  filterTimer = setTimeout(() => loadLogs({ reset: true }), SEARCH_DEBOUNCE_MS);
}

function changePage(direction) {
  const total = logsPage.total || 0;
  const limit = logsPage.limit || pageSize();
  if (!total) return;
  const lastOffset = Math.floor((total - 1) / limit) * limit;
  if (direction === "first") logsOffset = 0;
  if (direction === "prev") logsOffset = Math.max(0, (logsPage.offset || 0) - limit);
  if (direction === "next") logsOffset = Math.min(lastOffset, (logsPage.offset || 0) + limit);
  if (direction === "last") logsOffset = lastOffset;
  loadLogs();
}

function updateAutoRefresh() {
  clearInterval(autoRefreshTimer);
  autoRefreshTimer = null;
  if ($("#logs-autorefresh")?.checked) {
    autoRefreshTimer = setInterval(() => {
      if ($("#tab-logs")?.classList.contains("active")) loadLogs({ force: true });
    }, 5000);
  }
}

document.addEventListener("click", event => {
  if (!event.target.closest?.("#logs-refresh")) return;
  event.preventDefault();
  loadLogs({ force: true });
});

onReady(() => {
  $("#logs-filter")?.addEventListener("input", scheduleLoad);
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
  $("#logs-first")?.addEventListener("click", () => changePage("first"));
  $("#logs-prev")?.addEventListener("click", () => changePage("prev"));
  $("#logs-next")?.addEventListener("click", () => changePage("next"));
  $("#logs-last")?.addEventListener("click", () => changePage("last"));
  $("#logs-autorefresh")?.addEventListener("change", updateAutoRefresh);
  updateAutoRefresh();
});

export { loadAudit } from "./app-audit-log.js";
