import {
  $, SEARCH_DEBOUNCE_MS, errorText, escapeHtml, fetchError, isAbortError,
  onReady, queryGet, tr,
} from "./app.js";
// ---- Audit log ----
let _auditCache = { entries: [], total: 0, limit: 50, offset: 0 };
let _auditOffset = 0;
let _auditFilterTimer = null;
let _auditRequestSeq = 0;

function auditPageSize() {
  const raw = parseInt($("#audit-limit")?.value || "50", 10);
  if (!Number.isFinite(raw)) return 50;
  return Math.max(1, Math.min(raw, 500));
}

export async function loadAudit(opts = {}) {
  clearTimeout(_auditFilterTimer);
  _auditFilterTimer = null;
  if (opts.reset) _auditOffset = 0;
  const params = new URLSearchParams();
  const q = ($("#audit-filter")?.value || "").trim();
  const limit = auditPageSize();
  if (q) params.set("q", q);
  params.set("limit", String(limit));
  params.set("offset", String(Math.max(0, _auditOffset)));
  const requestSeq = ++_auditRequestSeq;
  try {
    const payload = await queryGet("audit", "/api/audit?" + params.toString(), { force: opts.force });
    if (requestSeq !== _auditRequestSeq) return;
    _auditCache = payload;
    _auditOffset = payload.offset || 0;
    renderAudit();
  } catch (e) {
    if (isAbortError(e)) return;
    if (requestSeq !== _auditRequestSeq) return;
    fetchError("audit", e);
    _auditCache = { entries: [], total: 0, limit: auditPageSize(), offset: 0 };
    _auditOffset = 0;
    const tb = $("#t-audit tbody");
    if (tb) tb.innerHTML = `<tr><td colspan="5" class="muted">${escapeHtml(tr("common.error"))}: ${escapeHtml(errorText(e))}</td></tr>`;
    const count = $("#audit-count");
    if (count) count.textContent = "";
    updateAuditPager();
  }
}

function renderAudit() {
  const tb = $("#t-audit tbody"); if (!tb) return;
  const entries = _auditCache.entries || [];
  tb.innerHTML = "";
  for (const entry of entries) {
    const row = document.createElement("tr");
    const outcome = String(entry.outcome || "").toLowerCase();
    row.innerHTML = `
      <td class="log-time">${escapeHtml(new Date((entry.ts || 0) * 1000).toLocaleString())}</td>
      <td><code>${escapeHtml(entry.actor || "")}</code></td>
      <td><code>${escapeHtml(entry.action || "")}</code></td>
      <td><span class="log-level ${outcome === "ok" ? "info" : "error"}">${escapeHtml(entry.outcome || "")}</span></td>
      <td class="log-message">${escapeHtml(entry.detail || "")}</td>`;
    tb.appendChild(row);
  }
  if (!entries.length) {
    tb.innerHTML = `<tr><td colspan="5" class="muted">${escapeHtml(tr("audit.empty"))}</td></tr>`;
  }
  const count = $("#audit-count");
  const total = _auditCache.total || 0;
  const offset = _auditCache.offset || 0;
  const from = entries.length ? offset + 1 : 0;
  const to = entries.length ? offset + entries.length : 0;
  if (count) count.textContent = tr("audit.showing_range", { from, to, total });
  updateAuditPager();
}

function updateAuditPager() {
  const total = _auditCache.total || 0;
  const limit = _auditCache.limit || auditPageSize();
  const offset = _auditCache.offset || 0;
  const pageCount = total ? Math.ceil(total / limit) : 1;
  const page = total ? Math.floor(offset / limit) + 1 : 0;
  const info = $("#audit-page-info");
  if (info) info.textContent = total ? tr("logs.page_info", { page, pages: pageCount }) : tr("logs.page_info_empty");
  const atStart = offset <= 0;
  const atEnd = !total || offset + limit >= total;
  $("#audit-first") && ($("#audit-first").disabled = atStart);
  $("#audit-prev") && ($("#audit-prev").disabled = atStart);
  $("#audit-next") && ($("#audit-next").disabled = atEnd);
  $("#audit-last") && ($("#audit-last").disabled = atEnd);
}

function scheduleAuditLoad() {
  _auditRequestSeq++;
  clearTimeout(_auditFilterTimer);
  const q = ($("#audit-filter")?.value || "").trim();
  if (!q) {
    loadAudit({ reset: true });
    return;
  }
  _auditFilterTimer = setTimeout(() => loadAudit({ reset: true }), SEARCH_DEBOUNCE_MS);
}

function changeAuditPage(direction) {
  const total = _auditCache.total || 0;
  const limit = _auditCache.limit || auditPageSize();
  if (!total) return;
  const lastOffset = Math.floor((total - 1) / limit) * limit;
  if (direction === "first") _auditOffset = 0;
  if (direction === "prev") _auditOffset = Math.max(0, (_auditCache.offset || 0) - limit);
  if (direction === "next") _auditOffset = Math.min(lastOffset, (_auditCache.offset || 0) + limit);
  if (direction === "last") _auditOffset = lastOffset;
  loadAudit();
}

onReady(() => {
  $("#audit-refresh")?.addEventListener("click", () => loadAudit({ force: true }));
  $("#audit-filter")?.addEventListener("input", scheduleAuditLoad);
  $("#audit-limit")?.addEventListener("change", () => loadAudit({ reset: true }));
  $("#audit-first")?.addEventListener("click", () => changeAuditPage("first"));
  $("#audit-prev")?.addEventListener("click", () => changeAuditPage("prev"));
  $("#audit-next")?.addEventListener("click", () => changeAuditPage("next"));
  $("#audit-last")?.addEventListener("click", () => changeAuditPage("last"));
});
