// Shared client-side pagination for finite UI tables.
// Rows stay in the DOM so save/export routines that collect table inputs still
// see every row, including rows outside the current page.
(function () {
  const tr = (key, vars = {}) => window.klaxondI18n?.t ? window.klaxondI18n.t(key, vars) : key;
  const escapeHtml = s => String(s).replace(/[&<>"']/g, c => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;",
  }[c]));

  const TABLE_PAGER_SIZES = [10, 25, 50, 100, 200];
  const TABLE_PAGER_CONFIG = {
    "t-deliv": { pageSize: 25, collapseDetails: true },
    "t-inhib-rules": { pageSize: 10 },
    "t-inhib": { pageSize: 10 },
    "t-acks": { pageSize: 10 },
    "t-schedules": { pageSize: 10 },
    "t-cas": { pageSize: 10 },
    "t-rc": { pageSize: 10 },
    "t-pol": { pageSize: 10 },
    "t-rules": { pageSize: 10 },
    "t-tokens": { pageSize: 10 },
    "t-passkeys": { pageSize: 10 },
    "t-channel-matrix": { pageSize: 10 },
  };
  const tablePagerState = new Map();

  function reapplyReadOnlyViewerMode() {
    if (!document.body.classList.contains("viewer-readonly")) return;
    if (typeof window.applyReadOnlyViewerMode === "function") {
      window.applyReadOnlyViewerMode(window.klaxondCurrentUser || {});
    }
  }

  function tablePagerStateFor(tableId) {
    if (!tablePagerState.has(tableId)) {
      const cfg = TABLE_PAGER_CONFIG[tableId] || {};
      tablePagerState.set(tableId, { page: 1, pageSize: cfg.pageSize || 25 });
    }
    return tablePagerState.get(tableId);
  }

  function ensureTablePager(tableId) {
    const table = document.getElementById(tableId);
    if (!table) return null;
    const state = tablePagerStateFor(tableId);
    let pager = document.querySelector(`[data-table-pager="${tableId}"]`);
    if (!pager) {
      pager = document.createElement("div");
      pager.className = "table-pager";
      pager.dataset.tablePager = tableId;
      pager.innerHTML = `
        <label class="table-pager-size">
          <span data-i18n="pager.page_size">${escapeHtml(tr("pager.page_size"))}</span>
          <select data-pager-size>
            ${TABLE_PAGER_SIZES.map(size => `<option value="${size}">${size}</option>`).join("")}
          </select>
        </label>
        <span data-pager-range class="muted"></span>
        <button class="btn" data-pager-first data-i18n-title="pager.first_page" title="${escapeHtml(tr("pager.first_page"))}" aria-label="${escapeHtml(tr("pager.first_page"))}">&lt;&lt;</button>
        <button class="btn" data-pager-prev data-i18n-title="pager.previous_page" title="${escapeHtml(tr("pager.previous_page"))}" aria-label="${escapeHtml(tr("pager.previous_page"))}">&lt;</button>
        <span data-pager-info class="muted"></span>
        <button class="btn" data-pager-next data-i18n-title="pager.next_page" title="${escapeHtml(tr("pager.next_page"))}" aria-label="${escapeHtml(tr("pager.next_page"))}">&gt;</button>
        <button class="btn" data-pager-last data-i18n-title="pager.last_page" title="${escapeHtml(tr("pager.last_page"))}" aria-label="${escapeHtml(tr("pager.last_page"))}">&gt;&gt;</button>`;
      const insertAfter = table.closest(".table-scroll") || table;
      insertAfter.insertAdjacentElement("afterend", pager);
      pager.querySelector("[data-pager-size]").addEventListener("change", e => {
        state.pageSize = parseInt(e.target.value, 10) || state.pageSize;
        state.page = 1;
        applyTablePager(tableId);
      });
      pager.querySelector("[data-pager-first]").addEventListener("click", () => { state.page = 1; applyTablePager(tableId); });
      pager.querySelector("[data-pager-prev]").addEventListener("click", () => { state.page -= 1; applyTablePager(tableId); });
      pager.querySelector("[data-pager-next]").addEventListener("click", () => { state.page += 1; applyTablePager(tableId); });
      pager.querySelector("[data-pager-last]").addEventListener("click", () => { state.page = Number.MAX_SAFE_INTEGER; applyTablePager(tableId); });
    }
    const size = pager.querySelector("[data-pager-size]");
    if (size) size.value = String(state.pageSize);
    return { table, pager, state };
  }

  function applyTablePager(tableId, opts = {}) {
    const ctx = ensureTablePager(tableId);
    if (!ctx) return;
    const { table, pager, state } = ctx;
    const body = table.tBodies[0];
    if (!body) return;
    const cfg = TABLE_PAGER_CONFIG[tableId] || {};
    if (cfg.collapseDetails) {
      body.querySelectorAll("tr.deliv-detail").forEach(row => row.remove());
      body.querySelectorAll("tr.expanded").forEach(row => row.classList.remove("expanded"));
    }
    const rows = Array.from(body.querySelectorAll("tr"));
    const emptyOnly = rows.length === 1
      && rows[0].children.length === 1
      && rows[0].children[0].hasAttribute("colspan");
    const total = emptyOnly ? 0 : rows.length;
    if (opts.reset) state.page = 1;
    if (opts.page === "last") state.page = Number.MAX_SAFE_INTEGER;
    if (total <= state.pageSize) {
      rows.forEach(row => { row.style.display = ""; });
      pager.hidden = true;
      reapplyReadOnlyViewerMode();
      return;
    }
    const pageCount = Math.max(1, Math.ceil(total / state.pageSize));
    state.page = Math.min(Math.max(1, state.page), pageCount);
    const start = (state.page - 1) * state.pageSize;
    const end = Math.min(start + state.pageSize, total);
    rows.forEach((row, idx) => {
      row.style.display = idx >= start && idx < end ? "" : "none";
    });
    pager.hidden = false;
    const range = pager.querySelector("[data-pager-range]");
    const info = pager.querySelector("[data-pager-info]");
    if (range) range.textContent = tr("pager.range", { from: start + 1, to: end, total });
    if (info) info.textContent = tr("pager.page_info", { page: state.page, pages: pageCount });
    pager.querySelector("[data-pager-first]").disabled = state.page <= 1;
    pager.querySelector("[data-pager-prev]").disabled = state.page <= 1;
    pager.querySelector("[data-pager-next]").disabled = state.page >= pageCount;
    pager.querySelector("[data-pager-last]").disabled = state.page >= pageCount;
    reapplyReadOnlyViewerMode();
  }

  function refreshTablePagers() {
    document.querySelectorAll("[data-table-pager]").forEach(pager => {
      if (pager.dataset.tablePager) applyTablePager(pager.dataset.tablePager);
    });
  }

  function showTableRowPage(tableId, row) {
    const table = document.getElementById(tableId);
    if (!table || !row) return;
    const rows = Array.from(table.tBodies[0]?.querySelectorAll("tr") || []);
    const idx = rows.indexOf(row);
    if (idx < 0) return;
    const state = tablePagerStateFor(tableId);
    state.page = Math.floor(idx / state.pageSize) + 1;
    applyTablePager(tableId);
  }

  window.KlaxondTablePager = Object.freeze({
    applyTablePager,
    refreshTablePagers,
    showTableRowPage,
  });
  window.applyTablePager = applyTablePager;
  window.refreshTablePagers = refreshTablePagers;
  window.showTableRowPage = showTableRowPage;
})();
