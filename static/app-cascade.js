import {
  $, $$, J, applyTablePager, escapeHtml, fetchError, markTabDirty, notifyError, notifySuccess, queryGet,
  showTableRowPage, tr,
} from "./app.js";
import { loadStatus } from "./app-status.js";

const TIER_OPTS = ["ntfy", "telegram", "smtp"];
let casData = { tiers: [], default_enabled_for_webhook: false };

export async function loadCascade() {
  try {
    casData = await queryGet("cascade-config", "/api/cascade-config");
    renderCascadeTable();
    $("#cas-default").checked = !!casData.default_enabled_for_webhook;
  } catch (e) {
    fetchError("cascade", e);
  }
}

export function renderCascadeTable() {
  const tb = $("#t-cas tbody");
  tb.innerHTML = "";
  casData.tiers.forEach((tier, index) => addCasRow(tier.name, tier.timeout_seconds, index, { deferPager: true }));
  applyTablePager("t-cas", { reset: true });
}

function addCasRow(name = "ntfy", timeout = 5, idx = -1, opts = {}) {
  const tb = $("#t-cas tbody");
  const index = idx === -1 ? tb.children.length : idx;
  const row = document.createElement("tr");
  const tierOpts = TIER_OPTS
    .map(option => `<option ${option === name ? "selected" : ""}>${option}</option>`)
    .join("");
  row.innerHTML = `
    <td><span class="muted">${index + 1}</span> <button data-up title="${escapeHtml(tr("cascade.move_up"))}">↑</button><button data-dn title="${escapeHtml(tr("cascade.move_down"))}">↓</button></td>
    <td><select data-f="name">${tierOpts}</select></td>
    <td><input type="number" min="1" max="60" value="${timeout}" data-f="timeout"></td>
    <td><button class="danger" data-del>×</button></td>`;
  row.querySelector("[data-del]").addEventListener("click", () => {
    row.remove();
    renumberCas();
    applyTablePager("t-cas");
  });
  row.querySelector("[data-up]").addEventListener("click", () => {
    const previous = row.previousElementSibling;
    if (previous) tb.insertBefore(row, previous);
    renumberCas();
    showTableRowPage("t-cas", row);
  });
  row.querySelector("[data-dn]").addEventListener("click", () => {
    const next = row.nextElementSibling;
    if (next) tb.insertBefore(next, row);
    renumberCas();
    showTableRowPage("t-cas", row);
  });
  tb.appendChild(row);
  renumberCas();
  if (!opts.deferPager) applyTablePager("t-cas", { page: "last" });
}

function renumberCas() {
  $$("#t-cas tbody tr").forEach((row, index) => {
    const num = row.querySelector(".muted");
    if (num) num.textContent = index + 1;
  });
}

$("#btn-cas-add").addEventListener("click", () => addCasRow());
$("#btn-cas-save").addEventListener("click", async () => {
  const tiers = [];
  $$("#t-cas tbody tr").forEach(row => {
    const name = row.querySelector('[data-f="name"]').value;
    const timeout = parseInt(row.querySelector('[data-f="timeout"]').value, 10);
    if (name && timeout > 0) tiers.push({ name, timeout_seconds: timeout });
  });
  try {
    await J("/api/cascade-config", {
      method: "POST",
      body: JSON.stringify({ tiers, default_enabled_for_webhook: $("#cas-default").checked }),
      headers: { "Content-Type": "application/json" },
    });
    notifySuccess(tr("cascade.saved", { count: tiers.length }), { status: "#cas-status", clearMs: 3000 });
    markTabDirty("cascade", false);
    loadStatus();
  } catch (e) {
    notifyError("cascade-save", e, { status: "#cas-status" });
  }
});
