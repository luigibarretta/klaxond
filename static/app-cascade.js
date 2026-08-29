import {
  $, $$, J, applyTablePager, confirmDialog, escapeHtml, fetchError, markTabDirty, notifyError, notifySuccess,
  notifyValidationError, queryGet, showTableRowPage, showToast, tr,
} from "./app.js";
import { loadStatus } from "./app-status.js";

const TIER_OPTS = ["ntfy", "telegram", "smtp"];
const FALLBACK_TIMEOUT_POLICY = {
  min_seconds: 1,
  max_seconds: 60,
  recommended_seconds: { ntfy: 15, telegram: 8, smtp: 10 },
  warning_below_seconds: { ntfy: 15 },
};
let casData = {
  tiers: [],
  default_enabled_for_webhook: false,
  timeout_policy: FALLBACK_TIMEOUT_POLICY,
};

export async function loadCascade() {
  try {
    casData = await queryGet("cascade-config", "/api/cascade-config");
    casData.timeout_policy = {
      ...FALLBACK_TIMEOUT_POLICY,
      ...(casData.timeout_policy || {}),
      recommended_seconds: {
        ...FALLBACK_TIMEOUT_POLICY.recommended_seconds,
        ...(casData.timeout_policy?.recommended_seconds || {}),
      },
      warning_below_seconds: {
        ...FALLBACK_TIMEOUT_POLICY.warning_below_seconds,
        ...(casData.timeout_policy?.warning_below_seconds || {}),
      },
    };
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
  updateTimeoutWarnings();
}

function addCasRow(name = "ntfy", timeout = null, idx = -1, opts = {}) {
  const tb = $("#t-cas tbody");
  const index = idx === -1 ? tb.children.length : idx;
  const policy = casData.timeout_policy;
  const selectedTimeout = timeout ?? policy.recommended_seconds[name] ?? 5;
  const row = document.createElement("tr");
  const tierOpts = TIER_OPTS
    .map(option => `<option ${option === name ? "selected" : ""}>${option}</option>`)
    .join("");
  row.innerHTML = `
    <td><span class="muted">${index + 1}</span> <button data-up title="${escapeHtml(tr("cascade.move_up"))}">↑</button><button data-dn title="${escapeHtml(tr("cascade.move_down"))}">↓</button></td>
    <td><select data-f="name">${tierOpts}</select></td>
    <td><input type="number" min="${policy.min_seconds}" max="${policy.max_seconds}" value="${selectedTimeout}" data-f="timeout" aria-describedby="cas-timeout-help cas-timeout-risk"></td>
    <td><button class="danger" data-del>×</button></td>`;
  row.querySelector('[data-f="name"]').addEventListener("change", updateTimeoutWarnings);
  row.querySelector('[data-f="timeout"]').addEventListener("input", updateTimeoutWarnings);
  row.querySelector("[data-del]").addEventListener("click", () => {
    row.remove();
    renumberCas();
    applyTablePager("t-cas");
    updateTimeoutWarnings();
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
  updateTimeoutWarnings();
}

function renumberCas() {
  $$("#t-cas tbody tr").forEach((row, index) => {
    const num = row.querySelector(".muted");
    if (num) num.textContent = index + 1;
  });
}

function cascadeRows() {
  return Array.from($$("#t-cas tbody tr")).map(row => {
    const input = row.querySelector('[data-f="timeout"]');
    return {
      name: row.querySelector('[data-f="name"]').value,
      input,
      timeout: Number(input.value),
    };
  });
}

function riskyNtfyRows() {
  const threshold = casData.timeout_policy.warning_below_seconds.ntfy;
  return cascadeRows().filter(row =>
    row.name === "ntfy" && Number.isInteger(row.timeout) && row.timeout < threshold
  );
}

function updateTimeoutWarnings() {
  const rows = cascadeRows();
  const risky = riskyNtfyRows();
  const threshold = casData.timeout_policy.warning_below_seconds.ntfy;
  rows.forEach(row => row.input.classList.toggle(
    "input-warning",
    row.name === "ntfy" && Number.isInteger(row.timeout) && row.timeout < threshold
  ));
  const notice = $("#cas-timeout-risk");
  notice.classList.toggle("hidden", risky.length === 0);
  if (risky.length) {
    notice.textContent = tr("cascade.timeout_risk", {
      timeout: Math.min(...risky.map(row => row.timeout)),
      recommended: casData.timeout_policy.warning_below_seconds.ntfy,
    });
  }
}

$("#btn-cas-add").addEventListener("click", () => addCasRow());
$("#btn-cas-save").addEventListener("click", async () => {
  const rows = cascadeRows();
  const { min_seconds: min, max_seconds: max } = casData.timeout_policy;
  const invalid = rows.find(row =>
    !Number.isInteger(row.timeout) || row.timeout < min || row.timeout > max
  );
  if (!rows.length || invalid) {
    notifyValidationError(
      "cascade-timeout",
      tr("cascade.timeout_invalid", { min, max }),
      $("#cas-status")
    );
    invalid?.input.focus();
    return;
  }
  const risky = riskyNtfyRows();
  if (risky.length && !await confirmDialog(tr("cascade.low_timeout_confirm", {
    timeout: Math.min(...risky.map(row => row.timeout)),
    recommended: casData.timeout_policy.warning_below_seconds.ntfy,
  }), { title: tr("cascade.timeout_risk_title"), confirmLabel: tr("common.save_changes") })) return;
  const tiers = rows.map(row => ({ name: row.name, timeout_seconds: row.timeout }));
  try {
    const response = await J("/api/cascade-config", {
      method: "POST",
      body: JSON.stringify({ tiers, default_enabled_for_webhook: $("#cas-default").checked }),
      headers: { "Content-Type": "application/json" },
    });
    notifySuccess(tr("cascade.saved", { count: tiers.length }), { status: "#cas-status", clearMs: 3000 });
    if (response.warnings?.length) {
      showToast(tr("cascade.saved_with_warning"), "warn", 7000);
    }
    markTabDirty("cascade", false);
    loadStatus();
  } catch (e) {
    notifyError("cascade-save", e, { status: "#cas-status" });
  }
});
