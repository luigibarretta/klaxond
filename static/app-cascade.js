import {
  $, $$, J, applyTablePager, confirmDialog, escapeHtml, fetchError, notifyError, notifySuccess,
  notifyValidationError, queryGet, showTableRowPage, showToast, tr,
} from "./app.js";
import { loadStatus } from "./app-status.js";
import { iconButton, refreshDeliveryIcons } from "./app-delivery-editor.js";
import { deliverySectionRevision, markDeliverySectionDirty } from "./app-delivery-state.js";

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
let cascadeSaveInFlight = false;

export async function loadCascade() {
  const requestedRevision = deliverySectionRevision("cascade");
  try {
    const nextData = await queryGet("cascade-config", "/api/cascade-config");
    if (deliverySectionRevision("cascade") !== requestedRevision) return;
    casData = nextData;
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
    fetchError("delivery-cascade", e);
  }
}

export function renderCascadeTable() {
  const tb = $("#t-cas tbody");
  tb.innerHTML = "";
  casData.tiers.forEach((tier, index) => addCasRow(tier.name, tier.timeout_seconds, index, { deferPager: true }));
  applyTablePager("t-cas", { reset: true });
  updateTimeoutWarnings();
  renderCascadeDiagram();
}

function addCasRow(name = "ntfy", timeout = null, idx = -1, opts = {}) {
  const tb = $("#t-cas tbody");
  const index = idx === -1 ? tb.children.length : idx;
  const policy = casData.timeout_policy;
  const selectedTimeout = timeout ?? policy.recommended_seconds[name] ?? 5;
  const row = document.createElement("tr");
  row.innerHTML = cascadeRowMarkup(name, selectedTimeout, index, policy);
  bindCascadeFields(row);
  bindCascadeActions(row, tb);
  tb.appendChild(row);
  refreshCascadeEditor(opts);
}

function cascadeRowMarkup(name, timeout, index, policy) {
  const tierOptions = TIER_OPTS
    .map(option => `<option ${option === name ? "selected" : ""}>${option}</option>`)
    .join("");
  return `
    <td data-label="${escapeHtml(tr("delivery.rule_priority"))}"><span class="muted" data-tier-position>${index + 1}</span><span class="rule-order-actions">${iconButton("up", "arrow-up", tr("cascade.move_up"))}${iconButton("down", "arrow-down", tr("cascade.move_down"))}</span></td>
    <td data-label="${escapeHtml(tr("common.channel"))}"><select data-f="name">${tierOptions}</select></td>
    <td data-label="${escapeHtml(tr("cascade.timeout"))}"><input type="number" min="${policy.min_seconds}" max="${policy.max_seconds}" value="${timeout}" data-f="timeout" aria-describedby="cas-timeout-help cas-timeout-risk"></td>
    <td data-label="${escapeHtml(tr("common.actions"))}">${iconButton("delete", "trash-2", tr("common.delete"), "danger")}</td>`;
}

function bindCascadeFields(row) {
  row.querySelector('[data-f="name"]').addEventListener("change", () => {
    renumberCas();
    updateTimeoutWarnings();
    renderCascadeDiagram();
    markDeliverySectionDirty("cascade");
  });
  row.querySelector('[data-f="timeout"]').addEventListener("input", () => {
    updateTimeoutWarnings();
    renderCascadeDiagram();
    markDeliverySectionDirty("cascade");
  });
}

function bindCascadeActions(row, tableBody) {
  row.querySelector('[data-action="delete"]').addEventListener("click", () => removeCascadeRow(row, tableBody));
  row.querySelector('[data-action="up"]').addEventListener("click", event => {
    moveCascadeRow(row, tableBody, -1, event.currentTarget);
  });
  row.querySelector('[data-action="down"]').addEventListener("click", event => {
    moveCascadeRow(row, tableBody, 1, event.currentTarget);
  });
}

async function removeCascadeRow(row, tableBody) {
  const position = [...tableBody.children].indexOf(row) + 1;
  const channel = row.querySelector('[data-f="name"]').value;
  if (!await confirmDialog(tr("cascade.delete_tier_confirm", { position, channel }), {
    title: tr("cascade.delete_tier_title"), confirmLabel: tr("common.delete"), danger: true,
  })) return;
  const focusTarget = row.nextElementSibling || row.previousElementSibling;
  row.remove();
  renumberCas();
  applyTablePager("t-cas");
  updateTimeoutWarnings();
  renderCascadeDiagram();
  markDeliverySectionDirty("cascade");
  (focusTarget?.querySelector('[data-f="name"]') || $("#btn-cas-add"))?.focus();
}

function moveCascadeRow(row, tableBody, direction, button) {
  const sibling = direction < 0 ? row.previousElementSibling : row.nextElementSibling;
  if (!sibling) return;
  if (direction < 0) tableBody.insertBefore(row, sibling);
  else tableBody.insertBefore(sibling, row);
  renumberCas();
  showTableRowPage("t-cas", row);
  renderCascadeDiagram();
  markDeliverySectionDirty("cascade");
  const fallback = row.querySelector(`[data-action="${direction < 0 ? "down" : "up"}"]`);
  (button.disabled ? fallback : button)?.focus();
  const position = [...tableBody.children].indexOf(row) + 1;
  $("#cas-status").textContent = tr("cascade.tier_moved", { position });
}

function refreshCascadeEditor(opts) {
  renumberCas();
  refreshDeliveryIcons();
  if (!opts.deferPager) applyTablePager("t-cas", { page: "last" });
  updateTimeoutWarnings();
  renderCascadeDiagram();
}

function renderCascadeDiagram() {
  const target = $("#cascade-diagram");
  if (!target) return;
  const rows = cascadeRows();
  const path = rows.map(row => `${row.name} (${row.timeout}s)`);
  target.setAttribute("aria-label", tr("delivery.cascade_diagram_label", {
    path: path.join(" → "),
  }));
  target.innerHTML = rows.map((row, index) => `
    ${index ? '<span class="cascade-arrow" aria-hidden="true">→</span>' : ""}
    <span class="cascade-node">
      <strong>${escapeHtml(row.name)}</strong>
      <small>${escapeHtml(String(row.timeout))}s</small>
    </span>`).join("");
}

function renumberCas() {
  const rows = $$("#t-cas tbody tr");
  rows.forEach((row, index) => {
    const position = index + 1;
    const channel = row.querySelector('[data-f="name"]');
    row.querySelector("[data-tier-position]").textContent = position;
    channel.setAttribute("aria-label", tr("cascade.tier_channel_label", { position }));
    row.querySelector('[data-f="timeout"]').setAttribute("aria-label", tr("cascade.tier_timeout_label", { position }));
    row.querySelector('[data-action="up"]').disabled = index === 0;
    row.querySelector('[data-action="down"]').disabled = index === rows.length - 1;
    const remove = row.querySelector('[data-action="delete"]');
    remove.disabled = rows.length === 1;
    remove.setAttribute("aria-label", tr("cascade.tier_remove_label", { position, channel: channel.value }));
    remove.title = remove.getAttribute("aria-label");
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

$("#btn-cas-add").addEventListener("click", () => {
  addCasRow();
  markDeliverySectionDirty("cascade");
});
$("#cas-default").addEventListener("change", () => markDeliverySectionDirty("cascade"));
$("#btn-cas-save").addEventListener("click", async () => {
  if (cascadeSaveInFlight) return;
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
    if (invalid) showTableRowPage("t-cas", invalid.input.closest("tr"));
    invalid?.input.focus();
    return;
  }
  const risky = riskyNtfyRows();
  if (risky.length && !await confirmDialog(tr("cascade.low_timeout_confirm", {
    timeout: Math.min(...risky.map(row => row.timeout)),
    recommended: casData.timeout_policy.warning_below_seconds.ntfy,
  }), { title: tr("cascade.timeout_risk_title"), confirmLabel: tr("common.save_changes") })) return;
  const tiers = rows.map(row => ({ name: row.name, timeout_seconds: row.timeout }));
  const savedRevision = deliverySectionRevision("cascade");
  const saveButton = $("#btn-cas-save");
  cascadeSaveInFlight = true;
  saveButton.disabled = true;
  try {
    const response = await J("/api/cascade-config", {
      method: "POST",
      body: JSON.stringify({ tiers, default_enabled_for_webhook: $("#cas-default").checked }),
      headers: { "Content-Type": "application/json" },
    });
    const hasNewerChanges = deliverySectionRevision("cascade") !== savedRevision;
    notifySuccess(tr(hasNewerChanges ? "cascade.saved_newer_changes" : "cascade.saved", {
      count: tiers.length,
    }), { status: "#cas-status", clearMs: 3000 });
    if (response.warnings?.length) {
      showToast(tr("cascade.saved_with_warning"), "warn", 7000);
    }
    if (!hasNewerChanges) markDeliverySectionDirty("cascade", false);
    document.dispatchEvent(new CustomEvent("klaxond:cascade-saved", { detail: { tiers } }));
    loadStatus();
  } catch (e) {
    notifyError("cascade-save", e, { status: "#cas-status" });
  } finally {
    cascadeSaveInFlight = false;
    saveButton.disabled = false;
  }
});
