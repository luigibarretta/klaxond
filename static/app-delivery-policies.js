import {
  $, $$, applyTablePager, confirmDialog, escapeHtml, notifyValidationError,
  setInlineStatus, showTableRowPage, tr,
} from "./app.js";
import {
  appendPolicyTier, iconButton, refreshDeliveryIcons, refreshPolicyTierRows,
  tierSummary,
} from "./app-delivery-editor.js";
import { markDeliverySectionDirty } from "./app-delivery-state.js";
import { refreshRulePolicySelectors } from "./app-delivery-rules.js";

function policyNames(data) {
  return ["cascade", ...data.policies.map(policy => policy.name)];
}

export function renderDeliveryDefault(data) {
  const select = $("#d-default-policy");
  if (!select) return;
  select.innerHTML = policyNames(data)
    .map(name => `<option ${name === data.default_policy ? "selected" : ""}>${escapeHtml(name)}</option>`)
    .join("");
}

export function renderPoliciesTable(data) {
  const body = $("#t-pol tbody");
  body.innerHTML = "";
  addBuiltInPolicyRow(data, body);
  data.policies.forEach(policy => addPolicyRow(data, policy, true));
  refreshPolicyRows();
  applyTablePager("t-pol", { reset: true });
}

function addBuiltInPolicyRow(data, body) {
  const tiers = data.legacy_cascade_tiers || [];
  const row = document.createElement("tr");
  row.className = "policy-built-in";
  row.innerHTML = `
    <td data-label="${escapeHtml(tr("common.name"))}"><code>cascade</code> <span class="policy-badge">${escapeHtml(tr("delivery.builtin"))}</span></td>
    <td data-label="${escapeHtml(tr("common.mode"))}"><span class="mode-badge mode-cascade">cascade</span></td>
    <td data-label="${escapeHtml(tr("delivery.tiers_order"))}">${tierSummary(tiers)}</td>
    <td data-label="${escapeHtml(tr("common.actions"))}"><button type="button" data-edit-cascade><i data-lucide="settings-2" aria-hidden="true"></i>${escapeHtml(tr("delivery.configure_cascade"))}</button></td>`;
  row.querySelector("[data-edit-cascade]").addEventListener("click", focusCascadeEditor);
  body.appendChild(row);
  refreshDeliveryIcons();
}

function focusCascadeEditor() {
  const section = $("#delivery-cascade-section");
  section?.scrollIntoView({ behavior: "smooth", block: "start" });
  section?.focus({ preventScroll: true });
}

export function addPolicyRow(data, policy = {}, deferPager = false) {
  const body = $("#t-pol tbody");
  const row = document.createElement("tr");
  const name = policy.name || nextPolicyName();
  row.dataset.policyCustom = "";
  row.dataset.policyName = name;
  row.innerHTML = policyRowMarkup(name, policy.mode || "cascade");
  const editor = row.querySelector('[data-f="tiers"]');
  const tiers = policy.tiers?.length ? policy.tiers : [{ name: "ntfy", timeout_seconds: 15 }];
  tiers.forEach(tier => appendPolicyTier(editor, tier, availableTierNames(data), markPoliciesDirty));
  bindPolicyRow(data, row, editor);
  body.appendChild(row);
  if (!deferPager) collectPoliciesFromTable(data);
  refreshPolicyEditor(data, row);
  if (!deferPager) applyTablePager("t-pol", { page: "last" });
}

function nextPolicyName() {
  const names = new Set(Array.from($$("#t-pol tbody tr[data-policy-custom]"), row =>
    row.querySelector('[data-f="name"]').value.trim() || row.dataset.policyName
  ));
  let suffix = 1;
  while (names.has(suffix === 1 ? "new-policy" : `new-policy-${suffix}`)) suffix += 1;
  return suffix === 1 ? "new-policy" : `new-policy-${suffix}`;
}

function policyRowMarkup(name, mode) {
  return `
    <td data-label="${escapeHtml(tr("common.name"))}"><input type="text" required maxlength="64" value="${escapeHtml(name)}" data-f="name"><small class="field-error hidden" data-policy-error role="alert"></small></td>
    <td data-label="${escapeHtml(tr("common.mode"))}"><select data-f="mode">
      <option value="cascade" ${mode === "cascade" ? "selected" : ""}>cascade</option>
      <option value="broadcast" ${mode === "broadcast" ? "selected" : ""}>broadcast</option>
    </select><small class="muted" data-mode-help></small></td>
    <td data-label="${escapeHtml(tr("delivery.tiers_order"))}"><div class="policy-tier-editor" data-f="tiers"></div><button type="button" class="policy-tier-add">${escapeHtml(tr("cascade.add_tier"))}</button></td>
    <td data-label="${escapeHtml(tr("common.actions"))}">${iconButton("delete-policy", "trash-2", tr("common.delete"), "danger")}</td>`;
}

function bindPolicyRow(data, row, editor) {
  row.querySelector('[data-action="delete-policy"]').addEventListener("click", () => removePolicyRow(data, row));
  row.querySelector('[data-f="name"]').addEventListener("input", () => {
    showPolicyError(row);
    refreshPolicyRows();
    markPoliciesDirty();
  });
  row.querySelector('[data-f="name"]').addEventListener("change", () => renamePolicy(data, row));
  row.querySelector('[data-f="mode"]').addEventListener("change", () => {
    updateModeHelp(row);
    markPoliciesDirty();
  });
  row.querySelector(".policy-tier-add").addEventListener("click", () => {
    appendPolicyTier(editor, { name: "ntfy", timeout_seconds: 15 }, availableTierNames(data), markPoliciesDirty);
    refreshPolicyRows();
    markPoliciesDirty();
  });
}

function renamePolicy(data, row) {
  const previousName = row.dataset.policyName;
  const nextName = row.querySelector('[data-f="name"]').value.trim();
  if (!isAvailablePolicyName(row, nextName)) return;
  row.dataset.policyName = nextName;
  collectPoliciesFromTable(data);
  if (data.default_policy === previousName) data.default_policy = nextName || "cascade";
  renderDeliveryDefault(data);
  refreshRulePolicySelectors(data, { previousName, nextName });
  refreshPolicyRows();
  markPoliciesDirty();
}

function isAvailablePolicyName(row, name) {
  if (!name || name === "cascade") return false;
  return !Array.from($$("#t-pol tbody tr[data-policy-custom]")).some(candidate =>
    candidate !== row && candidate.querySelector('[data-f="name"]').value.trim() === name
  );
}

function refreshPolicyEditor(data, row) {
  updateModeHelp(row);
  refreshPolicyRows();
  refreshDeliveryIcons();
  renderDeliveryDefault(data);
  refreshRulePolicySelectors(data);
}

function availableTierNames(data) {
  return data.available_tiers?.length ? data.available_tiers : ["ntfy", "telegram", "smtp"];
}

function markPoliciesDirty() {
  markDeliverySectionDirty("policies");
}

function updateModeHelp(row) {
  const mode = row.querySelector('[data-f="mode"]').value;
  row.querySelector("[data-mode-help]").textContent = tr(`delivery.${mode}_summary`);
}

function policyReferences(name) {
  const references = [];
  if ($("#d-default-policy").value === name) references.push(tr("delivery.reference_default"));
  $$("#t-rules tbody tr").forEach((row, index) => {
    if (row.querySelector('[data-f="policy"]').value === name) {
      references.push(tr("delivery.reference_rule", { position: index + 1 }));
    }
  });
  return references;
}

async function removePolicyRow(data, row) {
  const draftName = row.querySelector('[data-f="name"]').value.trim();
  const referenceName = row.dataset.policyName || draftName;
  const name = draftName || referenceName || tr("delivery.unnamed_policy");
  const references = policyReferences(referenceName);
  if (references.length) return showPolicyInUse(name, referenceName, references);
  if (!await confirmDialog(tr("delivery.delete_policy_confirm", { name }), {
    title: tr("delivery.delete_policy_title"), confirmLabel: tr("common.delete"), danger: true,
  })) return;
  const focusTarget = row.nextElementSibling?.querySelector('[data-f="name"]')
    || row.previousElementSibling?.querySelector('[data-f="name"]') || $("#btn-pol-add");
  row.remove();
  collectPoliciesFromTable(data);
  refreshPolicyRows();
  renderDeliveryDefault(data);
  refreshRulePolicySelectors(data);
  applyTablePager("t-pol");
  markPoliciesDirty();
  focusTarget?.focus();
  setInlineStatus("#delivery-status", tr("delivery.policy_removed", { name }));
}

function showPolicyInUse(name, referenceName, references) {
  notifyValidationError("delivery-policy-in-use", tr("delivery.delete_policy_in_use", {
    name, references: references.join(", "),
  }), $("#delivery-status"));
  const target = $("#d-default-policy").value === referenceName
    ? $("#d-default-policy")
    : Array.from($$("#t-rules select[data-f='policy']")).find(
      select => select.value === referenceName
    );
  if (target?.closest("#t-rules")) showTableRowPage("t-rules", target.closest("tr"));
  target?.focus();
}

function refreshPolicyRows() {
  $$("#t-pol tbody tr[data-policy-custom]").forEach((row, index) => {
    const position = index + 1;
    const input = row.querySelector('[data-f="name"]');
    const error = row.querySelector("[data-policy-error]");
    input.setAttribute("aria-label", tr("delivery.policy_name_label", { position }));
    error.id = `delivery-policy-name-error-${position}`;
    input.setAttribute("aria-describedby", error.id);
    row.querySelector('[data-f="mode"]').setAttribute("aria-label", tr("delivery.policy_mode_label", { position }));
    const remove = row.querySelector('[data-action="delete-policy"]');
    remove.setAttribute("aria-label", tr("delivery.policy_remove_label", { position }));
    remove.title = remove.getAttribute("aria-label");
    refreshPolicyTierRows(row.querySelector('[data-f="tiers"]'));
  });
}

export function collectPoliciesFromTable(data) {
  data.policies = Array.from($$("#t-pol tbody tr[data-policy-custom]")).flatMap(row => {
    const draftName = row.querySelector('[data-f="name"]').value.trim();
    const name = isAvailablePolicyName(row, draftName) ? draftName : row.dataset.policyName;
    if (!name) return [];
    const tiers = Array.from(row.querySelectorAll(".policy-tier-row"), tier => ({
      name: tier.querySelector("[data-tier-name]").value,
      timeout_seconds: Number(tier.querySelector("[data-tier-timeout]").value),
    }));
    return [{ name, mode: row.querySelector('[data-f="mode"]').value, tiers }];
  });
  return data.policies;
}

export function validatePolicyRows() {
  const names = new Set();
  for (const row of $$("#t-pol tbody tr[data-policy-custom]")) {
    const input = row.querySelector('[data-f="name"]');
    const name = input.value.trim();
    let message = "";
    if (!name) message = tr("delivery.policy_name_required");
    else if (names.has(name) || name === "cascade") message = tr("delivery.policy_name_unique", { name });
    else if (!row.querySelectorAll(".policy-tier-row").length) message = tr("delivery.policy_tier_required", { name });
    if (message) {
      showPolicyError(row, message);
      notifyValidationError("delivery-policy", message, $("#delivery-status"));
      showTableRowPage("t-pol", row);
      input.focus();
      return false;
    }
    showPolicyError(row);
    names.add(name);
  }
  return true;
}

function showPolicyError(row, message = "") {
  const input = row.querySelector('[data-f="name"]');
  const error = row.querySelector("[data-policy-error]");
  input.setAttribute("aria-invalid", message ? "true" : "false");
  error.textContent = message;
  error.classList.toggle("hidden", !message);
}
