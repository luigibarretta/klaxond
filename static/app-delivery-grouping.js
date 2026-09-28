import {
  $, $$, J, dirtyTabs, fetchError, notifyError, notifySuccess, notifyValidationError, queryGet,
  showTableRowPage, tr,
} from "./app.js";
import {
  addPolicyRow, collectPoliciesFromTable, renderDeliveryDefault as renderDefault,
  renderPoliciesTable as renderPolicies, validatePolicyRows,
} from "./app-delivery-policies.js";
import {
  addRuleRow, collectValidRules, refreshRuleRows, renderRulesTable as renderRules,
  showDeliveryRuleServerError,
} from "./app-delivery-rules.js";
import { tierSummary } from "./app-delivery-editor.js";
import { deliverySectionRevision, markDeliverySectionDirty } from "./app-delivery-state.js";

export { loadCascade, renderCascadeTable } from "./app-cascade.js";
export { loadDedup, renderDedupCards } from "./app-noise-control.js";

let deliveryData = {
  default_policy: "cascade",
  policies: [],
  rules: [],
  available_tiers: [],
  legacy_cascade_tiers: [],
};
let deliverySaveInFlight = false;

export async function loadDelivery(opts = {}) {
  const requestedRevision = deliverySectionRevision("policies");
  try {
    const nextData = await queryGet("delivery-config", "/api/delivery-config", { force: opts.force });
    if (dirtyTabs.has("delivery") || deliverySectionRevision("policies") !== requestedRevision) return;
    deliveryData = nextData;
    renderDeliveryDefault();
    renderPoliciesTable();
    renderRulesTable();
  } catch (error) {
    fetchError("delivery", error);
  }
}

export function renderDeliveryDefault() {
  renderDefault(deliveryData);
}

export function renderPoliciesTable() {
  renderPolicies(deliveryData);
}

export function renderRulesTable() {
  renderRules(deliveryData);
}

$("#d-default-policy").addEventListener("change", event => {
  deliveryData.default_policy = event.target.value;
  refreshRuleRows();
  markDeliverySectionDirty("policies");
});

$("#btn-pol-add").addEventListener("click", () => {
  addPolicyRow(deliveryData);
  markDeliverySectionDirty("policies");
});

$("#btn-rule-add").addEventListener("click", () => {
  addRuleRow(deliveryData);
  markDeliverySectionDirty("policies");
});

function invalidPolicyTimeout() {
  return Array.from($$("#t-pol [data-tier-timeout]")).find(input => {
    const value = Number(input.value);
    return !Number.isInteger(value) || value < 1 || value > 60;
  });
}

async function saveDeliveryPolicies() {
  if (deliverySaveInFlight) return;
  const invalidTimeout = invalidPolicyTimeout();
  if (invalidTimeout) {
    notifyValidationError("delivery-policy-timeout", tr("cascade.timeout_invalid", {
      min: 1, max: 60,
    }), $("#delivery-status"));
    showTableRowPage("t-pol", invalidTimeout.closest("tr"));
    invalidTimeout.focus();
    return;
  }
  if (!validatePolicyRows()) return;
  const policies = collectPoliciesFromTable(deliveryData);
  const rules = collectValidRules();
  if (!rules) return;
  const payload = {
    default_policy: $("#d-default-policy").value,
    policies,
    rules,
  };
  const savedRevision = deliverySectionRevision("policies");
  const saveButtons = $$('[data-delivery-save]');
  deliverySaveInFlight = true;
  saveButtons.forEach(button => { button.disabled = true; });
  try {
    await J("/api/delivery-config", {
      method: "POST",
      body: JSON.stringify(payload),
      headers: { "Content-Type": "application/json" },
    });
    deliveryData.rules = rules;
    const hasNewerChanges = deliverySectionRevision("policies") !== savedRevision;
    const message = tr(hasNewerChanges ? "delivery.saved_newer_changes" : "delivery.saved", {
      policies: policies.length, rules: rules.length,
    });
    notifySuccess(message, {
      status: "#delivery-status", clearMs: 4000,
    });
    if (!hasNewerChanges) markDeliverySectionDirty("policies", false);
  } catch (error) {
    if (!showDeliveryRuleServerError(error)) {
      notifyError("delivery-save", error, { status: "#delivery-status" });
    }
  } finally {
    deliverySaveInFlight = false;
    saveButtons.forEach(button => { button.disabled = false; });
  }
}

$$('[data-delivery-save]').forEach(button => button.addEventListener("click", saveDeliveryPolicies));

document.addEventListener("klaxond:cascade-saved", event => {
  const tiers = event.detail?.tiers;
  if (!Array.isArray(tiers)) return;
  deliveryData.legacy_cascade_tiers = tiers;
  const cell = $("#t-pol .policy-built-in td:nth-child(3)");
  if (cell) cell.innerHTML = tierSummary(tiers);
});
