import {
  $, $$, applyTablePager, confirmDialog, escapeHtml, notifyValidationError,
  setInlineStatus, showTableRowPage, tr,
} from "./app.js";
import {
  iconButton, parseRuleMatch, refreshDeliveryIcons, showRuleError,
} from "./app-delivery-editor.js";
import { markDeliverySectionDirty } from "./app-delivery-state.js";

function policyNames(data) {
  return ["cascade", ...data.policies.map(policy => policy.name)];
}

export function refreshRulePolicySelectors(data, { previousName = "", nextName = "" } = {}) {
  const names = policyNames(data);
  $$("#t-rules select[data-f='policy']").forEach(select => {
    const desired = select.value === previousName ? nextName : select.value;
    const availableNames = desired && !names.includes(desired) ? [...names, desired] : names;
    select.innerHTML = availableNames
      .map(name => `<option ${name === desired ? "selected" : ""}>${escapeHtml(name)}</option>`)
      .join("");
  });
}

export function renderRulesTable(data) {
  const body = $("#t-rules tbody");
  body.innerHTML = "";
  data.rules.forEach((rule, index) => addRuleRow(data, rule.match || {}, rule.policy, index, true));
  refreshRuleRows();
  applyTablePager("t-rules", { reset: true });
}

export function addRuleRow(data, match = {}, policy = "cascade", index = -1, deferPager = false) {
  const body = $("#t-rules tbody");
  const position = index === -1 ? body.children.length : index;
  const row = document.createElement("tr");
  const matchText = Object.entries(match).map(([key, value]) => `${key}=${value}`).join("\n");
  const policyOptions = policyNames(data)
    .map(name => `<option ${name === policy ? "selected" : ""}>${escapeHtml(name)}</option>`)
    .join("");
  row.innerHTML = ruleRowMarkup(position, matchText, policyOptions);
  bindRuleRow(row);
  body.appendChild(row);
  refreshRuleRows();
  refreshDeliveryIcons();
  if (!deferPager) applyTablePager("t-rules", { page: "last" });
}

function ruleRowMarkup(position, matchText, policyOptions) {
  return `
    <td data-label="${escapeHtml(tr("delivery.rule_priority"))}"><span class="muted" data-rule-position>${position + 1}</span><span class="rule-order-actions">${iconButton("rule-up", "arrow-up", tr("delivery.rule_move_up"))}${iconButton("rule-down", "arrow-down", tr("delivery.rule_move_down"))}</span></td>
    <td data-label="${escapeHtml(tr("delivery.rule_match"))}"><textarea data-f="match" rows="3" placeholder="severity=critical\ncomponent=host\nhost=re:^prod-.*">${escapeHtml(matchText)}</textarea><small class="field-error hidden" data-rule-error role="alert"></small></td>
    <td data-label="${escapeHtml(tr("delivery.policy"))}"><select data-f="policy">${policyOptions}</select></td>
    <td data-label="${escapeHtml(tr("common.actions"))}">${iconButton("rule-delete", "trash-2", tr("common.delete"), "danger")}</td>`;
}

function bindRuleRow(row) {
  row.querySelector('[data-action="rule-delete"]').addEventListener("click", () => removeRule(row));
  row.querySelector('[data-action="rule-up"]').addEventListener("click", event => moveRule(row, -1, event.currentTarget));
  row.querySelector('[data-action="rule-down"]').addEventListener("click", event => moveRule(row, 1, event.currentTarget));
  row.querySelector('[data-f="match"]').addEventListener("input", () => {
    showRuleError(row);
    markDeliverySectionDirty("policies");
  });
  row.querySelector('[data-f="policy"]').addEventListener("change", () => {
    markDeliverySectionDirty("policies");
  });
}

async function removeRule(row) {
  const position = rulePosition(row);
  if (!await confirmDialog(tr("delivery.delete_rule_confirm", { position }), {
    title: tr("delivery.delete_rule_title"), confirmLabel: tr("common.delete"), danger: true,
  })) return;
  const focusTarget = row.nextElementSibling || row.previousElementSibling;
  row.remove();
  refreshRuleRows();
  applyTablePager("t-rules");
  markDeliverySectionDirty("policies");
  (focusTarget?.querySelector('[data-f="match"]') || $("#btn-rule-add"))?.focus();
}

function rulePosition(row) {
  return Array.from($$("#t-rules tbody tr")).indexOf(row) + 1;
}

function moveRule(row, direction, button) {
  const sibling = direction < 0 ? row.previousElementSibling : row.nextElementSibling;
  if (!sibling) return;
  if (direction < 0) row.parentElement.insertBefore(row, sibling);
  else row.parentElement.insertBefore(sibling, row);
  refreshRuleRows();
  showTableRowPage("t-rules", row);
  markDeliverySectionDirty("policies");
  const fallback = row.querySelector(`[data-action="rule-${direction < 0 ? "down" : "up"}"]`);
  (button.disabled ? fallback : button)?.focus();
  setInlineStatus("#delivery-status", tr("delivery.rule_moved", { position: rulePosition(row) }));
}

export function refreshRuleRows() {
  const rows = $$("#t-rules tbody tr");
  rows.forEach((row, index) => updateRuleRow(row, index, rows.length));
  const empty = $("#delivery-rules-empty");
  empty?.classList.toggle("hidden", rows.length > 0);
  if (empty) empty.textContent = tr("delivery.rules_empty", {
    policy: $("#d-default-policy")?.value || "cascade",
  });
}

function updateRuleRow(row, index, count) {
  const position = index + 1;
  const match = row.querySelector('[data-f="match"]');
  const error = row.querySelector("[data-rule-error]");
  row.querySelector("[data-rule-position]").textContent = position;
  match.setAttribute("aria-label", tr("delivery.rule_match_label", { position }));
  error.id = `delivery-rule-error-${position}`;
  match.setAttribute("aria-describedby", error.id);
  row.querySelector('[data-f="policy"]').setAttribute("aria-label", tr("delivery.rule_policy_label", { position }));
  row.querySelector('[data-action="rule-up"]').disabled = index === 0;
  row.querySelector('[data-action="rule-down"]').disabled = index === count - 1;
  const remove = row.querySelector('[data-action="rule-delete"]');
  remove.setAttribute("aria-label", tr("delivery.rule_remove_label", { position }));
  remove.title = remove.getAttribute("aria-label");
}

export function collectValidRules() {
  const rules = [];
  const rows = $$("#t-rules tbody tr");
  for (let index = 0; index < rows.length; index += 1) {
    const row = rows[index];
    const parsed = parseRuleMatch(row.querySelector('[data-f="match"]').value, index + 1);
    showRuleError(row, parsed.error);
    if (parsed.error) {
      notifyValidationError("delivery-rule", parsed.error, $("#delivery-status"));
      showTableRowPage("t-rules", row);
      row.querySelector('[data-f="match"]').focus();
      return null;
    }
    rules.push({ match: parsed.match, policy: row.querySelector('[data-f="policy"]').value });
  }
  return rules;
}

export function showDeliveryRuleServerError(error) {
  const message = error instanceof Error ? error.message : String(error || "");
  const match = message.match(/delivery rule (\d+)/i);
  if (!match) return false;
  const row = $$("#t-rules tbody tr")[Number(match[1]) - 1];
  if (!row) return false;
  showRuleError(row, message);
  notifyValidationError("delivery-rule", message, $("#delivery-status"));
  showTableRowPage("t-rules", row);
  row.querySelector('[data-f="match"]').focus();
  return true;
}
