import {
  $, $$, APP_META, J, SEARCH_DEBOUNCE_MS, apiFetch, applyTablePager, debounce, errorText,
  escapeHtml, fetchError, fetchOk, getAuthPasswordPolicy, getCurrentUser, isAbortError, isPublicInfoPage,
  markTabDirty, notifyError, notifyResponseError, notifySuccess, notifyValidationError, onReady,
  queryGet, refreshTablePagers, setAuthPasswordPolicy, setInlineStatus, setLocalTotpEnabled,
  showTableRowPage, syncTabFromPath, tr, updateAllTabAccessibleLabels, updatePublicLoginLinksText,
} from "./app.js";
export { loadCascade, renderCascadeTable } from "./app-cascade.js";
export { loadDedup, renderDedupCards } from "./app-noise-control.js";

// ---- Delivery (policies + rules) ----
// The synthetic policy built from the global [cascade] block is exposed by
// the backend with name="cascade" (see delivery::legacy_cascade_policy).
// The UI matches that for consistency: no "legacy-cascade" string anywhere.
let delivData = { default_policy: "cascade", policies: [], rules: [], available_tiers: [], legacy_cascade_tiers: [] };

export async function loadDelivery() {
  try {
    delivData = await queryGet("delivery-config", "/api/delivery-config");
    renderDeliveryDefault();
    renderPoliciesTable();
    renderRulesTable();
  } catch (e) { fetchError("delivery", e); }
}

function policyNames() {
  return ["cascade", ...delivData.policies.map(p => p.name)];
}

export function renderDeliveryDefault() {
  const sel = $("#d-default-policy");
  if (!sel) return;
  const cur = delivData.default_policy;
  sel.innerHTML = policyNames().map(n => `<option ${n === cur ? "selected" : ""}>${escapeHtml(n)}</option>`).join("");
}

export function renderPoliciesTable() {
  const tb = $("#t-pol tbody"); tb.innerHTML = "";
  delivData.policies.forEach((p, i) => addPolicyRow(p.name, p.mode, p.tiers, i, { deferPager: true }));
  applyTablePager("t-pol", { reset: true });
}

function addPolicyRow(name = "new-policy", mode = "cascade", tiers = [], idx = null, opts = {}) {
  const tb = $("#t-pol tbody");
  const tr = document.createElement("tr");
  const tierTxt = tiers.map(t => `${t.name}(${t.timeout_seconds}s)`).join(" → ");
  const tiersAvail = delivData.available_tiers || ["ntfy", "telegram", "smtp"];
  tr.innerHTML = `
    <td><input type="text" value="${escapeHtml(name)}" data-f="name"></td>
    <td><select data-f="mode">
      <option value="cascade" ${mode === "cascade" ? "selected" : ""}>cascade</option>
      <option value="broadcast" ${mode === "broadcast" ? "selected" : ""}>broadcast</option>
    </select></td>
    <td><input type="text" value="${escapeHtml(JSON.stringify(tiers))}" data-f="tiers" placeholder='[{"name":"ntfy","timeout_seconds":5}]' style="font-family:monospace;font-size:11px"></td>
    <td><button class="danger" data-del>×</button></td>`;
  tr.querySelector("[data-del]").addEventListener("click", () => {
    tr.remove();
    renderDeliveryDefault();
    applyTablePager("t-pol");
  });
  // Re-populate the default-policy dropdown when name changes
  tr.querySelector('[data-f="name"]').addEventListener("input", () => { collectPoliciesFromTable(); renderDeliveryDefault(); });
  tb.appendChild(tr);
  renderDeliveryDefault();
  if (!opts.deferPager) applyTablePager("t-pol", { page: "last" });
}

function collectPoliciesFromTable() {
  const policies = [];
  $$("#t-pol tbody tr").forEach(tr => {
    const name = tr.querySelector('[data-f="name"]').value.trim();
    const mode = tr.querySelector('[data-f="mode"]').value;
    let tiers = [];
    try { tiers = JSON.parse(tr.querySelector('[data-f="tiers"]').value); } catch (e) {}
    if (name && Array.isArray(tiers)) policies.push({ name, mode, tiers });
  });
  delivData.policies = policies;
  return policies;
}

export function renderRulesTable() {
  const tb = $("#t-rules tbody"); tb.innerHTML = "";
  delivData.rules.forEach((r, i) => addRuleRow(r.match || {}, r.policy, i, { deferPager: true }));
  applyTablePager("t-rules", { reset: true });
}

function addRuleRow(match = {}, policy = "cascade", idx = -1, rowOpts = {}) {
  const tb = $("#t-rules tbody");
  const i = idx === -1 ? tb.children.length : idx;
  const tr = document.createElement("tr");
  const matchTxt = Object.entries(match).map(([k, v]) => `${k}=${v}`).join("\n");
  const policyOpts = policyNames().map(n => `<option ${n === policy ? "selected" : ""}>${escapeHtml(n)}</option>`).join("");
  tr.innerHTML = `
    <td><span class="muted">${i + 1}</span></td>
    <td><textarea data-f="match" rows="3" style="font-family:monospace;font-size:11px" placeholder="severity=critical\ncomponent=host\nhost=re:^prod-.*">${escapeHtml(matchTxt)}</textarea></td>
    <td><select data-f="policy">${policyOpts}</select></td>
    <td><button class="danger" data-del>×</button></td>`;
  tr.querySelector("[data-del]").addEventListener("click", () => {
    tr.remove();
    renumberRules();
    applyTablePager("t-rules");
  });
  tb.appendChild(tr);
  renumberRules();
  if (!rowOpts.deferPager) applyTablePager("t-rules", { page: "last" });
}

function renumberRules() {
  $$("#t-rules tbody tr").forEach((tr, i) => {
    const num = tr.querySelector(".muted");
    if (num) num.textContent = i + 1;
  });
}

$("#btn-pol-add").addEventListener("click", () => addPolicyRow());
$("#btn-rule-add").addEventListener("click", () => addRuleRow());
$("#btn-delivery-save").addEventListener("click", async () => {
  const policies = collectPoliciesFromTable();
  const rules = [];
  $$("#t-rules tbody tr").forEach(tr => {
    const txt = tr.querySelector('[data-f="match"]').value.trim();
    const match = {};
    txt.split(/\n/).forEach(line => {
      const eq = line.indexOf("=");
      if (eq > 0) match[line.slice(0, eq).trim()] = line.slice(eq + 1).trim();
    });
    const pol = tr.querySelector('[data-f="policy"]').value;
    if (pol && Object.keys(match).length) rules.push({ match, policy: pol });
  });
  const payload = {
    default_policy: $("#d-default-policy").value,
    policies,
    rules
  };
  try {
    await J("/api/delivery-config", {
      method: "POST",
      body: JSON.stringify(payload),
      headers: { "Content-Type": "application/json" }
    });
    notifySuccess(tr("delivery.saved", { policies: policies.length, rules: rules.length }), {
      status: "#delivery-status",
      clearMs: 4000,
    });
    markTabDirty("delivery", false);
  } catch (e) { notifyError("delivery-save", e, { status: "#delivery-status" }); }
});

