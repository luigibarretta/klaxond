import {
  $, $$, APP_META, J, SEARCH_DEBOUNCE_MS, apiFetch, applyTablePager, debounce, errorText,
  escapeHtml, fetchError, fetchOk, getAuthPasswordPolicy, getCurrentUser, isAbortError, isPublicInfoPage,
  markTabDirty, notifyError, notifyResponseError, notifySuccess, notifyValidationError, onReady,
  queryGet, refreshTablePagers, setAuthPasswordPolicy, setInlineStatus, setLocalTotpEnabled,
  showTableRowPage, syncTabFromPath, tr, updateAllTabAccessibleLabels, updatePublicLoginLinksText,
} from "./app.js";
import { clearAllSuppressions, loadAcks, loadInhib } from "./app-inhibitions-active.js";
import { collectInhibitionRulesFromTable, createInhibitionRuleRow } from "./app-inhibitions-row.js";
export { loadAcks, loadInhib };

async function testInhibitionRule() {
  const source = $("#inhib-test-source").value;
  const raw = $("#inhib-test-labels").value || "";
  const labels = {};
  const errors = [];
  raw.split(/\r?\n/).forEach((line, i) => {
    const t = line.trim();
    if (!t) return;
    const eq = t.indexOf("=");
    if (eq < 1) { errors.push(`line ${i+1}: expected "label=value"`); return; }
    labels[t.slice(0, eq).trim()] = t.slice(eq + 1).trim();
  });
  const status = $("#inhib-test-status");
  const result = $("#inhib-test-result");
  if (errors.length) {
    notifyValidationError("inhibition-test", errors[0], status);
    result.innerHTML = "";
    return;
  }
  setInlineStatus(status, tr("status.testing"));
  try {
    const res = await apiFetch("/api/inhibition-rules/test", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({source, labels}),
    });
    if (!res.ok) {
      const txt = await res.text();
      notifyResponseError("inhibition-test", res, txt, status);
      return;
    }
    const r = await res.json();
    setInlineStatus(status, "");
    const verdict = r.would_send
      ? `<span style="color:var(--green)"><b>${escapeHtml(tr("inhib.would_deliver"))}</b></span> (${escapeHtml(tr("inhib.reason"))}: <code>${escapeHtml(r.reason)}</code>)`
      : `<span style="color:var(--red)"><b>${escapeHtml(tr("inhib.would_suppress"))}</b></span> ${escapeHtml(tr("inhib.by_rule"))} <code>${escapeHtml(r.matched_rule || "")}</code>`;
    const arm = r.would_arm_suppression
      ? `<br/><span style="color:var(--accent)">${escapeHtml(tr("inhib.source_alert_arm"))}</span>`
      : "";
    const considered = (r.considered_rules || []).length
      ? `<br/><small class="muted">${escapeHtml(tr("inhib.rules_considered"))} <code>${escapeHtml(source)}</code>: ${r.considered_rules.map(s => `<code>${escapeHtml(s)}</code>`).join(", ")}</small>`
      : `<br/><small class="muted">${escapeHtml(tr("inhib.no_rules_apply"))} <code>${escapeHtml(source)}</code>.</small>`;
    result.innerHTML = verdict + arm + considered;
  } catch (e) {
    notifyError("inhibition-test", e, { status, inlineText: "❌ " + errorText(e) });
  }
}

export { loadSchedules } from "./app-inhibitions-schedules.js";


// ---- Inhibition rules (CRUD) ----
let _inhibAvailableSources = [];

export async function loadInhibRules() {
  try {
    const data = await queryGet("inhibition-rules", "/api/inhibition-rules");
    _inhibAvailableSources = data.available_sources || [];
    const tb = $("#t-inhib-rules tbody"); tb.innerHTML = "";
    for (const r of (data.rules || [])) tb.appendChild(createInhibitionRuleRow(r, _inhibAvailableSources));
    $("#inhib-save-status").textContent = "";
    applyTablePager("t-inhib-rules", { reset: true });
  } catch (e) { fetchError("inhibition-rules", e); }
}

async function saveInhibRules() {
  const collected = collectInhibitionRulesFromTable();
  const status = $("#inhib-save-status");
  if (collected.error) {
    notifyValidationError("inhibition-rules", collected.error, status);
    return;
  }
  setInlineStatus(status, tr("status.saving"));
  try {
    const res = await apiFetch("/api/inhibition-rules", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({ rules: collected.rules }),
    });
    if (!res.ok) {
      const txt = await res.text();
      notifyResponseError("inhibition-rules", res, txt, status);
      return;
    }
    const r = await res.json();
    const savedMessage = tr("inhib.rules_saved", { count: r.count, cleared: r.cleared_suppressions });
    markTabDirty("inhibitions", false);
    await loadInhibRules();
    await loadInhib();
    notifySuccess(savedMessage, { status });
  } catch (e) {
    notifyError("inhibition-rules", e, { status, inlineText: "❌ " + errorText(e) });
  }
}

onReady(() => {
  const add = document.getElementById("inhib-add");
  const save = document.getElementById("inhib-save");
  const clearAll = document.getElementById("inhib-clear-all");
  if (add) add.addEventListener("click", () => {
    const tb = $("#t-inhib-rules tbody");
    tb.appendChild(createInhibitionRuleRow(
      {source: "", ttl_seconds: 900, applies_to: [], match_by: ""},
      _inhibAvailableSources,
    ));
    applyTablePager("t-inhib-rules", { page: "last" });
  });
  if (save) save.addEventListener("click", saveInhibRules);
  if (clearAll) clearAll.addEventListener("click", clearAllSuppressions);
  const testBtn = document.getElementById("inhib-test-run");
  if (testBtn) testBtn.addEventListener("click", testInhibitionRule);
});
