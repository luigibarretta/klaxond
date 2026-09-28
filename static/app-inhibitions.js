import {
  $, $$, APP_META, J, SEARCH_DEBOUNCE_MS, apiFetch, applyTablePager, debounce, errorText,
  escapeHtml, fetchError, fetchOk, getAuthPasswordPolicy, getCurrentUser, isAbortError, isPublicInfoPage,
  markTabDirty, notifyError, notifyResponseError, notifySuccess, notifyValidationError, onReady,
  queryGet, refreshTablePagers, setAuthPasswordPolicy, setInlineStatus, setLocalTotpEnabled,
  showTableRowPage, syncTabFromPath, tr, updateAllTabAccessibleLabels, updatePublicLoginLinksText,
} from "./app.js";
import { clearAllSuppressions, loadAcks, loadInhib } from "./app-inhibitions-active.js";
import {
  collectInhibitionRulesFromTable, createInhibitionRuleRow, refreshInhibitionRuleRows,
} from "./app-inhibitions-row.js";
import { validateAllInhibitionRegexes } from "./app-inhibitions-regex.js";
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

const INHIBITION_PRESETS = {
  same_host: { source: "node-down", ttl_seconds: 3600, applies_to: [], match_by: "host" },
  same_service: { source: "service-down", ttl_seconds: 1800, applies_to: [], match_by: "service" },
  job_regex: { source: "target-down", ttl_seconds: 1800, applies_to: [], match_label: "job", match_regex: "^blackbox-.*" },
};

function appendInhibitionRule(rule) {
  const tb = $("#t-inhib-rules tbody");
  if (!tb) return;
  const row = createInhibitionRuleRow(rule, _inhibAvailableSources);
  tb.appendChild(row);
  applyTablePager("t-inhib-rules", { page: "last" });
  showTableRowPage("t-inhib-rules", row);
  markTabDirty("inhibitions", true);
}

function installInhibitionPresetControl(addButton) {
  if (!addButton || document.getElementById("inhib-preset")) return;
  const control = document.createElement("div");
  control.className = "inhib-preset-control";
  control.innerHTML = `
    <label>
      <span>${escapeHtml(tr("inhib.preset_label"))}</span>
      <select id="inhib-preset" data-dirty-ignore>
        <option value="same_host">${escapeHtml(tr("inhib.preset_same_host"))}</option>
        <option value="same_service">${escapeHtml(tr("inhib.preset_same_service"))}</option>
        <option value="job_regex">${escapeHtml(tr("inhib.preset_job_regex"))}</option>
      </select>
    </label>
    <button type="button" class="btn" id="inhib-preset-add">${escapeHtml(tr("inhib.add_preset"))}</button>`;
  addButton.insertAdjacentElement("beforebegin", control);
  control.querySelector("#inhib-preset-add")?.addEventListener("click", () => {
    const preset = INHIBITION_PRESETS[control.querySelector("#inhib-preset")?.value];
    if (preset) appendInhibitionRule({ ...preset, applies_to: [...preset.applies_to] });
  });
}

function refreshInhibitionEditorLanguage(addButton) {
  document.getElementById("inhib-preset")?.closest(".inhib-preset-control")?.remove();
  installInhibitionPresetControl(addButton);
  refreshInhibitionRuleRows();
}

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
  await validateAllInhibitionRegexes();
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
  installInhibitionPresetControl(add);
  document.addEventListener("klaxond:languagechange", () => refreshInhibitionEditorLanguage(add));
  if (add) add.addEventListener("click", () => {
    appendInhibitionRule(
      {source: "", ttl_seconds: 900, applies_to: [], match_by: ""},
    );
  });
  if (save) save.addEventListener("click", saveInhibRules);
  if (clearAll) clearAll.addEventListener("click", clearAllSuppressions);
  const testBtn = document.getElementById("inhib-test-run");
  if (testBtn) testBtn.addEventListener("click", testInhibitionRule);
});
