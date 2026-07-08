import {
  $, $$, APP_META, J, SEARCH_DEBOUNCE_MS, apiFetch, applyTablePager, debounce, errorText,
  escapeHtml, fetchError, fetchOk, getAuthPasswordPolicy, getCurrentUser, isAbortError, isPublicInfoPage,
  markTabDirty, notifyError, notifyResponseError, notifySuccess, notifyValidationError, onReady,
  queryGet, refreshTablePagers, setAuthPasswordPolicy, setInlineStatus, setLocalTotpEnabled,
  showTableRowPage, syncTabFromPath, tr, updateAllTabAccessibleLabels, updatePublicLoginLinksText,
} from "./app.js";
import { loadStatus } from "./app-status.js";

// ---- Cascade tiers ----
const TIER_OPTS = ["ntfy", "telegram", "smtp"];
let casData = { tiers: [], default_enabled_for_webhook: false };

export async function loadCascade() {
  try {
    casData = await queryGet("cascade-config", "/api/cascade-config");
    renderCascadeTable();
    $("#cas-default").checked = !!casData.default_enabled_for_webhook;
  } catch (e) { fetchError("cascade", e); }
}

export function renderCascadeTable() {
  const tb = $("#t-cas tbody"); tb.innerHTML = "";
  casData.tiers.forEach((t, i) => addCasRow(t.name, t.timeout_seconds, i, { deferPager: true }));
  applyTablePager("t-cas", { reset: true });
}

function addCasRow(name = "ntfy", timeout = 5, idx = -1, opts = {}) {
  const tb = $("#t-cas tbody");
  const i = idx === -1 ? tb.children.length : idx;
  const row = document.createElement("tr");
  const tierOpts = TIER_OPTS.map(o => `<option ${o === name ? "selected" : ""}>${o}</option>`).join("");
  row.innerHTML = `
    <td><span class="muted">${i + 1}</span> <button data-up title="${escapeHtml(tr("cascade.move_up"))}">↑</button><button data-dn title="${escapeHtml(tr("cascade.move_down"))}">↓</button></td>
    <td><select data-f="name">${tierOpts}</select></td>
    <td><input type="number" min="1" max="60" value="${timeout}" data-f="timeout"></td>
    <td><button class="danger" data-del>×</button></td>`;
  row.querySelector("[data-del]").addEventListener("click", () => {
    row.remove();
    renumberCas();
    applyTablePager("t-cas");
  });
  row.querySelector("[data-up]").addEventListener("click", () => {
    const prev = row.previousElementSibling;
    if (prev) tb.insertBefore(row, prev);
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
  $$("#t-cas tbody tr").forEach((tr, i) => {
    const num = tr.querySelector(".muted");
    if (num) num.textContent = i + 1;
  });
}

$("#btn-cas-add").addEventListener("click", () => addCasRow());
$("#btn-cas-save").addEventListener("click", async () => {
  const tiers = [];
  $$("#t-cas tbody tr").forEach(tr => {
    const name = tr.querySelector('[data-f="name"]').value;
    const t = parseInt(tr.querySelector('[data-f="timeout"]').value, 10);
    if (name && t > 0) tiers.push({ name, timeout_seconds: t });
  });
  try {
    await J("/api/cascade-config", {
      method: "POST",
      body: JSON.stringify({ tiers, default_enabled_for_webhook: $("#cas-default").checked }),
      headers: { "Content-Type": "application/json" }
    });
    notifySuccess(tr("cascade.saved", { count: tiers.length }), { status: "#cas-status", clearMs: 3000 });
    markTabDirty("cascade", false);
    loadStatus();
  } catch (e) { notifyError("cascade-save", e, { status: "#cas-status" }); }
});



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


// ---- Dedup / grouping ----
let dedupData = { settings: {}, sources: [], pending_counts: {}, defaults: {} };

const STRATEGY_HELP = {
  none: "dedup.help_none",
  time: "dedup.help_time",
  key:  "dedup.help_key",
};

const SOURCE_HELP = {
  wud:          "dedup.source_wud",
  grafana:      "dedup.source_grafana",
  beszel:       "dedup.source_beszel",
  healthchecks: "dedup.source_healthchecks",
  authentik:    "dedup.source_authentik",
  shelfmark:    "dedup.source_shelfmark",
  prowlarr:     "dedup.source_prowlarr",
  decypharr:    "dedup.source_decypharr",
};

export async function loadDedup() {
  try {
    const j = await queryGet("dedup-config", "/api/dedup-config");
    dedupData = j;
    renderDedupCards();
  } catch (e) {
    const c = $("#dedup-cards");
    if (c) c.innerHTML = '<p class="muted">Error loading dedup config: ' + e.message + "</p>";
    fetchError("dedup", e);
  }
}

export function renderDedupCards() {
  const c = $("#dedup-cards");
  if (!c) return;
  const sources = dedupData.sources || ["grafana", "beszel", "healthchecks", "wud", "authentik", "shelfmark", "prowlarr", "decypharr"];
  const settings = dedupData.settings || {};
  const pending = dedupData.pending_counts || {};
  let html = '<div class="grid2">';
  for (const src of sources) {
    const s = settings[src] || {};
    const help = SOURCE_HELP[src] ? tr(SOURCE_HELP[src]) : "";
    const pcount = pending[src] || 0;
    html += `
      <div class="card" data-src="${src}">
        <h3 style="margin-top:0">${src.toUpperCase()}
          <small class="muted" style="font-weight:normal">${pcount > 0 ? `· ${escapeHtml(tr("dedup.pending", { count: pcount }))}` : ""}</small>
        </h3>
        <p class="muted"><small>${help}</small></p>
        <label><input type="checkbox" class="d-enabled" ${s.enabled ? "checked" : ""}> ${escapeHtml(tr("dedup.enabled"))}</label>
        <label>${escapeHtml(tr("dedup.strategy"))}
          <select class="d-strategy">
            <option value="key" ${s.strategy === "key" ? "selected" : ""}>${escapeHtml(tr("dedup.key_recommended"))}</option>
            <option value="time" ${s.strategy === "time" ? "selected" : ""}>${escapeHtml(tr("dedup.time"))}</option>
            <option value="none" ${s.strategy === "none" ? "selected" : ""}>${escapeHtml(tr("dedup.none"))}</option>
          </select>
        </label>
        <label>${escapeHtml(tr("dedup.window"))}
          <input type="number" class="d-window" min="5" max="3600" value="${s.window_s || 90}">
        </label>
        <label title="${escapeHtml(tr("dedup.override_title"))}">
          <input type="checkbox" class="d-override" ${s.override_critical ? "checked" : ""}>
          ${escapeHtml(tr("dedup.override_critical"))}
        </label>
      </div>`;
  }
  html += "</div>";
  c.innerHTML = html;
}

$("#dedup-save")?.addEventListener("click", async () => {
  const out = {};
  for (const card of document.querySelectorAll("#dedup-cards [data-src]")) {
    const src = card.dataset.src;
    out[src] = {
      enabled:           card.querySelector(".d-enabled").checked,
      strategy:          card.querySelector(".d-strategy").value,
      window_s:          parseInt(card.querySelector(".d-window").value, 10) || 90,
      override_critical: card.querySelector(".d-override").checked,
    };
  }
  setInlineStatus("#dedup-status", tr("status.saving"));
  try {
    const r = await J("/api/dedup-config", {
      method: "POST",
      body: JSON.stringify({ settings: out }),
      headers: { "Content-Type": "application/json" },
    });
    if (r.ok) {
      dedupData.settings = r.settings;
      notifySuccess(tr("dedup.saved"), { status: "#dedup-status", clearMs: 3000 });
      markTabDirty("grouping", false);
    } else {
      notifyError("dedup-save", new Error(r.error || "unknown"), { status: "#dedup-status" });
    }
  } catch (e) {
    notifyError("dedup-save", e, { status: "#dedup-status" });
  }
});

// Refresh pending counts when the grouping tab is shown
document.querySelectorAll('[data-tab="grouping"]').forEach(btn => {
  btn.addEventListener("click", () => { loadDedup(); });
});


