import {
  $, $$, APP_META, J, SEARCH_DEBOUNCE_MS, apiFetch, applyTablePager, debounce, errorText,
  escapeHtml, fetchError, fetchOk, getAuthPasswordPolicy, getCurrentUser, isAbortError, isPublicInfoPage,
  markTabDirty, notifyError, notifyResponseError, notifySuccess, notifyValidationError, onReady,
  queryGet, refreshTablePagers, setAuthPasswordPolicy, setInlineStatus, setLocalTotpEnabled,
  showTableRowPage, syncTabFromPath, tr, updateAllTabAccessibleLabels, updatePublicLoginLinksText,
} from "./app.js";
import { loadStatusActivity } from "./app-status.js";

// ---- Inhibitions (active suppressions) ----
export async function loadInhib() {
  try {
    const rows = await queryGet("inhibitions", "/api/inhibitions");
    const tb = $("#t-inhib tbody"); tb.innerHTML = "";
    if (!rows.length) {
      tb.innerHTML = `<tr><td colspan="5" class="muted">${escapeHtml(tr("inhib.no_active"))}</td></tr>`;
      applyTablePager("t-inhib", { reset: true });
      return;
    }
    for (const r of rows) {
      const row = document.createElement("tr");
      const scope = Array.isArray(r.applies_to) ? r.applies_to.join(", ") : "*";
      row.innerHTML = `<td><code>${escapeHtml(r.source)}</code></td><td>${escapeHtml(r.anchor)}</td><td><code>${escapeHtml(scope)}</code></td><td>${fmtSecs(r.expires_in_seconds)}</td><td><button class="btn" data-clear-suppression title="${escapeHtml(tr("inhib.clear_one_title"))}" style="color:var(--red); padding:2px 8px">✕</button></td>`;
      row.querySelector("[data-clear-suppression]").addEventListener("click", () => clearSuppression(r.source, r.anchor));
      tb.appendChild(row);
    }
    applyTablePager("t-inhib");
  } catch (e) { fetchError("inhibitions", e); }
}

async function clearSuppression(source, anchor) {
  const status = $("#inhib-clear-status");
  try {
    const res = await apiFetch("/api/inhibitions/clear", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({source, anchor}),
    });
    if (!res.ok) {
      notifyResponseError("inhibition-clear", res, await res.text(), status);
      return;
    }
    const r = await res.json();
    notifySuccess(tr("inhib.cleared_for_source", { count: r.cleared, source }), { status, clearMs: 3000 });
    await loadInhib();
    loadStatusActivity();
  } catch (e) {
    notifyError("inhibition-clear", e, { status, inlineText: "❌ " + errorText(e) });
  }
}

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

// ---- Ack-snoozes (active, 0.9.20+) ----
export async function loadAcks() {
  const tb = $("#t-acks tbody"); if (!tb) return;
  try {
    const acks = await queryGet("acks", "/api/acks");
    tb.innerHTML = "";
    if (!acks.length) {
      tb.innerHTML = `<tr><td colspan="3" class="muted">${escapeHtml(tr("inhib.no_acks"))}</td></tr>`;
      applyTablePager("t-acks", { reset: true });
      return;
    }
    for (const a of acks) {
      const row = document.createElement("tr");
      row.innerHTML = `<td><code>${escapeHtml(a.alertname)}</code></td><td>${fmtSecs(a.expires_in_seconds)}</td><td>
        <button class="btn" data-clear-ack="${escapeHtml(a.alertname)}" title="${escapeHtml(tr("inhib.clear_ack_title"))}" style="color:var(--red); padding:2px 8px">✕</button>
      </td>`;
      row.querySelector("[data-clear-ack]").addEventListener("click", () => clearAck(a.alertname));
      tb.appendChild(row);
    }
    applyTablePager("t-acks");
  } catch (e) { fetchError("acks", e); }
}

async function clearAck(alertname) {
  if (!confirm(`Force-clear ack-snooze for "${alertname}"?\n\nFuture alerts with this alertname will resume normal delivery.`)) return;
  try {
    const res = await apiFetch("/api/acks/clear", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({alertname}),
    });
    if (!res.ok) {
      notifyResponseError("ack-clear", res, await res.text());
      return;
    }
    const r = await res.json();
    notifySuccess(tr("inhib.ack_cleared", { count: r.cleared }), { durationMs: 3000 });
    loadAcks();
  } catch (e) {
    notifyError("ack-clear", e);
  }
}


// ---- Schedules (maintenance windows, 0.9.19+) ----
let _schedAvailableSources = ["grafana", "beszel", "healthchecks", "wud", "authentik", "shelfmark", "prowlarr", "decypharr"];
let _schedActiveMutes = {};   // name → seconds remaining

function _renderSchedRow(s) {
  const row = document.createElement("tr");
  row.classList.add("sched-row");

  const td = (html) => { const x = document.createElement("td"); x.innerHTML = html; return x; };

  // Name
  const inName = document.createElement("input");
  inName.type = "text"; inName.value = s.name || ""; inName.dataset.k = "name";
  inName.placeholder = "backup-window"; inName.style.width = "100%";
  const tdN = document.createElement("td"); tdN.appendChild(inName); row.appendChild(tdN);

  // Cron
  const inCron = document.createElement("input");
  inCron.type = "text"; inCron.value = s.cron || ""; inCron.dataset.k = "cron";
  inCron.placeholder = "30 4 * * 0"; inCron.style.width = "100%";
  inCron.style.fontFamily = "ui-monospace, monospace"; inCron.style.fontSize = "12px";
  const tdC = document.createElement("td"); tdC.appendChild(inCron); row.appendChild(tdC);

  // Duration
  const inDur = document.createElement("input");
  inDur.type = "number"; inDur.min = "1"; inDur.max = "1440";
  inDur.value = s.duration_minutes || 30; inDur.dataset.k = "duration_minutes";
  inDur.style.width = "5em";
  const tdD = document.createElement("td"); tdD.appendChild(inDur); row.appendChild(tdD);

  // Match (key=val per line)
  const matchObj = s.match || {};
  const matchTxt = Object.entries(matchObj).map(([k,v]) => `${k}=${v}`).join("\n");
  const taMatch = document.createElement("textarea");
  taMatch.dataset.k = "match"; taMatch.rows = 3; taMatch.value = matchTxt;
  taMatch.placeholder = "component=storage\nseverity=info";
  taMatch.style.fontFamily = "ui-monospace, monospace"; taMatch.style.fontSize = "12px";
  const tdM = document.createElement("td"); tdM.appendChild(taMatch); row.appendChild(tdM);

  // Applies to (checkbox cluster)
  const tdA = document.createElement("td");
  const wrap = document.createElement("div");
  wrap.dataset.k = "applies_to";
  wrap.style.display = "flex"; wrap.style.flexWrap = "wrap"; wrap.style.gap = "0.3em";
  const selected = new Set(s.applies_to || []);
  for (const src of _schedAvailableSources) {
    const lbl = document.createElement("label");
    lbl.style.fontSize = "11px"; lbl.style.whiteSpace = "nowrap"; lbl.style.margin = "0";
    const cb = document.createElement("input"); cb.type = "checkbox"; cb.value = src; cb.checked = selected.has(src);
    lbl.appendChild(cb); lbl.appendChild(document.createTextNode(" " + src));
    wrap.appendChild(lbl);
  }
  tdA.appendChild(wrap); row.appendChild(tdA);

  // Status (active/idle)
  const tdS = td("");
  const updStatus = () => {
    const name = inName.value.trim();
    const remain = _schedActiveMutes[name];
    if (remain && remain > 0) {
      const m = Math.ceil(remain / 60);
      tdS.innerHTML = `<span style="color:var(--yellow)">${escapeHtml(tr("sched.active"))}</span><br/><small>${escapeHtml(tr("sched.left_minutes", { minutes: m }))}</small>`;
    } else {
      tdS.innerHTML = `<span class="muted">${escapeHtml(tr("sched.idle"))}</span>`;
    }
  };
  updStatus();
  inName.addEventListener("input", updStatus);
  row.appendChild(tdS);

  // Delete
  const tdDel = document.createElement("td");
  const del = document.createElement("button");
  del.className = "btn"; del.textContent = "✕"; del.title = tr("sched.delete_title");
  del.style.color = "var(--red)"; del.style.padding = "2px 8px";
  del.addEventListener("click", () => {
    row.remove();
    applyTablePager("t-schedules");
  });
  tdDel.appendChild(del); row.appendChild(tdDel);

  return row;
}

export async function loadSchedules() {
  const tb = $("#t-schedules tbody"); if (!tb) return;
  try {
    const data = await queryGet("schedules", "/api/schedules");
    _schedActiveMutes = data.active_mutes || {};
    tb.innerHTML = "";
    for (const s of (data.schedules || [])) tb.appendChild(_renderSchedRow(s));
    $("#sched-save-status").textContent = "";
    applyTablePager("t-schedules", { reset: true });
  } catch (e) { fetchError("schedules", e); }
}

function _collectSchedules() {
  const rows = document.querySelectorAll("#t-schedules tbody tr.sched-row");
  const out = [];
  for (const tr of rows) {
    const get = k => tr.querySelector(`[data-k="${k}"]`);
    const name = get("name").value.trim();
    if (!name) continue;
    const cron = get("cron").value.trim();
    if (cron.split(/\s+/).filter(Boolean).length !== 5) {
      return { error: `schedule "${name}": cron must have exactly 5 fields` };
    }
    const duration = parseInt(get("duration_minutes").value || "30", 10);
    if (!(duration >= 1 && duration <= 1440)) {
      return { error: `schedule "${name}": duration_minutes 1..1440` };
    }
    const matchTxt = get("match").value.trim();
    const match = {};
    for (const line of matchTxt.split(/\r?\n/)) {
      const t = line.trim(); if (!t) continue;
      const eq = t.indexOf("=");
      if (eq < 1) return { error: `schedule "${name}": match line must be "label=value"` };
      match[t.slice(0, eq).trim()] = t.slice(eq + 1).trim();
    }
    const applies = Array.from(tr.querySelectorAll('[data-k="applies_to"] input[type=checkbox]'))
                    .filter(cb => cb.checked).map(cb => cb.value);
    out.push({ name, cron, duration_minutes: duration, match, applies_to: applies });
  }
  return { schedules: out };
}

async function saveSchedules() {
  const status = $("#sched-save-status");
  const collected = _collectSchedules();
  if (collected.error) {
    notifyValidationError("schedules", collected.error, status);
    return;
  }
  setInlineStatus(status, tr("status.saving"));
  try {
    const res = await apiFetch("/api/schedules", {
      method: "POST", headers: {"Content-Type": "application/json"},
      body: JSON.stringify({ schedules: collected.schedules }),
    });
    if (!res.ok) {
      const txt = await res.text();
      notifyResponseError("schedules", res, txt, status);
      return;
    }
    const r = await res.json();
    const savedMessage = tr("sched.saved", { count: r.count });
    markTabDirty("inhibitions", false);
    await loadSchedules();
    notifySuccess(savedMessage, { status });
  } catch (e) {
    notifyError("schedules", e, { status, inlineText: "❌ " + errorText(e) });
  }
}

onReady(() => {
  const add = document.getElementById("sched-add");
  const save = document.getElementById("sched-save");
  if (add) add.addEventListener("click", () => {
    const tb = $("#t-schedules tbody");
    tb.appendChild(_renderSchedRow({name:"", cron:"", duration_minutes:30, match:{}, applies_to:[]}));
    applyTablePager("t-schedules", { page: "last" });
  });
  if (save) save.addEventListener("click", saveSchedules);
});


async function clearAllSuppressions() {
  const status = $("#inhib-clear-status");
  // Native confirm — appropriate for a force-clear action that bypasses TTL.
  if (!confirm("Force-clear ALL active suppressions? Suppressions will re-arm on the next source alert. Continue?")) return;
  try {
    const res = await apiFetch("/api/inhibitions/clear", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({all: true}),
    });
    if (!res.ok) {
      notifyResponseError("inhibitions-clear-all", res, await res.text(), status);
      return;
    }
    const r = await res.json();
    notifySuccess(tr("inhib.cleared_all", { count: r.cleared }), { status, clearMs: 3000 });
    await loadInhib();
    loadStatusActivity();
  } catch (e) {
    notifyError("inhibitions-clear-all", e, { status, inlineText: "❌ " + errorText(e) });
  }
}

// ---- Inhibition rules (CRUD) ----
let _inhibAvailableSources = [];

function _matchTypeOf(r) {
  if (r.match_all) return "match_all";
  if (r.match_label && r.match_regex) return "match_label";
  if (r.match_by) return "match_by";
  return "match_by";
}

// Common alert-label autocomplete values for the match_by field.
const _COMMON_LABEL_NAMES = ["host", "job", "alertname", "instance", "service", "component", "severity"];

function _renderInhibRuleRow(r) {
  const row = document.createElement("tr");
  row.classList.add("inhib-rule-row");
  const mt = _matchTypeOf(r);

  // --- Source name ---
  const tdSrc = document.createElement("td");
  const inSrc = document.createElement("input");
  inSrc.type = "text"; inSrc.value = r.source || ""; inSrc.dataset.k = "source";
  inSrc.placeholder = "e.g. node-down"; inSrc.style.width = "100%";
  inSrc.addEventListener("input", () => _markRowValidity(row));
  tdSrc.appendChild(inSrc); row.appendChild(tdSrc);

  // --- Match type select ---
  const tdMt = document.createElement("td");
  const sel = document.createElement("select"); sel.dataset.k = "match_type";
  const _MT_LABELS = {match_by: "match_by", match_label: "match_label + regex", match_all: "match_all"};
  for (const opt of ["match_by", "match_label", "match_all"]) {
    const o = document.createElement("option"); o.value = opt; o.textContent = _MT_LABELS[opt];
    if (opt === mt) o.selected = true;
    sel.appendChild(o);
  }
  tdMt.appendChild(sel); row.appendChild(tdMt);

  // --- Match value cell ---
  // Two distinct inputs (label + regex), shown/hidden by match_type. For
  // match_by we show only the label input; for match_label we show both;
  // for match_all both are hidden and a hint is shown instead.
  const tdMv = document.createElement("td");
  const mvWrap = document.createElement("div");
  mvWrap.style.display = "flex"; mvWrap.style.gap = "0.4em"; mvWrap.style.alignItems = "center";

  const inLabel = document.createElement("input");
  inLabel.type = "text"; inLabel.dataset.k = "match_label";
  inLabel.placeholder = "host"; inLabel.style.flex = "0 0 8em";
  inLabel.setAttribute("list", "inhib-label-suggestions");
  inLabel.value = r.match_by || r.match_label || "";
  inLabel.addEventListener("input", () => _markRowValidity(row));

  const eqSign = document.createElement("span");
  eqSign.textContent = "="; eqSign.style.color = "var(--muted)";

  const inRegex = document.createElement("input");
  inRegex.type = "text"; inRegex.dataset.k = "match_regex";
  inRegex.placeholder = "^blackbox-.*"; inRegex.style.flex = "1 1 auto";
  inRegex.style.fontFamily = "ui-monospace, monospace"; inRegex.style.fontSize = "12px";
  inRegex.value = r.match_regex || "";
  inRegex.addEventListener("input", () => _markRowValidity(row));

  const mvHint = document.createElement("span");
  mvHint.style.color = "var(--muted)"; mvHint.style.fontSize = "12px";
  mvHint.textContent = tr("inhib.suppresses_all");

  mvWrap.appendChild(inLabel);
  mvWrap.appendChild(eqSign);
  mvWrap.appendChild(inRegex);
  mvWrap.appendChild(mvHint);
  tdMv.appendChild(mvWrap); row.appendChild(tdMv);

  function _applyMatchType(v) {
    inLabel.style.display = (v === "match_all") ? "none" : "";
    eqSign.style.display  = (v === "match_label") ? "" : "none";
    inRegex.style.display = (v === "match_label") ? "" : "none";
    mvHint.style.display  = (v === "match_all") ? "" : "none";
    inLabel.placeholder = v === "match_label" ? "job" : "host";
    // NB: do NOT call _markRowValidity here on the initial render — the
    // ttl/applies_to/actions cells aren't appended yet so the validator's
    // tr.querySelector('[data-k="ttl_seconds"]') would be null and crash
    // with "Cannot read properties of null (reading 'value')". The final
    // _markRowValidity at the end of _renderInhibRuleRow handles the
    // first-pass validation; user-driven `change` events from the select
    // call this again later, when the row IS complete.
  }
  _applyMatchType(mt);
  sel.addEventListener("change", () => { _applyMatchType(sel.value); _markRowValidity(row); });

  // --- Applies to (checkboxes) ---
  const tdAp = document.createElement("td");
  const wrap = document.createElement("div");
  wrap.dataset.k = "applies_to";
  wrap.style.display = "flex"; wrap.style.flexWrap = "wrap"; wrap.style.gap = "0.4em";
  const selected = new Set(r.applies_to || []);
  for (const s of _inhibAvailableSources) {
    const lbl = document.createElement("label");
    lbl.style.fontSize = "0.85em"; lbl.style.whiteSpace = "nowrap"; lbl.style.margin = "0";
    const cb = document.createElement("input");
    cb.type = "checkbox"; cb.value = s; cb.checked = selected.has(s);
    lbl.appendChild(cb);
    lbl.appendChild(document.createTextNode(" " + s));
    wrap.appendChild(lbl);
  }
  const allHint = document.createElement("small");
  allHint.className = "muted"; allHint.style.fontSize = "11px";
  allHint.textContent = tr("inhib.empty_all_sources");
  tdAp.appendChild(wrap); tdAp.appendChild(allHint); row.appendChild(tdAp);

  // --- TTL ---
  const tdTtl = document.createElement("td");
  const ttlWrap = document.createElement("div");
  ttlWrap.style.display = "flex"; ttlWrap.style.gap = "0.3em"; ttlWrap.style.alignItems = "center"; ttlWrap.style.flexWrap = "wrap";
  const inTtl = document.createElement("input");
  inTtl.type = "number"; inTtl.min = "30"; inTtl.max = "86400";
  inTtl.value = r.ttl_seconds || 900; inTtl.dataset.k = "ttl_seconds";
  inTtl.style.width = "5.5em";
  inTtl.addEventListener("input", () => _markRowValidity(row));
  ttlWrap.appendChild(inTtl);
  for (const [lbl, sec] of [["5m", 300], ["15m", 900], ["30m", 1800], ["1h", 3600]]) {
    const btn = document.createElement("button");
    btn.type = "button"; btn.className = "btn"; btn.textContent = lbl;
    btn.style.padding = "2px 6px"; btn.style.fontSize = "11px";
    btn.title = `Set TTL to ${sec}s`;
    btn.addEventListener("click", () => { inTtl.value = sec; _markRowValidity(row); });
    ttlWrap.appendChild(btn);
  }
  tdTtl.appendChild(ttlWrap); row.appendChild(tdTtl);

  // --- Actions (duplicate + delete) ---
  const tdAct = document.createElement("td");
  tdAct.style.whiteSpace = "nowrap";
  const dup = document.createElement("button");
  dup.type = "button"; dup.className = "btn";
  dup.textContent = "⎘"; dup.title = tr("inhib.duplicate_title");
  dup.style.padding = "2px 8px"; dup.style.marginRight = "4px";
  dup.addEventListener("click", () => {
    // Snapshot current row state and append a clone below it.
    const get = k => row.querySelector(`[data-k="${k}"]`);
    const mt = get("match_type").value;
    const snapshot = {
      source: get("source").value.trim() + " (copy)",
      ttl_seconds: parseInt(get("ttl_seconds").value || "900", 10),
      applies_to: Array.from(row.querySelectorAll('[data-k="applies_to"] input[type=checkbox]'))
                  .filter(cb => cb.checked).map(cb => cb.value),
    };
    if (mt === "match_by") snapshot.match_by = get("match_label").value.trim();
    else if (mt === "match_label") {
      snapshot.match_label = get("match_label").value.trim();
      snapshot.match_regex = get("match_regex").value.trim();
    } else snapshot.match_all = true;
    const clone = _renderInhibRuleRow(snapshot);
    row.parentNode.insertBefore(clone, row.nextSibling);
    showTableRowPage("t-inhib-rules", clone);
  });
  const btn = document.createElement("button");
  btn.type = "button"; btn.className = "btn";
  btn.textContent = "✕"; btn.title = tr("inhib.delete_rule_title");
  btn.style.color = "var(--red)"; btn.style.padding = "2px 8px";
  btn.addEventListener("click", () => {
    row.remove();
    applyTablePager("t-inhib-rules");
  });
  tdAct.appendChild(dup); tdAct.appendChild(btn);
  row.appendChild(tdAct);

  _markRowValidity(row);
  return row;
}

// Validate a single rule row in-place and flash the bad cell.
// Returns null if valid, or a human-readable error string.
function _validateInhibRow(tr) {
  const get = k => tr.querySelector(`[data-k="${k}"]`);
  const src = get("source").value.trim();
  if (!src) return "source name is required";
  const mt = get("match_type").value;
  if (mt === "match_by") {
    if (!get("match_label").value.trim()) return "label name is required for match_by";
  } else if (mt === "match_label") {
    if (!get("match_label").value.trim()) return "label name is required";
    const rx = get("match_regex").value.trim();
    if (!rx) return "regex is required";
    try { new RegExp(rx); } catch (e) { return "invalid regex: " + e.message; }
  }
  const ttl = parseInt(get("ttl_seconds").value || "0", 10);
  if (!Number.isFinite(ttl) || ttl < 30 || ttl > 86400) return "TTL must be 30..86400 seconds";
  return null;
}

function _markRowValidity(tr) {
  const err = _validateInhibRow(tr);
  if (err) tr.dataset.invalid = err;
  else delete tr.dataset.invalid;
  tr.style.outline = err ? "1px solid var(--red)" : "";
}

export async function loadInhibRules() {
  try {
    const data = await queryGet("inhibition-rules", "/api/inhibition-rules");
    _inhibAvailableSources = data.available_sources || [];
    const tb = $("#t-inhib-rules tbody"); tb.innerHTML = "";
    for (const r of (data.rules || [])) tb.appendChild(_renderInhibRuleRow(r));
    $("#inhib-save-status").textContent = "";
    applyTablePager("t-inhib-rules", { reset: true });
  } catch (e) { fetchError("inhibition-rules", e); }
}

function _collectInhibRules() {
  const rows = document.querySelectorAll("#t-inhib-rules tbody tr.inhib-rule-row");
  const out = [];
  for (const tr of rows) {
    const err = _validateInhibRow(tr);
    if (err) {
      const src = tr.querySelector('[data-k="source"]').value.trim() || "(unnamed)";
      return { error: `rule "${src}": ${err}` };
    }
    const get = k => tr.querySelector(`[data-k="${k}"]`);
    const source = get("source").value.trim();
    const mt = get("match_type").value;
    const ttl = parseInt(get("ttl_seconds").value || "900", 10);
    const applies = Array.from(tr.querySelectorAll('[data-k="applies_to"] input[type=checkbox]'))
                    .filter(cb => cb.checked).map(cb => cb.value);
    const rule = { source, ttl_seconds: ttl, applies_to: applies };
    if (mt === "match_by") {
      rule.match_by = get("match_label").value.trim();
    } else if (mt === "match_label") {
      rule.match_label = get("match_label").value.trim();
      rule.match_regex = get("match_regex").value.trim();
    } else {
      rule.match_all = true;
    }
    out.push(rule);
  }
  return { rules: out };
}

async function saveInhibRules() {
  const collected = _collectInhibRules();
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
    tb.appendChild(_renderInhibRuleRow({source: "", ttl_seconds: 900, applies_to: [], match_by: ""}));
    applyTablePager("t-inhib-rules", { page: "last" });
  });
  if (save) save.addEventListener("click", saveInhibRules);
  if (clearAll) clearAll.addEventListener("click", clearAllSuppressions);
  const testBtn = document.getElementById("inhib-test-run");
  if (testBtn) testBtn.addEventListener("click", testInhibitionRule);
});

function fmtSecs(s) {
  if (s < 60) return s + "s";
  if (s < 3600) return Math.round(s/60) + "m";
  return Math.round(s/3600 * 10) / 10 + "h";
}
