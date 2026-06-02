// klaxond admin UI — vanilla JS, no framework.

const $ = sel => document.querySelector(sel);
const $$ = sel => document.querySelectorAll(sel);

const J = async (url, opts) => {
  const r = await fetch(url, opts);
  if (!r.ok) throw new Error(`${r.status} ${r.statusText}`);
  const ct = r.headers.get("content-type") || "";
  return ct.includes("json") ? r.json() : r.text();
};

// ---- Tab switching (with URL hash routing) ----
function activateTab(tabId) {
  $$(".tab").forEach(x => x.classList.remove("active"));
  $$(".tabpane").forEach(x => x.classList.remove("active"));
  const btn = document.querySelector(`.tab[data-tab="${tabId}"]`);
  const pane = $("#tab-" + tabId);
  if (btn && pane) {
    btn.classList.add("active");
    pane.classList.add("active");
    _onTabActivated(tabId);
    return true;
  }
  return false;
}

// Per-tab initializer hook — called on EVERY activation (click OR hash route).
// Loaders are idempotent (re-fetching is cheap). Add `case` here for new tabs.
function _onTabActivated(tabId) {
  try {
    switch (tabId) {
      case "flow":        if (typeof loadFlow === "function")       { loadFlow(); if (typeof _setupFlowAutorefresh === "function") _setupFlowAutorefresh(); } break;
      case "auth":        if (typeof loadAuth === "function")        loadAuth(); break;
      case "routing":     if (typeof loadNtfyTopics === "function") loadNtfyTopics(); if (typeof loadIngestAuth === "function") loadIngestAuth(); break;
      case "grouping":    if (typeof loadDedup === "function")       loadDedup(); break;
      case "inhibitions": if (typeof loadInhibRules === "function") loadInhibRules(); if (typeof loadSchedules === "function") loadSchedules(); if (typeof loadAcks === "function") loadAcks(); break;
    }
  } catch (e) { console.warn("tab init failed:", tabId, e); }
}

function syncTabFromHash() {
  const h = (location.hash || "").replace(/^#/, "");
  if (h && activateTab(h)) return;
  activateTab("status");  // default
}

$$(".tab").forEach(t => {
  t.addEventListener("click", () => {
    location.hash = "#" + t.dataset.tab;  // triggers hashchange
  });
});

window.addEventListener("hashchange", syncTabFromHash);
syncTabFromHash();

// ---- Status ----
async function loadStatus() {
  try {
    const s = await J("/api/status");
    const setCh = (id, up, url) => {
      const card = $("#" + id);
      const dot = card.querySelector(".dot");
      dot.className = "dot " + (up ? "up" : "down");
      dot.title = up ? "Reachable" : "Unreachable";
      // Add a textual status next to the dot (accessibility — color alone
      // isn't enough for colorblind users + screen readers).
      let statusText = card.querySelector(".ch-status-text");
      if (!statusText) {
        statusText = document.createElement("small");
        statusText.className = "ch-status-text";
        statusText.style.marginLeft = "6px";
        dot.insertAdjacentElement("afterend", statusText);
      }
      statusText.textContent = up ? "✓ up" : "✗ down";
      statusText.style.color = up ? "var(--green)" : "var(--red)";
      card.querySelector(".ch-url").textContent = url || "";
    };
    setCh("ch-ntfy", s.channels.ntfy, s.ntfy_url);
    setCh("ch-telegram", s.channels.telegram, s.telegram_configured ? "bot configured" : "(not configured)");
    setCh("ch-smtp", s.channels.smtp, s.smtp_host ? `${s.smtp_host}` : "(not configured)");
    $("#cas-default").textContent = s.cascade_enabled_default;
    $("#cas-runtime").textContent = s.cascade_enabled_runtime;
  } catch (e) { fetchError("status", e); }
  loadStatusActivity();
}

// Update the small count chip next to a tab label.
// kind: '' (neutral) | 'warn' (yellow) | 'crit' (red). count=0 hides the badge.
function setTabBadge(tabId, count, kind = "") {
  const tab = document.querySelector(`.tab[data-tab="${tabId}"]`);
  if (!tab) return;
  let badge = tab.querySelector(".tab-badge");
  if (!count || count <= 0) {
    if (badge) badge.remove();
    return;
  }
  if (!badge) {
    badge = document.createElement("span");
    badge.className = "tab-badge";
    tab.appendChild(badge);
  }
  badge.className = "tab-badge" + (kind ? " " + kind : "");
  badge.textContent = count > 99 ? "99+" : String(count);
}

// Aggregate 24h activity from existing endpoints (no new backend needed).
// Also updates the tab badges (deliveries24h / suppressions / dedup-pending).
async function loadStatusActivity() {
  // Deliveries: fetch ring buffer + count last 24h
  try {
    const items = await J("/api/deliveries");
    const cutoff = Date.now() / 1000 - 24 * 3600;
    const recent = (items || []).filter(it => (it.ts || 0) >= cutoff);
    const bySource = {};
    for (const it of recent) {
      const k = it.source || "?";
      bySource[k] = (bySource[k] || 0) + 1;
    }
    $("#stat-deliv-total").textContent = recent.length;
    const parts = Object.entries(bySource).sort((a,b) => b[1]-a[1])
                  .map(([k,v]) => `${k}: ${v}`);
    $("#stat-deliv-breakdown").innerHTML = parts.length
      ? "by source: " + parts.map(p => `<code>${escapeHtml(p)}</code>`).join(" · ")
      : "by source: <span class='muted'>(no activity)</span>";
    setTabBadge("deliveries", recent.length);
  } catch (e) {
    $("#stat-deliv-total").textContent = "?";
    $("#stat-deliv-breakdown").textContent = "deliveries unreachable";
  }
  // Active suppressions count
  try {
    const inhib = await J("/api/inhibitions");
    const n = (inhib || []).length;
    $("#stat-suppr-count").textContent = n;
    setTabBadge("inhibitions", n, n > 0 ? "warn" : "");
  } catch (e) { $("#stat-suppr-count").textContent = "?"; }
  // Dedup pending count (sum across all sources)
  try {
    const d = await J("/api/dedup-config");
    const pc = d.pending_counts || {};
    const total = Object.values(pc).reduce((a, b) => a + (b || 0), 0);
    $("#stat-dedup-count").textContent = total;
    setTabBadge("grouping", total, total > 0 ? "warn" : "");
  } catch (e) { $("#stat-dedup-count").textContent = "?"; }
  // Refresh config backup list (also belongs to the Status pane)
  if (typeof loadConfigBackups === "function") loadConfigBackups();
}

$("#btn-cascade-toggle").addEventListener("click", async () => {
  await J("/api/cascade/toggle", { method: "POST", body: "{}" });
  loadStatus();
});


// ---- Config backup / restore ----
async function loadConfigBackups() {
  const ul = $("#cfg-backup-list"); if (!ul) return;
  try {
    const r = await J("/api/config/backups");
    if (r.dir) $("#cfg-backup-dir").textContent = r.dir;
    if (r.keep_max) $("#cfg-backup-keep").textContent = r.keep_max;
    const items = r.backups || [];
    if (!items.length) { ul.innerHTML = "<li>(no backups yet — saved on next config change)</li>"; return; }
    ul.innerHTML = items.slice(0, 10).map(b => {
      const kb = Math.round(b.size / 1024);
      return `<li><code>${escapeHtml(b.name)}</code> · ${kb} KB · ${escapeHtml(b.mtime_iso)}</li>`;
    }).join("");
  } catch (e) { ul.innerHTML = `<li class='muted'>backups list unavailable: ${escapeHtml(e.message)}</li>`; }
}

// Download is a plain anchor href — the browser handles content-disposition.
document.addEventListener("DOMContentLoaded", () => {
  const dl = document.getElementById("cfg-backup-download");
  if (dl) dl.href = "/api/config/backup";

  const fileInput = document.getElementById("cfg-restore-file");
  if (fileInput) fileInput.addEventListener("change", async e => {
    const f = e.target.files[0]; if (!f) return;
    const status = $("#cfg-restore-status");
    if (!confirm(`Restore klaxond config from "${f.name}" (${f.size} bytes)?\n\nThe current config will be auto-backed-up first. After upload, in-memory state reloads. Continue?`)) {
      e.target.value = ""; return;
    }
    status.textContent = "Uploading…"; status.style.color = "";
    try {
      const raw = await f.text();
      const res = await fetch("/api/config/restore", {
        method: "POST", headers: {"Content-Type": "application/toml"}, body: raw,
      });
      if (!res.ok) {
        const txt = await res.text();
        status.textContent = `❌ ${res.status} ${txt.slice(0, 200)}`;
        status.style.color = "var(--red)"; return;
      }
      const j = await res.json();
      status.textContent = `✓ Restored ${j.bytes_written} bytes. Pre-restore backup: ${j.pre_restore_backup || '(none)'}`;
      status.style.color = "var(--green)";
      showToast("Config restored — reload page to see all UI state refresh", "success", 6000);
      loadConfigBackups();
    } catch (err) {
      status.textContent = "❌ " + err.message;
      status.style.color = "var(--red)";
    } finally {
      e.target.value = "";
    }
  });
});

// ---- Inhibitions (active suppressions) ----
async function loadInhib() {
  try {
    const rows = await J("/api/inhibitions");
    const tb = $("#t-inhib tbody"); tb.innerHTML = "";
    if (!rows.length) { tb.innerHTML = '<tr><td colspan="5" class="muted">No active suppressions.</td></tr>'; return; }
    for (const r of rows) {
      const tr = document.createElement("tr");
      const scope = Array.isArray(r.applies_to) ? r.applies_to.join(", ") : "*";
      tr.innerHTML = `<td><code>${escapeHtml(r.source)}</code></td><td>${escapeHtml(r.anchor)}</td><td><code>${escapeHtml(scope)}</code></td><td>${fmtSecs(r.expires_in_seconds)}</td><td><button class="btn" data-clear-suppression title="Force-clear this suppression" style="color:var(--red); padding:2px 8px">✕</button></td>`;
      tr.querySelector("[data-clear-suppression]").addEventListener("click", () => clearSuppression(r.source, r.anchor));
      tb.appendChild(tr);
    }
  } catch (e) { fetchError("inhibitions", e); }
}

async function clearSuppression(source, anchor) {
  const status = $("#inhib-clear-status");
  try {
    const res = await fetch("/api/inhibitions/clear", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({source, anchor}),
    });
    if (!res.ok) {
      status.textContent = "❌ " + (await res.text() || res.statusText);
      status.style.color = "var(--red)"; return;
    }
    const r = await res.json();
    status.textContent = `Cleared ${r.cleared} suppression(s) for ${source}`;
    status.style.color = "var(--green)";
    setTimeout(() => { status.textContent = ""; }, 3000);
    await loadInhib();
    if (typeof loadStatusActivity === "function") loadStatusActivity();
  } catch (e) {
    status.textContent = "❌ " + e.message;
    status.style.color = "var(--red)";
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
    status.textContent = "❌ " + errors[0];
    status.style.color = "var(--red)";
    result.innerHTML = "";
    return;
  }
  status.textContent = "Testing…";
  status.style.color = "";
  try {
    const res = await fetch("/api/inhibition-rules/test", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({source, labels}),
    });
    if (!res.ok) {
      const txt = await res.text();
      status.textContent = "❌ " + (txt || res.statusText);
      status.style.color = "var(--red)"; return;
    }
    const r = await res.json();
    status.textContent = "";
    const verdict = r.would_send
      ? `<span style="color:var(--green)">✓ <b>Would be delivered</b></span> (reason: <code>${escapeHtml(r.reason)}</code>)`
      : `<span style="color:var(--red)">✗ <b>Would be SUPPRESSED</b></span> by rule <code>${escapeHtml(r.matched_rule || "")}</code>`;
    const arm = r.would_arm_suppression
      ? '<br/><span style="color:var(--accent)">⚡ Source alert detected — would ARM a new suppression for this rule.</span>'
      : "";
    const considered = (r.considered_rules || []).length
      ? `<br/><small class="muted">Rules considered for source <code>${escapeHtml(source)}</code>: ${r.considered_rules.map(s => `<code>${escapeHtml(s)}</code>`).join(", ")}</small>`
      : `<br/><small class="muted">No rules apply to source <code>${escapeHtml(source)}</code>.</small>`;
    result.innerHTML = verdict + arm + considered;
  } catch (e) {
    status.textContent = "❌ " + e.message;
    status.style.color = "var(--red)";
  }
}

// ---- Ack-snoozes (active, 0.9.20+) ----
async function loadAcks() {
  const tb = $("#t-acks tbody"); if (!tb) return;
  try {
    const acks = await J("/api/acks");
    tb.innerHTML = "";
    if (!acks.length) { tb.innerHTML = '<tr><td colspan="3" class="muted">No active ack-snoozes.</td></tr>'; return; }
    for (const a of acks) {
      const tr = document.createElement("tr");
      tr.innerHTML = `<td><code>${escapeHtml(a.alertname)}</code></td><td>${fmtSecs(a.expires_in_seconds)}</td><td>
        <button class="btn" data-clear-ack="${escapeHtml(a.alertname)}" title="Force-clear this ack" style="color:var(--red); padding:2px 8px">✕</button>
      </td>`;
      tr.querySelector("[data-clear-ack]").addEventListener("click", () => clearAck(a.alertname));
      tb.appendChild(tr);
    }
  } catch (e) { console.warn("acks fetch:", e); }
}

async function clearAck(alertname) {
  if (!confirm(`Force-clear ack-snooze for "${alertname}"?\n\nFuture alerts with this alertname will resume normal delivery.`)) return;
  try {
    const res = await fetch("/api/acks/clear", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({alertname}),
    });
    if (!res.ok) {
      showToast(`Ack clear failed: ${res.status}`, "error"); return;
    }
    const r = await res.json();
    showToast(`✓ Cleared ${r.cleared} ack-snooze${r.cleared === 1 ? "" : "s"}`, "success", 3000);
    loadAcks();
  } catch (e) {
    showToast(`Ack clear error: ${e.message}`, "error");
  }
}


// ---- Schedules (maintenance windows, 0.9.19+) ----
let _schedAvailableSources = ["grafana", "beszel", "healthchecks", "wud", "authentik"];
let _schedActiveMutes = {};   // name → seconds remaining

function _renderSchedRow(s) {
  const tr = document.createElement("tr");
  tr.classList.add("sched-row");

  const td = (html) => { const x = document.createElement("td"); x.innerHTML = html; return x; };

  // Name
  const inName = document.createElement("input");
  inName.type = "text"; inName.value = s.name || ""; inName.dataset.k = "name";
  inName.placeholder = "backup-window"; inName.style.width = "100%";
  const tdN = document.createElement("td"); tdN.appendChild(inName); tr.appendChild(tdN);

  // Cron
  const inCron = document.createElement("input");
  inCron.type = "text"; inCron.value = s.cron || ""; inCron.dataset.k = "cron";
  inCron.placeholder = "30 4 * * 0"; inCron.style.width = "100%";
  inCron.style.fontFamily = "ui-monospace, monospace"; inCron.style.fontSize = "12px";
  const tdC = document.createElement("td"); tdC.appendChild(inCron); tr.appendChild(tdC);

  // Duration
  const inDur = document.createElement("input");
  inDur.type = "number"; inDur.min = "1"; inDur.max = "1440";
  inDur.value = s.duration_minutes || 30; inDur.dataset.k = "duration_minutes";
  inDur.style.width = "5em";
  const tdD = document.createElement("td"); tdD.appendChild(inDur); tr.appendChild(tdD);

  // Match (key=val per line)
  const matchObj = s.match || {};
  const matchTxt = Object.entries(matchObj).map(([k,v]) => `${k}=${v}`).join("\n");
  const taMatch = document.createElement("textarea");
  taMatch.dataset.k = "match"; taMatch.rows = 3; taMatch.value = matchTxt;
  taMatch.placeholder = "component=storage\nseverity=info";
  taMatch.style.fontFamily = "ui-monospace, monospace"; taMatch.style.fontSize = "12px";
  const tdM = document.createElement("td"); tdM.appendChild(taMatch); tr.appendChild(tdM);

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
  tdA.appendChild(wrap); tr.appendChild(tdA);

  // Status (active/idle)
  const tdS = td("");
  const updStatus = () => {
    const name = inName.value.trim();
    const remain = _schedActiveMutes[name];
    if (remain && remain > 0) {
      const m = Math.ceil(remain / 60);
      tdS.innerHTML = `<span style="color:var(--yellow)">⚡ ACTIVE</span><br/><small>${m}m left</small>`;
    } else {
      tdS.innerHTML = `<span class="muted">idle</span>`;
    }
  };
  updStatus();
  inName.addEventListener("input", updStatus);
  tr.appendChild(tdS);

  // Delete
  const tdDel = document.createElement("td");
  const del = document.createElement("button");
  del.className = "btn"; del.textContent = "✕"; del.title = "Delete this schedule";
  del.style.color = "var(--red)"; del.style.padding = "2px 8px";
  del.addEventListener("click", () => tr.remove());
  tdDel.appendChild(del); tr.appendChild(tdDel);

  return tr;
}

async function loadSchedules() {
  const tb = $("#t-schedules tbody"); if (!tb) return;
  try {
    const data = await J("/api/schedules");
    _schedActiveMutes = data.active_mutes || {};
    tb.innerHTML = "";
    for (const s of (data.schedules || [])) tb.appendChild(_renderSchedRow(s));
    $("#sched-save-status").textContent = "";
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
    status.textContent = "❌ " + collected.error; status.style.color = "var(--red)"; return;
  }
  status.textContent = "Saving…"; status.style.color = "";
  try {
    const res = await fetch("/api/schedules", {
      method: "POST", headers: {"Content-Type": "application/json"},
      body: JSON.stringify({ schedules: collected.schedules }),
    });
    if (!res.ok) {
      const txt = await res.text();
      status.textContent = "❌ " + (txt || res.statusText);
      status.style.color = "var(--red)"; return;
    }
    const r = await res.json();
    status.textContent = `✓ Saved ${r.count} schedule(s).`;
    status.style.color = "var(--green)";
    _markTabDirty("inhibitions", false);
    await loadSchedules();
  } catch (e) {
    status.textContent = "❌ " + e.message;
    status.style.color = "var(--red)";
  }
}

document.addEventListener("DOMContentLoaded", () => {
  const add = document.getElementById("sched-add");
  const save = document.getElementById("sched-save");
  if (add) add.addEventListener("click", () => {
    const tb = $("#t-schedules tbody");
    tb.appendChild(_renderSchedRow({name:"", cron:"", duration_minutes:30, match:{}, applies_to:[]}));
  });
  if (save) save.addEventListener("click", saveSchedules);
});


async function clearAllSuppressions() {
  const status = $("#inhib-clear-status");
  // Native confirm — appropriate for a force-clear action that bypasses TTL.
  if (!confirm("Force-clear ALL active suppressions? Suppressions will re-arm on the next source alert. Continue?")) return;
  try {
    const res = await fetch("/api/inhibitions/clear", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({all: true}),
    });
    if (!res.ok) {
      status.textContent = "❌ " + (await res.text() || res.statusText);
      status.style.color = "var(--red)"; return;
    }
    const r = await res.json();
    status.textContent = `Cleared ${r.cleared} suppression(s)`;
    status.style.color = "var(--green)";
    setTimeout(() => { status.textContent = ""; }, 3000);
    await loadInhib();
    if (typeof loadStatusActivity === "function") loadStatusActivity();
  } catch (e) {
    status.textContent = "❌ " + e.message;
    status.style.color = "var(--red)";
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
  const tr = document.createElement("tr");
  tr.classList.add("inhib-rule-row");
  const mt = _matchTypeOf(r);

  // --- Source name ---
  const tdSrc = document.createElement("td");
  const inSrc = document.createElement("input");
  inSrc.type = "text"; inSrc.value = r.source || ""; inSrc.dataset.k = "source";
  inSrc.placeholder = "e.g. node-down"; inSrc.style.width = "100%";
  inSrc.addEventListener("input", () => _markRowValidity(tr));
  tdSrc.appendChild(inSrc); tr.appendChild(tdSrc);

  // --- Match type select ---
  const tdMt = document.createElement("td");
  const sel = document.createElement("select"); sel.dataset.k = "match_type";
  const _MT_LABELS = {match_by: "match_by", match_label: "match_label + regex", match_all: "match_all"};
  for (const opt of ["match_by", "match_label", "match_all"]) {
    const o = document.createElement("option"); o.value = opt; o.textContent = _MT_LABELS[opt];
    if (opt === mt) o.selected = true;
    sel.appendChild(o);
  }
  tdMt.appendChild(sel); tr.appendChild(tdMt);

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
  inLabel.addEventListener("input", () => _markRowValidity(tr));

  const eqSign = document.createElement("span");
  eqSign.textContent = "="; eqSign.style.color = "var(--muted)";

  const inRegex = document.createElement("input");
  inRegex.type = "text"; inRegex.dataset.k = "match_regex";
  inRegex.placeholder = "^blackbox-.*"; inRegex.style.flex = "1 1 auto";
  inRegex.style.fontFamily = "ui-monospace, monospace"; inRegex.style.fontSize = "12px";
  inRegex.value = r.match_regex || "";
  inRegex.addEventListener("input", () => _markRowValidity(tr));

  const mvHint = document.createElement("span");
  mvHint.style.color = "var(--muted)"; mvHint.style.fontSize = "12px";
  mvHint.textContent = "(suppresses every alert)";

  mvWrap.appendChild(inLabel);
  mvWrap.appendChild(eqSign);
  mvWrap.appendChild(inRegex);
  mvWrap.appendChild(mvHint);
  tdMv.appendChild(mvWrap); tr.appendChild(tdMv);

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
  sel.addEventListener("change", () => { _applyMatchType(sel.value); _markRowValidity(tr); });

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
  allHint.textContent = "(empty = all sources)";
  tdAp.appendChild(wrap); tdAp.appendChild(allHint); tr.appendChild(tdAp);

  // --- TTL ---
  const tdTtl = document.createElement("td");
  const ttlWrap = document.createElement("div");
  ttlWrap.style.display = "flex"; ttlWrap.style.gap = "0.3em"; ttlWrap.style.alignItems = "center"; ttlWrap.style.flexWrap = "wrap";
  const inTtl = document.createElement("input");
  inTtl.type = "number"; inTtl.min = "30"; inTtl.max = "86400";
  inTtl.value = r.ttl_seconds || 900; inTtl.dataset.k = "ttl_seconds";
  inTtl.style.width = "5.5em";
  inTtl.addEventListener("input", () => _markRowValidity(tr));
  ttlWrap.appendChild(inTtl);
  for (const [lbl, sec] of [["5m", 300], ["15m", 900], ["30m", 1800], ["1h", 3600]]) {
    const btn = document.createElement("button");
    btn.type = "button"; btn.className = "btn"; btn.textContent = lbl;
    btn.style.padding = "2px 6px"; btn.style.fontSize = "11px";
    btn.title = `Set TTL to ${sec}s`;
    btn.addEventListener("click", () => { inTtl.value = sec; _markRowValidity(tr); });
    ttlWrap.appendChild(btn);
  }
  tdTtl.appendChild(ttlWrap); tr.appendChild(tdTtl);

  // --- Actions (duplicate + delete) ---
  const tdAct = document.createElement("td");
  tdAct.style.whiteSpace = "nowrap";
  const dup = document.createElement("button");
  dup.type = "button"; dup.className = "btn";
  dup.textContent = "⎘"; dup.title = "Duplicate this rule";
  dup.style.padding = "2px 8px"; dup.style.marginRight = "4px";
  dup.addEventListener("click", () => {
    // Snapshot current row state and append a clone below it.
    const get = k => tr.querySelector(`[data-k="${k}"]`);
    const mt = get("match_type").value;
    const snapshot = {
      source: get("source").value.trim() + " (copy)",
      ttl_seconds: parseInt(get("ttl_seconds").value || "900", 10),
      applies_to: Array.from(tr.querySelectorAll('[data-k="applies_to"] input[type=checkbox]'))
                  .filter(cb => cb.checked).map(cb => cb.value),
    };
    if (mt === "match_by") snapshot.match_by = get("match_label").value.trim();
    else if (mt === "match_label") {
      snapshot.match_label = get("match_label").value.trim();
      snapshot.match_regex = get("match_regex").value.trim();
    } else snapshot.match_all = true;
    const clone = _renderInhibRuleRow(snapshot);
    tr.parentNode.insertBefore(clone, tr.nextSibling);
  });
  const btn = document.createElement("button");
  btn.type = "button"; btn.className = "btn";
  btn.textContent = "✕"; btn.title = "Delete this rule";
  btn.style.color = "var(--red)"; btn.style.padding = "2px 8px";
  btn.addEventListener("click", () => tr.remove());
  tdAct.appendChild(dup); tdAct.appendChild(btn);
  tr.appendChild(tdAct);

  _markRowValidity(tr);
  return tr;
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

async function loadInhibRules() {
  try {
    const data = await J("/api/inhibition-rules");
    _inhibAvailableSources = data.available_sources || [];
    const tb = $("#t-inhib-rules tbody"); tb.innerHTML = "";
    for (const r of (data.rules || [])) tb.appendChild(_renderInhibRuleRow(r));
    $("#inhib-save-status").textContent = "";
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
  if (collected.error) { status.textContent = "❌ " + collected.error; status.style.color = "#e57373"; return; }
  status.textContent = "Saving…"; status.style.color = "";
  try {
    const res = await fetch("/api/inhibition-rules", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({ rules: collected.rules }),
    });
    if (!res.ok) {
      const txt = await res.text();
      status.textContent = "❌ " + (txt || res.statusText);
      status.style.color = "#e57373"; return;
    }
    const r = await res.json();
    status.textContent = `✓ Saved ${r.count} rule(s). Cleared ${r.cleared_suppressions} active suppression(s).`;
    status.style.color = "#81c784";
    _markTabDirty("inhibitions", false);
    await loadInhibRules();
    await loadInhib();
  } catch (e) {
    status.textContent = "❌ " + e.message;
    status.style.color = "#e57373";
  }
}

document.addEventListener("DOMContentLoaded", () => {
  const add = document.getElementById("inhib-add");
  const save = document.getElementById("inhib-save");
  const clearAll = document.getElementById("inhib-clear-all");
  if (add) add.addEventListener("click", () => {
    const tb = $("#t-inhib-rules tbody");
    tb.appendChild(_renderInhibRuleRow({source: "", ttl_seconds: 900, applies_to: [], match_by: ""}));
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

// ---- Deliveries ----
let _delivCache = [];  // most recent fetch — filter applies client-side without re-fetching

async function loadDeliv() {
  try {
    _delivCache = await J("/api/deliveries");
  } catch (e) {
    fetchError("deliveries", e);
    _delivCache = [];
  }
  renderDeliv();
}

function renderDeliv() {
  const tb = $("#t-deliv tbody"); if (!tb) return;
  tb.innerHTML = "";
  const filter = ($("#deliv-filter")?.value || "").trim().toLowerCase();
  const showSuppressed = $("#deliv-show-suppressed")?.checked !== false;
  const rows = (_delivCache || []).slice().reverse();
  let shown = 0, total = rows.length;
  for (const r of rows) {
    const isSupp = r.channel === "suppressed" || r.channel === "dry-run-suppressed";
    if (isSupp && !showSuppressed) continue;
    if (filter) {
      const hay = `${r.source} ${r.severity} ${r.title} ${r.channel} ${r.suppressed_by || ""}`.toLowerCase();
      if (!hay.includes(filter)) continue;
    }
    const tr = document.createElement("tr");
    tr.classList.add("deliv-row");
    const t = new Date(r.ts * 1000).toLocaleTimeString();
    let chCell;
    if (r.channel === "suppressed") {
      chCell = `<span class="ch-suppressed">suppressed by <code>${escapeHtml(r.suppressed_by || "?")}</code></span>`;
    } else if (r.channel === "dry-run") {
      chCell = `<span class="ch-dry-run">dry-run</span>`;
    } else if (r.channel === "dry-run-suppressed") {
      chCell = `<span class="ch-suppressed">dry-run (would suppress: <code>${escapeHtml(r.suppressed_by || "?")}</code>)</span>`;
    } else {
      chCell = `<span class="ch-${r.channel}">${escapeHtml(r.channel)}</span>`;
    }
    tr.innerHTML = `<td>${t}</td><td>${escapeHtml(r.source)}</td><td class="sev-${r.severity}">${r.severity}</td><td>${escapeHtml(r.title)}</td><td>${chCell}</td>`;
    tr.addEventListener("click", () => _toggleDelivExpand(tr, r));
    tr.style.cursor = "pointer";
    tb.appendChild(tr); shown++;
  }
  const cnt = $("#deliv-count");
  if (cnt) cnt.textContent = total === shown ? `${total} event(s)` : `${shown} / ${total} event(s)`;
  if (!shown) tb.innerHTML = `<tr><td colspan="5" class="muted">${total ? "No events match the filter." : "No deliveries yet."}</td></tr>`;
}

function _toggleDelivExpand(tr, r) {
  const next = tr.nextElementSibling;
  if (next && next.classList.contains("deliv-detail")) {
    next.remove();
    tr.classList.remove("expanded");
    return;
  }
  const detail = document.createElement("tr");
  detail.classList.add("deliv-detail");
  const ts = new Date(r.ts * 1000);
  const tsFull = ts.toISOString() + " (" + ts.toLocaleString() + ")";
  const rows = [
    ["timestamp", `<code>${escapeHtml(tsFull)}</code>`],
    ["source",    `<code>${escapeHtml(r.source || "")}</code>`],
    ["severity",  `<code>${escapeHtml(r.severity || "")}</code>`],
    ["title",     `<code>${escapeHtml(r.title || "")}</code>`],
    ["channel",   `<code>${escapeHtml(r.channel || "")}</code>`],
  ];
  if (r.suppressed_by) rows.push(["suppressed_by", `<code>${escapeHtml(r.suppressed_by)}</code>`]);
  const html = rows.map(([k, v]) => `<div class="kv"><span class="kv-k">${k}</span><span class="kv-v">${v}</span></div>`).join("");
  detail.innerHTML = `<td colspan="5" class="deliv-detail-cell">${html}</td>`;
  tr.insertAdjacentElement("afterend", detail);
  tr.classList.add("expanded");
}

// Re-render (client-side, no fetch) when filter changes
document.addEventListener("DOMContentLoaded", () => {
  $("#deliv-filter")?.addEventListener("input", renderDeliv);
  $("#deliv-show-suppressed")?.addEventListener("change", renderDeliv);
  $("#deliv-export-csv")?.addEventListener("click", exportDeliveriesCsv);
});

// Apply the same filter as renderDeliv so the CSV matches what the user sees.
function _filteredDelivRows() {
  const filter = ($("#deliv-filter")?.value || "").trim().toLowerCase();
  const showSuppressed = $("#deliv-show-suppressed")?.checked !== false;
  return (_delivCache || []).slice().reverse().filter(r => {
    const isSupp = r.channel === "suppressed" || r.channel === "dry-run-suppressed";
    if (isSupp && !showSuppressed) return false;
    if (filter) {
      const hay = `${r.source} ${r.severity} ${r.title} ${r.channel} ${r.suppressed_by || ""}`.toLowerCase();
      if (!hay.includes(filter)) return false;
    }
    return true;
  });
}

// RFC 4180 CSV: wrap in double-quotes if it contains commas/quotes/newlines;
// escape embedded double-quotes by doubling them.
function _csvCell(v) {
  const s = String(v == null ? "" : v);
  if (/[",\r\n]/.test(s)) return '"' + s.replace(/"/g, '""') + '"';
  return s;
}

function exportDeliveriesCsv() {
  const rows = _filteredDelivRows();
  if (!rows.length) { showToast("No rows to export", "warn", 4000); return; }
  const header = ["timestamp_iso", "timestamp_epoch", "source", "severity", "title", "channel", "suppressed_by"];
  const lines = [header.join(",")];
  for (const r of rows) {
    const iso = new Date((r.ts || 0) * 1000).toISOString();
    lines.push([iso, r.ts || "", r.source || "", r.severity || "", r.title || "", r.channel || "", r.suppressed_by || ""]
                .map(_csvCell).join(","));
  }
  const blob = new Blob([lines.join("\r\n") + "\r\n"], { type: "text/csv;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = "klaxond-deliveries-" + new Date().toISOString().replace(/[:.]/g, "-") + ".csv";
  a.click();
  URL.revokeObjectURL(url);
  showToast(`Exported ${rows.length} row(s)`, "success", 3000);
}

const escapeHtml = s => String(s).replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));

// ---- Render config ----
let rcData = {};
async function loadRC() {
  try {
    const j = await J("/api/render-config");
    $("#gbase").textContent = j.grafana_base;
    rcData = j.component_dashboards;
    renderRCTable();
    populateTestComponentSelect();
  } catch (e) { fetchError("render-config", e); }
}

function populateTestComponentSelect() {
  const sel = $("#t-component");
  if (!sel) return;
  const cur = sel.value;
  sel.innerHTML = `<option value="">(none — freeform, no button)</option>` +
    Object.keys(rcData).sort().map(k => `<option value="${escapeHtml(k)}">${escapeHtml(k)} → ${escapeHtml(rcData[k][0])}</option>`).join("");
  if (cur && rcData[cur]) sel.value = cur;
}

function renderRCTable() {
  const tb = $("#t-rc tbody"); tb.innerHTML = "";
  for (const [k, v] of Object.entries(rcData)) addRCRow(k, v[0], v[1]);
}

function addRCRow(component="", label="", url="") {
  const tb = $("#t-rc tbody");
  const tr = document.createElement("tr");
  tr.innerHTML = `
    <td><input type="text" value="${escapeHtml(component)}" data-f="key"></td>
    <td><input type="text" value="${escapeHtml(label)}" data-f="label"></td>
    <td><input type="text" value="${escapeHtml(url)}" data-f="url"></td>
    <td>
      <button data-test title="Open URL in new tab">↗</button>
      <button class="danger" data-del>×</button>
    </td>`;
  tr.querySelector("[data-del]").addEventListener("click", () => tr.remove());
  tr.querySelector("[data-test]").addEventListener("click", () => {
    const u = tr.querySelector('[data-f="url"]').value.trim();
    if (!u) return;
    const full = u.startsWith("http") ? u : ($("#gbase").textContent.replace(/\/$/, "") + u);
    window.open(full, "_blank", "noopener");
  });
  tb.appendChild(tr);
}

$("#btn-rc-add").addEventListener("click", () => addRCRow());
$("#btn-rc-save").addEventListener("click", async () => {
  const out = {};
  $$("#t-rc tbody tr").forEach(tr => {
    const k = tr.querySelector('[data-f="key"]').value.trim();
    const l = tr.querySelector('[data-f="label"]').value.trim();
    const u = tr.querySelector('[data-f="url"]').value.trim();
    if (k && l && u) out[k] = [l, u];
  });
  try {
    const r = await J("/api/render-config", { method: "POST", body: JSON.stringify({component_dashboards: out}), headers: {"Content-Type": "application/json"} });
    $("#rc-status").textContent = `Saved (${r.count} mappings) ✓`;
    setTimeout(() => $("#rc-status").textContent = "", 3000);
    _markTabDirty("render", false);
    rcData = out;
    populateTestComponentSelect();
  } catch (e) { $("#rc-status").textContent = "Error: " + e.message; }
});

// ---- Render preview ----
const grafanaSample = {
  "status": "firing",
  "commonLabels": {"alertname":"HostDiskFull","host":"web-01","severity":"warning","component":"host"},
  "commonAnnotations": {"summary":"Disk usage > 85% on web-01","description":"Approaching critical threshold. Investigate and free space."},
  "alerts":[{"labels":{"alertname":"HostDiskFull","host":"web-01"},"generatorURL":"https://grafana.example.com/alerting/grafana/uid/abc/view"}]
};
const beszelSample = {
  "alert": "CPU usage > 80",
  "system": "web-01",
  "value": "86.4",
  "threshold": "80",
  "status": "triggered",
  "url": "https://beszel.example.com/system/web-01"
};
const healthchecksSample = {
  "check": "semaphore-app-db-backup",
  "status": "down",
  "code": "01d415d8-e39f-4e87-bd44-5c60c2a0fd0a",
  "last_ping": "2026-05-30T03:00:00Z",
  "tags": "semaphore backup",
  "url": "https://hc.luigibarretta.com/checks/01d415d8/details/"
};
const wudSample = {
  "title": "Container update available",
  "body": "Container nginx (docker.io/library/nginx:1.27.0) can be updated to 1.27.1",
  "wud_url": "http://192.168.50.110:3033/"
};

$("#btn-load-grafana-sample").addEventListener("click", () => $("#pv-input").value = JSON.stringify(grafanaSample, null, 2));
$("#btn-load-beszel-sample").addEventListener("click", () => $("#pv-input").value = JSON.stringify(beszelSample, null, 2));
const _hcBtn = $("#btn-load-healthchecks-sample"); if (_hcBtn) _hcBtn.addEventListener("click", () => $("#pv-input").value = JSON.stringify(healthchecksSample, null, 2));
const _wudBtn = $("#btn-load-wud-sample"); if (_wudBtn) _wudBtn.addEventListener("click", () => $("#pv-input").value = JSON.stringify(wudSample, null, 2));

async function _runPreviewRender() {
  let payload;
  try { payload = JSON.parse($("#pv-input").value || "{}"); }
  catch (e) {
    // JSON not yet valid (user mid-typing) — show in output but keep mock as-is
    $("#pv-output").textContent = "Invalid JSON: " + e.message;
    return;
  }
  try {
    const r = await J("/api/render-preview", {
      method: "POST",
      body: JSON.stringify({severity: $("#pv-sev").value, payload}),
      headers: {"Content-Type": "application/json"}
    });
    $("#pv-output").textContent = JSON.stringify(r, null, 2);
    renderNtfyMock(r);
  } catch (e) {
    $("#pv-output").textContent = "Error: " + e.message;
    $("#pv-vis-body").textContent = "Error rendering preview";
  }
}

// Manual button still works for users who prefer explicit action
$("#btn-preview").addEventListener("click", _runPreviewRender);

// Live update: debounce 500ms on payload edit / severity change.
// Skipped on initial render so an empty textarea doesn't fire a useless call.
let _previewDebounce = null;
function _schedulePreview() {
  if (_previewDebounce) clearTimeout(_previewDebounce);
  _previewDebounce = setTimeout(() => {
    const v = $("#pv-input")?.value || "";
    if (!v.trim()) return;  // nothing typed yet
    _runPreviewRender();
  }, 500);
}
$("#pv-input")?.addEventListener("input", _schedulePreview);
$("#pv-sev")?.addEventListener("change", _schedulePreview);
// Trigger after loading a sample (sample buttons set value via .value=…
// which doesn't fire 'input', so we hook the loaders themselves).
["#btn-load-grafana-sample", "#btn-load-beszel-sample", "#btn-load-healthchecks-sample", "#btn-load-wud-sample"].forEach(sel => {
  $(sel)?.addEventListener("click", () => _schedulePreview());
});

function renderNtfyMock(r) {
  const h = r.headers || {};
  $("#pv-vis-title").textContent = h["Title (raw)"] || "—";
  $("#pv-vis-body").textContent = r.body || "(empty body)";
  const tags = (h["Tags"] || "").split(",").filter(Boolean);
  $("#pv-vis-tags").innerHTML = tags.map(t => `<span class="chip">${escapeHtml(t)}</span>`).join("");
  const prio = (h["Priority"] || "default").toLowerCase();
  const prioEl = $("#pv-vis-prio");
  prioEl.textContent = prio.toUpperCase();
  prioEl.className = "ntfy-mock-prio " + prio;
  const actions = (h["Actions"] || "").split(";").map(s => s.trim()).filter(Boolean);
  $("#pv-vis-actions").innerHTML = actions.map(a => {
    const [kind, label, url] = a.split(",").map(x => x.trim());
    return `<a href="${escapeHtml(url)}" target="_blank" rel="noopener">${escapeHtml(label)}</a>`;
  }).join("");
}


// ---- Send test ----
// When "Dry-run" is checked, route to /webhook/<sev>?dry_run=1 with a
// Grafana-shape payload so the FULL ingest pipeline runs (normalize +
// inhibition + parse + render) without actually delivering. Otherwise
// the legacy /api/test/<sev> path that calls deliver() directly is used.
$("#btn-test-fire").addEventListener("click", async () => {
  const sev = $("#t-sev").value;
  const dryRun = $("#t-dry-run")?.checked || false;
  const button = $("#btn-test-fire");
  button.disabled = true;
  try {
    if (dryRun) {
      // Build a Grafana-shape payload that exercises the real pipeline.
      // Mirror what _handle_api_test does internally so the render output
      // matches what a real Grafana alert would produce.
      const title = $("#t-title").value || `klaxond test [${sev}]`;
      const body  = $("#t-body").value  || "Synthetic alert from Send-test (dry-run)";
      const component = $("#t-component").value || "";
      const host      = $("#t-host").value || "";
      const fake = {
        status: "firing",
        commonLabels: { alertname: title, severity: sev, component, host },
        commonAnnotations: { summary: body },
        alerts: [{ labels: { alertname: title, host, component }, annotations: { summary: body }, generatorURL: "" }],
      };
      const r = await J(`/webhook/${sev}?dry_run=1`, {
        method: "POST", body: JSON.stringify(fake),
        headers: {"Content-Type": "application/json"},
      });
      $("#t-result").textContent = JSON.stringify(r, null, 2);
      showToast(`Dry-run: ${r.would_send ? "would deliver" : "would suppress"} (${r.reason})`, r.would_send ? "info" : "warn", 5000);
      setTimeout(loadDeliv, 500);
      return;
    }
    const payload = {
      title:     $("#t-title").value,
      body:      $("#t-body").value,
      component: $("#t-component").value,
      host:      $("#t-host").value,
    };
    const r = await J(`/api/test/${sev}`, {
      method: "POST",
      body: JSON.stringify(payload),
      headers: {"Content-Type": "application/json"}
    });
    $("#t-result").textContent = JSON.stringify(r, null, 2);
    setTimeout(loadDeliv, 1000);
  } catch (e) {
    $("#t-result").textContent = "Error: " + e.message;
    showToast("Send-test failed: " + e.message, "error");
  } finally {
    button.disabled = false;
  }
});



// ---- ntfy topics (0.7.1+ editor) ----
let ntfyTopicsData = { topics: [], known_severities: [], note: "", writeable: false };

async function loadNtfyTopics() {
  try {
    const j = await J("/api/ntfy-topics");
    ntfyTopicsData = j;
    renderNtfyTopicsEditor();
    const sev = (j.known_severities || []).filter(s => s !== "resolved");
    const sevStr = sev.length ? sev.map(s => `<code>${escapeHtml(s)}</code>`).join(", ") : "<em>none</em>";
    $("#ntfy-topics-summary").innerHTML = `<small>${(j.topics || []).length} topic(s) · severities routed: ${sevStr}</small>`;
    $("#ntfy-topics-note").textContent = j.note || "";
  } catch (e) {
    fetchError("ntfy-topics", e);
  }
}

function _renderTopicRow(t, idx) {
  const handlesStr = (t.handles || []).join(", ");
  return `
    <div class="card" data-topic-idx="${idx}" style="margin-bottom:8px">
      <div class="grid2">
        <label>Topic name <input type="text" class="ntfy-t-name" value="${escapeHtml(t.name || "")}" placeholder="ntfy topic id"></label>
        <label>Token
          <input type="password" class="ntfy-t-token" value="${escapeHtml(t.token || "")}" placeholder="${t.token === '***SET***' ? '(keep existing — leave as ***SET***)' : 'tk_... (or empty for env fallback)'}">
          <small class="muted">${t.token === '***SET***' ? '<span style="color:#2c8a47">✓ token set</span> — clear field to remove' : '<span style="color:#c44">✗ no token set</span>'}</small>
        </label>
      </div>
      <label>Handles severities (comma-separated, any string allowed)
        <input type="text" class="ntfy-t-handles" value="${escapeHtml(handlesStr)}" placeholder="info, warning, critical">
      </label>
      <p class="row" style="margin-top:8px">
        <button type="button" class="ntfy-t-delete" data-idx="${idx}" style="color:#c44">Delete topic</button>
      </p>
    </div>`;
}

function renderNtfyTopicsEditor() {
  const c = $("#ntfy-topics-editor");
  if (!c) return;
  const topics = ntfyTopicsData.topics || [];
  c.innerHTML = topics.map((t, i) => _renderTopicRow(t, i)).join("");
  // Wire delete buttons
  c.querySelectorAll(".ntfy-t-delete").forEach(b => {
    b.addEventListener("click", () => {
      const idx = parseInt(b.dataset.idx, 10);
      ntfyTopicsData.topics.splice(idx, 1);
      renderNtfyTopicsEditor();
    });
  });
}

$("#ntfy-topic-add")?.addEventListener("click", () => {
  if (!ntfyTopicsData.topics) ntfyTopicsData.topics = [];
  ntfyTopicsData.topics.push({ name: "", token: "", handles: ["info"] });
  renderNtfyTopicsEditor();
});

$("#ntfy-topics-save")?.addEventListener("click", async () => {
  // Collect from DOM
  const out = [];
  $("#ntfy-topics-editor")?.querySelectorAll("[data-topic-idx]").forEach(card => {
    const name = card.querySelector(".ntfy-t-name").value.trim();
    const tokenRaw = card.querySelector(".ntfy-t-token").value;
    const handlesStr = card.querySelector(".ntfy-t-handles").value;
    const handles = handlesStr.split(",").map(s => s.trim().toLowerCase()).filter(Boolean);
    if (!name) return;  // skip empty rows on save (use Delete instead)
    out.push({ name, token: tokenRaw, handles });
  });
  $("#ntfy-topics-status").textContent = "Saving…";
  $("#ntfy-topics-status").style.color = "";
  try {
    const r = await fetch("/api/ntfy-topics", {
      method: "POST",
      body: JSON.stringify({ topics: out }),
      headers: { "Content-Type": "application/json" },
    });
    if (!r.ok) {
      const txt = await r.text();
      $("#ntfy-topics-status").style.color = "#c44";
      $("#ntfy-topics-status").textContent = `Error ${r.status}: ${txt.slice(0, 200)}`;
      return;
    }
    const j = await r.json();
    $("#ntfy-topics-status").style.color = "#2c8a47";
    $("#ntfy-topics-status").textContent = `Saved ✓ (${j.topics.length} topic(s), severities: ${(j.known_severities || []).filter(s => s !== "resolved").join(", ")})`;
    _markTabDirty("routing", false);
    // Reload to refresh badges
    setTimeout(() => loadNtfyTopics(), 500);
  } catch (e) {
    $("#ntfy-topics-status").style.color = "#c44";
    $("#ntfy-topics-status").textContent = "Error: " + e.message;
  }
});



// ---- Routing (channel config) ----
async function loadRouting() {
  try {
    const c = await J("/api/channel-config");
    $("#r-ntfy-url").value = c.ntfy.url || "";
    // ntfy topics are managed by the rich-view editor below (loadNtfyTopics).
    // The "Save routing" button only persists ntfy URL + telegram + smtp.
    $("#r-ntfy-status").innerHTML = c.ntfy.url_from_env ? "<em>url overridden by env</em>" : "";
    $("#r-tg-chat").value = c.telegram.chat_id || "";
    $("#r-tg-status").innerHTML = `bot token: ${badge(c.telegram.bot_token_configured)}` +
      (c.telegram.chat_id_from_env ? " · <em>chat_id overridden by env</em>" : "");
    $("#r-smtp-host").value = c.smtp.host || "";
    $("#r-smtp-port").value = c.smtp.port || 587;
    $("#r-smtp-from").value = c.smtp.from_addr || "";
    $("#r-smtp-to").value = c.smtp.to_addr || "";
    $("#r-smtp-status").innerHTML = `user: ${badge(c.smtp.user_configured)} password: ${badge(c.smtp.password_configured)}` +
      (c.smtp.host_from_env ? " · <em>host overridden by env</em>" : "");
  } catch (e) { fetchError("routing", e); }
}

const badge = ok => ok ? "<span style='color:var(--green)'>✓ configured</span>" : "<span style='color:var(--red)'>✗ missing</span>";

$("#btn-routing-save").addEventListener("click", async () => {
  // ntfy topics intentionally omitted — managed by the topic editor + /api/ntfy-topics.
  const payload = {
    ntfy: { url: $("#r-ntfy-url").value.trim() },
    telegram: { chat_id: $("#r-tg-chat").value.trim() },
    smtp: {
      host: $("#r-smtp-host").value.trim(),
      port: parseInt($("#r-smtp-port").value, 10) || 587,
      from_addr: $("#r-smtp-from").value.trim(),
      to_addr: $("#r-smtp-to").value.trim(),
    }
  };
  try {
    await J("/api/channel-config", { method: "POST", body: JSON.stringify(payload), headers: { "Content-Type": "application/json" } });
    $("#routing-msg").textContent = "Saved ✓ (env vars still take precedence if set)";
    setTimeout(() => $("#routing-msg").textContent = "", 4000);
    _markTabDirty("routing", false);
    loadStatus();
  } catch (e) { $("#routing-msg").textContent = "Error: " + e.message; }
});


// ---- Ingest auth (per-source webhook secret, 0.9.18+) ----
async function loadIngestAuth() {
  const tb = $("#t-ingest-auth tbody"); if (!tb) return;
  try {
    const data = await J("/api/ingest-auth");
    const srcs = data.sources || {};
    tb.innerHTML = "";
    for (const src of Object.keys(srcs).sort()) {
      const info = srcs[src];
      const tr = document.createElement("tr");
      const status = info.configured
        ? `<span style='color:var(--green)'>✓ secret set</span>`
        : `<span style='color:var(--muted)'>(permissive — no secret)</span>`;
      const from = info.from === "env" ? `<code>env</code> (read-only, set <code>KLAXOND_INGEST_SECRET_${src.toUpperCase()}</code>)`
                  : info.from === "toml" ? `<code>klaxon.toml</code>`
                  : "—";
      const isEnv = info.from === "env";
      tr.innerHTML = `
        <td><code>${escapeHtml(src)}</code></td>
        <td>${status}</td>
        <td><small>${from}</small></td>
        <td>
          <button class="btn primary" data-act="generate" data-src="${escapeHtml(src)}" ${isEnv ? "disabled title='env override active'" : ""}>Generate</button>
          <button class="btn" data-act="set" data-src="${escapeHtml(src)}" ${isEnv ? "disabled" : ""}>Set custom…</button>
          <button class="btn" data-act="clear" data-src="${escapeHtml(src)}" ${(!info.configured || isEnv) ? "disabled" : ""} style="color:var(--red)">Clear</button>
        </td>`;
      tb.appendChild(tr);
    }
    // Wire button handlers
    tb.querySelectorAll("button[data-act]").forEach(btn => {
      btn.addEventListener("click", () => _ingestAuthAction(btn.dataset.src, btn.dataset.act));
    });
  } catch (e) { console.warn("ingest-auth fetch:", e); }
}

async function _ingestAuthAction(src, action) {
  let body = { source: src, action };
  if (action === "set") {
    const sec = prompt(`Paste the secret to use for source "${src}":\n\n(min 16 chars; will be shown to emitter ONCE here)`);
    if (!sec) return;
    if (sec.length < 16) { showToast("Secret must be ≥16 chars", "error"); return; }
    body.secret = sec;
  }
  if (action === "clear") {
    if (!confirm(`Clear webhook secret for "${src}"?\n\nSource will return to permissive mode (any caller accepted). Confirm?`)) return;
  }
  try {
    const res = await fetch("/api/ingest-auth", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify(body),
    });
    if (!res.ok) {
      const txt = await res.text();
      showToast(`Ingest-auth ${action} failed: ${res.status} ${txt.slice(0, 200)}`, "error");
      return;
    }
    const r = await res.json();
    if (r.secret) {
      // Show generated secret in a copy-friendly prompt
      window.prompt(
        `✓ Secret generated for source "${src}".\n\nCopy it now and paste it into the emitter configuration — it WON'T be shown again. (klaxond stores only this value; once you close this dialog you can't retrieve it from the UI.)`,
        r.secret
      );
    } else {
      showToast(`✓ Ingest-auth ${action} OK for ${src}`, "success", 4000);
    }
    loadIngestAuth();
  } catch (e) {
    showToast(`Ingest-auth ${action} error: ${e.message}`, "error");
  }
}


// ---- Cascade tiers ----
const TIER_OPTS = ["ntfy", "telegram", "smtp"];
let casData = { tiers: [], default_enabled_for_webhook: false };

async function loadCascade() {
  try {
    casData = await J("/api/cascade-config");
    renderCascadeTable();
    $("#cas-default").checked = !!casData.default_enabled_for_webhook;
  } catch (e) { fetchError("cascade", e); }
}

function renderCascadeTable() {
  const tb = $("#t-cas tbody"); tb.innerHTML = "";
  casData.tiers.forEach((t, i) => addCasRow(t.name, t.timeout_seconds, i));
}

function addCasRow(name = "ntfy", timeout = 5, idx = -1) {
  const tb = $("#t-cas tbody");
  const i = idx === -1 ? tb.children.length : idx;
  const tr = document.createElement("tr");
  const opts = TIER_OPTS.map(o => `<option ${o === name ? "selected" : ""}>${o}</option>`).join("");
  tr.innerHTML = `
    <td><span class="muted">${i + 1}</span> <button data-up title="Move up">↑</button><button data-dn title="Move down">↓</button></td>
    <td><select data-f="name">${opts}</select></td>
    <td><input type="number" min="1" max="60" value="${timeout}" data-f="timeout"></td>
    <td><button class="danger" data-del>×</button></td>`;
  tr.querySelector("[data-del]").addEventListener("click", () => { tr.remove(); renumberCas(); });
  tr.querySelector("[data-up]").addEventListener("click", () => {
    const prev = tr.previousElementSibling;
    if (prev) tb.insertBefore(tr, prev);
    renumberCas();
  });
  tr.querySelector("[data-dn]").addEventListener("click", () => {
    const next = tr.nextElementSibling;
    if (next) tb.insertBefore(next, tr);
    renumberCas();
  });
  tb.appendChild(tr);
  renumberCas();
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
    $("#cas-status").textContent = `Saved (${tiers.length} tiers) ✓`;
    setTimeout(() => $("#cas-status").textContent = "", 3000);
    _markTabDirty("cascade", false);
    loadStatus();
  } catch (e) { $("#cas-status").textContent = "Error: " + e.message; }
});



// ---- Delivery (policies + rules) ----
// The synthetic policy built from the global [cascade] block is exposed by
// the backend with name="cascade" (see _legacy_cascade_policy in app.py —
// the Python function name is historical, the returned dict says "cascade").
// The UI matches that for consistency: no "legacy-cascade" string anywhere.
let delivData = { default_policy: "cascade", policies: [], rules: [], available_tiers: [], legacy_cascade_tiers: [] };

async function loadDelivery() {
  try {
    delivData = await J("/api/delivery-config");
    renderDeliveryDefault();
    renderPoliciesTable();
    renderRulesTable();
  } catch (e) { fetchError("delivery", e); }
}

function policyNames() {
  return ["cascade", ...delivData.policies.map(p => p.name)];
}

function renderDeliveryDefault() {
  const sel = $("#d-default-policy");
  if (!sel) return;
  const cur = delivData.default_policy;
  sel.innerHTML = policyNames().map(n => `<option ${n === cur ? "selected" : ""}>${escapeHtml(n)}</option>`).join("");
}

function renderPoliciesTable() {
  const tb = $("#t-pol tbody"); tb.innerHTML = "";
  delivData.policies.forEach((p, i) => addPolicyRow(p.name, p.mode, p.tiers, i));
}

function addPolicyRow(name = "new-policy", mode = "cascade", tiers = [], idx = null) {
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
  tr.querySelector("[data-del]").addEventListener("click", () => { tr.remove(); renderDeliveryDefault(); });
  // Re-populate the default-policy dropdown when name changes
  tr.querySelector('[data-f="name"]').addEventListener("input", () => { collectPoliciesFromTable(); renderDeliveryDefault(); });
  tb.appendChild(tr);
  renderDeliveryDefault();
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

function renderRulesTable() {
  const tb = $("#t-rules tbody"); tb.innerHTML = "";
  delivData.rules.forEach((r, i) => addRuleRow(r.match || {}, r.policy, i));
}

function addRuleRow(match = {}, policy = "cascade", idx = -1) {
  const tb = $("#t-rules tbody");
  const i = idx === -1 ? tb.children.length : idx;
  const tr = document.createElement("tr");
  const matchTxt = Object.entries(match).map(([k, v]) => `${k}=${v}`).join("\n");
  const opts = policyNames().map(n => `<option ${n === policy ? "selected" : ""}>${escapeHtml(n)}</option>`).join("");
  tr.innerHTML = `
    <td><span class="muted">${i + 1}</span></td>
    <td><textarea data-f="match" rows="3" style="font-family:monospace;font-size:11px" placeholder="severity=critical\ncomponent=host\nhost=re:^prod-.*">${escapeHtml(matchTxt)}</textarea></td>
    <td><select data-f="policy">${opts}</select></td>
    <td><button class="danger" data-del>×</button></td>`;
  tr.querySelector("[data-del]").addEventListener("click", () => { tr.remove(); renumberRules(); });
  tb.appendChild(tr);
  renumberRules();
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
    $("#delivery-status").textContent = `Saved (${policies.length} policies, ${rules.length} rules) ✓`;
    setTimeout(() => $("#delivery-status").textContent = "", 4000);
    _markTabDirty("delivery", false);
  } catch (e) { $("#delivery-status").textContent = "Error: " + e.message; }
});


// ---- Dedup / grouping ----
let dedupData = { settings: {}, sources: [], pending_counts: {}, defaults: {} };

const STRATEGY_HELP = {
  none: "no grouping (immediate delivery, equivalent to disabled)",
  time: "all events in the window batched together",
  key:  "group items sharing the same dedup key (per source)",
};

const SOURCE_HELP = {
  wud:          "WUD container image updates — key=image.name → 1 notif per image even if fires on N hosts",
  grafana:      "Grafana alerts (via /webhook/*) — key=commonLabels.alertname",
  beszel:       "Beszel host/container metrics — key=container_name",
  healthchecks: "Healthchecks deadman — key=check name",
};

async function loadDedup() {
  try {
    const j = await J("/api/dedup-config");
    dedupData = j;
    renderDedupCards();
  } catch (e) {
    const c = $("#dedup-cards");
    if (c) c.innerHTML = '<p class="muted">Error loading dedup config: ' + e.message + "</p>";
  }
}

function renderDedupCards() {
  const c = $("#dedup-cards");
  if (!c) return;
  const sources = dedupData.sources || ["grafana", "beszel", "healthchecks", "wud"];
  const settings = dedupData.settings || {};
  const pending = dedupData.pending_counts || {};
  let html = '<div class="grid2">';
  for (const src of sources) {
    const s = settings[src] || {};
    const help = SOURCE_HELP[src] || "";
    const pcount = pending[src] || 0;
    html += `
      <div class="card" data-src="${src}">
        <h3 style="margin-top:0">${src.toUpperCase()}
          <small class="muted" style="font-weight:normal">${pcount > 0 ? `· ${pcount} pending` : ""}</small>
        </h3>
        <p class="muted"><small>${help}</small></p>
        <label><input type="checkbox" class="d-enabled" ${s.enabled ? "checked" : ""}> Enabled</label>
        <label>Strategy
          <select class="d-strategy">
            <option value="key" ${s.strategy === "key" ? "selected" : ""}>key (recommended)</option>
            <option value="time" ${s.strategy === "time" ? "selected" : ""}>time</option>
            <option value="none" ${s.strategy === "none" ? "selected" : ""}>none</option>
          </select>
        </label>
        <label>Window (seconds, 5..3600)
          <input type="number" class="d-window" min="5" max="3600" value="${s.window_s || 90}">
        </label>
        <label title="By default, severity=critical events bypass the dedup window and deliver immediately. Toggle to also debounce critical (risky).">
          <input type="checkbox" class="d-override" ${s.override_critical ? "checked" : ""}>
          Override critical (debounce critical too)
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
  $("#dedup-status").textContent = "Saving…";
  try {
    const r = await J("/api/dedup-config", {
      method: "POST",
      body: JSON.stringify({ settings: out }),
      headers: { "Content-Type": "application/json" },
    });
    if (r.ok) {
      dedupData.settings = r.settings;
      $("#dedup-status").textContent = "Saved ✓";
      setTimeout(() => { $("#dedup-status").textContent = ""; }, 3000);
      _markTabDirty("grouping", false);
    } else {
      $("#dedup-status").textContent = "Error: " + (r.error || "unknown");
    }
  } catch (e) {
    $("#dedup-status").textContent = "Error: " + e.message;
  }
});

// Refresh pending counts when the grouping tab is shown
document.querySelectorAll('[data-tab="grouping"]').forEach(btn => {
  btn.addEventListener("click", () => { loadDedup(); });
});


// ---- Authentication tab ----
let authData = { settings: {}, current_user: {} };

const OIDC_ISSUER_HINTS = {
  authentik: "https://idp.example.com/application/o/klaxond/",
  keycloak:  "https://idp.example.com/realms/<realm>",
  authelia:  "https://idp.example.com",
  google:    "https://accounts.google.com",
  other:     "",
};

function _showSubcard(mode) {
  const map = {
    none: [],
    basic: ["auth-basic-h", "auth-basic-card"],
    oidc:  ["auth-oidc-h", "auth-oidc-card"],
    "trusted-proxy": ["auth-tp-h", "auth-tp-card"],
  };
  for (const id of ["auth-basic-h","auth-basic-card","auth-oidc-h","auth-oidc-card","auth-tp-h","auth-tp-card"]) {
    document.getElementById(id)?.classList.add("hidden");
  }
  for (const id of (map[mode] || [])) {
    document.getElementById(id)?.classList.remove("hidden");
  }
}

async function loadAuth() {
  try {
    const j = await J("/api/auth-config");
    authData = j;
    const s = j.settings || {};
    document.querySelectorAll('input[name="auth-mode"]').forEach(r => {
      r.checked = (r.value === (s.mode || "none"));
    });
    _showSubcard(s.mode || "none");
    $("#auth-bcrypt-warn")?.classList.toggle("hidden", !!j.bcrypt_available);
    $("#auth-jwt-warn")?.classList.toggle("hidden", !!j.jwt_available);
    $("#auth-session-h").value = s.session_timeout_hours || 8;
    const cu = j.current_user || {};
    $("#auth-current-user").textContent = `${cu.sub || "?"} (mode=${cu.mode || "?"})`;
    // basic
    const b = s.basic || {};
    $("#auth-basic-user").value = b.username || "";
    $("#auth-basic-realm").value = b.realm || "klaxond";
    $("#auth-basic-pwd").value = "";
    $("#auth-basic-status").textContent = b.password_hash === "***SET***" ? "set" : "not set";
    // oidc
    const o = s.oidc || {};
    $("#auth-oidc-provider").value = o.provider || "authentik";
    $("#auth-oidc-issuer").value = o.issuer || "";
    $("#auth-oidc-cid").value = o.client_id || "";
    $("#auth-oidc-csec").value = "";
    $("#auth-oidc-csec-status").textContent = o.client_secret === "***SET***" ? "set" : "not set";
    $("#auth-oidc-scopes").value = o.scopes || "openid profile email";
    $("#auth-oidc-group").value = o.required_group || "";
    $("#auth-oidc-redirect").value = o.redirect_path || "/auth/callback";
    $("#auth-oidc-full-redirect").textContent = `${location.protocol}//${location.host}${o.redirect_path || "/auth/callback"}`;
    // trusted-proxy
    const tp = s.trusted_proxy || {};
    $("#auth-tp-uheader").value = tp.user_header || "X-Forwarded-User";
    $("#auth-tp-eheader").value = tp.email_header || "X-Forwarded-Email";
    $("#auth-tp-gheader").value = tp.groups_header || "X-Forwarded-Groups";
    $("#auth-tp-cidrs").value = (tp.trusted_cidrs || []).join(", ");
  } catch (e) {
    $("#auth-status").textContent = "Error loading: " + e.message;
  }
}

document.querySelectorAll('input[name="auth-mode"]').forEach(r => {
  r.addEventListener("change", () => _showSubcard(r.value));
});
document.getElementById("auth-oidc-provider")?.addEventListener("change", e => {
  const hint = OIDC_ISSUER_HINTS[e.target.value] || "";
  if (hint) $("#auth-oidc-issuer").placeholder = hint;
});

$("#auth-save")?.addEventListener("click", async () => {
  const mode = document.querySelector('input[name="auth-mode"]:checked')?.value || "none";
  const out = {
    mode,
    session_timeout_hours: parseInt($("#auth-session-h").value, 10) || 8,
    basic: {
      username: $("#auth-basic-user").value.trim(),
      realm:    $("#auth-basic-realm").value.trim(),
      password: $("#auth-basic-pwd").value,  // empty = keep
    },
    oidc: {
      provider:       $("#auth-oidc-provider").value,
      issuer:         $("#auth-oidc-issuer").value.trim(),
      client_id:      $("#auth-oidc-cid").value.trim(),
      client_secret:  $("#auth-oidc-csec").value,  // empty = keep
      scopes:         $("#auth-oidc-scopes").value.trim(),
      required_group: $("#auth-oidc-group").value.trim(),
      redirect_path:  $("#auth-oidc-redirect").value.trim() || "/auth/callback",
    },
    trusted_proxy: {
      user_header:   $("#auth-tp-uheader").value.trim(),
      email_header:  $("#auth-tp-eheader").value.trim(),
      groups_header: $("#auth-tp-gheader").value.trim(),
      trusted_cidrs: $("#auth-tp-cidrs").value.split(",").map(x => x.trim()).filter(Boolean),
    },
  };
  $("#auth-status").textContent = "Saving…";
  try {
    const r = await J("/api/auth-config", {
      method: "POST",
      body: JSON.stringify({ settings: out }),
      headers: { "Content-Type": "application/json" },
    });
    if (r.ok) {
      $("#auth-status").textContent = `Saved ✓ (mode=${r.settings.mode}). Reload page to apply.`;
      _markTabDirty("auth", false);
      authData.settings = r.settings;
      _showSubcard(r.settings.mode);
    } else {
      $("#auth-status").textContent = "Error: " + (r.error || "unknown");
    }
  } catch (e) {
    $("#auth-status").textContent = "Error: " + e.message;
  }
});

document.querySelectorAll('[data-tab="auth"]').forEach(btn => {
  btn.addEventListener("click", () => { loadAuth(); });
});
document.querySelectorAll('[data-tab="routing"]').forEach(btn => {
  btn.addEventListener("click", () => { loadNtfyTopics(); });
});


// ---- Flow tab ----
// Dynamic Mermaid diagram from all configs. Click nodes → switch tab.
// Stats overlay reads /api/deliveries (24h window).

// Make tab-switcher callable from outside (mermaid click handlers).
// Use the existing tab button's click handler so location.hash stays in sync
// with the active pane — direct DOM manipulation would leave URL stale and
// break subsequent tab navigation (clicking the same hash = no hashchange).
function switchToTab(name) {
  const btn = document.querySelector(`.tab[data-tab="${name}"]`);
  if (btn) {
    btn.click();  // delegates to the existing hashchange-aware handler
  } else {
    // Fallback: direct DOM update if the button doesn't exist (defensive)
    document.querySelectorAll(".tab").forEach(b => b.classList.toggle("active", b.dataset.tab === name));
    document.querySelectorAll(".tabpane").forEach(s => s.classList.toggle("active", s.id === `tab-${name}`));
  }
}
window.flowGotoTab = switchToTab;  // expose to mermaid click callbacks

function _aggregateDeliveries24h(items) {
  // items from /api/deliveries: latest-first list of audit records
  // Each: {source, severity, channel, ok, timestamp(ms)}
  const cutoff = Date.now() - 24 * 3600 * 1000;
  const bySource = {};       // source → count
  const bySeverity = {};     // severity → count
  const byChannel = {};      // channel → count
  const bySourceSeverity = {}; // "source|severity" → count
  for (const it of items || []) {
    const ts = it.timestamp || 0;
    if (ts < cutoff) continue;
    if (it.source)   bySource[it.source]   = (bySource[it.source] || 0) + 1;
    if (it.severity) bySeverity[it.severity] = (bySeverity[it.severity] || 0) + 1;
    if (it.channel)  byChannel[it.channel] = (byChannel[it.channel] || 0) + 1;
    const k = `${it.source}|${it.severity}`;
    bySourceSeverity[k] = (bySourceSeverity[k] || 0) + 1;
  }
  return { bySource, bySeverity, byChannel, bySourceSeverity };
}

function _mermaidEscape(s) {
  // Avoid quotes that break mermaid label parsing
  return String(s || "").replace(/"/g, "\\\"").replace(/\n/g, "<br/>");
}

function buildMermaidDiagram(cfgs, stats) {
  const { channel, cascade, ntfy, dedup, auth } = cfgs;
  const s = stats || { bySource: {}, byChannel: {}, bySeverity: {} };

  // Severity stat string per source
  const srcStat = (source) => {
    const n = s.bySource[source] || 0;
    return n ? `<br/><small>${n} in 24h</small>` : "";
  };
  const dedupStat = (source) => {
    const d = (dedup && dedup.settings) ? (dedup.settings[source] || {}) : {};
    if (!d.enabled) return "";
    return `<br/><small>dedup: ${d.strategy} ${d.window_s}s</small>`;
  };
  const chStat = (chan) => {
    const n = s.byChannel[chan] || 0;
    return n ? `<br/><small>${n} delivered</small>` : "";
  };

  // ntfy topics — group as one collapsed sub-node or list inline
  let ntfyLabel = `ntfy${chStat("ntfy")}`;
  if (ntfy && ntfy.topics && ntfy.topics.length) {
    const lines = ntfy.topics.slice(0, 6).map(t =>
      `${t.name}: ${(t.handles || []).join(", ")}`);
    if (ntfy.topics.length > 6) lines.push(`… +${ntfy.topics.length - 6} more`);
    ntfyLabel = `ntfy<br/><small>${lines.join("<br/>")}${chStat("ntfy") ? "<br/>" + (s.byChannel["ntfy"] || 0) + " delivered/24h" : ""}</small>`;
  }

  // Cascade
  const cascadeOn = cascade ? (cascade.runtime_enabled !== false) : true;
  const tiers = (cascade && cascade.tiers) || [{name:"ntfy"},{name:"telegram"},{name:"smtp"}];

  // Telegram / SMTP configured?
  const tgConfigured = !!(channel && channel.telegram && channel.telegram.chat_id);
  const smtpConfigured = !!(channel && channel.smtp && channel.smtp.host);

  // Auth chip in title
  const authMode = (auth && auth.settings && auth.settings.mode) || "?";

  const lines = [];
  lines.push("---");
  lines.push("config:");
  lines.push("  flowchart:");
  lines.push("    htmlLabels: true");
  lines.push("    curve: basis");
  lines.push("---");
  lines.push(`flowchart LR`);
  lines.push("  %% auto-generated from /api/* config");
  lines.push("  classDef src fill:#2c5282,color:#fff,stroke:#5b8def");
  lines.push("  classDef klx fill:#553c9a,color:#fff,stroke:#9b6bff");
  lines.push("  classDef sink fill:#22543d,color:#fff,stroke:#48bb78");
  lines.push("  classDef disabled fill:#444,color:#999,stroke:#666");

  // Upstream sources — what feeds the actual emitters.
  // Grafana → Alertmanager (which then POSTs to klaxond /webhook/).
  lines.push(`  subgraph UPS["Upstream"]`);
  lines.push(`    GRA["Grafana<br/><small>alert rules</small>"]`);
  lines.push("  end");
  lines.push("  class GRA src");

  lines.push(`  subgraph SRC["Emitters → klaxond HTTP (auth: ${authMode})"]`);
  lines.push(`    AM["Alertmanager<br/>POST /webhook/sev<br/><small>group + inhibit + repeat</small>${srcStat("grafana")}${dedupStat("grafana")}"]`);
  lines.push(`    BSZ["Beszel<br/>POST /beszel/sev${srcStat("beszel")}${dedupStat("beszel")}"]`);
  lines.push(`    HC["Healthchecks<br/>POST /healthchecks/sev${srcStat("healthchecks")}${dedupStat("healthchecks")}"]`);
  lines.push(`    WUD["WUD<br/>POST /wud/sev${srcStat("wud")}${dedupStat("wud")}"]`);
  lines.push(`    AKN["Authentik<br/>POST /authentik/sev${srcStat("authentik")}${dedupStat("authentik")}"]`);
  lines.push("  end");

  lines.push("  class AM,BSZ,HC,WUD,AKN src");

  lines.push("  GRA --> AM");

  // Inhibition is source-agnostic (0.9.6+): ALL emitters flow through it.
  // Source-alert ARMING (the inhibition_source label) is grafana-only, but
  // EVERY source is subject to existing suppressions via _normalize_labels.
  lines.push("  INH{\"Inhibition rules<br/><small>cross-source (all emitters)</small>\"}");
  lines.push("  DROP[\"suppress\"]");
  lines.push("  RND[\"Render<br/>title/body/tags/actions\"]");
  lines.push("  CAS{\"Cascade " + (cascadeOn ? "✓ on" : "✗ off") + "\"}");
  lines.push("  class INH,DROP,RND,CAS klx");

  lines.push("  AM --> INH");
  lines.push("  BSZ --> INH");
  lines.push("  HC --> INH");
  lines.push("  WUD --> INH");
  lines.push("  AKN --> INH");
  lines.push("  INH -->|matched| DROP");
  lines.push("  INH -->|pass| RND");

  lines.push("  RND --> CAS");

  // ntfy node
  lines.push(`  NTFY["${_mermaidEscape(ntfyLabel)}"]`);
  lines.push("  class NTFY sink");
  lines.push("  CAS -->|tier 1| NTFY");

  // Telegram
  if (tiers.find(t => t.name === "telegram")) {
    const tgClass = tgConfigured ? "sink" : "disabled";
    const tgLabel = tgConfigured
      ? `Telegram<br/><small>chat ${channel.telegram.chat_id}${chStat("telegram") ? "<br/>" + (s.byChannel["telegram"] || 0) + " delivered/24h" : ""}</small>`
      : "Telegram<br/><small>not configured</small>";
    lines.push(`  TG["${_mermaidEscape(tgLabel)}"]`);
    lines.push(`  class TG ${tgClass}`);
    lines.push(`  CAS -.->|"tier 2 on ntfy fail"| TG`);
  }

  // SMTP
  if (tiers.find(t => t.name === "smtp")) {
    const smClass = smtpConfigured ? "sink" : "disabled";
    const smLabel = smtpConfigured
      ? `SMTP<br/><small>${channel.smtp.host}:${channel.smtp.port}${chStat("smtp") ? "<br/>" + (s.byChannel["smtp"] || 0) + " delivered/24h" : ""}</small>`
      : "SMTP<br/><small>not configured</small>";
    lines.push(`  SMTP["${_mermaidEscape(smLabel)}"]`);
    lines.push(`  class SMTP ${smClass}`);
    lines.push(`  CAS -.->|"tier 3 on tg fail"| SMTP`);
  }

  // Click-to-edit handlers
  // GRA (Grafana upstream) → open external Grafana UI (not a klaxond tab)
  lines.push(`  click GRA "https://grafana.luigibarretta.com/alerting/list" _blank`);
  lines.push(`  click AM call flowGotoTab("inhibitions") "Inhibitions tab"`);
  lines.push(`  click BSZ call flowGotoTab("grouping") "Grouping (dedup) tab"`);
  lines.push(`  click HC call flowGotoTab("grouping") "Grouping (dedup) tab"`);
  lines.push(`  click WUD call flowGotoTab("grouping") "Grouping (dedup) tab"`);
  lines.push(`  click AKN call flowGotoTab("grouping") "Grouping (dedup) tab"`);
  lines.push(`  click INH call flowGotoTab("inhibitions") "Inhibitions tab"`);
  lines.push(`  click RND call flowGotoTab("render") "Render config tab"`);
  lines.push(`  click CAS call flowGotoTab("cascade") "Cascade tab"`);
  lines.push(`  click NTFY call flowGotoTab("routing") "Routing tab (ntfy topics)"`);
  if (tiers.find(t => t.name === "telegram")) lines.push(`  click TG call flowGotoTab("routing") "Routing tab"`);
  if (tiers.find(t => t.name === "smtp"))    lines.push(`  click SMTP call flowGotoTab("routing") "Routing tab"`);

  return lines.join("\n");
}

let _flowMermaidInitialized = false;

// Wait for mermaid.min.js to finish loading (3.3MB async script).
// Returns true if library is available within timeoutMs, false otherwise.
async function _waitForMermaid(timeoutMs = 15000) {
  if (window.mermaid) return true;
  const t0 = Date.now();
  $("#flow-status").textContent = "Loading Mermaid library (3.3MB)…";
  while (!window.mermaid) {
    if (Date.now() - t0 > timeoutMs) return false;
    await new Promise(r => setTimeout(r, 100));
  }
  return true;
}

async function loadFlow() {
  if (!await _waitForMermaid()) {
    $("#flow-status").textContent = "Mermaid library failed to load (timeout). Check Network tab.";
    return;
  }
  if (!_flowMermaidInitialized) {
    mermaid.initialize({ startOnLoad: false, theme: "dark", securityLevel: "loose" });
    _flowMermaidInitialized = true;
  }
  $("#flow-status").textContent = "Fetching config…";
  let cfgs = {}, stats = null;
  try {
    const [channel, cascade, ntfy, dedup, auth, deliveries] = await Promise.all([
      J("/api/channel-config"),
      J("/api/cascade-config"),
      J("/api/ntfy-topics"),
      J("/api/dedup-config"),
      J("/api/auth-config"),
      J("/api/deliveries"),
    ]);
    cfgs = { channel, cascade, ntfy, dedup, auth };
    stats = _aggregateDeliveries24h(deliveries);
  } catch (e) {
    $("#flow-status").textContent = "Config fetch failed: " + e.message;
    return;
  }
  const src = buildMermaidDiagram(cfgs, stats);
  $("#flow-source").textContent = src;
  try {
    const { svg, bindFunctions } = await mermaid.render("flow-svg-" + Date.now(), src);
    $("#flow-diagram").innerHTML = svg;
    if (bindFunctions) bindFunctions($("#flow-diagram"));
    // Apply animation class based on toolbar toggle
    $("#flow-diagram")?.classList.toggle("animate", !!$("#flow-animate")?.checked);
    // Pulse nodes that had any activity in the last 60s
    _pulseRecentActivityNodes(stats);
    $("#flow-status").textContent = "Rendered ✓ at " + new Date().toLocaleTimeString();
  } catch (e) {
    $("#flow-diagram").innerHTML = `<pre style="color:#c44">Mermaid render error: ${e.message}</pre>`;
    $("#flow-status").textContent = "Render failed";
  }
}

// Map source name → mermaid node id (matches buildMermaidDiagram)
const _NODE_FOR_SOURCE = { grafana: "AM", beszel: "BSZ", healthchecks: "HC", wud: "WUD", authentik: "AKN" };
const _NODE_FOR_CHANNEL = { ntfy: "NTFY", telegram: "TG", smtp: "SMTP" };

function _pulseRecentActivityNodes(stats) {
  // Clear previous pulse markers
  $("#flow-diagram")?.querySelectorAll(".node.recent-activity").forEach(n => n.classList.remove("recent-activity"));
  if (!stats) return;
  // Compute activity in last 60s (re-fetch a fresh slice for live feel)
  // Use what we have from /api/deliveries; cutoff at 60s window
  const activeNodes = new Set();
  for (const [src, cnt] of Object.entries(stats.bySource || {})) {
    if (cnt > 0 && _NODE_FOR_SOURCE[src]) activeNodes.add(_NODE_FOR_SOURCE[src]);
  }
  for (const [chan, cnt] of Object.entries(stats.byChannel || {})) {
    if (cnt > 0 && _NODE_FOR_CHANNEL[chan]) activeNodes.add(_NODE_FOR_CHANNEL[chan]);
  }
  activeNodes.forEach(id => {
    const n = $("#flow-diagram")?.querySelector(`[id$="-${id}"], [id$="-${id}-1"]`);
    if (n) n.classList.add("recent-activity");
  });
}

// Stats-only refresh — fetch /api/deliveries, recompute 24h aggregates,
// update text labels in the existing SVG (no full re-render)
async function refreshFlowStats() {
  if (!$("#flow-diagram")?.querySelector("svg")) return;  // no diagram yet
  try {
    const deliveries = await J("/api/deliveries");
    const stats = _aggregateDeliveries24h(deliveries);
    _pulseRecentActivityNodes(stats);
    // Update status timestamp
    const ts = $("#flow-status");
    if (ts) ts.textContent = "Stats refreshed at " + new Date().toLocaleTimeString();
  } catch (e) {
    // silent
  }
}

let _flowAutorefreshTimer = null;
function _setupFlowAutorefresh() {
  if (_flowAutorefreshTimer) { clearInterval(_flowAutorefreshTimer); _flowAutorefreshTimer = null; }
  if ($("#flow-autorefresh")?.checked) {
    _flowAutorefreshTimer = setInterval(refreshFlowStats, 30000);
  }
}

$("#flow-refresh")?.addEventListener("click", () => loadFlow());
$("#flow-animate")?.addEventListener("change", e => {
  $("#flow-diagram")?.classList.toggle("animate", e.target.checked);
});
$("#flow-autorefresh")?.addEventListener("change", _setupFlowAutorefresh);
$("#flow-show-source")?.addEventListener("change", e => {
  $("#flow-source")?.classList.toggle("hidden", !e.target.checked);
});
$("#flow-download-svg")?.addEventListener("click", () => {
  const svg = $("#flow-diagram")?.querySelector("svg");
  if (!svg) return;
  const blob = new Blob([svg.outerHTML], { type: "image/svg+xml" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = "klaxond-flow-" + new Date().toISOString().split("T")[0] + ".svg";
  a.click();
  URL.revokeObjectURL(url);
});
document.querySelectorAll('[data-tab="flow"]').forEach(btn => {
  btn.addEventListener("click", () => { loadFlow(); _setupFlowAutorefresh(); });
});
// Stop autorefresh when leaving the tab (any tab click)
document.querySelectorAll('.tab:not([data-tab="flow"])').forEach(btn => {
  btn.addEventListener("click", () => {
    if (_flowAutorefreshTimer) { clearInterval(_flowAutorefreshTimer); _flowAutorefreshTimer = null; }
  });
});


// ---- Polling ----
async function refreshAll() {
  await Promise.all([loadStatus(), loadInhib(), loadInhibRules(), loadDeliv(), loadRC(), loadCascade(), loadRouting(), loadNtfyTopics(), loadDelivery(), loadDedup(), loadAuth(), loadIngestAuth(), loadSchedules(), loadAcks()]);
}
refreshAll();
setInterval(() => { loadStatus(); loadInhib(); loadDeliv(); }, 10000);


// ---- Theme toggle (light / dark) ----
// Bootstrap happens inline in <head> (avoids flash of wrong theme). This
// just wires the button click to flip and persist.
(function setupThemeToggle() {
  const btn = document.getElementById("theme-toggle");
  if (!btn) return;
  const updateGlyph = () => {
    const cur = document.documentElement.getAttribute("data-theme") || "dark";
    btn.textContent = cur === "light" ? "🌞" : "🌙";
    btn.title = `Switch to ${cur === "light" ? "dark" : "light"} mode`;
  };
  updateGlyph();
  btn.addEventListener("click", () => {
    const cur = document.documentElement.getAttribute("data-theme") || "dark";
    const next = cur === "light" ? "dark" : "light";
    document.documentElement.setAttribute("data-theme", next);
    try { localStorage.setItem("klaxond.theme", next); } catch (e) {}
    updateGlyph();
  });
})();

// ---- Toast notifications (non-blocking error / info banner) ----
// Replaces the silent console.warn pattern in load* functions. Toasts stack
// in the top-right and auto-dismiss after 10s; click X to dismiss manually.
function showToast(msg, kind = "error", durationMs = 10000) {
  let container = document.getElementById("toast-container");
  if (!container) {
    container = document.createElement("div");
    container.id = "toast-container";
    document.body.appendChild(container);
  }
  const toast = document.createElement("div");
  toast.className = "toast toast-" + kind;
  toast.innerHTML = `<span class="toast-msg"></span><button class="toast-close" title="Dismiss">✕</button>`;
  toast.querySelector(".toast-msg").textContent = msg;
  toast.querySelector(".toast-close").addEventListener("click", () => toast.remove());
  container.appendChild(toast);
  setTimeout(() => { if (toast.isConnected) toast.remove(); }, durationMs);
  return toast;
}

// Per-key dedup so polling loops don't flood the screen with the same error
// every 10s. The first failure shows a toast; subsequent failures with the
// same key within DEDUP_MS are silent (logged to console only).
const _TOAST_DEDUP_MS = 60000;
const _toastErrLast = new Map();
function fetchError(key, e) {
  console.warn(key + ":", e);
  const now = Date.now();
  const last = _toastErrLast.get(key) || 0;
  if (now - last < _TOAST_DEDUP_MS) return;
  _toastErrLast.set(key, now);
  showToast(`${key}: ${e.message || e}`, "error");
}
function fetchOk(key) { _toastErrLast.delete(key); }

// ---- Dirty-state tracking (unsaved changes warning) ----
// Track which tab panes have unsaved edits. A pane becomes dirty when any
// input/select/textarea inside it changes; cleared when load*/save* runs.
const _dirtyTabs = new Set();

function _markTabDirty(tabId, dirty = true) {
  if (dirty) _dirtyTabs.add(tabId); else _dirtyTabs.delete(tabId);
  const tab = document.querySelector(`.tab[data-tab="${tabId}"]`);
  if (!tab) return;
  let dot = tab.querySelector(".tab-dirty");
  if (dirty && !dot) {
    dot = document.createElement("span");
    dot.className = "tab-dirty";
    dot.title = "Unsaved changes";
    tab.appendChild(dot);
  } else if (!dirty && dot) {
    dot.remove();
  }
}

// Bind change/input listeners to every form field inside each tabpane so
// edits flip the dirty flag. Excludes search/filter inputs (they're not
// "edits" the user expects to persist).
function _wireDirtyTracking() {
  document.querySelectorAll(".tabpane").forEach(pane => {
    const tabId = pane.id.replace(/^tab-/, "");
    if (!tabId) return;
    pane.addEventListener("input", e => {
      const t = e.target;
      if (!t || ["BUTTON"].includes(t.tagName)) return;
      // Skip search/filter fields — those aren't edits
      if (t.type === "search" || t.id === "deliv-filter" || t.id === "inhib-test-labels") return;
      _markTabDirty(tabId, true);
    });
    pane.addEventListener("change", e => {
      const t = e.target;
      if (!t || ["BUTTON"].includes(t.tagName)) return;
      if (t.id === "deliv-show-suppressed" || t.id === "inhib-test-source") return;
      _markTabDirty(tabId, true);
    });
  });
}

// Warn on page unload if any tab is dirty
window.addEventListener("beforeunload", e => {
  if (_dirtyTabs.size === 0) return;
  e.preventDefault();
  e.returnValue = "";
  return "";
});

// Wrap activateTab so we warn on tab switch when the current tab is dirty.
// The user gets a chance to abort or proceed; proceed clears dirty for the
// active tab (since we assume they're abandoning the edit).
const _origActivateTab = window.activateTab || activateTab;
function activateTabWithDirtyGuard(tabId) {
  const active = document.querySelector(".tabpane.active");
  const activeId = active ? active.id.replace(/^tab-/, "") : null;
  if (activeId && _dirtyTabs.has(activeId) && activeId !== tabId) {
    if (!confirm(`Tab "${activeId}" has unsaved changes. Discard and switch to "${tabId}"?`)) return false;
    _markTabDirty(activeId, false);
  }
  return _origActivateTab(tabId);
}
window.activateTab = activateTabWithDirtyGuard;

document.addEventListener("DOMContentLoaded", _wireDirtyTracking);

// ---- Keyboard shortcuts ----
// Cmd/Ctrl+S → click primary save button on the active tab
// Esc        → blur active input; if it was a search input, clear it too
// ?          → toggle the shortcut overlay (when not typing in an input)
const _SHORTCUT_HELP = [
  ["Ctrl/Cmd + S", "Save the active tab (clicks its primary Save button)"],
  ["Esc",          "Blur the focused input; clears search filters"],
  ["?",            "Show this help overlay"],
  ["1..9 / 0",     "Jump to tab by position (when no input is focused)"],
];

function _activeTabPane() {
  return document.querySelector(".tabpane.active");
}

function _clickPrimarySaveOnActiveTab() {
  const pane = _activeTabPane();
  if (!pane) return false;
  // Find the most likely "save" button — class=primary takes precedence,
  // then look for any button whose text starts with "Save".
  const primary = pane.querySelector("button.primary");
  if (primary) { primary.click(); return true; }
  for (const b of pane.querySelectorAll("button")) {
    if ((b.textContent || "").trim().toLowerCase().startsWith("save")) {
      b.click(); return true;
    }
  }
  return false;
}

function _showShortcutHelp() {
  let box = document.getElementById("shortcut-help");
  if (box) { box.remove(); return; }
  box = document.createElement("div");
  box.id = "shortcut-help";
  box.innerHTML = `
    <div class="shortcut-help-inner">
      <h3 style="margin-top:0; text-transform:none; color:var(--text); letter-spacing:0; font-size:1.1em">Keyboard shortcuts</h3>
      <table style="border:none">
        ${_SHORTCUT_HELP.map(([k, d]) => `<tr><td style="border:none;padding:4px 12px 4px 0"><code>${escapeHtml(k)}</code></td><td style="border:none;padding:4px 0">${escapeHtml(d)}</td></tr>`).join("")}
      </table>
      <p class="muted" style="margin-top:1em; font-size:11px">Press <code>?</code> or click outside to close.</p>
    </div>`;
  box.addEventListener("click", e => { if (e.target === box) box.remove(); });
  document.body.appendChild(box);
}

document.addEventListener("keydown", e => {
  // Cmd/Ctrl + S
  if ((e.metaKey || e.ctrlKey) && e.key === "s") {
    e.preventDefault();
    _clickPrimarySaveOnActiveTab();
    return;
  }
  // Don't intercept other shortcuts while typing
  const inInput = ["INPUT", "TEXTAREA", "SELECT"].includes(document.activeElement?.tagName);
  if (e.key === "Escape") {
    if (inInput) {
      const a = document.activeElement;
      if (a.type === "search" || a.id === "deliv-filter") { a.value = ""; a.dispatchEvent(new Event("input")); }
      a.blur();
    }
    const help = document.getElementById("shortcut-help"); if (help) help.remove();
    return;
  }
  if (inInput) return;  // remaining shortcuts only when not typing
  if (e.key === "?") { e.preventDefault(); _showShortcutHelp(); return; }
  // Number keys 1..9, 0 → tab by position
  if (/^[0-9]$/.test(e.key)) {
    const idx = e.key === "0" ? 9 : parseInt(e.key, 10) - 1;
    const tabs = document.querySelectorAll(".tab");
    if (tabs[idx]) tabs[idx].click();
  }
});

