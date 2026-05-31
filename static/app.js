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
    return true;
  }
  return false;
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
      card.querySelector(".dot").className = "dot " + (up ? "up" : "down");
      card.querySelector(".ch-url").textContent = url || "";
    };
    setCh("ch-ntfy", s.channels.ntfy, s.ntfy_url);
    setCh("ch-telegram", s.channels.telegram, s.telegram_configured ? "bot configured" : "(not configured)");
    setCh("ch-smtp", s.channels.smtp, s.smtp_host ? `${s.smtp_host}` : "(not configured)");
    $("#cas-default").textContent = s.cascade_enabled_default;
    $("#cas-runtime").textContent = s.cascade_enabled_runtime;
  } catch (e) { console.warn("status fetch:", e); }
}

$("#btn-cascade-toggle").addEventListener("click", async () => {
  await J("/api/cascade/toggle", { method: "POST", body: "{}" });
  loadStatus();
});

// ---- Inhibitions ----
async function loadInhib() {
  try {
    const rows = await J("/api/inhibitions");
    const tb = $("#t-inhib tbody"); tb.innerHTML = "";
    if (!rows.length) { tb.innerHTML = '<tr><td colspan="3" class="muted">No active suppressions.</td></tr>'; return; }
    for (const r of rows) {
      const tr = document.createElement("tr");
      tr.innerHTML = `<td><code>${r.source}</code></td><td>${r.anchor}</td><td>${fmtSecs(r.expires_in_seconds)}</td>`;
      tb.appendChild(tr);
    }
  } catch (e) { console.warn("inhib fetch:", e); }
}

function fmtSecs(s) {
  if (s < 60) return s + "s";
  if (s < 3600) return Math.round(s/60) + "m";
  return Math.round(s/3600 * 10) / 10 + "h";
}

// ---- Deliveries ----
async function loadDeliv() {
  try {
    const rows = await J("/api/deliveries");
    const tb = $("#t-deliv tbody"); tb.innerHTML = "";
    if (!rows.length) { tb.innerHTML = '<tr><td colspan="5" class="muted">No deliveries yet.</td></tr>'; return; }
    rows.slice().reverse().forEach(r => {
      const tr = document.createElement("tr");
      const t = new Date(r.ts * 1000).toLocaleTimeString();
      tr.innerHTML = `<td>${t}</td><td>${r.source}</td><td class="sev-${r.severity}">${r.severity}</td><td>${escapeHtml(r.title)}</td><td class="ch-${r.channel}">${r.channel}</td>`;
      tb.appendChild(tr);
    });
  } catch (e) { console.warn("deliv fetch:", e); }
}

const escapeHtml = s => String(s).replace(/[&<>"]/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));

// ---- Render config ----
let rcData = {};
async function loadRC() {
  try {
    const j = await J("/api/render-config");
    $("#gbase").textContent = j.grafana_base;
    rcData = j.component_dashboards;
    renderRCTable();
    populateTestComponentSelect();
  } catch (e) { console.warn("rc fetch:", e); }
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

$("#btn-preview").addEventListener("click", async () => {
  try {
    const payload = JSON.parse($("#pv-input").value || "{}");
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
$("#btn-test-fire").addEventListener("click", async () => {
  const sev = $("#t-sev").value;
  const payload = {
    title:     $("#t-title").value,
    body:      $("#t-body").value,
    component: $("#t-component").value,
    host:      $("#t-host").value,
  };
  try {
    const r = await J(`/api/test/${sev}`, {
      method: "POST",
      body: JSON.stringify(payload),
      headers: {"Content-Type": "application/json"}
    });
    $("#t-result").textContent = JSON.stringify(r, null, 2);
    setTimeout(loadDeliv, 1000);
  } catch (e) {
    $("#t-result").textContent = "Error: " + e.message;
  }
});



// ---- Routing (channel config) ----
async function loadRouting() {
  try {
    const c = await J("/api/channel-config");
    $("#r-ntfy-url").value = c.ntfy.url || "";
    $("#r-ntfy-info").value = c.ntfy.topics.info || "";
    $("#r-ntfy-warn").value = c.ntfy.topics.warning || "";
    $("#r-ntfy-crit").value = c.ntfy.topics.critical || "";
    const tok = c.ntfy.tokens_configured;
    $("#r-ntfy-status").innerHTML = `tokens: info=${badge(tok.info)} warning=${badge(tok.warning)} critical=${badge(tok.critical)}` +
      (c.ntfy.url_from_env ? " · <em>url overridden by env</em>" : "");
    $("#r-tg-chat").value = c.telegram.chat_id || "";
    $("#r-tg-status").innerHTML = `bot token: ${badge(c.telegram.bot_token_configured)}` +
      (c.telegram.chat_id_from_env ? " · <em>chat_id overridden by env</em>" : "");
    $("#r-smtp-host").value = c.smtp.host || "";
    $("#r-smtp-port").value = c.smtp.port || 587;
    $("#r-smtp-from").value = c.smtp.from_addr || "";
    $("#r-smtp-to").value = c.smtp.to_addr || "";
    $("#r-smtp-status").innerHTML = `user: ${badge(c.smtp.user_configured)} password: ${badge(c.smtp.password_configured)}` +
      (c.smtp.host_from_env ? " · <em>host overridden by env</em>" : "");
  } catch (e) { console.warn("routing fetch:", e); }
}

const badge = ok => ok ? "<span style='color:var(--green)'>✓ configured</span>" : "<span style='color:var(--red)'>✗ missing</span>";

$("#btn-routing-save").addEventListener("click", async () => {
  const payload = {
    ntfy: {
      url: $("#r-ntfy-url").value.trim(),
      topics: {
        info:     $("#r-ntfy-info").value.trim(),
        warning:  $("#r-ntfy-warn").value.trim(),
        critical: $("#r-ntfy-crit").value.trim(),
      }
    },
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
    loadStatus();
  } catch (e) { $("#routing-msg").textContent = "Error: " + e.message; }
});


// ---- Cascade tiers ----
const TIER_OPTS = ["ntfy", "telegram", "smtp"];
let casData = { tiers: [], default_enabled_for_webhook: false };

async function loadCascade() {
  try {
    casData = await J("/api/cascade-config");
    renderCascadeTable();
    $("#cas-default").checked = !!casData.default_enabled_for_webhook;
  } catch (e) { console.warn("cas fetch:", e); }
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
    loadStatus();
  } catch (e) { $("#cas-status").textContent = "Error: " + e.message; }
});



// ---- Delivery (policies + rules) ----
let delivData = { default_policy: "legacy-cascade", policies: [], rules: [], available_tiers: [], legacy_cascade_tiers: [] };

async function loadDelivery() {
  try {
    delivData = await J("/api/delivery-config");
    renderDeliveryDefault();
    renderPoliciesTable();
    renderRulesTable();
  } catch (e) { console.warn("delivery fetch:", e); }
}

function policyNames() {
  return ["legacy-cascade", ...delivData.policies.map(p => p.name)];
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

function addRuleRow(match = {}, policy = "legacy-cascade", idx = -1) {
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


// ---- Polling ----
async function refreshAll() {
  await Promise.all([loadStatus(), loadInhib(), loadDeliv(), loadRC(), loadCascade(), loadRouting(), loadDelivery(), loadDedup(), loadAuth()]);
}
refreshAll();
setInterval(() => { loadStatus(); loadInhib(); loadDeliv(); }, 10000);

// ---- About banner (dismissible + persisted) ----
(function aboutBanner() {
  const KEY = "klaxond.about.hidden";
  const box = document.getElementById("about-box");
  const btn = document.getElementById("about-close");
  if (!box || !btn) return;
  if (localStorage.getItem(KEY) === "1") box.classList.add("hidden");
  btn.addEventListener("click", () => {
    box.classList.add("hidden");
    try { localStorage.setItem(KEY, "1"); } catch (e) {}
  });
})();
