// Klaxon admin UI — vanilla JS, no framework.

const $ = sel => document.querySelector(sel);
const $$ = sel => document.querySelectorAll(sel);

const J = async (url, opts) => {
  const r = await fetch(url, opts);
  if (!r.ok) throw new Error(`${r.status} ${r.statusText}`);
  const ct = r.headers.get("content-type") || "";
  return ct.includes("json") ? r.json() : r.text();
};

// ---- Tab switching ----
$$(".tab").forEach(t => {
  t.addEventListener("click", () => {
    $$(".tab").forEach(x => x.classList.remove("active"));
    $$(".tabpane").forEach(x => x.classList.remove("active"));
    t.classList.add("active");
    $("#tab-" + t.dataset.tab).classList.add("active");
  });
});

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
  } catch (e) { console.warn("rc fetch:", e); }
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

$("#btn-load-grafana-sample").addEventListener("click", () => $("#pv-input").value = JSON.stringify(grafanaSample, null, 2));
$("#btn-load-beszel-sample").addEventListener("click", () => $("#pv-input").value = JSON.stringify(beszelSample, null, 2));

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
  try {
    const r = await J(`/api/test/${sev}`, {
      method: "POST",
      body: JSON.stringify({title: $("#t-title").value, body: $("#t-body").value}),
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


// ---- Polling ----
async function refreshAll() {
  await Promise.all([loadStatus(), loadInhib(), loadDeliv(), loadRC(), loadCascade(), loadRouting()]);
}
refreshAll();
setInterval(() => { loadStatus(); loadInhib(); loadDeliv(); }, 10000);
