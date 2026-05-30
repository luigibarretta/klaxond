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
    <td><button class="danger" data-del>×</button></td>`;
  tr.querySelector("[data-del]").addEventListener("click", () => tr.remove());
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
  "commonLabels": {"alertname":"HostDiskFull","host":"it1-prd-mgmt-01","severity":"warning","component":"host"},
  "commonAnnotations": {"summary":"Disk usage > 85% on mgmt-01","description":"Approaching critical threshold. Investigate and free space."},
  "alerts":[{"labels":{"alertname":"HostDiskFull","host":"it1-prd-mgmt-01"},"generatorURL":"https://grafana.luigibarretta.com/alerting/grafana/uid/abc/view"}]
};
const beszelSample = {
  "alert": "CPU usage > 80",
  "system": "it1-prd-mgmt-01",
  "value": "86.4",
  "threshold": "80",
  "status": "triggered",
  "url": "https://beszel.luigibarretta.com/system/mgmt-01"
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
  } catch (e) {
    $("#pv-output").textContent = "Error: " + e.message;
  }
});

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

// ---- Polling ----
async function refreshAll() {
  await Promise.all([loadStatus(), loadInhib(), loadDeliv(), loadRC()]);
}
refreshAll();
setInterval(() => { loadStatus(); loadInhib(); loadDeliv(); }, 10000);
