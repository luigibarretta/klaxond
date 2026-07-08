import {
  $, $$, APP_META, J, SEARCH_DEBOUNCE_MS, apiFetch, applyTablePager, debounce, errorText,
  escapeHtml, fetchError, fetchOk, getAuthPasswordPolicy, getCurrentUser, isAbortError, isPublicInfoPage,
  markTabDirty, notifyError, notifyResponseError, notifySuccess, notifyValidationError, onReady,
  queryGet, refreshTablePagers, setAuthPasswordPolicy, setInlineStatus, setLocalTotpEnabled,
  showTableRowPage, syncTabFromPath, tr, updateAllTabAccessibleLabels, updatePublicLoginLinksText,
} from "./app.js";
import { loadDeliv } from "./app-deliveries-logs.js";

// ---- Render config ----
let rcData = {};
let rcRuntimeSettings = {};
export async function loadRC() {
  try {
    const j = await queryGet("render-config", "/api/render-config");
    $("#gbase").textContent = j.grafana_base;
    rcData = j.component_dashboards;
    rcRuntimeSettings = j.settings || {};
    $("#rc-grafana-base").value = rcRuntimeSettings.grafana_base || j.grafana_base || "";
    $("#rc-public-url").value = rcRuntimeSettings.public_url || "";
    $("#rc-grafana-render-base").value = rcRuntimeSettings.grafana_render_base || "";
    $("#rc-grafana-render-token").value = "";
    $("#rc-grafana-render-token").placeholder = rcRuntimeSettings.grafana_render_token_configured ? "***SET***" : "";
    $("#rc-grafana-render-token-clear").checked = false;
    $("#rc-render-image-ttl").value = rcRuntimeSettings.render_image_ttl || 900;
    $("#rc-ack-default-ttl").value = rcRuntimeSettings.ack_default_ttl || 3600;
    const env = rcRuntimeSettings.from_env || {};
    const overridden = Object.entries(env).filter(([, v]) => v).map(([k]) => k);
    $("#rc-runtime-status").textContent = overridden.length ? tr("render.env_override", { keys: overridden.join(", ") }) : "";
    renderRCTable();
    populateTestComponentSelect();
  } catch (e) { fetchError("render-config", e); }
}

export function populateTestComponentSelect() {
  const sel = $("#t-component");
  if (!sel) return;
  const cur = sel.value;
  sel.innerHTML = `<option value="">${escapeHtml(tr("render.none_freeform"))}</option>` +
    Object.keys(rcData).sort().map(k => `<option value="${escapeHtml(k)}">${escapeHtml(k)} → ${escapeHtml(rcData[k][0])}</option>`).join("");
  if (cur && rcData[cur]) sel.value = cur;
}

export function renderRCTable() {
  const tb = $("#t-rc tbody"); tb.innerHTML = "";
  for (const [k, v] of Object.entries(rcData)) addRCRow(k, v[0], v[1], { deferPager: true });
  applyTablePager("t-rc", { reset: true });
}

function addRCRow(component="", label="", url="", opts = {}) {
  const tb = $("#t-rc tbody");
  const row = document.createElement("tr");
  row.innerHTML = `
    <td><input type="text" value="${escapeHtml(component)}" data-f="key"></td>
    <td><input type="text" value="${escapeHtml(label)}" data-f="label"></td>
    <td><input type="text" value="${escapeHtml(url)}" data-f="url"></td>
    <td>
      <button data-test title="${escapeHtml(tr("render.open_title"))}">↗</button>
      <button class="danger" data-del>×</button>
    </td>`;
  row.querySelector("[data-del]").addEventListener("click", () => {
    row.remove();
    applyTablePager("t-rc");
  });
  row.querySelector("[data-test]").addEventListener("click", () => {
    const u = row.querySelector('[data-f="url"]').value.trim();
    if (!u) return;
    const full = u.startsWith("http") ? u : ($("#gbase").textContent.replace(/\/$/, "") + u);
    window.open(full, "_blank", "noopener");
  });
  tb.appendChild(row);
  if (!opts.deferPager) applyTablePager("t-rc", { page: "last" });
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
  const settings = {
    grafana_base: $("#rc-grafana-base").value.trim(),
    public_url: $("#rc-public-url").value.trim(),
    grafana_render_base: $("#rc-grafana-render-base").value.trim(),
    render_image_ttl: parseInt($("#rc-render-image-ttl").value, 10) || 900,
    ack_default_ttl: parseInt($("#rc-ack-default-ttl").value, 10) || 3600,
  };
  const renderToken = $("#rc-grafana-render-token").value.trim();
  if ($("#rc-grafana-render-token-clear").checked) settings.grafana_render_token = "";
  else if (renderToken) settings.grafana_render_token = renderToken;
  try {
    const r = await J("/api/render-config", { method: "POST", body: JSON.stringify({component_dashboards: out, settings}), headers: {"Content-Type": "application/json"} });
    notifySuccess(tr("render.saved_mappings", { count: r.count }), { status: "#rc-status", clearMs: 3000 });
    markTabDirty("render", false);
    rcData = out;
    await loadRC();
    populateTestComponentSelect();
  } catch (e) { notifyError("render-config-save", e, { status: "#rc-status" }); }
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
const shelfmarkSample = {
  "version": "1.0",
  "title": "Download complete",
  "message": "\"The Way of Kings\" by Brandon Sanderson downloaded successfully (EPUB)",
  "type": "success",
  "event": "download_complete"
};
const prowlarrSample = {
  "eventType": "Health",
  "instanceName": "Prowlarr",
  "applicationUrl": "https://prowlarr.luigibarretta.com",
  "health": {
    "type": "warning",
    "message": "Indexers unavailable due to failures: EZTV, 1337x",
    "wikiUrl": "https://wiki.servarr.com/prowlarr/system#indexers-are-unavailable-due-to-failures"
  }
};
const decypharrSample = {
  "hash": "dd8255ecdc7ca55fb0bbf81323d87062db1f6d1c",
  "name": "Big Buck Bunny",
  "status": "success",
  "event": "download_complete",
  "debrid": "realdebrid",
  "content_path": "/downloads/Big Buck Bunny",
  "message": "Download completed: Big Buck Bunny [] -> /downloads/Big Buck Bunny"
};

$("#btn-load-grafana-sample").addEventListener("click", () => $("#pv-input").value = JSON.stringify(grafanaSample, null, 2));
$("#btn-load-beszel-sample").addEventListener("click", () => $("#pv-input").value = JSON.stringify(beszelSample, null, 2));
const _hcBtn = $("#btn-load-healthchecks-sample"); if (_hcBtn) _hcBtn.addEventListener("click", () => $("#pv-input").value = JSON.stringify(healthchecksSample, null, 2));
const _wudBtn = $("#btn-load-wud-sample"); if (_wudBtn) _wudBtn.addEventListener("click", () => $("#pv-input").value = JSON.stringify(wudSample, null, 2));
const _shfBtn = $("#btn-load-shelfmark-sample"); if (_shfBtn) _shfBtn.addEventListener("click", () => $("#pv-input").value = JSON.stringify(shelfmarkSample, null, 2));
const _prwBtn = $("#btn-load-prowlarr-sample"); if (_prwBtn) _prwBtn.addEventListener("click", () => $("#pv-input").value = JSON.stringify(prowlarrSample, null, 2));
const _dcyBtn = $("#btn-load-decypharr-sample"); if (_dcyBtn) _dcyBtn.addEventListener("click", () => $("#pv-input").value = JSON.stringify(decypharrSample, null, 2));

async function _runPreviewRender() {
  let payload;
  try { payload = JSON.parse($("#pv-input").value || "{}"); }
  catch (e) {
    // JSON not yet valid (user mid-typing) — show in output but keep mock as-is
    $("#pv-output").textContent = tr("preview.invalid_json", { message: e.message });
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
    if (isAuthRedirectError(e)) return;
    notifyError("render-preview", e);
    $("#pv-output").textContent = tr("common.error") + ": " + errorText(e);
    $("#pv-vis-body").textContent = tr("preview.error_rendering");
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
["#btn-load-grafana-sample", "#btn-load-beszel-sample", "#btn-load-healthchecks-sample", "#btn-load-wud-sample", "#btn-load-shelfmark-sample", "#btn-load-prowlarr-sample", "#btn-load-decypharr-sample"].forEach(sel => {
  $(sel)?.addEventListener("click", () => _schedulePreview());
});

function renderNtfyMock(r) {
  const h = r.headers || {};
  $("#pv-vis-title").textContent = h["Title (raw)"] || "—";
  $("#pv-vis-body").textContent = r.body || tr("preview.empty_body");
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
      showToast(tr("test.dry_run_toast", {
        verdict: r.would_send ? tr("test.would_deliver") : tr("test.would_suppress"),
        reason: r.reason
      }), r.would_send ? "info" : "warn", 5000);
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
    if (isAuthRedirectError(e)) return;
    $("#t-result").textContent = tr("common.error") + ": " + errorText(e);
    showToast(tr("test.send_failed", { message: errorText(e) }), "error");
  } finally {
    button.disabled = false;
  }
});



