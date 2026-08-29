import {
  $, $$, APP_META, J, SEARCH_DEBOUNCE_MS, apiFetch, applyTablePager, debounce, errorText,
  escapeHtml, fetchError, fetchOk, getAuthPasswordPolicy, getCurrentUser, isAbortError, isPublicInfoPage,
  markTabDirty, navigateToTab, notifyError, notifyResponseError, notifySuccess, notifyValidationError, onReady,
  queryGet, refreshTablePagers, setAuthPasswordPolicy, setInlineStatus, setLocalTotpEnabled,
  showTableRowPage, syncTabFromPath, tr, updateAllTabAccessibleLabels, updatePublicLoginLinksText,
} from "./app.js";
import { aggregateDeliveries24h, buildMermaidDiagram } from "./app-flow-diagram.js";
import { fetchDeliveries } from "./app-status.js";

// Make tab-switcher callable from outside (mermaid click handlers).
// Use the SPA router so the path stays in sync with the active pane.
function switchToTab(name) {
  if (!navigateToTab(name)) {
    // Fallback: direct DOM update if the button doesn't exist (defensive)
    document.querySelectorAll(".tab").forEach(b => b.classList.toggle("active", b.dataset.tab === name));
    document.querySelectorAll(".tabpane").forEach(s => s.classList.toggle("active", s.id === `tab-${name}`));
  }
}
window.flowGotoTab = switchToTab;  // expose to mermaid click callbacks

let _flowMermaidInitialized = false;

// Wait for mermaid.min.js to finish loading (3.3MB async script).
// Returns true if library is available within timeoutMs, false otherwise.
async function _waitForMermaid(timeoutMs = 15000) {
  if (window.mermaid) return true;
  const t0 = Date.now();
  $("#flow-status").textContent = tr("flow.loading_mermaid");
  while (!window.mermaid) {
    if (Date.now() - t0 > timeoutMs) return false;
    await new Promise(r => setTimeout(r, 100));
  }
  return true;
}

export async function loadFlow() {
  if (!await _waitForMermaid()) {
    $("#flow-status").textContent = tr("flow.mermaid_timeout");
    return;
  }
  if (!_flowMermaidInitialized) {
    mermaid.initialize({ startOnLoad: false, theme: "dark", securityLevel: "loose" });
    _flowMermaidInitialized = true;
  }
  $("#flow-status").textContent = tr("flow.fetching_config");
  let cfgs = {}, stats = null;
  try {
    const [channel, cascade, ntfy, dedup, auth, render, deliveries] = await Promise.all([
      queryGet("flow-channel-config", "/api/channel-config", { cancelPrevious: false }),
      queryGet("flow-cascade-config", "/api/cascade-config", { cancelPrevious: false }),
      queryGet("flow-ntfy-topics", "/api/ntfy-topics", { cancelPrevious: false }),
      queryGet("flow-dedup-config", "/api/dedup-config", { cancelPrevious: false }),
      J("/api/auth/config"),
      queryGet("flow-render-config", "/api/render-config", { cancelPrevious: false }),
      fetchDeliveries(10000, { scope: "flow-deliveries" }),
    ]);
    cfgs = { channel, cascade, ntfy, dedup, auth, render };
    stats = aggregateDeliveries24h(deliveries);
  } catch (e) {
    notifyError("flow-config", e, { status: "#flow-status", inlineText: tr("flow.config_fetch_failed", { message: errorText(e) }) });
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
    $("#flow-status").textContent = tr("flow.rendered_at", { time: new Date().toLocaleTimeString() });
  } catch (e) {
    notifyError("flow-render", e, { status: "#flow-status", inlineText: tr("flow.render_failed") });
    $("#flow-diagram").innerHTML = `<pre style="color:#c44">Mermaid render error: ${escapeHtml(errorText(e))}</pre>`;
    $("#flow-status").textContent = tr("flow.render_failed");
  }
}

// Map source name → mermaid node id (matches buildMermaidDiagram)
const _NODE_FOR_SOURCE = { grafana: "AM", beszel: "BSZ", healthchecks: "HC", wud: "WUD", authentik: "AKN", shelfmark: "SHF", prowlarr: "PRW", decypharr: "DCY" };
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
    const deliveries = await fetchDeliveries(10000, { scope: "flow-stats", force: true });
    const stats = aggregateDeliveries24h(deliveries);
    _pulseRecentActivityNodes(stats);
    // Update status timestamp
    const ts = $("#flow-status");
    if (ts) ts.textContent = tr("flow.stats_refreshed", { time: new Date().toLocaleTimeString() });
  } catch (e) {
    fetchError("flow-stats", e);
  }
}

let _flowAutorefreshTimer = null;
export function setupFlowAutorefresh() {
  if (_flowAutorefreshTimer) { clearInterval(_flowAutorefreshTimer); _flowAutorefreshTimer = null; }
  if ($("#flow-autorefresh")?.checked) {
    _flowAutorefreshTimer = setInterval(refreshFlowStats, 30000);
  }
}

$("#flow-refresh")?.addEventListener("click", () => loadFlow());
$("#flow-animate")?.addEventListener("change", e => {
  $("#flow-diagram")?.classList.toggle("animate", e.target.checked);
});
$("#flow-autorefresh")?.addEventListener("change", setupFlowAutorefresh);
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
  btn.addEventListener("click", () => { loadFlow(); setupFlowAutorefresh(); });
});
// Stop autorefresh when leaving the tab (any tab click)
document.querySelectorAll('.tab:not([data-tab="flow"])').forEach(btn => {
  btn.addEventListener("click", () => {
    if (_flowAutorefreshTimer) { clearInterval(_flowAutorefreshTimer); _flowAutorefreshTimer = null; }
  });
});
