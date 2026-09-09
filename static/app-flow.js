import { $, J, debounce, errorText, escapeHtml, navigateToTab, notifyError, queryGet, tr } from "./app.js";
import { aggregateDeliveries24h, buildMermaidDiagram, sourceNodeId } from "./app-flow-diagram.js";
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
let _flowZoom = 1;
let _flowNaturalSize = null;

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

export async function loadFlow(options = {}) {
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
    const [channel, cascade, ntfy, dedup, auth, render, ingest, inhibition, emergency, deliveries] = await Promise.all([
      queryGet("flow-channel-config", "/api/channel-config", { cancelPrevious: false }),
      queryGet("flow-cascade-config", "/api/cascade-config", { cancelPrevious: false }),
      queryGet("flow-ntfy-topics", "/api/ntfy-topics", { cancelPrevious: false }),
      queryGet("flow-dedup-config", "/api/dedup-config", { cancelPrevious: false }),
      J("/api/auth/config"),
      queryGet("flow-render-config", "/api/render-config", { cancelPrevious: false }),
      queryGet("flow-ingest-auth", "/api/ingest-auth", { cancelPrevious: false }),
      queryGet("flow-inhibition-rules", "/api/inhibition-rules", { cancelPrevious: false }),
      queryGet("flow-emergency-config", "/api/emergency-config", { cancelPrevious: false }),
      fetchDeliveries(10000, { scope: "flow-deliveries" }),
    ]);
    cfgs = { channel, cascade, ntfy, dedup, auth, render, ingest, inhibition, emergency };
    stats = aggregateDeliveries24h(deliveries);
    _renderFlowSummary(cfgs);
  } catch (e) {
    notifyError("flow-config", e, { status: "#flow-status", inlineText: tr("flow.config_fetch_failed", { message: errorText(e) }) });
    return;
  }
  const src = buildMermaidDiagram(cfgs, stats);
  $("#flow-source").textContent = src;
  try {
    const viewport = $("#flow-diagram");
    const previous = options.preserveViewport ? {
      zoom: _flowZoom,
      left: viewport?.scrollLeft || 0,
      top: viewport?.scrollTop || 0,
    } : null;
    const { svg, bindFunctions } = await mermaid.render("flow-svg-" + Date.now(), src);
    viewport.innerHTML = '<div class="flow-canvas"></div>';
    const canvas = viewport.querySelector(".flow-canvas");
    canvas.innerHTML = svg;
    if (bindFunctions) bindFunctions(canvas);
    _prepareFlowZoom(previous?.zoom || (window.innerWidth <= 760 ? 4 : 1));
    if (previous) {
      viewport.scrollLeft = previous.left;
      viewport.scrollTop = previous.top;
    }
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

function _renderFlowSummary(cfgs) {
  const target = $("#flow-config-summary");
  if (!target) return;
  const sourceCount = Object.values(cfgs.ingest?.sources || {}).filter(source => source?.configured).length;
  const inhibitionCount = (cfgs.inhibition?.rules || []).length;
  const tierCount = (cfgs.cascade?.tiers || []).length;
  const profileCount = (cfgs.emergency?.settings?.profiles || []).filter(profile => profile.enabled).length;
  const items = [
    ["/routing", tr("flow.summary_sources", { count: sourceCount })],
    ["/inhibitions", tr("flow.summary_inhibitions", { count: inhibitionCount })],
    ["/cascade", tr("flow.summary_tiers", { count: tierCount })],
    ["/emergencies", tr("flow.summary_emergencies", { count: profileCount })],
  ];
  target.innerHTML = items.map(([href, label]) => `<a class="flow-summary-chip" href="${href}">${escapeHtml(label)}</a>`).join("");
}

const _NODE_FOR_CHANNEL = { ntfy: "NTFY", telegram: "TG", smtp: "SMTP" };

function _pulseRecentActivityNodes(stats) {
  // Clear previous pulse markers
  $("#flow-diagram")?.querySelectorAll(".node.recent-activity").forEach(n => n.classList.remove("recent-activity"));
  if (!stats) return;
  // Compute activity in last 60s (re-fetch a fresh slice for live feel)
  // Use what we have from /api/deliveries; cutoff at 60s window
  const activeNodes = new Set();
  const cutoff = Date.now() / 1000 - 60;
  for (const [src, timestamp] of Object.entries(stats.lastBySource || {})) {
    if (timestamp >= cutoff) activeNodes.add(sourceNodeId(src));
  }
  for (const [chan, timestamp] of Object.entries(stats.lastByChannel || {})) {
    if (timestamp >= cutoff && _NODE_FOR_CHANNEL[chan]) activeNodes.add(_NODE_FOR_CHANNEL[chan]);
  }
  activeNodes.forEach(id => {
    const n = $("#flow-diagram")?.querySelector(`[id$="-${id}"], [id$="-${id}-1"]`);
    if (n) n.classList.add("recent-activity");
  });
}

async function refreshFlowStats() {
  if (!$("#flow-diagram")?.querySelector("svg")) return;  // no diagram yet
  await loadFlow({ preserveViewport: true });
}

function _prepareFlowZoom(zoom) {
  const svg = $("#flow-diagram")?.querySelector("svg");
  if (!svg) return;
  const viewBox = svg.viewBox?.baseVal;
  const rect = svg.getBoundingClientRect();
  _flowNaturalSize = {
    width: Number(viewBox?.width) || rect.width || 1,
    height: Number(viewBox?.height) || rect.height || 1,
  };
  svg.style.maxWidth = "none";
  svg.style.display = "block";
  svg.style.transformOrigin = "top left";
  _flowZoom = zoom;
  _applyFlowZoom();
}

function _applyFlowZoom() {
  const viewport = $("#flow-diagram");
  const canvas = viewport?.querySelector(".flow-canvas");
  const svg = canvas?.querySelector("svg");
  if (!viewport || !canvas || !svg || !_flowNaturalSize) return;
  const availableWidth = Math.max(1, viewport.clientWidth - 32);
  const fit = Math.min(1, availableWidth / _flowNaturalSize.width);
  const scale = fit * _flowZoom;
  svg.style.width = `${_flowNaturalSize.width}px`;
  svg.style.height = `${_flowNaturalSize.height}px`;
  svg.style.transform = `scale(${scale})`;
  canvas.style.width = `${Math.ceil(_flowNaturalSize.width * scale)}px`;
  canvas.style.height = `${Math.ceil(_flowNaturalSize.height * scale)}px`;
  const output = $("#flow-zoom-level");
  if (output) output.textContent = `${Math.round(_flowZoom * 100)}%`;
  if ($("#flow-zoom-out")) $("#flow-zoom-out").disabled = _flowZoom <= 0.5;
  if ($("#flow-zoom-in")) $("#flow-zoom-in").disabled = _flowZoom >= 5;
}

function _changeFlowZoom(delta) {
  _flowZoom = Math.max(0.5, Math.min(5, Math.round((_flowZoom + delta) * 100) / 100));
  _applyFlowZoom();
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
$("#flow-zoom-out")?.addEventListener("click", () => _changeFlowZoom(-0.25));
$("#flow-zoom-in")?.addEventListener("click", () => _changeFlowZoom(0.25));
$("#flow-zoom-fit")?.addEventListener("click", () => {
  _flowZoom = 1;
  _applyFlowZoom();
  $("#flow-diagram")?.scrollTo({ left: 0, top: 0 });
});
$("#flow-diagram")?.addEventListener("wheel", event => {
  if (!event.ctrlKey && !event.metaKey) return;
  event.preventDefault();
  _changeFlowZoom(event.deltaY < 0 ? 0.25 : -0.25);
}, { passive: false });
$("#flow-diagram")?.addEventListener("keydown", event => {
  if (!event.ctrlKey && !event.metaKey) return;
  if (["+", "="].includes(event.key)) { event.preventDefault(); _changeFlowZoom(0.25); }
  if (event.key === "-") { event.preventDefault(); _changeFlowZoom(-0.25); }
  if (event.key === "0") { event.preventDefault(); _flowZoom = 1; _applyFlowZoom(); }
});
window.addEventListener("resize", debounce(_applyFlowZoom));
if (window.matchMedia?.("(prefers-reduced-motion: reduce)").matches && $("#flow-animate")) {
  $("#flow-animate").checked = false;
}
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
