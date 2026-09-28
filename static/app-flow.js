import {
  $,
  J,
  debounce,
  errorText,
  escapeHtml,
  fetchError,
  navigateToTab,
  notifyError,
  queryGet,
  tr,
} from "./app.js";
import { buildMermaidDiagram, sourceNodeId } from "./app-flow-diagram.js";
import { renderFlowStructure } from "./app-flow-structure.js";
import { buildFlowSteps } from "./app-flow-steps.js";
import { fetchDeliveryActivity } from "./app-status.js";
import { renderFlowSummary } from "./app-flow-summary.js";
function switchToTab(name) {
  if (!navigateToTab(name)) {
    document
      .querySelectorAll(".tab")
      .forEach((b) => b.classList.toggle("active", b.dataset.tab === name));
    document
      .querySelectorAll(".tabpane")
      .forEach((s) => s.classList.toggle("active", s.id === `tab-${name}`));
  }
}
window.flowGotoTab = switchToTab;
let _flowMermaidInitialized = false;
let _flowZoom = 1;
let _flowNaturalSize = null;
async function _waitForMermaid(timeoutMs = 15e3) {
  if (window.mermaid) return true;
  const t0 = Date.now();
  $("#flow-status").textContent = tr("flow.loading_mermaid");
  while (!window.mermaid) {
    if (Date.now() - t0 > timeoutMs) return false;
    await new Promise((r) => setTimeout(r, 100));
  }
  return true;
}

async function fetchFlowConfiguration() {
  const [channel, cascade, delivery, ntfy, dedup, auth, render, ingest, inhibition, emergency, activity] = await Promise.all([
    queryGet("flow-channel-config", "/api/channel-config", { cancelPrevious: false }),
    queryGet("flow-cascade-config", "/api/cascade-config", { cancelPrevious: false }),
    queryGet("flow-delivery-config", "/api/delivery-config", { cancelPrevious: false }),
    queryGet("flow-ntfy-topics", "/api/ntfy-topics", { cancelPrevious: false }),
    queryGet("flow-dedup-config", "/api/dedup-config", { cancelPrevious: false }),
    J("/api/auth/config"),
    queryGet("flow-render-config", "/api/render-config", { cancelPrevious: false }),
    queryGet("flow-ingest-auth", "/api/ingest-auth", { cancelPrevious: false }),
    queryGet("flow-inhibition-rules", "/api/inhibition-rules", { cancelPrevious: false }),
    queryGet("flow-emergency-config", "/api/emergency-config", { cancelPrevious: false }),
    fetchDeliveryActivity(24, { scope: "flow-delivery-activity" }).catch((error) => {
      fetchError("flow-delivery-activity", error);
      return null;
    }),
  ]);
  return {
    cfgs: { channel, cascade, delivery, ntfy, dedup, auth, render, ingest, inhibition, emergency },
    stats: activity
      ? {
          bySource: activity.by_source || {},
          bySeverity: activity.by_severity || {},
          byChannel: activity.by_channel || {},
          lastBySource: activity.latest_by_source || {},
          lastByChannel: activity.latest_by_channel || {},
        }
      : null,
  };
}

async function renderFlowDiagram(src, stats, options) {
  try {
    const viewport = $("#flow-diagram");
    const previous = options.preserveViewport
      ? { zoom: _flowZoom, left: viewport?.scrollLeft || 0, top: viewport?.scrollTop || 0 }
      : null;
    const { svg, bindFunctions } = await mermaid.render(`flow-svg-${Date.now()}`, src);
    viewport.innerHTML = '<div class="flow-canvas"></div>';
    const canvas = viewport.querySelector(".flow-canvas");
    canvas.innerHTML = svg;
    if (bindFunctions) bindFunctions(canvas);
    _prepareFlowZoom(previous?.zoom ?? null);
    if (previous) {
      viewport.scrollLeft = previous.left;
      viewport.scrollTop = previous.top;
    }
    $("#flow-diagram")?.classList.toggle("animate", !!$("#flow-animate")?.checked);
    _pulseRecentActivityNodes(stats);
    $("#flow-status").textContent = tr("flow.rendered_at", {
      time: new Date().toLocaleTimeString(),
    });
  } catch (e) {
    notifyError("flow-render", e, {
      status: "#flow-status",
      inlineText: tr("flow.render_failed"),
    });
    $("#flow-diagram").innerHTML =
      `<pre style="color:#c44">Mermaid render error: ${escapeHtml(errorText(e))}</pre>`;
    $("#flow-status").textContent = tr("flow.render_failed");
  }
}

export async function loadFlow(options = {}) {
  if (!(await _waitForMermaid())) {
    $("#flow-status").textContent = tr("flow.mermaid_timeout");
    return;
  }
  if (!_flowMermaidInitialized) {
    mermaid.initialize({
      startOnLoad: false,
      theme: "dark",
      securityLevel: "loose",
    });
    _flowMermaidInitialized = true;
  }
  $("#flow-status").textContent = tr("flow.fetching_config");
  let cfgs = {};
  let stats = null;
  try {
    ({ cfgs, stats } = await fetchFlowConfiguration());
    renderFlowSummary(cfgs);
    renderFlowStructure(buildFlowSteps(cfgs, stats));
  } catch (e) {
    notifyError("flow-config", e, {
      status: "#flow-status",
      inlineText: tr("flow.config_fetch_failed", { message: errorText(e) }),
    });
    return;
  }
  const src = buildMermaidDiagram(cfgs, stats);
  $("#flow-source").textContent = src;
  await renderFlowDiagram(src, stats, options);
}
const _NODE_FOR_CHANNEL = { ntfy: "NTFY", telegram: "TG", smtp: "SMTP" };
function _pulseRecentActivityNodes(stats) {
  $("#flow-diagram")
    ?.querySelectorAll(".node.recent-activity")
    .forEach((n) => n.classList.remove("recent-activity"));
  if (!stats) return;
  const activeNodes = new Set();
  const cutoff = Date.now() / 1e3 - 60;
  for (const [src, timestamp] of Object.entries(stats.lastBySource || {})) {
    if (timestamp >= cutoff) activeNodes.add(sourceNodeId(src));
  }
  for (const [chan, timestamp] of Object.entries(stats.lastByChannel || {})) {
    if (timestamp >= cutoff && _NODE_FOR_CHANNEL[chan])
      activeNodes.add(_NODE_FOR_CHANNEL[chan]);
  }
  activeNodes.forEach((id) => {
    const n = $("#flow-diagram")?.querySelector(
      `[id$="-${id}"], [id$="-${id}-1"]`,
    );
    if (n) n.classList.add("recent-activity");
  });
}
async function refreshFlowStats() {
  if (!$("#flow-diagram")?.querySelector("svg")) return;
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
  if (zoom === null) {
    const viewport = $("#flow-diagram");
    const availableWidth = Math.max(1, (viewport?.clientWidth || 1) - 32);
    const fit = Math.min(1, availableWidth / _flowNaturalSize.width);
    _flowZoom = Math.max(1, Math.min(5, 0.85 / fit));
  } else {
    _flowZoom = zoom;
  }
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
  if (output) output.textContent = `${Math.round(scale * 100)}%`;
  if ($("#flow-zoom-out")) $("#flow-zoom-out").disabled = _flowZoom <= 0.5;
  if ($("#flow-zoom-in")) $("#flow-zoom-in").disabled = _flowZoom >= 5;
}
function _changeFlowZoom(delta) {
  _flowZoom = Math.max(
    0.5,
    Math.min(5, Math.round((_flowZoom + delta) * 100) / 100),
  );
  _applyFlowZoom();
}
let _flowAutorefreshTimer = null;
export function setupFlowAutorefresh() {
  if (_flowAutorefreshTimer) {
    clearInterval(_flowAutorefreshTimer);
    _flowAutorefreshTimer = null;
  }
  if ($("#flow-autorefresh")?.checked) {
    _flowAutorefreshTimer = setInterval(refreshFlowStats, 3e4);
  }
}
$("#flow-refresh")?.addEventListener("click", () => loadFlow());
$("#flow-animate")?.addEventListener("change", (e) => {
  $("#flow-diagram")?.classList.toggle("animate", e.target.checked);
});
$("#flow-autorefresh")?.addEventListener("change", setupFlowAutorefresh);
$("#flow-show-source")?.addEventListener("change", (e) => {
  $("#flow-source")?.classList.toggle("hidden", !e.target.checked);
});
$("#flow-zoom-out")?.addEventListener("click", () => _changeFlowZoom(-0.25));
$("#flow-zoom-in")?.addEventListener("click", () => _changeFlowZoom(0.25));
$("#flow-zoom-fit")?.addEventListener("click", () => {
  _flowZoom = 1;
  _applyFlowZoom();
  $("#flow-diagram")?.scrollTo({ left: 0, top: 0 });
});
$("#flow-diagram")?.addEventListener(
  "wheel",
  (event) => {
    if (!event.ctrlKey && !event.metaKey) return;
    event.preventDefault();
    _changeFlowZoom(event.deltaY < 0 ? 0.25 : -0.25);
  },
  { passive: false },
);
$("#flow-diagram")?.addEventListener("keydown", (event) => {
  if (!event.ctrlKey && !event.metaKey) return;
  if (["+", "="].includes(event.key)) {
    event.preventDefault();
    _changeFlowZoom(0.25);
  }
  if (event.key === "-") {
    event.preventDefault();
    _changeFlowZoom(-0.25);
  }
  if (event.key === "0") {
    event.preventDefault();
    _flowZoom = 1;
    _applyFlowZoom();
  }
});
window.addEventListener("resize", debounce(_applyFlowZoom));
if (
  window.matchMedia?.("(prefers-reduced-motion: reduce)").matches &&
  $("#flow-animate")
) {
  $("#flow-animate").checked = false;
}
$("#flow-download-svg")?.addEventListener("click", () => {
  const svg = $("#flow-diagram")?.querySelector("svg");
  if (!svg) return;
  const blob = new Blob([svg.outerHTML], { type: "image/svg+xml" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download =
    "klaxond-flow-" + new Date().toISOString().split("T")[0] + ".svg";
  a.click();
  URL.revokeObjectURL(url);
});
document.querySelectorAll('[data-tab="flow"]').forEach((btn) => {
  btn.addEventListener("click", () => {
    loadFlow();
    setupFlowAutorefresh();
  });
});
document.querySelectorAll('.tab:not([data-tab="flow"])').forEach((btn) => {
  btn.addEventListener("click", () => {
    if (_flowAutorefreshTimer) {
      clearInterval(_flowAutorefreshTimer);
      _flowAutorefreshTimer = null;
    }
  });
});
