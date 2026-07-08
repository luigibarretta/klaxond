import {
  $, $$, APP_META, J, SEARCH_DEBOUNCE_MS, apiFetch, applyTablePager, debounce, errorText,
  escapeHtml, fetchError, fetchOk, getAuthPasswordPolicy, getCurrentUser, isAbortError, isPublicInfoPage,
  markTabDirty, navigateToTab, notifyError, notifyResponseError, notifySuccess, notifyValidationError, onReady,
  queryGet, refreshTablePagers, setAuthPasswordPolicy, setInlineStatus, setLocalTotpEnabled,
  showTableRowPage, syncTabFromPath, tr, updateAllTabAccessibleLabels, updatePublicLoginLinksText,
} from "./app.js";
import { deliveryTsSeconds, fetchDeliveries } from "./app-status.js";

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

function _aggregateDeliveries24h(items) {
  // Items from /api/deliveries can be legacy array rows or paginated entries.
  // Each row uses ts(seconds); older browser-only helpers may use timestamp(ms).
  const cutoff = Date.now() / 1000 - 24 * 3600;
  const bySource = {};       // source → count
  const bySeverity = {};     // severity → count
  const byChannel = {};      // channel → count
  const bySourceSeverity = {}; // "source|severity" → count
  for (const it of items || []) {
    const ts = deliveryTsSeconds(it);
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
    return n ? `<br/><small>${tr("flow.in_24h", { count: n })}</small>` : "";
  };
  const dedupStat = (source) => {
    const d = (dedup && dedup.settings) ? (dedup.settings[source] || {}) : {};
    if (!d.enabled) return "";
    return `<br/><small>dedup: ${d.strategy} ${d.window_s}s</small>`;
  };
  const chStat = (chan) => {
    const n = s.byChannel[chan] || 0;
    return n ? `<br/><small>${tr("flow.delivered", { count: n })}</small>` : "";
  };

  // ntfy topics — group as one collapsed sub-node or list inline
  let ntfyLabel = `ntfy${chStat("ntfy")}`;
  if (ntfy && ntfy.topics && ntfy.topics.length) {
    const lines = ntfy.topics.slice(0, 6).map(t =>
      `${t.name}: ${(t.handles || []).join(", ")}`);
    if (ntfy.topics.length > 6) lines.push(`… +${ntfy.topics.length - 6} more`);
    ntfyLabel = `ntfy<br/><small>${lines.join("<br/>")}${chStat("ntfy") ? "<br/>" + tr("flow.delivered_24h", { count: s.byChannel["ntfy"] || 0 }) : ""}</small>`;
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
  lines.push(`    GRA["Grafana<br/><small>${_mermaidEscape(tr("flow.alert_rules"))}</small>"]`);
  lines.push("  end");
  lines.push("  class GRA src");

  lines.push(`  subgraph SRC["Emitters → klaxond HTTP (auth: ${authMode})"]`);
  lines.push(`    AM["Alertmanager<br/>POST /webhook/sev<br/><small>group + inhibit + repeat</small>${srcStat("grafana")}${dedupStat("grafana")}"]`);
  lines.push(`    BSZ["Beszel<br/>POST /beszel/sev${srcStat("beszel")}${dedupStat("beszel")}"]`);
  lines.push(`    HC["Healthchecks<br/>POST /healthchecks/sev${srcStat("healthchecks")}${dedupStat("healthchecks")}"]`);
  lines.push(`    WUD["WUD<br/>POST /wud/sev${srcStat("wud")}${dedupStat("wud")}"]`);
  lines.push(`    AKN["Authentik<br/>POST /authentik/sev${srcStat("authentik")}${dedupStat("authentik")}"]`);
  lines.push(`    SHF["Shelfmark<br/>POST /shelfmark/sev${srcStat("shelfmark")}${dedupStat("shelfmark")}"]`);
  lines.push(`    PRW["Prowlarr<br/>POST /prowlarr/sev${srcStat("prowlarr")}${dedupStat("prowlarr")}"]`);
  lines.push(`    DCY["Decypharr<br/>POST /decypharr/sev${srcStat("decypharr")}${dedupStat("decypharr")}"]`);
  lines.push("  end");

  lines.push("  class AM,BSZ,HC,WUD,AKN,SHF,PRW,DCY src");

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
  lines.push("  SHF --> INH");
  lines.push("  PRW --> INH");
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
      ? `Telegram<br/><small>chat ${channel.telegram.chat_id}${chStat("telegram") ? "<br/>" + tr("flow.delivered_24h", { count: s.byChannel["telegram"] || 0 }) : ""}</small>`
      : `Telegram<br/><small>${_mermaidEscape(tr("flow.not_configured"))}</small>`;
    lines.push(`  TG["${_mermaidEscape(tgLabel)}"]`);
    lines.push(`  class TG ${tgClass}`);
    lines.push(`  CAS -.->|"tier 2 on ntfy fail"| TG`);
  }

  // SMTP
  if (tiers.find(t => t.name === "smtp")) {
    const smClass = smtpConfigured ? "sink" : "disabled";
    const smLabel = smtpConfigured
      ? `SMTP<br/><small>${channel.smtp.host}:${channel.smtp.port}${chStat("smtp") ? "<br/>" + tr("flow.delivered_24h", { count: s.byChannel["smtp"] || 0 }) : ""}</small>`
      : `SMTP<br/><small>${_mermaidEscape(tr("flow.not_configured"))}</small>`;
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
  lines.push(`  click SHF call flowGotoTab("grouping") "Grouping (dedup) tab"`);
  lines.push(`  click PRW call flowGotoTab("grouping") "Grouping (dedup) tab"`);
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
    const [channel, cascade, ntfy, dedup, auth, deliveries] = await Promise.all([
      queryGet("flow-channel-config", "/api/channel-config", { cancelPrevious: false }),
      queryGet("flow-cascade-config", "/api/cascade-config", { cancelPrevious: false }),
      queryGet("flow-ntfy-topics", "/api/ntfy-topics", { cancelPrevious: false }),
      queryGet("flow-dedup-config", "/api/dedup-config", { cancelPrevious: false }),
      J("/api/auth/config"),
      fetchDeliveries(10000, { scope: "flow-deliveries" }),
    ]);
    cfgs = { channel, cascade, ntfy, dedup, auth };
    stats = _aggregateDeliveries24h(deliveries);
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
    const stats = _aggregateDeliveries24h(deliveries);
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
