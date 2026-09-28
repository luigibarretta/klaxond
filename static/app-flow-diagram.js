import {
  appendKlaxondFlow,
  appendDeliveryPolicies,
  enabledNoiseSources as enabledNoiseSourcesForDiagram,
  sinkConfigured,
} from "./app-flow-diagram-delivery.js";
export { enabledNoiseSourcesForDiagram as enabledNoiseSources, sinkConfigured };
import { tr } from "./app.js";
import { deliveryTsSeconds } from "./app-status.js";
import {
  cascadeFallbackAudience,
  configuredDeliveryPolicies,
} from "./app-flow-policy-model.js";
const SOURCE_ROUTES = { grafana: "/webhook/sev" };
const SOURCE_LABELS = {
  grafana: "Alertmanager",
  "uptime-kuma": "Uptime Kuma",
  wud: "WUD",
  pve: "Proxmox VE",
};
const SINK_IDS = { ntfy: "NTFY", telegram: "TG", smtp: "SMTP" };
export function sourceNodeId(source) {
  return `SRC_${String(source || "unknown")
    .toUpperCase()
    .replace(/[^A-Z0-9_]/g, "_")}`;
}
export function aggregateDeliveries24h(items) {
  const cutoff = Date.now() / 1e3 - 24 * 3600;
  const bySource = {};
  const bySeverity = {};
  const byChannel = {};
  const bySourceSeverity = {};
  const lastBySource = {};
  const lastByChannel = {};
  for (const it of items || []) {
    const ts = deliveryTsSeconds(it);
    if (ts < cutoff) continue;
    if (it.source) {
      bySource[it.source] = (bySource[it.source] || 0) + 1;
      lastBySource[it.source] = Math.max(lastBySource[it.source] || 0, ts);
    }
    if (it.severity)
      bySeverity[it.severity] = (bySeverity[it.severity] || 0) + 1;
    if (it.channel) {
      byChannel[it.channel] = (byChannel[it.channel] || 0) + 1;
      lastByChannel[it.channel] = Math.max(lastByChannel[it.channel] || 0, ts);
    }
    const key = `${it.source}|${it.severity}`;
    bySourceSeverity[key] = (bySourceSeverity[key] || 0) + 1;
  }
  return {
    bySource: bySource,
    bySeverity: bySeverity,
    byChannel: byChannel,
    bySourceSeverity: bySourceSeverity,
    lastBySource: lastBySource,
    lastByChannel: lastByChannel,
  };
}
export function buildMermaidDiagram(cfgs, stats) {
  const safeStats = stats || { bySource: {}, byChannel: {}, bySeverity: {} };
  const sources = configuredSources(cfgs.ingest);
  const lines = [];
  appendDiagramHeader(lines);
  appendUpstream(lines, sources);
  const emitterIds = appendEmitters(
    lines,
    sources,
    cfgs.ingest,
    cfgs.auth,
    safeStats,
    cfgs.dedup,
  );
  const flow = appendKlaxondFlow(lines, emitterIds, cfgs);
  const delivery = appendDeliveryPolicies(
    lines,
    flow.policyNode,
    cfgs,
    safeStats,
  );
  appendClickHandlers(lines, sources, flow.clickableIds, delivery, cfgs.render);
  return lines.join("\n");
}
export function configuredSources(ingest) {
  return Object.entries(ingest?.sources || {})
    .filter(([, value]) => value?.configured)
    .map(([source]) => source)
    .sort((a, b) => a.localeCompare(b));
}
function mermaidEscape(value) {
  return String(value || "")
    .replace(/"/g, '\\"')
    .replace(/\n/g, "<br/>");
}
function titleCase(value) {
  return String(value || "")
    .split(/[-_]/)
    .filter(Boolean)
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
}
export function channelDisplayName(value) {
  const name = String(value || "").toLowerCase();
  return (
    { ntfy: "ntfy", telegram: "Telegram", smtp: "SMTP" }[name] ||
    titleCase(name)
  );
}
export function sourceRoute(source, ingest) {
  const configured = ingest?.sources?.[source]?.endpoint;
  return (
    configured?.replace("{severity}", "sev") ||
    SOURCE_ROUTES[source] ||
    `/${source}/sev`
  );
}
export function sourceDisplayName(source, ingest) {
  return (
    ingest?.sources?.[source]?.display_name ||
    SOURCE_LABELS[source] ||
    titleCase(source)
  );
}
function sourceStat(stats, source) {
  const count = stats.bySource[source] || 0;
  return count
    ? `<br/><small>${tr("flow.in_24h", { count: count })}</small>`
    : "";
}
function noiseStat(dedup, source) {
  const config = dedup?.settings?.[source] || {};
  const parts = [];
  if (config.enabled)
    parts.push(
      `${tr("flow.grouping_short")}: ${config.strategy} ${config.window_s}s`,
    );
  if (config.repeat_suppression_enabled)
    parts.push(`${tr("flow.repeat_short")}: ${config.repeat_window_s}s`);
  return parts.length ? `<br/><small>${parts.join(" · ")}</small>` : "";
}
function channelStat(stats, channel) {
  const count = stats.byChannel[channel] || 0;
  return count
    ? `<br/><small>${tr("flow.delivered", { count: count })}</small>`
    : "";
}
function appendDiagramHeader(lines) {
  lines.push("---");
  lines.push("config:");
  lines.push("  flowchart:");
  lines.push("    htmlLabels: true");
  lines.push("    curve: basis");
  lines.push("---");
  lines.push("flowchart LR");
  lines.push("  %% generated from the active /api configuration");
  lines.push("  classDef src fill:#2c5282,color:#fff,stroke:#5b8def");
  lines.push("  classDef klx fill:#553c9a,color:#fff,stroke:#9b6bff");
  lines.push("  classDef sink fill:#22543d,color:#fff,stroke:#48bb78");
  lines.push("  classDef inactive fill:#5c481f,color:#fff,stroke:#d69e2e");
  lines.push("  classDef disabled fill:#444,color:#bbb,stroke:#777");
}
function appendUpstream(lines, sources) {
  if (!sources.includes("grafana")) return;
  lines.push('  subgraph UPS["Upstream"]');
  lines.push(
    `    GRA["Grafana<br/><small>${mermaidEscape(tr("flow.alert_rules"))}</small>"]`,
  );
  lines.push("  end");
  lines.push("  class GRA src");
}
function appendEmitters(lines, sources, ingest, auth, stats, dedup) {
  const authMode = auth?.settings?.mode || "?";
  lines.push(
    `  subgraph SRC["${mermaidEscape(tr("flow.enabled_emitters", { count: sources.length, mode: authMode }))}"]`,
  );
  if (!sources.length) {
    lines.push(
      `    SRC_NONE["${mermaidEscape(tr("flow.no_enabled_sources"))}"]`,
    );
    lines.push("    class SRC_NONE disabled");
    lines.push("  end");
    return ["SRC_NONE"];
  }
  const ids = [];
  for (const source of sources) {
    const id = sourceNodeId(source);
    const label = sourceDisplayName(source, ingest);
    const route = mermaidEscape(sourceRoute(source, ingest));
    lines.push(
      `    ${id}["${mermaidEscape(label)}<br/><small>POST ${route}</small>${sourceStat(stats, source)}${noiseStat(dedup, source)}"]`,
    );
    ids.push(id);
  }
  lines.push("  end");
  lines.push(`  class ${ids.join(",")} src`);
  if (sources.includes("grafana"))
    lines.push(`  GRA --\x3e ${sourceNodeId("grafana")}`);
  return ids;
}
function appendClickHandlers(lines, sources, clickableIds, delivery, render) {
  const grafanaBase = String(render?.grafana_base || "").replace(/\/$/, "");
  if (sources.includes("grafana") && /^https?:\/\//.test(grafanaBase)) {
    lines.push(
      `  click GRA "${mermaidEscape(grafanaBase)}/alerting/list" _blank`,
    );
  }
  for (const source of sources) {
    lines.push(
      `  click ${sourceNodeId(source)} call flowGotoTab("grouping") "${mermaidEscape(tr("tab.grouping"))}"`,
    );
  }
  if (clickableIds.includes("INH"))
    lines.push(
      `  click INH call flowGotoTab("inhibitions") "${mermaidEscape(tr("tab.inhibitions"))}"`,
    );
  if (clickableIds.includes("GROUP"))
    lines.push(
      `  click GROUP call flowGotoTab("grouping") "${mermaidEscape(tr("tab.grouping"))}"`,
    );
  if (clickableIds.includes("REPEAT"))
    lines.push(
      `  click REPEAT call flowGotoTab("grouping") "${mermaidEscape(tr("tab.grouping"))}"`,
    );
  if (clickableIds.includes("EMERGENCY"))
    lines.push(
      `  click EMERGENCY call flowGotoTab("emergencies") "${mermaidEscape(tr("tab.emergencies"))}"`,
    );
  if (clickableIds.includes("EMERGENCY_PATH"))
    lines.push(
      `  click EMERGENCY_PATH call flowGotoTab("emergencies") "${mermaidEscape(tr("tab.emergencies"))}"`,
    );
  lines.push(
    `  click RND call flowGotoTab("render") "${mermaidEscape(tr("tab.render"))}"`,
  );
  lines.push(
    `  click POLICY call flowGotoTab("delivery") "${mermaidEscape(tr("tab.delivery"))}"`,
  );
  for (const id of delivery.policyIds)
    lines.push(
      `  click ${id} call flowGotoTab("delivery") "${mermaidEscape(tr("tab.delivery"))}"`,
    );
  for (const [id] of delivery.sinkIds)
    lines.push(
      `  click ${id} call flowGotoTab("routing") "${mermaidEscape(tr("tab.routing"))}"`,
    );
}
