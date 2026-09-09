import { tr } from "./app.js";
import { deliveryTsSeconds } from "./app-status.js";

const SOURCE_ROUTES = {
  grafana: "/webhook/sev",
};

const SOURCE_LABELS = {
  grafana: "Alertmanager",
  "uptime-kuma": "Uptime Kuma",
  wud: "WUD",
  pve: "Proxmox VE",
};

const SINK_IDS = { ntfy: "NTFY", telegram: "TG", smtp: "SMTP" };

export function sourceNodeId(source) {
  return `SRC_${String(source || "unknown").toUpperCase().replace(/[^A-Z0-9_]/g, "_")}`;
}

export function aggregateDeliveries24h(items) {
  const cutoff = Date.now() / 1000 - 24 * 3600;
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
    if (it.severity) bySeverity[it.severity] = (bySeverity[it.severity] || 0) + 1;
    if (it.channel) {
      byChannel[it.channel] = (byChannel[it.channel] || 0) + 1;
      lastByChannel[it.channel] = Math.max(lastByChannel[it.channel] || 0, ts);
    }
    const key = `${it.source}|${it.severity}`;
    bySourceSeverity[key] = (bySourceSeverity[key] || 0) + 1;
  }
  return { bySource, bySeverity, byChannel, bySourceSeverity, lastBySource, lastByChannel };
}

export function buildMermaidDiagram(cfgs, stats) {
  const safeStats = stats || { bySource: {}, byChannel: {}, bySeverity: {} };
  const sources = configuredSources(cfgs.ingest);
  const tiers = configuredTiers(cfgs.cascade);
  const lines = [];

  appendDiagramHeader(lines);
  appendUpstream(lines, sources);
  const emitterIds = appendEmitters(lines, sources, cfgs.ingest, cfgs.auth, safeStats, cfgs.dedup);
  const stageIds = appendKlaxondFlow(lines, emitterIds, cfgs);
  const sinkIds = appendSinks(lines, stageIds[stageIds.length - 1], cfgs.channel, cfgs.ntfy, tiers, safeStats);
  appendClickHandlers(lines, sources, stageIds, sinkIds, cfgs.render);
  return lines.join("\n");
}

function configuredSources(ingest) {
  return Object.entries(ingest?.sources || {})
    .filter(([, value]) => value?.configured)
    .map(([source]) => source)
    .sort((a, b) => a.localeCompare(b));
}

function configuredTiers(cascade) {
  const tiers = Array.isArray(cascade?.tiers) ? cascade.tiers : [];
  return tiers.length ? tiers : [{ name: "ntfy", timeout_seconds: 15 }];
}

function mermaidEscape(value) {
  return String(value || "").replace(/"/g, "\\\"").replace(/\n/g, "<br/>");
}

function titleCase(value) {
  return String(value || "")
    .split(/[-_]/)
    .filter(Boolean)
    .map(part => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
}

function sourceRoute(source, ingest) {
  const configured = ingest?.sources?.[source]?.endpoint;
  return configured?.replace("{severity}", "sev") || SOURCE_ROUTES[source] || `/${source}/sev`;
}

function sourceStat(stats, source) {
  const count = stats.bySource[source] || 0;
  return count ? `<br/><small>${tr("flow.in_24h", { count })}</small>` : "";
}

function noiseStat(dedup, source) {
  const config = dedup?.settings?.[source] || {};
  const parts = [];
  if (config.enabled) parts.push(`${tr("flow.grouping_short")}: ${config.strategy} ${config.window_s}s`);
  if (config.repeat_suppression_enabled) parts.push(`${tr("flow.repeat_short")}: ${config.repeat_window_s}s`);
  return parts.length ? `<br/><small>${parts.join(" · ")}</small>` : "";
}

function channelStat(stats, channel) {
  const count = stats.byChannel[channel] || 0;
  return count ? `<br/><small>${tr("flow.delivered", { count })}</small>` : "";
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
  lines.push("  classDef disabled fill:#444,color:#bbb,stroke:#777");
}

function appendUpstream(lines, sources) {
  if (!sources.includes("grafana")) return;
  lines.push('  subgraph UPS["Upstream"]');
  lines.push(`    GRA["Grafana<br/><small>${mermaidEscape(tr("flow.alert_rules"))}</small>"]`);
  lines.push("  end");
  lines.push("  class GRA src");
}

function appendEmitters(lines, sources, ingest, auth, stats, dedup) {
  const authMode = auth?.settings?.mode || "?";
  lines.push(`  subgraph SRC["${mermaidEscape(tr("flow.enabled_emitters", { count: sources.length, mode: authMode }))}"]`);
  if (!sources.length) {
    lines.push(`    SRC_NONE["${mermaidEscape(tr("flow.no_enabled_sources"))}"]`);
    lines.push("    class SRC_NONE disabled");
    lines.push("  end");
    return ["SRC_NONE"];
  }
  const ids = [];
  for (const source of sources) {
    const id = sourceNodeId(source);
    const label = ingest?.sources?.[source]?.display_name || SOURCE_LABELS[source] || titleCase(source);
    const route = mermaidEscape(sourceRoute(source, ingest));
    lines.push(`    ${id}["${mermaidEscape(label)}<br/><small>POST ${route}</small>${sourceStat(stats, source)}${noiseStat(dedup, source)}"]`);
    ids.push(id);
  }
  lines.push("  end");
  lines.push(`  class ${ids.join(",")} src`);
  if (sources.includes("grafana")) lines.push(`  GRA --> ${sourceNodeId("grafana")}`);
  return ids;
}

function enabledNoiseSources(dedup, field) {
  return Object.entries(dedup?.settings || {})
    .filter(([, config]) => !!config?.[field])
    .map(([source]) => source);
}

function appendKlaxondFlow(lines, emitters, cfgs) {
  const stages = [];
  const rules = cfgs.inhibition?.rules || [];
  const grouped = enabledNoiseSources(cfgs.dedup, "enabled");
  const repeated = enabledNoiseSources(cfgs.dedup, "repeat_suppression_enabled");

  if (rules.length) {
    lines.push(`  INH{"${mermaidEscape(tr("flow.inhibition_stage", { count: rules.length }))}"}`);
    lines.push(`  DROP["${mermaidEscape(tr("flow.suppressed"))}"]`);
    lines.push("  class INH,DROP klx");
    lines.push(`  INH -->|${mermaidEscape(tr("flow.matched"))}| DROP`);
    stages.push("INH");
  }
  if (grouped.length) {
    lines.push(`  GROUP["${mermaidEscape(tr("flow.grouping_stage", { count: grouped.length }))}"]`);
    lines.push("  class GROUP klx");
    stages.push("GROUP");
  }
  if (repeated.length) {
    lines.push(`  REPEAT{"${mermaidEscape(tr("flow.repeat_stage", { count: repeated.length }))}"}`);
    lines.push(`  REPEAT_DROP["${mermaidEscape(tr("flow.repeat_suppressed"))}"]`);
    lines.push("  class REPEAT,REPEAT_DROP klx");
    lines.push(`  REPEAT -->|${mermaidEscape(tr("flow.duplicate"))}| REPEAT_DROP`);
    stages.push("REPEAT");
  }
  if (cfgs.emergency?.settings?.enabled) {
    const profileCount = (cfgs.emergency.settings.profiles || []).filter(profile => profile.enabled).length;
    lines.push(`  EMERGENCY{"${mermaidEscape(tr("flow.emergency_stage", { count: profileCount }))}"}`);
    lines.push("  class EMERGENCY klx");
    stages.push("EMERGENCY");
  }
  lines.push(`  RND["${mermaidEscape(tr("flow.render_stage"))}<br/><small>title · body · tags · actions</small>"]`);
  lines.push(`  CAS{"${mermaidEscape(tr(cfgs.cascade?.runtime_enabled === false ? "flow.cascade_off" : "flow.cascade_on"))}"}`);
  lines.push("  class RND,CAS klx");
  stages.push("RND", "CAS");

  for (const emitter of emitters) lines.push(`  ${emitter} --> ${stages[0]}`);
  for (let index = 0; index < stages.length - 1; index += 1) {
    const from = stages[index];
    const to = stages[index + 1];
    const edge = from === "INH" ? `|${mermaidEscape(tr("flow.pass"))}| ` : "";
    lines.push(`  ${from} -->${edge}${to}`);
  }
  return stages;
}

function appendSinks(lines, cascadeId, channel, ntfy, tiers, stats) {
  const sinkIds = [];
  tiers.forEach((tier, index) => {
    const name = String(tier.name || "").toLowerCase();
    const id = SINK_IDS[name] || `SINK_${index}`;
    const configured = sinkConfigured(name, channel, ntfy);
    lines.push(`  ${id}["${mermaidEscape(sinkLabel(name, channel, ntfy, stats))}"]`);
    lines.push(`  class ${id} ${configured ? "sink" : "disabled"}`);
    if (index === 0) lines.push(`  ${cascadeId} -->|${mermaidEscape(tr("flow.tier", { count: 1 }))}| ${id}`);
    else lines.push(`  ${cascadeId} -.->|${mermaidEscape(tr("flow.fallback_tier", { count: index + 1 }))}| ${id}`);
    sinkIds.push([id, name]);
  });
  return sinkIds;
}

function sinkConfigured(name, channel, ntfy) {
  if (name === "ntfy") return !!ntfy?.topics?.length;
  if (name === "telegram") return !!channel?.telegram?.chat_id;
  if (name === "smtp") return !!channel?.smtp?.host;
  return true;
}

function sinkLabel(name, channel, ntfy, stats) {
  if (name === "ntfy") {
    const topics = (ntfy?.topics || []).slice(0, 4).map(topic => topic.name).join(", ");
    return `ntfy${topics ? `<br/><small>${topics}</small>` : ""}${channelStat(stats, name)}`;
  }
  if (name === "telegram") {
    const detail = channel?.telegram?.chat_id ? tr("flow.configured") : tr("flow.not_configured");
    return `Telegram<br/><small>${detail}</small>${channelStat(stats, name)}`;
  }
  if (name === "smtp") {
    const detail = channel?.smtp?.host ? `${channel.smtp.host}:${channel.smtp.port}` : tr("flow.not_configured");
    return `SMTP<br/><small>${detail}</small>${channelStat(stats, name)}`;
  }
  return `${titleCase(name)}${channelStat(stats, name)}`;
}

function appendClickHandlers(lines, sources, stages, sinks, render) {
  const grafanaBase = String(render?.grafana_base || "").replace(/\/$/, "");
  if (sources.includes("grafana") && /^https?:\/\//.test(grafanaBase)) {
    lines.push(`  click GRA "${mermaidEscape(grafanaBase)}/alerting/list" _blank`);
  }
  for (const source of sources) {
    lines.push(`  click ${sourceNodeId(source)} call flowGotoTab("grouping") "${mermaidEscape(tr("tab.grouping"))}"`);
  }
  if (stages.includes("INH")) lines.push(`  click INH call flowGotoTab("inhibitions") "${mermaidEscape(tr("tab.inhibitions"))}"`);
  if (stages.includes("GROUP")) lines.push(`  click GROUP call flowGotoTab("grouping") "${mermaidEscape(tr("tab.grouping"))}"`);
  if (stages.includes("REPEAT")) lines.push(`  click REPEAT call flowGotoTab("grouping") "${mermaidEscape(tr("tab.grouping"))}"`);
  if (stages.includes("EMERGENCY")) lines.push(`  click EMERGENCY call flowGotoTab("emergencies") "${mermaidEscape(tr("tab.emergencies"))}"`);
  lines.push(`  click RND call flowGotoTab("render") "${mermaidEscape(tr("tab.render"))}"`);
  lines.push(`  click CAS call flowGotoTab("cascade") "${mermaidEscape(tr("tab.cascade"))}"`);
  for (const [id] of sinks) lines.push(`  click ${id} call flowGotoTab("routing") "${mermaidEscape(tr("tab.routing"))}"`);
}
