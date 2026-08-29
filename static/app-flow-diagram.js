import { tr } from "./app.js";
import { deliveryTsSeconds } from "./app-status.js";

export function aggregateDeliveries24h(items) {
  const cutoff = Date.now() / 1000 - 24 * 3600;
  const bySource = {};
  const bySeverity = {};
  const byChannel = {};
  const bySourceSeverity = {};
  for (const it of items || []) {
    const ts = deliveryTsSeconds(it);
    if (ts < cutoff) continue;
    if (it.source) bySource[it.source] = (bySource[it.source] || 0) + 1;
    if (it.severity) bySeverity[it.severity] = (bySeverity[it.severity] || 0) + 1;
    if (it.channel) byChannel[it.channel] = (byChannel[it.channel] || 0) + 1;
    const k = `${it.source}|${it.severity}`;
    bySourceSeverity[k] = (bySourceSeverity[k] || 0) + 1;
  }
  return { bySource, bySeverity, byChannel, bySourceSeverity };
}

export function buildMermaidDiagram(cfgs, stats) {
  const { channel, cascade, ntfy, dedup, auth, render } = cfgs;
  const safeStats = stats || { bySource: {}, byChannel: {}, bySeverity: {} };
  const authMode = (auth && auth.settings && auth.settings.mode) || "?";
  const cascadeOn = cascade ? (cascade.runtime_enabled !== false) : true;
  const tiers = (cascade && cascade.tiers) || [{name:"ntfy"},{name:"telegram"},{name:"smtp"}];
  const lines = [];

  appendDiagramHeader(lines);
  appendUpstream(lines);
  appendEmitters(lines, authMode, safeStats, dedup);
  appendKlaxondFlow(lines, cascadeOn);
  appendSinks(lines, channel, ntfy, tiers, safeStats);
  appendClickHandlers(lines, tiers, render);
  return lines.join("\n");
}

function mermaidEscape(s) {
  return String(s || "").replace(/"/g, "\\\"").replace(/\n/g, "<br/>");
}

function sourceStat(stats, source) {
  const n = stats.bySource[source] || 0;
  return n ? `<br/><small>${tr("flow.in_24h", { count: n })}</small>` : "";
}

function dedupStat(dedup, source) {
  const d = (dedup && dedup.settings) ? (dedup.settings[source] || {}) : {};
  if (!d.enabled) return "";
  return `<br/><small>dedup: ${d.strategy} ${d.window_s}s</small>`;
}

function channelStat(stats, chan) {
  const n = stats.byChannel[chan] || 0;
  return n ? `<br/><small>${tr("flow.delivered", { count: n })}</small>` : "";
}

function ntfyLabel(ntfy, stats) {
  let label = `ntfy${channelStat(stats, "ntfy")}`;
  if (!ntfy || !ntfy.topics || !ntfy.topics.length) return label;
  const lines = ntfy.topics.slice(0, 6).map(t => `${t.name}: ${(t.handles || []).join(", ")}`);
  if (ntfy.topics.length > 6) lines.push(`… +${ntfy.topics.length - 6} more`);
  const delivered = channelStat(stats, "ntfy")
    ? "<br/>" + tr("flow.delivered_24h", { count: stats.byChannel["ntfy"] || 0 })
    : "";
  return `ntfy<br/><small>${lines.join("<br/>")}${delivered}</small>`;
}

function appendDiagramHeader(lines) {
  lines.push("---");
  lines.push("config:");
  lines.push("  flowchart:");
  lines.push("    htmlLabels: true");
  lines.push("    curve: basis");
  lines.push("---");
  lines.push("flowchart LR");
  lines.push("  %% auto-generated from /api/* config");
  lines.push("  classDef src fill:#2c5282,color:#fff,stroke:#5b8def");
  lines.push("  classDef klx fill:#553c9a,color:#fff,stroke:#9b6bff");
  lines.push("  classDef sink fill:#22543d,color:#fff,stroke:#48bb78");
  lines.push("  classDef disabled fill:#444,color:#999,stroke:#666");
}

function appendUpstream(lines) {
  lines.push('  subgraph UPS["Upstream"]');
  lines.push(`    GRA["Grafana<br/><small>${mermaidEscape(tr("flow.alert_rules"))}</small>"]`);
  lines.push("  end");
  lines.push("  class GRA src");
}

function appendEmitters(lines, authMode, stats, dedup) {
  const emitters = [
    ["AM", "Alertmanager<br/>POST /webhook/sev<br/><small>group + inhibit + repeat</small>", "grafana"],
    ["BSZ", "Beszel<br/>POST /beszel/sev", "beszel"],
    ["HC", "Healthchecks<br/>POST /healthchecks/sev", "healthchecks"],
    ["WUD", "WUD<br/>POST /wud/sev", "wud"],
    ["AKN", "Authentik<br/>POST /authentik/sev", "authentik"],
    ["SHF", "Shelfmark<br/>POST /shelfmark/sev", "shelfmark"],
    ["PRW", "Prowlarr<br/>POST /prowlarr/sev", "prowlarr"],
    ["DCY", "Decypharr<br/>POST /decypharr/sev", "decypharr"],
  ];
  lines.push(`  subgraph SRC["Emitters → klaxond HTTP (auth: ${authMode})"]`);
  for (const [id, label, source] of emitters) {
    lines.push(`    ${id}["${label}${sourceStat(stats, source)}${dedupStat(dedup, source)}"]`);
  }
  lines.push("  end");
  lines.push("  class AM,BSZ,HC,WUD,AKN,SHF,PRW,DCY src");
  lines.push("  GRA --> AM");
}

function appendKlaxondFlow(lines, cascadeOn) {
  lines.push('  INH{"Inhibition rules<br/><small>cross-source (all emitters)</small>"}');
  lines.push('  DROP["suppress"]');
  lines.push('  RND["Render<br/>title/body/tags/actions"]');
  lines.push(`  CAS{"Cascade ${cascadeOn ? "✓ on" : "✗ off"}"}`);
  lines.push("  class INH,DROP,RND,CAS klx");
  for (const id of ["AM", "BSZ", "HC", "WUD", "AKN", "SHF", "PRW"]) {
    lines.push(`  ${id} --> INH`);
  }
  lines.push("  INH -->|matched| DROP");
  lines.push("  INH -->|pass| RND");
  lines.push("  RND --> CAS");
}

function appendSinks(lines, channel, ntfy, tiers, stats) {
  lines.push(`  NTFY["${mermaidEscape(ntfyLabel(ntfy, stats))}"]`);
  lines.push("  class NTFY sink");
  lines.push("  CAS -->|tier 1| NTFY");
  if (tiers.find(t => t.name === "telegram")) appendTelegramSink(lines, channel, stats);
  if (tiers.find(t => t.name === "smtp")) appendSmtpSink(lines, channel, stats);
}

function appendTelegramSink(lines, channel, stats) {
  const configured = !!(channel && channel.telegram && channel.telegram.chat_id);
  const cssClass = configured ? "sink" : "disabled";
  const label = configured
    ? `Telegram<br/><small>chat ${channel.telegram.chat_id}${delivered24h(stats, "telegram")}</small>`
    : `Telegram<br/><small>${mermaidEscape(tr("flow.not_configured"))}</small>`;
  lines.push(`  TG["${mermaidEscape(label)}"]`);
  lines.push(`  class TG ${cssClass}`);
  lines.push('  CAS -.->|"tier 2 on ntfy fail"| TG');
}

function appendSmtpSink(lines, channel, stats) {
  const configured = !!(channel && channel.smtp && channel.smtp.host);
  const cssClass = configured ? "sink" : "disabled";
  const label = configured
    ? `SMTP<br/><small>${channel.smtp.host}:${channel.smtp.port}${delivered24h(stats, "smtp")}</small>`
    : `SMTP<br/><small>${mermaidEscape(tr("flow.not_configured"))}</small>`;
  lines.push(`  SMTP["${mermaidEscape(label)}"]`);
  lines.push(`  class SMTP ${cssClass}`);
  lines.push('  CAS -.->|"tier 3 on tg fail"| SMTP');
}

function delivered24h(stats, channel) {
  return channelStat(stats, channel)
    ? "<br/>" + tr("flow.delivered_24h", { count: stats.byChannel[channel] || 0 })
    : "";
}

function appendClickHandlers(lines, tiers, render) {
  const grafanaBase = String((render && render.grafana_base) || "").replace(/\/$/, "");
  if (/^https?:\/\//.test(grafanaBase)) {
    lines.push(`  click GRA "${mermaidEscape(grafanaBase)}/alerting/list" _blank`);
  }
  lines.push('  click AM call flowGotoTab("inhibitions") "Inhibitions tab"');
  for (const id of ["BSZ", "HC", "WUD", "AKN", "SHF", "PRW"]) {
    lines.push(`  click ${id} call flowGotoTab("grouping") "Grouping (dedup) tab"`);
  }
  lines.push('  click INH call flowGotoTab("inhibitions") "Inhibitions tab"');
  lines.push('  click RND call flowGotoTab("render") "Render config tab"');
  lines.push('  click CAS call flowGotoTab("cascade") "Cascade tab"');
  lines.push('  click NTFY call flowGotoTab("routing") "Routing tab (ntfy topics)"');
  if (tiers.find(t => t.name === "telegram")) lines.push('  click TG call flowGotoTab("routing") "Routing tab"');
  if (tiers.find(t => t.name === "smtp")) lines.push('  click SMTP call flowGotoTab("routing") "Routing tab"');
}
