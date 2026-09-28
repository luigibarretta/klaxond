import { tr } from "./app.js";
import {
  cascadeFallbackAudience,
  configuredDeliveryPolicies,
} from "./app-flow-policy-model.js";
const SINK_IDS = { ntfy: "NTFY", telegram: "TG", smtp: "SMTP" };
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
function channelDisplayName(value) {
  const name = String(value || "").toLowerCase();
  return { ntfy: "ntfy", telegram: "Telegram", smtp: "SMTP" }[name] || titleCase(name);
}
function configuredSources(ingest) {
  return Object.entries(ingest?.sources || {})
    .filter(([, value]) => value?.configured)
    .map(([source]) => source)
    .sort((a, b) => a.localeCompare(b));
}
function channelStat(stats, channel) {
  const count = stats?.byChannel?.[channel] || 0;
  return count ? `<br/><small>${tr("flow.channel_count", { count })}</small>` : "";
}
export function enabledNoiseSources(dedup, field) {
  return Object.entries(dedup?.settings || {})
    .filter(([, config]) => !!config?.[field])
    .map(([source]) => source);
}
function connectFlowNode(context, node, label = "") {
  const edge = label ? `|${mermaidEscape(label)}| ` : "";
  for (const from of context.frontier) {
    context.lines.push(`  ${from} --\x3e${edge}${node}`);
  }
  context.frontier = [node];
}

function appendInhibitionStage(context, rules) {
  if (!rules.length) return;
  context.lines.push(
    `  INH{"${mermaidEscape(tr("flow.inhibition_stage", { count: rules.length }))}"}`,
    `  DROP["${mermaidEscape(tr("flow.suppressed"))}"]`,
    "  class INH,DROP klx",
    `  INH --\x3e|${mermaidEscape(tr("flow.matched"))}| DROP`,
  );
  connectFlowNode(context, "INH");
  context.clickableIds.push("INH");
}

function appendGroupingStage(context, grouped, rules) {
  if (!grouped.length) return;
  context.lines.push(
    `  GROUP["${mermaidEscape(tr("flow.grouping_stage", { count: grouped.length }))}"]`,
    "  class GROUP klx",
  );
  connectFlowNode(context, "GROUP", rules.length ? tr("flow.pass") : "");
  context.clickableIds.push("GROUP");
}

function appendEmergencyStage(context, cfgs) {
  if (!cfgs.emergency?.settings?.enabled) return;
  const profileCount = (cfgs.emergency.settings.profiles || []).filter(
    (profile) => profile.enabled,
  ).length;
  context.lines.push(
    `  EMERGENCY{"${mermaidEscape(tr("flow.emergency_stage", { count: profileCount }))}"}`,
    `  EMERGENCY_PATH["${mermaidEscape(tr("flow.emergency_managed_path"))}"]`,
    "  class EMERGENCY,EMERGENCY_PATH klx",
  );
  connectFlowNode(context, "EMERGENCY");
  context.lines.push(
    `  EMERGENCY -.->|${mermaidEscape(tr("flow.managed"))}| EMERGENCY_PATH`,
  );
  context.clickableIds.push("EMERGENCY", "EMERGENCY_PATH");
}

function appendRepeatStage(context, repeated, cfgs) {
  if (!repeated.length) return;
  context.lines.push(
    `  REPEAT{"${mermaidEscape(tr("flow.repeat_stage", { count: repeated.length }))}"}`,
    `  REPEAT_DROP["${mermaidEscape(tr("flow.repeat_suppressed"))}"]`,
    "  class REPEAT,REPEAT_DROP klx",
  );
  connectFlowNode(
    context,
    "REPEAT",
    cfgs.emergency?.settings?.enabled ? tr("flow.normal") : "",
  );
  context.lines.push(
    `  REPEAT --\x3e|${mermaidEscape(tr("flow.duplicate"))}| REPEAT_DROP`,
  );
  context.clickableIds.push("REPEAT");
}

function appendRenderStage(context, cfgs, repeated) {
  context.lines.push(
    `  RND["${mermaidEscape(tr("flow.render_stage"))}<br/><small>title · body · tags · actions</small>"]`,
  );
  const model = configuredDeliveryPolicies(cfgs.delivery, cfgs.cascade);
  context.lines.push(
    `  POLICY{"${mermaidEscape(tr("flow.policy_stage", { policy: model.effectiveDefault, count: model.rules.length }))}"}`,
    "  class RND,POLICY klx",
  );
  connectFlowNode(
    context,
    "RND",
    cfgs.emergency?.settings?.enabled && !repeated.length
      ? tr("flow.normal")
      : "",
  );
  context.lines.push("  RND --\x3e POLICY");
  context.clickableIds.push("RND", "POLICY");
}

export function appendKlaxondFlow(lines, emitters, cfgs) {
  const context = { lines: lines, frontier: emitters, clickableIds: [] };
  const rules = cfgs.inhibition?.rules || [];
  const grouped = enabledNoiseSources(cfgs.dedup, "enabled");
  const repeated = enabledNoiseSources(cfgs.dedup, "repeat_suppression_enabled");
  appendInhibitionStage(context, rules);
  appendGroupingStage(context, grouped, rules);
  appendEmergencyStage(context, cfgs);
  appendRepeatStage(context, repeated, cfgs);
  appendRenderStage(context, cfgs, repeated);
  return { policyNode: "POLICY", clickableIds: context.clickableIds };
}
export function appendDeliveryPolicies(lines, selectorId, cfgs, stats) {
  const model = configuredDeliveryPolicies(cfgs.delivery, cfgs.cascade);
  const fallbackAudience = cascadeFallbackAudience(
    cfgs.cascade,
    configuredSources(cfgs.ingest),
  );
  const policyIds = [];
  const sinkIds = [];
  for (const policy of model.policies.filter((item) => item.reachable)) {
    const id = policy.nodeId;
    const detail = `${policy.mode} · ${policy.tiers.map((tier) => channelDisplayName(tier.name)).join(" + ") || tr("flow.not_configured")}`;
    lines.push(
      `  ${id}["${mermaidEscape(policy.name)}<br/><small>${mermaidEscape(detail)}</small>"]`,
    );
    lines.push(`  class ${id} klx`);
    const selectedBy = policy.isDefault
      ? tr("flow.default_policy")
      : tr("flow.rules", { rules: policy.ruleIndexes.join(", ") });
    lines.push(`  ${selectorId} --\x3e|${mermaidEscape(selectedBy)}| ${id}`);
    policyIds.push(id);
    policy.tiers.forEach((tier, index) => {
      const name = String(tier.name || "").toLowerCase();
      const sinkId = `${id}_${SINK_IDS[name] || `SINK_${index}`}`;
      const configured = sinkConfigured(name, cfgs.channel, cfgs.ntfy);
      const inactiveFallback =
        policy.mode === "cascade" && index > 0 && fallbackAudience === "none";
      lines.push(
        `  ${sinkId}["${mermaidEscape(sinkLabel(name, cfgs.channel, cfgs.ntfy, stats))}"]`,
      );
      lines.push(
        `  class ${sinkId} ${!configured ? "disabled" : inactiveFallback ? "inactive" : "sink"}`,
      );
      const edgeKey =
        policy.mode === "broadcast"
          ? "flow.broadcast_tier"
          : index === 0
            ? "flow.tier"
            : "flow.fallback_tier";
      const edge = policy.mode === "cascade" && index > 0 ? "-.->" : "--\x3e";
      let edgeLabel = tr(edgeKey, { count: index + 1 });
      if (
        policy.mode === "cascade" &&
        index > 0 &&
        fallbackAudience !== "all"
      ) {
        edgeLabel += ` · ${tr(fallbackAudience === "none" ? "flow.fallback_inactive_grafana" : "flow.fallback_non_grafana")}`;
      }
      lines.push(`  ${id} ${edge}|${mermaidEscape(edgeLabel)}| ${sinkId}`);
      sinkIds.push([sinkId, name]);
    });
  }
  return { policyIds: policyIds, sinkIds: sinkIds };
}
export function sinkConfigured(name, channel, ntfy) {
  if (name === "ntfy") return !!ntfy?.topics?.length;
  if (name === "telegram") return !!channel?.telegram?.chat_id;
  if (name === "smtp") return !!channel?.smtp?.host;
  return true;
}
function sinkLabel(name, channel, ntfy, stats) {
  if (name === "ntfy") {
    const topics = (ntfy?.topics || [])
      .slice(0, 4)
      .map((topic) => topic.name)
      .join(", ");
    return `ntfy${topics ? `<br/><small>${topics}</small>` : ""}${channelStat(stats, name)}`;
  }
  if (name === "telegram") {
    const detail = channel?.telegram?.chat_id
      ? tr("flow.configured")
      : tr("flow.not_configured");
    return `Telegram<br/><small>${detail}</small>${channelStat(stats, name)}`;
  }
  if (name === "smtp") {
    const detail = channel?.smtp?.host
      ? `${channel.smtp.host}:${channel.smtp.port}`
      : tr("flow.not_configured");
    return `SMTP<br/><small>${detail}</small>${channelStat(stats, name)}`;
  }
  return `${titleCase(name)}${channelStat(stats, name)}`;
}
