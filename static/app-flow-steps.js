import { tr } from "./app.js";
import {
  channelDisplayName, configuredSources, enabledNoiseSources, sinkConfigured,
  sourceDisplayName, sourceRoute,
} from "./app-flow-diagram.js";
import { cascadeFallbackAudience, configuredDeliveryPolicies } from "./app-flow-policy-model.js";

function sourceStep(cfgs, stats) {
  const sources = configuredSources(cfgs.ingest);
  const details = sources.map(source => (
    `${sourceDisplayName(source, cfgs.ingest)} · POST ${sourceRoute(source, cfgs.ingest)}`
  ));
  const events = sources.reduce((total, source) => total + Number(stats?.bySource?.[source] || 0), 0);
  return {
    id: "sources",
    kind: "source",
    title: tr("flow.structure_sources", { count: sources.length }),
    detail: details.join(" · ") || tr("flow.no_enabled_sources"),
    meta: stats
      ? tr("flow.structure_events", { count: events })
      : tr("flow.structure_stats_unavailable"),
    href: "/routing",
  };
}

function appendProcessingSteps(steps, cfgs) {
  const rules = cfgs.inhibition?.rules || [];
  const grouped = enabledNoiseSources(cfgs.dedup, "enabled");
  const repeated = enabledNoiseSources(cfgs.dedup, "repeat_suppression_enabled");
  const profiles = (cfgs.emergency?.settings?.profiles || []).filter(profile => profile.enabled);
  if (rules.length) {
    steps.push({ id: "inhibition", kind: "policy", title: tr("flow.structure_inhibition"),
      detail: tr("flow.structure_inhibition_detail", { count: rules.length }), href: "/inhibitions" });
  }
  if (grouped.length) {
    steps.push({ id: "grouping", kind: "policy", title: tr("flow.structure_grouping"),
      detail: tr("flow.structure_sources_detail", { sources: grouped.join(", ") }), href: "/grouping" });
  }
  if (cfgs.emergency?.settings?.enabled) {
    steps.push({ id: "emergency", kind: "branch", marker: "↳", title: tr("flow.structure_emergency"),
      detail: tr("flow.structure_emergency_detail", { count: profiles.length }),
      meta: tr("flow.structure_emergency_bypass"), href: "/emergencies" });
  }
  if (repeated.length) {
    steps.push({ id: "repeat", kind: "policy", title: tr("flow.structure_repeat"),
      detail: tr("flow.structure_sources_detail", { sources: repeated.join(", ") }),
      meta: cfgs.emergency?.settings?.enabled ? tr("flow.structure_normal_only") : "", href: "/grouping" });
  }
  steps.push({ id: "render", kind: "render", title: tr("flow.structure_render"),
    detail: tr("flow.structure_render_detail"), href: "/render" });
}

function policyDetail(policy) {
  const channels = policy.tiers.length
    ? policy.tiers.map(tier => channelDisplayName(tier.name)).join(" → ")
    : tr("flow.structure_no_tiers");
  return tr(policy.mode === "broadcast" ? "flow.structure_policy_broadcast" : "flow.structure_policy_cascade", {
    channels,
  });
}

function policyReadiness(policy, cfgs, fallbackAudience) {
  const reachableTiers = policy.mode === "cascade" && fallbackAudience === "none"
    ? policy.tiers.slice(0, 1)
    : policy.tiers;
  const missing = reachableTiers
    .map(tier => String(tier.name || "").toLowerCase())
    .filter(channel => !sinkConfigured(channel, cfgs.channel, cfgs.ntfy));
  return missing.length
    ? tr("flow.structure_policy_missing", { channels: missing.map(channelDisplayName).join(", ") })
    : tr("flow.structure_policy_ready");
}

function appendDeliverySteps(steps, cfgs) {
  const model = configuredDeliveryPolicies(cfgs.delivery, cfgs.cascade);
  const fallbackAudience = cascadeFallbackAudience(cfgs.cascade, configuredSources(cfgs.ingest));
  steps.push({
    id: "policy-selector",
    kind: "policy",
    title: tr("flow.structure_policy_selector"),
    detail: tr("flow.structure_policy_selector_detail", {
      policy: model.effectiveDefault,
      count: model.rules.length,
    }),
    href: "/delivery",
  });
  model.policies.forEach(policy => {
    const fallbackNote = policy.mode !== "cascade" || policy.tiers.length < 2 || fallbackAudience === "all"
      ? ""
      : tr(fallbackAudience === "none"
        ? "flow.structure_fallback_inactive"
        : "flow.structure_fallback_non_grafana");
    const refs = policy.ruleIndexes.length
      ? tr("flow.structure_policy_rules", { rules: policy.ruleIndexes.join(", ") })
      : policy.isDefault
        ? tr("flow.structure_policy_default_meta")
        : tr("flow.structure_policy_unused");
    steps.push({
      id: `policy-${policy.index}`,
      kind: "delivery",
      marker: "↳",
      title: tr(policy.isDefault ? "flow.structure_policy_default" : "flow.structure_policy_named", {
        name: policy.name,
      }),
      detail: policyDetail(policy),
      meta: [refs, policyReadiness(policy, cfgs, fallbackAudience), fallbackNote].filter(Boolean).join(" · "),
      state: policy.tiers.some((tier, index) => (
        !(policy.mode === "cascade" && fallbackAudience === "none" && index > 0)
        && !sinkConfigured(tier.name, cfgs.channel, cfgs.ntfy)
      )) ? "missing" : fallbackNote ? "conditional" : "ready",
      href: "/delivery",
    });
  });
}

export function buildFlowSteps(cfgs, stats = {}) {
  const steps = [sourceStep(cfgs, stats)];
  appendProcessingSteps(steps, cfgs);
  appendDeliverySteps(steps, cfgs);
  return steps;
}
