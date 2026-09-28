const DEFAULT_TIERS = [
  { name: "ntfy", timeout_seconds: 15 },
  { name: "telegram", timeout_seconds: 8 },
  { name: "smtp", timeout_seconds: 10 },
];

export function configuredCascadeTiers(cascade, delivery = {}) {
  const fromDelivery = Array.isArray(delivery.legacy_cascade_tiers)
    ? delivery.legacy_cascade_tiers
    : [];
  const fromCascade = Array.isArray(cascade?.tiers) ? cascade.tiers : [];
  const tiers = fromDelivery.length ? fromDelivery : fromCascade;
  return tiers.length ? tiers : DEFAULT_TIERS;
}

function normalizePolicy(policy, fallbackTiers, index) {
  const mode = policy.mode === "broadcast" ? "broadcast" : "cascade";
  const configuredTiers = Array.isArray(policy.tiers) ? policy.tiers : [];
  const name = String(policy.name || "").trim();
  return {
    index,
    name,
    nodeId: policyNodeId(index, name),
    mode,
    tiers: mode === "cascade" && configuredTiers.length === 0 ? fallbackTiers : configuredTiers,
  };
}

export function configuredDeliveryPolicies(delivery = {}, cascade = {}) {
  const cascadeTiers = configuredCascadeTiers(cascade, delivery);
  const policies = [normalizePolicy(
    { name: "cascade", mode: "cascade", tiers: cascadeTiers },
    cascadeTiers,
    0,
  )];
  for (const policy of delivery.policies || []) {
    const normalized = normalizePolicy(policy, DEFAULT_TIERS, policies.length);
    if (!normalized.name || normalized.name === "cascade") continue;
    policies.push(normalized);
  }

  const requestedDefault = String(delivery.default_policy || "cascade");
  const effectiveDefault = policies.some(policy => policy.name === requestedDefault)
    ? requestedDefault
    : "cascade";
  const rules = Array.isArray(delivery.rules) ? delivery.rules : [];
  const ruleIndexesByPolicy = new Map();
  rules.forEach((rule, index) => {
    if (!policies.some(policy => policy.name === rule.policy)) return;
    const indexes = ruleIndexesByPolicy.get(rule.policy) || [];
    indexes.push(index + 1);
    ruleIndexesByPolicy.set(rule.policy, indexes);
  });

  return {
    requestedDefault,
    effectiveDefault,
    rules,
    policies: policies.map(policy => ({
      ...policy,
      isDefault: policy.name === effectiveDefault,
      ruleIndexes: ruleIndexesByPolicy.get(policy.name) || [],
      reachable: policy.name === effectiveDefault || ruleIndexesByPolicy.has(policy.name),
      synthetic: policy.name === "cascade",
    })),
  };
}

export function cascadeFallbackAudience(cascade, sources) {
  if (cascade?.default_enabled_for_webhook || !sources.includes("grafana")) return "all";
  return sources.some(source => source !== "grafana") ? "non_grafana" : "none";
}

export function policyNodeId(index, name) {
  const readableName = String(name || "policy").toUpperCase().replace(/[^A-Z0-9_]/g, "_");
  return `POL_${index}_${readableName}`;
}
