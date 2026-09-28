import { escapeHtml, tr, $ } from "./app.js";

export function renderFlowSummary(cfgs) {
  const target = $("#flow-config-summary");
  if (!target) return;
  const sourceCount = Object.values(cfgs.ingest?.sources || {}).filter(
    (source) => source?.configured,
  ).length;
  const inhibitionCount = (cfgs.inhibition?.rules || []).length;
  const policyCount = (cfgs.delivery?.policies || []).length + 1;
  const profileCount = (cfgs.emergency?.settings?.profiles || []).filter(
    (profile) => profile.enabled,
  ).length;
  const items = [
    ["/routing", tr("flow.summary_sources", { count: sourceCount })],
    ["/inhibitions", tr("flow.summary_inhibitions", { count: inhibitionCount })],
    ["/delivery", tr("flow.summary_policies", { count: policyCount })],
    ["/emergencies", tr("flow.summary_emergencies", { count: profileCount })],
  ];
  target.innerHTML = items
    .map(([href, label]) =>
      `<a class="flow-summary-chip" href="${href}">${escapeHtml(label)}</a>`,
    )
    .join("");
}
