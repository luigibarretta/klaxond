import { $, escapeHtml, markTabDirty, tr } from "./app.js";
import { REPEAT_DURATIONS, durationOptions } from "./app-duration-options.js";

let draftRules = [];

export function renderNoiseRules(data, sources) {
  draftRules = sources.flatMap(source => (
    (data.settings?.[source]?.rules || []).map(rule => ({ ...rule, source }))
  ));
  renderDraft(sources);
}

export function collectNoiseRules(sources, { validate = true } = {}) {
  const bySource = Object.fromEntries(sources.map(source => [source, []]));
  const rules = readRuleElements();
  for (const [index, rule] of rules.entries()) {
    const error = validate ? validateRule(rule, index) : "";
    if (error) return { error, element: rule.element };
    const { element: _element, source, ...payload } = rule;
    if (!bySource[source]) continue;
    if (validate && bySource[source].length >= 50) {
      return { error: tr("dedup.rules_too_many", { source }), element: rule.element };
    }
    bySource[source].push(payload);
  }
  return { bySource, rules };
}

function validateRule(rule, index) {
  const position = index + 1;
  if (!rule.name) return tr("dedup.rule_error_name", { position });
  if (!rule.pattern) return tr("dedup.rule_error_pattern", { position });
  if (rule.field === "label" && !rule.label) {
    return tr("dedup.rule_error_label", { position });
  }
  return "";
}

function readRuleElements() {
  return [...document.querySelectorAll("#dedup-rules [data-noise-rule]")].map(element => ({
    element,
    source: field(element, "source").value,
    name: field(element, "name").value.trim(),
    enabled: field(element, "enabled").checked,
    field: field(element, "field").value,
    label: field(element, "label").value.trim(),
    operator: field(element, "operator").value,
    pattern: field(element, "pattern").value.trim(),
    case_sensitive: field(element, "case_sensitive").checked,
    action: field(element, "action").value,
    cooldown_s: Number(field(element, "cooldown_s").value) || 7200,
    include_critical: field(element, "include_critical").checked,
  }));
}

function field(element, name) {
  return element.querySelector(`[data-rule-field="${name}"]`);
}

function renderDraft(sources) {
  const container = $("#dedup-rules");
  if (!container) return;
  if (!draftRules.length) {
    container.innerHTML = `<div class="noise-rules-empty">
      <strong>${escapeHtml(tr("dedup.rules_empty_title"))}</strong>
      <span class="muted">${escapeHtml(tr("dedup.rules_empty_desc"))}</span>
    </div>`;
    return;
  }
  container.innerHTML = draftRules.map((rule, index) => ruleMarkup(rule, index, sources)).join("");
  container.querySelectorAll("[data-noise-rule]").forEach(syncRuleVisibility);
}

function ruleMarkup(rule, index, sources) {
  const action = rule.action || "suppress";
  const fieldValue = rule.field || "title_or_body";
  return `<article class="noise-rule" data-noise-rule>
    <div class="noise-rule-head">
      <label class="toggle-line noise-rule-enabled">
        <input type="checkbox" data-rule-field="enabled" ${rule.enabled !== false ? "checked" : ""}>
        <span>${escapeHtml(tr("dedup.rule_enabled"))}</span>
      </label>
      <span class="noise-rule-order">${index + 1}</span>
      <label class="noise-rule-name">
        <input type="text" maxlength="80" data-rule-field="name" value="${escapeHtml(rule.name || "")}" placeholder="${escapeHtml(tr("dedup.rule_name_placeholder"))}" aria-label="${escapeHtml(tr("common.name"))}">
      </label>
      <div class="noise-rule-actions">
        ${iconButton("up", "↑", "dedup.rule_move_up")}
        ${iconButton("down", "↓", "dedup.rule_move_down")}
        ${iconButton("delete", "✕", "dedup.rule_delete")}
      </div>
    </div>
    <div class="noise-rule-clause">
      <strong>${escapeHtml(tr("dedup.rule_when"))}</strong>
      <label><span>${escapeHtml(tr("common.source"))}</span>
        <select data-rule-field="source">${options(sources, rule.source || "grafana", source => source.toUpperCase())}</select>
      </label>
      <label><span>${escapeHtml(tr("dedup.rule_field"))}</span>
        <select data-rule-field="field">
          ${translatedOptions(["title_or_body", "title", "body", "alertname", "label"], fieldValue, "dedup.rule_field_")}
        </select>
      </label>
      <label data-rule-label-name><span>${escapeHtml(tr("dedup.rule_label_name"))}</span>
        <input type="text" maxlength="128" data-rule-field="label" value="${escapeHtml(rule.label || "")}" placeholder="instance">
      </label>
      <label><span>${escapeHtml(tr("dedup.rule_operator"))}</span>
        <select data-rule-field="operator">
          ${translatedOptions(["contains", "exact", "regex"], rule.operator || "contains", "dedup.rule_operator_")}
        </select>
      </label>
      <label class="noise-rule-pattern"><span>${escapeHtml(tr("dedup.rule_pattern"))}</span>
        <input type="text" maxlength="512" data-rule-field="pattern" value="${escapeHtml(rule.pattern || "")}" placeholder="${escapeHtml(tr("dedup.rule_pattern_placeholder"))}">
      </label>
      <label class="toggle-line noise-rule-case">
        <input type="checkbox" data-rule-field="case_sensitive" ${rule.case_sensitive ? "checked" : ""}>
        <span>${escapeHtml(tr("dedup.rule_case_sensitive"))}</span>
      </label>
    </div>
    <div class="noise-rule-clause noise-rule-then">
      <strong>${escapeHtml(tr("dedup.rule_then"))}</strong>
      <label><span>${escapeHtml(tr("dedup.rule_action"))}</span>
        <select data-rule-field="action">
          ${translatedOptions(["suppress", "bypass"], action, "dedup.rule_action_")}
        </select>
      </label>
      <label data-rule-cooldown><span>${escapeHtml(tr("dedup.rule_cooldown"))}</span>
        <select data-rule-field="cooldown_s">${durationOptions(rule.cooldown_s || 7200, REPEAT_DURATIONS)}</select>
      </label>
      <label class="toggle-line" data-rule-critical>
        <input type="checkbox" data-rule-field="include_critical" ${rule.include_critical ? "checked" : ""}>
        <span>${escapeHtml(tr("dedup.rule_include_critical"))}</span>
      </label>
    </div>
  </article>`;
}

function iconButton(action, glyph, key) {
  const label = escapeHtml(tr(key));
  return `<button type="button" class="icon-btn" data-rule-action="${action}" title="${label}" aria-label="${label}">${glyph}</button>`;
}

function options(values, selected, label = value => value) {
  return values.map(value => (
    `<option value="${escapeHtml(value)}" ${value === selected ? "selected" : ""}>${escapeHtml(label(value))}</option>`
  )).join("");
}

function translatedOptions(values, selected, prefix) {
  return options(values, selected, value => tr(`${prefix}${value}`));
}

function syncRuleVisibility(rule) {
  const isLabel = field(rule, "field").value === "label";
  const suppresses = field(rule, "action").value === "suppress";
  rule.querySelector("[data-rule-label-name]").hidden = !isLabel;
  rule.querySelector("[data-rule-cooldown]").hidden = !suppresses;
  rule.querySelector("[data-rule-critical]").hidden = !suppresses;
}

function snapshotRules() {
  draftRules = readRuleElements().map(({ element: _element, ...rule }) => rule);
}

$("#dedup-rule-add")?.addEventListener("click", () => {
  snapshotRules();
  draftRules.push({
    source: "grafana", name: "", enabled: true, field: "title_or_body", label: "",
    operator: "contains", pattern: "", case_sensitive: false, action: "suppress",
    cooldown_s: 7200, include_critical: false,
  });
  renderDraft(sourceList());
  $("#dedup-rules [data-noise-rule]:last-child [data-rule-field=name]")?.focus();
  markTabDirty("grouping", true);
});

$("#dedup-rules")?.addEventListener("change", event => {
  const rule = event.target.closest("[data-noise-rule]");
  if (!rule) return;
  if (["field", "action"].includes(event.target.dataset.ruleField)) syncRuleVisibility(rule);
});

$("#dedup-rules")?.addEventListener("click", event => {
  const button = event.target.closest("[data-rule-action]");
  if (!button) return;
  const ruleElement = button.closest("[data-noise-rule]");
  const allElements = [...document.querySelectorAll("#dedup-rules [data-noise-rule]")];
  const index = allElements.indexOf(ruleElement);
  snapshotRules();
  if (button.dataset.ruleAction === "delete") {
    draftRules.splice(index, 1);
  } else {
    const sameSource = draftRules
      .map((rule, candidate) => rule.source === draftRules[index].source ? candidate : -1)
      .filter(candidate => candidate >= 0);
    const position = sameSource.indexOf(index);
    const target = button.dataset.ruleAction === "up"
      ? sameSource[position - 1]
      : sameSource[position + 1];
    if (target !== undefined) [draftRules[index], draftRules[target]] = [draftRules[target], draftRules[index]];
  }
  renderDraft(sourceList());
  markTabDirty("grouping", true);
});

function sourceList() {
  return [...document.querySelectorAll("#dedup-cards [data-src]")].map(card => card.dataset.src);
}
