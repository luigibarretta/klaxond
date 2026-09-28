import { applyTablePager, markTabDirty, showTableRowPage, tr } from "./app.js";
import { scheduleRegexValidation } from "./app-inhibitions-regex.js";
import {
  appendAppliesToCell,
  selectedSources,
  updateSourcePickerSummary,
} from "./app-inhibitions-scope.js";
import { updateInhibitionRowFeedback } from "./app-inhibitions-row-validation.js";
let feedbackSequence = 0;
function matchTypeOf(rule) {
  if (rule.match_all) return "match_all";
  if (rule.match_label && rule.match_regex) return "match_label";
  if (rule.match_by) return "match_by";
  return "match_by";
}
function makeCell(child, label) {
  const td = document.createElement("td");
  if (label) td.dataset.label = label;
  td.appendChild(child);
  return td;
}
function makeInput({
  type: type = "text",
  value: value = "",
  dataKey: dataKey,
  placeholder: placeholder,
  ariaLabel: ariaLabel,
}) {
  const input = document.createElement("input");
  input.type = type;
  input.value = value;
  input.dataset.k = dataKey;
  if (placeholder) input.placeholder = placeholder;
  if (ariaLabel) input.setAttribute("aria-label", ariaLabel);
  return input;
}
function humanDuration(seconds) {
  const value = Number(seconds) || 0;
  if (value >= 3600 && value % 3600 === 0)
    return tr("inhib.duration_hours", { count: value / 3600 });
  return tr("inhib.duration_minutes", {
    count: Math.max(1, Math.round(value / 60)),
  });
}
export function rulePreview(row) {
  const get = (key) => row.querySelector(`[data-k="${key}"]`);
  const source = get("source")?.value.trim() || "…";
  const matchType = get("match_type")?.value || "match_by";
  const label = get("match_label")?.value.trim() || "…";
  const regex = get("match_regex")?.value.trim() || "…";
  const sources = selectedSources(row);
  const scope = sources.length
    ? sources.join(", ")
    : tr("inhib.scope_all").toLocaleLowerCase();
  const duration = humanDuration(get("ttl_seconds")?.value);
  if (matchType === "match_all") {
    return tr("inhib.preview_all", {
      source: source,
      scope: scope,
      duration: duration,
    });
  }
  if (matchType === "match_label") {
    return tr("inhib.preview_regex", {
      source: source,
      scope: scope,
      label: label,
      regex: regex,
      duration: duration,
    });
  }
  return tr("inhib.preview_match_by", {
    source: source,
    scope: scope,
    label: label,
    duration: duration,
  });
}
function appendSourceCell(row, rule) {
  const input = makeInput({
    value: rule.source || "",
    dataKey: "source",
    placeholder: "e.g. node-down",
    ariaLabel: tr("inhib.rule_name"),
  });
  input.addEventListener("input", () => updateInhibitionRowFeedback(row));
  row.appendChild(makeCell(input, tr("common.source")));
}
function appendMatchTypeCell(row, matchType) {
  const select = document.createElement("select");
  select.dataset.k = "match_type";
  select.setAttribute("aria-label", tr("inhib.match_type"));
  const labels = {
    match_by: "match_by",
    match_label: "match_label + regex",
    match_all: "match_all",
  };
  for (const opt of ["match_by", "match_label", "match_all"]) {
    const option = document.createElement("option");
    option.value = opt;
    option.textContent = labels[opt];
    if (opt === matchType) option.selected = true;
    select.appendChild(option);
  }
  row.appendChild(makeCell(select, tr("inhib.match_type")));
  return select;
}
function appendMatchValueCell(row, rule, select, matchType) {
  const cell = document.createElement("td");
  cell.dataset.label = tr("inhib.match_value");
  const wrap = document.createElement("div");
  wrap.className = "inhib-match-editor";
  const labelInput = makeInput({
    value: rule.match_by || rule.match_label || "",
    dataKey: "match_label",
    placeholder: "host",
    ariaLabel: tr("inhib.label_name"),
  });
  labelInput.setAttribute("list", "inhib-label-suggestions");
  labelInput.addEventListener("input", () => updateInhibitionRowFeedback(row));
  const eqSign = document.createElement("span");
  eqSign.textContent = "=";
  eqSign.className = "muted";
  eqSign.setAttribute("aria-hidden", "true");
  const regexInput = makeInput({
    value: rule.match_regex || "",
    dataKey: "match_regex",
    placeholder: "^blackbox-.*",
    ariaLabel: tr("inhib.regex"),
  });
  regexInput.addEventListener("input", () => {
    scheduleRegexValidation(row);
    updateInhibitionRowFeedback(row);
  });
  const hint = document.createElement("span");
  hint.className = "muted inhib-match-all-hint";
  hint.textContent = tr("inhib.suppresses_all");
  wrap.appendChild(labelInput);
  wrap.appendChild(eqSign);
  wrap.appendChild(regexInput);
  wrap.appendChild(hint);
  cell.appendChild(wrap);
  const preview = document.createElement("p");
  const feedbackId = ++feedbackSequence;
  preview.className = "inhib-rule-preview";
  preview.dataset.inhibPreview = "";
  preview.id = `inhib-preview-${feedbackId}`;
  preview.setAttribute("aria-label", tr("inhib.preview_label"));
  const validation = document.createElement("small");
  validation.className = "inhib-validation";
  validation.dataset.inhibValidation = "";
  validation.id = `inhib-validation-${feedbackId}`;
  validation.setAttribute("role", "status");
  labelInput.setAttribute("aria-describedby", `${preview.id} ${validation.id}`);
  regexInput.setAttribute("aria-describedby", `${preview.id} ${validation.id}`);
  cell.appendChild(preview);
  cell.appendChild(validation);
  row.appendChild(cell);
  applyMatchType(matchType, labelInput, eqSign, regexInput, hint);
  select.addEventListener("change", () => {
    applyMatchType(select.value, labelInput, eqSign, regexInput, hint);
    if (select.value === "match_label") scheduleRegexValidation(row);
    updateInhibitionRowFeedback(row);
  });
}
function applyMatchType(value, labelInput, eqSign, regexInput, hint) {
  labelInput.hidden = value === "match_all";
  eqSign.hidden = value !== "match_label";
  regexInput.hidden = value !== "match_label";
  hint.hidden = value !== "match_all";
  labelInput.placeholder = value === "match_label" ? "job" : "host";
}
function appendTtlCell(row, rule) {
  const wrap = document.createElement("div");
  wrap.className = "inhib-ttl-editor";
  const input = makeInput({
    type: "number",
    value: rule.ttl_seconds || 900,
    dataKey: "ttl_seconds",
    ariaLabel: tr("inhib.ttl_sec"),
  });
  input.min = "30";
  input.max = "86400";
  input.addEventListener("input", () => updateInhibitionRowFeedback(row));
  wrap.appendChild(input);
  for (const [label, seconds] of [
    ["5m", 300],
    ["15m", 900],
    ["30m", 1800],
    ["1h", 3600],
  ]) {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "btn ttl-preset";
    button.textContent = label;
    button.title = tr("inhib.set_ttl", { value: label });
    button.addEventListener("click", () => {
      input.value = seconds;
      updateInhibitionRowFeedback(row);
      markTabDirty("inhibitions", true);
    });
    wrap.appendChild(button);
  }
  row.appendChild(makeCell(wrap, tr("inhib.ttl_sec")));
}
function appendActionCell(row, availableSources) {
  const cell = document.createElement("td");
  cell.dataset.label = tr("common.actions");
  const wrap = document.createElement("div");
  wrap.className = "inhib-row-actions";
  const duplicate = document.createElement("button");
  duplicate.type = "button";
  duplicate.className = "btn";
  duplicate.textContent = tr("inhib.duplicate_short");
  duplicate.title = tr("inhib.duplicate_title");
  duplicate.setAttribute("aria-label", tr("inhib.duplicate_title"));
  duplicate.addEventListener("click", () =>
    duplicateRow(row, availableSources),
  );
  const remove = document.createElement("button");
  remove.type = "button";
  remove.className = "btn";
  remove.textContent = tr("inhib.delete_short");
  remove.title = tr("inhib.delete_rule_title");
  remove.setAttribute("aria-label", tr("inhib.delete_rule_title"));
  remove.addEventListener("click", () => {
    row.remove();
    applyTablePager("t-inhib-rules");
    markTabDirty("inhibitions", true);
  });
  wrap.appendChild(duplicate);
  wrap.appendChild(remove);
  cell.appendChild(wrap);
  row.appendChild(cell);
}
function duplicateRow(row, availableSources) {
  const snapshot = rowSnapshot(row);
  snapshot.source += " (copy)";
  const clone = createInhibitionRuleRow(snapshot, availableSources);
  row.parentNode.insertBefore(clone, row.nextSibling);
  showTableRowPage("t-inhib-rules", clone);
  markTabDirty("inhibitions", true);
}
export function rowSnapshot(row) {
  const get = (k) => row.querySelector(`[data-k="${k}"]`);
  const matchType = get("match_type").value;
  const snapshot = {
    source: get("source").value.trim(),
    ttl_seconds: parseInt(get("ttl_seconds").value || "900", 10),
    applies_to: selectedSources(row),
  };
  if (matchType === "match_by")
    snapshot.match_by = get("match_label").value.trim();
  else if (matchType === "match_label") {
    snapshot.match_label = get("match_label").value.trim();
    snapshot.match_regex = get("match_regex").value.trim();
  } else {
    snapshot.match_all = true;
  }
  return snapshot;
}
export function createInhibitionRuleRow(rule, availableSources) {
  const row = document.createElement("tr");
  row.classList.add("inhib-rule-row");
  row.addEventListener("klaxond:regex-validation", () =>
    updateInhibitionRowFeedback(row),
  );
  const matchType = matchTypeOf(rule);
  appendSourceCell(row, rule);
  const select = appendMatchTypeCell(row, matchType);
  appendMatchValueCell(row, rule, select, matchType);
  appendAppliesToCell(row, rule, availableSources, () =>
    updateInhibitionRowFeedback(row),
  );
  appendTtlCell(row, rule);
  appendActionCell(row, availableSources);
  updateInhibitionRowFeedback(row);
  if (matchType === "match_label" && rule.match_regex)
    scheduleRegexValidation(row);
  return row;
}
