import { applyTablePager, showTableRowPage, tr } from "./app.js";

function matchTypeOf(rule) {
  if (rule.match_all) return "match_all";
  if (rule.match_label && rule.match_regex) return "match_label";
  if (rule.match_by) return "match_by";
  return "match_by";
}

function makeCell(child) {
  const td = document.createElement("td");
  td.appendChild(child);
  return td;
}

function makeInput({ type = "text", value = "", dataKey, placeholder, width }) {
  const input = document.createElement("input");
  input.type = type;
  input.value = value;
  input.dataset.k = dataKey;
  if (placeholder) input.placeholder = placeholder;
  if (width) input.style.width = width;
  return input;
}

function appendSourceCell(row, rule) {
  const input = makeInput({
    value: rule.source || "",
    dataKey: "source",
    placeholder: "e.g. node-down",
    width: "100%",
  });
  input.addEventListener("input", () => markInhibitionRowValidity(row));
  row.appendChild(makeCell(input));
}

function appendMatchTypeCell(row, matchType) {
  const select = document.createElement("select");
  select.dataset.k = "match_type";
  const labels = {match_by: "match_by", match_label: "match_label + regex", match_all: "match_all"};
  for (const opt of ["match_by", "match_label", "match_all"]) {
    const option = document.createElement("option");
    option.value = opt;
    option.textContent = labels[opt];
    if (opt === matchType) option.selected = true;
    select.appendChild(option);
  }
  row.appendChild(makeCell(select));
  return select;
}

function appendMatchValueCell(row, rule, select, matchType) {
  const cell = document.createElement("td");
  const wrap = document.createElement("div");
  wrap.style.display = "flex";
  wrap.style.gap = "0.4em";
  wrap.style.alignItems = "center";

  const labelInput = makeInput({
    value: rule.match_by || rule.match_label || "",
    dataKey: "match_label",
    placeholder: "host",
  });
  labelInput.style.flex = "0 0 8em";
  labelInput.setAttribute("list", "inhib-label-suggestions");
  labelInput.addEventListener("input", () => markInhibitionRowValidity(row));

  const eqSign = document.createElement("span");
  eqSign.textContent = "=";
  eqSign.style.color = "var(--muted)";

  const regexInput = makeInput({
    value: rule.match_regex || "",
    dataKey: "match_regex",
    placeholder: "^blackbox-.*",
  });
  regexInput.style.flex = "1 1 auto";
  regexInput.style.fontFamily = "ui-monospace, monospace";
  regexInput.style.fontSize = "12px";
  regexInput.addEventListener("input", () => markInhibitionRowValidity(row));

  const hint = document.createElement("span");
  hint.style.color = "var(--muted)";
  hint.style.fontSize = "12px";
  hint.textContent = tr("inhib.suppresses_all");

  wrap.appendChild(labelInput);
  wrap.appendChild(eqSign);
  wrap.appendChild(regexInput);
  wrap.appendChild(hint);
  cell.appendChild(wrap);
  row.appendChild(cell);

  applyMatchType(matchType, labelInput, eqSign, regexInput, hint);
  select.addEventListener("change", () => {
    applyMatchType(select.value, labelInput, eqSign, regexInput, hint);
    markInhibitionRowValidity(row);
  });
}

function applyMatchType(value, labelInput, eqSign, regexInput, hint) {
  labelInput.style.display = (value === "match_all") ? "none" : "";
  eqSign.style.display = (value === "match_label") ? "" : "none";
  regexInput.style.display = (value === "match_label") ? "" : "none";
  hint.style.display = (value === "match_all") ? "" : "none";
  labelInput.placeholder = value === "match_label" ? "job" : "host";
}

function appendAppliesToCell(row, rule, availableSources) {
  const cell = document.createElement("td");
  const wrap = document.createElement("div");
  wrap.dataset.k = "applies_to";
  wrap.style.display = "flex";
  wrap.style.flexWrap = "wrap";
  wrap.style.gap = "0.4em";
  const selected = new Set(rule.applies_to || []);
  for (const source of availableSources) {
    const label = document.createElement("label");
    label.style.fontSize = "0.85em";
    label.style.whiteSpace = "nowrap";
    label.style.margin = "0";
    const checkbox = document.createElement("input");
    checkbox.type = "checkbox";
    checkbox.value = source;
    checkbox.checked = selected.has(source);
    label.appendChild(checkbox);
    label.appendChild(document.createTextNode(" " + source));
    wrap.appendChild(label);
  }
  const allHint = document.createElement("small");
  allHint.className = "muted";
  allHint.style.fontSize = "11px";
  allHint.textContent = tr("inhib.empty_all_sources");
  cell.appendChild(wrap);
  cell.appendChild(allHint);
  row.appendChild(cell);
}

function appendTtlCell(row, rule) {
  const wrap = document.createElement("div");
  wrap.style.display = "flex";
  wrap.style.gap = "0.3em";
  wrap.style.alignItems = "center";
  wrap.style.flexWrap = "wrap";

  const input = makeInput({ type: "number", value: rule.ttl_seconds || 900, dataKey: "ttl_seconds" });
  input.min = "30";
  input.max = "86400";
  input.style.width = "5.5em";
  input.addEventListener("input", () => markInhibitionRowValidity(row));
  wrap.appendChild(input);

  for (const [label, seconds] of [["5m", 300], ["15m", 900], ["30m", 1800], ["1h", 3600]]) {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "btn";
    button.textContent = label;
    button.style.padding = "2px 6px";
    button.style.fontSize = "11px";
    button.title = `Set TTL to ${seconds}s`;
    button.addEventListener("click", () => {
      input.value = seconds;
      markInhibitionRowValidity(row);
    });
    wrap.appendChild(button);
  }
  row.appendChild(makeCell(wrap));
}

function appendActionCell(row, availableSources) {
  const cell = document.createElement("td");
  cell.style.whiteSpace = "nowrap";

  const duplicate = document.createElement("button");
  duplicate.type = "button";
  duplicate.className = "btn";
  duplicate.textContent = "⎘";
  duplicate.title = tr("inhib.duplicate_title");
  duplicate.style.padding = "2px 8px";
  duplicate.style.marginRight = "4px";
  duplicate.addEventListener("click", () => duplicateRow(row, availableSources));

  const remove = document.createElement("button");
  remove.type = "button";
  remove.className = "btn";
  remove.textContent = "✕";
  remove.title = tr("inhib.delete_rule_title");
  remove.style.color = "var(--red)";
  remove.style.padding = "2px 8px";
  remove.addEventListener("click", () => {
    row.remove();
    applyTablePager("t-inhib-rules");
  });

  cell.appendChild(duplicate);
  cell.appendChild(remove);
  row.appendChild(cell);
}

function duplicateRow(row, availableSources) {
  const snapshot = rowSnapshot(row);
  snapshot.source += " (copy)";
  const clone = createInhibitionRuleRow(snapshot, availableSources);
  row.parentNode.insertBefore(clone, row.nextSibling);
  showTableRowPage("t-inhib-rules", clone);
}

function rowSnapshot(row) {
  const get = k => row.querySelector(`[data-k="${k}"]`);
  const matchType = get("match_type").value;
  const snapshot = {
    source: get("source").value.trim(),
    ttl_seconds: parseInt(get("ttl_seconds").value || "900", 10),
    applies_to: Array.from(row.querySelectorAll('[data-k="applies_to"] input[type=checkbox]'))
      .filter(cb => cb.checked)
      .map(cb => cb.value),
  };
  if (matchType === "match_by") snapshot.match_by = get("match_label").value.trim();
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
  const matchType = matchTypeOf(rule);

  appendSourceCell(row, rule);
  const select = appendMatchTypeCell(row, matchType);
  appendMatchValueCell(row, rule, select, matchType);
  appendAppliesToCell(row, rule, availableSources);
  appendTtlCell(row, rule);
  appendActionCell(row, availableSources);

  markInhibitionRowValidity(row);
  return row;
}

export function validateInhibitionRuleRow(row) {
  const get = k => row.querySelector(`[data-k="${k}"]`);
  const source = get("source").value.trim();
  if (!source) return "source name is required";
  const matchType = get("match_type").value;
  if (matchType === "match_by") {
    if (!get("match_label").value.trim()) return "label name is required for match_by";
  } else if (matchType === "match_label") {
    if (!get("match_label").value.trim()) return "label name is required";
    const regex = get("match_regex").value.trim();
    if (!regex) return "regex is required";
    try {
      new RegExp(regex);
    } catch (e) {
      return "invalid regex: " + e.message;
    }
  }
  const ttl = parseInt(get("ttl_seconds").value || "0", 10);
  if (!Number.isFinite(ttl) || ttl < 30 || ttl > 86400) return "TTL must be 30..86400 seconds";
  return null;
}

function markInhibitionRowValidity(row) {
  const error = validateInhibitionRuleRow(row);
  if (error) row.dataset.invalid = error;
  else delete row.dataset.invalid;
  row.style.outline = error ? "1px solid var(--red)" : "";
}

export function collectInhibitionRulesFromTable() {
  const rows = document.querySelectorAll("#t-inhib-rules tbody tr.inhib-rule-row");
  const rules = [];
  for (const row of rows) {
    const error = validateInhibitionRuleRow(row);
    if (error) {
      const source = row.querySelector('[data-k="source"]').value.trim() || "(unnamed)";
      return { error: `rule "${source}": ${error}` };
    }
    rules.push(rowSnapshot(row));
  }
  return { rules };
}
