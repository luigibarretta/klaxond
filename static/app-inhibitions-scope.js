import { tr } from "./app.js";

export function selectedSources(row) {
  return Array.from(row.querySelectorAll('[data-k="applies_to"] input[type="checkbox"]'))
    .filter(checkbox => checkbox.checked)
    .map(checkbox => checkbox.value);
}

export function updateSourcePickerSummary(row) {
  const summary = row.querySelector(".inhib-source-picker > summary");
  if (!summary) return;
  const sources = selectedSources(row);
  summary.textContent = sources.length === 0
    ? tr("inhib.scope_all")
    : sources.length === 1
      ? `${tr("inhib.scope_one")} · ${sources[0]}`
      : tr("inhib.scope_many", { count: sources.length });
  summary.title = sources.join(", ") || tr("inhib.scope_all");
}

export function appendAppliesToCell(row, rule, availableSources, onChange) {
  const cell = document.createElement("td");
  cell.dataset.label = tr("common.applies_to");
  const picker = document.createElement("details");
  picker.className = "inhib-source-picker";
  const summary = document.createElement("summary");
  const panel = document.createElement("div");
  panel.className = "inhib-source-picker-panel";
  const search = document.createElement("input");
  search.type = "search";
  search.placeholder = tr("inhib.scope_search");
  search.setAttribute("aria-label", tr("inhib.scope_search"));
  search.dataset.dirtyIgnore = "";
  const options = document.createElement("div");
  options.dataset.k = "applies_to";
  options.className = "inhib-source-options";
  const selected = new Set(rule.applies_to || []);
  for (const source of availableSources) {
    const label = document.createElement("label");
    label.className = "inhib-source-option";
    const checkbox = document.createElement("input");
    checkbox.type = "checkbox";
    checkbox.value = source;
    checkbox.checked = selected.has(source);
    checkbox.addEventListener("change", () => {
      updateSourcePickerSummary(row);
      onChange();
    });
    label.appendChild(checkbox);
    label.appendChild(document.createTextNode(" " + source));
    options.appendChild(label);
  }
  const empty = document.createElement("small");
  empty.className = "muted inhib-source-empty";
  empty.textContent = tr("inhib.scope_no_results");
  empty.hidden = true;
  search.addEventListener("input", () => {
    const query = search.value.trim().toLocaleLowerCase();
    options.querySelectorAll(".inhib-source-option").forEach(option => {
      const filtered = Boolean(query)
        && !option.textContent.toLocaleLowerCase().includes(query);
      option.hidden = filtered;
      option.style.display = filtered ? "none" : "";
    });
    empty.hidden = Array.from(options.querySelectorAll(".inhib-source-option"))
      .some(option => !option.hidden);
  });
  panel.append(search, options, empty);
  picker.append(summary, panel);
  const hint = document.createElement("small");
  hint.className = "muted inhib-cell-hint";
  hint.textContent = tr("inhib.empty_all_sources");
  cell.append(picker, hint);
  row.appendChild(cell);
  updateSourcePickerSummary(row);
}
