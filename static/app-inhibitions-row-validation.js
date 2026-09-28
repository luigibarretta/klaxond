import { applyTablePager, markTabDirty, showTableRowPage, tr } from "./app.js";
import { scheduleRegexValidation } from "./app-inhibitions-regex.js";
import {
  appendAppliesToCell,
  selectedSources,
  updateSourcePickerSummary,
} from "./app-inhibitions-scope.js";
import { rowSnapshot, rulePreview } from "./app-inhibitions-row-build.js";
export function inhibitionRowValidation(row) {
  const get = (k) => row.querySelector(`[data-k="${k}"]`);
  const source = get("source").value.trim();
  if (!source)
    return { field: "source", message: tr("inhib.error_source_required") };
  const matchType = get("match_type").value;
  if (matchType === "match_by") {
    if (!get("match_label").value.trim())
      return {
        field: "match_label",
        message: tr("inhib.error_label_required"),
      };
  } else if (matchType === "match_label") {
    if (!get("match_label").value.trim())
      return {
        field: "match_label",
        message: tr("inhib.error_label_required"),
      };
    const regex = get("match_regex").value.trim();
    if (!regex)
      return {
        field: "match_regex",
        message: tr("inhib.error_regex_required"),
      };
    if (
      row.dataset.regexValue === regex &&
      row.dataset.regexState === "invalid"
    ) {
      return {
        field: "match_regex",
        message: tr("inhib.error_regex_invalid", {
          message: row.dataset.regexError || tr("inhib.regex_error_unknown"),
        }),
      };
    }
  }
  const ttl = parseInt(get("ttl_seconds").value || "0", 10);
  if (!Number.isFinite(ttl) || ttl < 30 || ttl > 86400) {
    return { field: "ttl_seconds", message: tr("inhib.error_ttl") };
  }
  return null;
}
export function validateInhibitionRuleRow(row) {
  return inhibitionRowValidation(row)?.message || null;
}
export function updateInhibitionRowFeedback(row) {
  const error = inhibitionRowValidation(row);
  row
    .querySelectorAll("[aria-invalid], [aria-errormessage]")
    .forEach((input) => {
      input.removeAttribute("aria-invalid");
      input.removeAttribute("aria-errormessage");
    });
  if (error) {
    row.dataset.invalid = error.message;
    const field = row.querySelector(`[data-k="${error.field}"]`);
    field?.setAttribute("aria-invalid", "true");
    field?.setAttribute(
      "aria-errormessage",
      row.querySelector("[data-inhib-validation]")?.id || "",
    );
  } else delete row.dataset.invalid;
  const preview = row.querySelector("[data-inhib-preview]");
  if (preview) preview.textContent = rulePreview(row);
  const validation = row.querySelector("[data-inhib-validation]");
  if (validation) {
    const matchType = row.querySelector('[data-k="match_type"]')?.value;
    const regex = row.querySelector('[data-k="match_regex"]')?.value.trim();
    const currentState =
      row.dataset.regexValue === regex ? row.dataset.regexState : "";
    const regexStatus =
      currentState === "pending"
        ? tr("inhib.regex_checking")
        : currentState === "valid"
          ? tr("inhib.valid_regex")
          : currentState === "unavailable"
            ? tr("inhib.regex_validation_unavailable")
            : "";
    validation.textContent =
      error?.message ||
      (matchType === "match_label" && regex ? regexStatus : "");
    validation.classList.toggle("is-error", Boolean(error));
  }
}
export function collectInhibitionRulesFromTable() {
  const rows = document.querySelectorAll(
    "#t-inhib-rules tbody tr.inhib-rule-row",
  );
  const rules = [];
  for (const row of rows) {
    updateInhibitionRowFeedback(row);
    const error = validateInhibitionRuleRow(row);
    if (error) {
      const source =
        row.querySelector('[data-k="source"]').value.trim() || "(unnamed)";
      row.querySelector('[aria-invalid="true"]')?.focus();
      return { error: `rule "${source}": ${error}` };
    }
    rules.push(rowSnapshot(row));
  }
  return { rules: rules };
}
export function refreshInhibitionRuleRows() {
  document
    .querySelectorAll("#t-inhib-rules tbody tr.inhib-rule-row")
    .forEach((row) => {
      updateSourcePickerSummary(row);
      updateInhibitionRowFeedback(row);
    });
}
