import { apiFetch } from "./app.js";

const validationTimers = new WeakMap();
const validationPromises = new WeakMap();

function notify(row) {
  row.dispatchEvent(new CustomEvent("klaxond:regex-validation"));
}

async function validateWithServer(row, pattern) {
  if (!pattern) return;
  row.dataset.regexValue = pattern;
  row.dataset.regexState = "pending";
  delete row.dataset.regexError;
  notify(row);
  const promise = apiFetch("/api/inhibition-rules/validate-regex", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ pattern }),
    __skipQueryInvalidation: true,
  });
  validationPromises.set(row, promise);
  try {
    const response = await promise;
    if (row.querySelector('[data-k="match_regex"]')?.value.trim() !== pattern) return;
    if (response.ok) {
      row.dataset.regexState = "valid";
    } else {
      const payload = await response.json().catch(() => ({}));
      row.dataset.regexState = "invalid";
      row.dataset.regexError = payload.error || response.statusText;
    }
  } catch (error) {
    if (row.querySelector('[data-k="match_regex"]')?.value.trim() !== pattern) return;
    row.dataset.regexState = "unavailable";
  } finally {
    if (validationPromises.get(row) === promise) validationPromises.delete(row);
    notify(row);
  }
}

export function scheduleRegexValidation(row) {
  clearTimeout(validationTimers.get(row));
  const pattern = row.querySelector('[data-k="match_regex"]')?.value.trim() || "";
  if (!pattern) {
    delete row.dataset.regexValue;
    delete row.dataset.regexState;
    delete row.dataset.regexError;
    notify(row);
    return;
  }
  row.dataset.regexValue = pattern;
  row.dataset.regexState = "pending";
  notify(row);
  const timer = setTimeout(() => validateWithServer(row, pattern), 300);
  validationTimers.set(row, timer);
}

export async function validateAllInhibitionRegexes() {
  const rows = Array.from(document.querySelectorAll("#t-inhib-rules tbody tr.inhib-rule-row"));
  await Promise.all(rows.map(async row => {
    if (row.querySelector('[data-k="match_type"]')?.value !== "match_label") return;
    const pattern = row.querySelector('[data-k="match_regex"]')?.value.trim() || "";
    if (!pattern) return;
    clearTimeout(validationTimers.get(row));
    await validateWithServer(row, pattern);
  }));
}
