import { escapeHtml, tr } from "./app.js";

export const GROUPING_DURATIONS = [5, 15, 30, 60, 90, 120, 300, 600, 900, 1800, 3600];
export const REPEAT_DURATIONS = [300, 900, 1800, 3600, 7200, 21600, 43200, 86400, 172800, 604800];

export function durationOptions(current, presets) {
  const value = Number(current);
  const values = presets.includes(value)
    ? presets
    : [...presets, value].filter(item => Number.isFinite(item) && item > 0).sort((a, b) => a - b);
  return values.map(item => (
    `<option value="${item}" ${item === value ? "selected" : ""}>${escapeHtml(durationLabel(item))}</option>`
  )).join("");
}

export function durationLabel(seconds) {
  if (seconds % 86400 === 0) return tr("dedup.duration_days", { count: seconds / 86400 });
  if (seconds % 3600 === 0) return tr("dedup.duration_hours", { count: seconds / 3600 });
  if (seconds % 60 === 0) return tr("dedup.duration_minutes", { count: seconds / 60 });
  return tr("dedup.duration_seconds", { count: seconds });
}
