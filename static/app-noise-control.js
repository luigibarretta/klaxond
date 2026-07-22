import {
  $, J, applyTablePager, dirtyTabs, escapeHtml, fetchError, markTabDirty, notifyError,
  notifySuccess, notifyValidationError, queryGet, setInlineStatus, tr,
} from "./app.js";
import { GROUPING_DURATIONS, REPEAT_DURATIONS, durationOptions } from "./app-duration-options.js";
import { collectNoiseRules, renderNoiseRules } from "./app-noise-rules.js";

const SOURCES = [
  "grafana", "beszel", "healthchecks", "wud", "authentik", "shelfmark",
  "prowlarr", "decypharr",
];
const SOURCE_HELP = Object.fromEntries(SOURCES.map(source => [source, `dedup.source_${source}`]));
const SOURCE_IDENTITY = Object.fromEntries(SOURCES.map(source => [source, `dedup.identity_${source}`]));

let dedupData = {
  settings: {},
  sources: [],
  pending_counts: {},
  recent_suppressed: [],
  defaults: {},
};

export async function loadDedup() {
  if (dirtyTabs.has("grouping")) return;
  try {
    dedupData = await queryGet("dedup-config", "/api/dedup-config");
    renderDedupCards();
    markTabDirty("grouping", false);
  } catch (error) {
    const cards = $("#dedup-cards");
    if (cards) {
      cards.innerHTML = `<p class="muted">${escapeHtml(tr("dedup.error_loading", {
        message: error.message,
      }))}</p>`;
    }
    fetchError("dedup", error);
  }
}

export function renderDedupCards() {
  const container = $("#dedup-cards");
  if (!container) return;
  const sources = dedupData.sources || SOURCES;
  container.innerHTML = `<div class="noise-card-grid">${sources.map(renderSourceCard).join("")}</div>`;
  container.querySelectorAll("[data-src]").forEach(card => {
    card.querySelector(".d-mode")?.addEventListener("change", () => syncCardMode(card));
    syncCardMode(card);
  });
  renderNoiseRules(dedupData, sources);
  renderRecentSuppressions();
}

function renderSourceCard(source) {
  const setting = dedupData.settings?.[source] || dedupData.defaults?.[source] || {};
  const pending = dedupData.pending_counts?.[source] || 0;
  const mode = modeFor(setting);
  return `
    <article class="card noise-card" data-src="${escapeHtml(source)}">
      <div class="noise-card-heading">
        <h3>${escapeHtml(source.toUpperCase())}</h3>
        ${pending ? `<span class="badge warn">${escapeHtml(tr("dedup.pending", { count: pending }))}</span>` : ""}
      </div>
      <p class="muted noise-source-help">${escapeHtml(tr(SOURCE_HELP[source] || "dedup.source_generic"))}</p>
      <label class="noise-mode">
        <span>${escapeHtml(tr("dedup.mode"))}</span>
        <select class="d-mode">
          ${modeOption("immediate", mode)}
          ${modeOption("group", mode)}
          ${modeOption("suppress", mode)}
          ${modeOption("group_suppress", mode)}
        </select>
      </label>
      <fieldset class="noise-feature" data-feature="grouping">
        <legend>${escapeHtml(tr("dedup.grouping_title"))}</legend>
        <label>${escapeHtml(tr("dedup.strategy"))}
          <select class="d-strategy">
            <option value="key" ${setting.strategy === "key" ? "selected" : ""}>${escapeHtml(tr("dedup.key_recommended"))}</option>
            <option value="time" ${setting.strategy === "time" ? "selected" : ""}>${escapeHtml(tr("dedup.time"))}</option>
          </select>
        </label>
        <label>${escapeHtml(tr("dedup.grouping_window"))}
          <select class="d-window">${durationOptions(setting.window_s || 90, GROUPING_DURATIONS)}</select>
        </label>
        <label class="toggle-line" title="${escapeHtml(tr("dedup.override_title"))}">
          <input type="checkbox" class="d-override" ${setting.override_critical ? "checked" : ""}>
          <span>${escapeHtml(tr("dedup.override_critical"))}</span>
        </label>
        <small class="muted">${escapeHtml(tr(SOURCE_IDENTITY[source] || "dedup.identity_generic"))}</small>
      </fieldset>
      <fieldset class="noise-feature" data-feature="repeat">
        <legend>${escapeHtml(tr("dedup.repeat_title"))}</legend>
        <label>${escapeHtml(tr("dedup.repeat_window"))}
          <select class="d-repeat-window">${durationOptions(setting.repeat_window_s || 7200, REPEAT_DURATIONS)}</select>
        </label>
        <label class="toggle-line" title="${escapeHtml(tr("dedup.repeat_override_title"))}">
          <input type="checkbox" class="d-repeat-override" ${setting.repeat_override_critical ? "checked" : ""}>
          <span>${escapeHtml(tr("dedup.repeat_override_critical"))}</span>
        </label>
        <small class="muted">${escapeHtml(tr("dedup.repeat_identity"))}</small>
      </fieldset>
    </article>`;
}

function modeOption(value, selected) {
  return `<option value="${value}" ${value === selected ? "selected" : ""}>${escapeHtml(tr(`dedup.mode_${value}`))}</option>`;
}

function modeFor(setting) {
  const grouping = Boolean(setting.enabled) && setting.strategy !== "none";
  const repeat = Boolean(setting.repeat_suppression_enabled);
  if (grouping && repeat) return "group_suppress";
  if (grouping) return "group";
  if (repeat) return "suppress";
  return "immediate";
}

function syncCardMode(card) {
  const mode = card.querySelector(".d-mode")?.value || "immediate";
  const grouping = mode === "group" || mode === "group_suppress";
  const repeat = mode === "suppress" || mode === "group_suppress";
  setFeatureEnabled(card.querySelector('[data-feature="grouping"]'), grouping);
  setFeatureEnabled(card.querySelector('[data-feature="repeat"]'), repeat);
}

function setFeatureEnabled(feature, enabled) {
  if (!feature) return;
  feature.hidden = !enabled;
  feature.querySelectorAll("select, input").forEach(control => {
    control.disabled = !enabled;
  });
}

function renderRecentSuppressions() {
  const body = $("#t-repeat-suppressed tbody");
  if (!body) return;
  const entries = dedupData.recent_suppressed || [];
  body.innerHTML = entries.length
    ? entries.map(entry => `
      <tr>
        <td>${escapeHtml(entry.source || "")}</td>
        <td><span class="sev-${escapeHtml(entry.severity || "info")}">${escapeHtml(entry.severity || "")}</span></td>
        <td>${escapeHtml(entry.title || "")}</td>
        <td>${escapeHtml(formatTimestamp(entry.last_delivered_at))}</td>
        <td>${escapeHtml(formatTimestamp(entry.last_suppressed_at))}</td>
        <td>${escapeHtml(String(entry.suppressed_count || 0))}</td>
        <td>${escapeHtml(entry.matched_rule || tr("dedup.source_default"))}</td>
        <td>${escapeHtml(formatNextAllowed(entry.next_allowed_at))}</td>
      </tr>`).join("")
    : `<tr><td colspan="8" class="muted">${escapeHtml(tr("dedup.no_recent_suppressed"))}</td></tr>`;
  applyTablePager("t-repeat-suppressed", { reset: true });
}

function formatTimestamp(epochSeconds) {
  if (!Number.isFinite(epochSeconds)) return "—";
  return new Date(epochSeconds * 1000).toLocaleString(document.documentElement.lang || "en");
}

function formatNextAllowed(epochSeconds) {
  if (!Number.isFinite(epochSeconds)) return "—";
  return epochSeconds <= Date.now() / 1000
    ? tr("dedup.available_now")
    : new Date(epochSeconds * 1000).toLocaleString(document.documentElement.lang || "en");
}

document.querySelectorAll("[data-dedup-save]").forEach(button => {
  button.addEventListener("click", saveNoiseControl);
});

async function saveNoiseControl() {
  const selective = collectNoiseRules(SOURCES);
  if (selective.error) {
    notifyValidationError("dedup-save", selective.error, $("#dedup-status"));
    selective.element?.querySelector("input, select")?.focus();
    return;
  }
  const settings = {};
  document.querySelectorAll("#dedup-cards [data-src]").forEach(card => {
    const mode = card.querySelector(".d-mode").value;
    const grouping = mode === "group" || mode === "group_suppress";
    const repeat = mode === "suppress" || mode === "group_suppress";
    settings[card.dataset.src] = {
      enabled: grouping,
      strategy: grouping ? card.querySelector(".d-strategy").value : "none",
      window_s: Number(card.querySelector(".d-window").value) || 90,
      override_critical: card.querySelector(".d-override").checked,
      repeat_suppression_enabled: repeat,
      repeat_window_s: Number(card.querySelector(".d-repeat-window").value) || 7200,
      repeat_override_critical: card.querySelector(".d-repeat-override").checked,
      rules: selective.bySource[card.dataset.src] || [],
    };
  });
  setInlineStatus("#dedup-status", tr("status.saving"));
  try {
    const response = await J("/api/dedup-config", {
      method: "POST",
      body: JSON.stringify({ settings }),
      headers: { "Content-Type": "application/json" },
    });
    dedupData.settings = response.settings;
    renderDedupCards();
    notifySuccess(tr("dedup.saved"), { status: "#dedup-status", clearMs: 3000 });
    markTabDirty("grouping", false);
  } catch (error) {
    notifyError("dedup-save", error, { status: "#dedup-status" });
  }
}

document.querySelectorAll('[data-tab="grouping"]').forEach(button => {
  button.addEventListener("click", loadDedup);
});
