import {
  $, $$, APP_META, J, SEARCH_DEBOUNCE_MS, apiFetch, applyTablePager, debounce, errorText,
  confirmDialog, escapeHtml, fetchError, fetchOk, getAuthPasswordPolicy, getCurrentUser,
  isAbortError, isPublicInfoPage,
  markTabDirty, notifyError, notifyResponseError, notifySuccess, notifyValidationError, onReady,
  queryGet, refreshTablePagers, setAuthPasswordPolicy, setInlineStatus, setLocalTotpEnabled,
  showTableRowPage, syncTabFromPath, tr, updateAllTabAccessibleLabels, updatePublicLoginLinksText,
} from "./app.js";

// ---- Setup / diagnostics ----
export async function loadSetup(opts = {}) {
  try {
    const [setup, history] = await Promise.all([
      queryGet("setup-status", "/api/setup-status", { force: opts.force, cancelPrevious: false }),
      queryGet("history-config", "/api/history-config", { force: opts.force, cancelPrevious: false }),
    ]);
    renderSetupChecklist(setup);
    renderChannelMatrix(setup.matrix || { channels: [] });
    renderHistoryConfig(history);
  } catch (e) {
    fetchError("setup", e);
    const box = $("#setup-checklist");
    if (box) box.innerHTML = `<p class="muted">${escapeHtml(tr("common.error"))}: ${escapeHtml(errorText(e))}</p>`;
  }
}

let historyConfig = { settings: {}, managed_fields: {} };

function renderHistoryConfig(payload) {
  historyConfig = payload || historyConfig;
  const settings = historyConfig.settings || {};
  $("#history-backend").value = settings.backend || "sqlite";
  $("#history-sqlite-path").value = settings.sqlite_path || "";
  $("#history-postgres-url").value = "";
  $("#history-postgres-url").placeholder = settings.postgres_url_configured ? "••••••••" : "postgres://user:password@db:5432/klaxond";
  $("#history-postgres-clear").checked = false;
  $("#history-postgres-status").textContent = settings.postgres_url_configured
    ? tr("history.postgres_configured", { target: settings.postgres_target || "PostgreSQL" })
    : tr("history.postgres_missing");
  $("#history-retention").value = settings.retention ?? 5000;
  $("#history-default-limit").value = settings.default_limit ?? 500;
  const managed = historyConfig.managed_fields || {};
  document.querySelectorAll("[data-history-field]").forEach(input => {
    const owner = managed[input.dataset.historyField] || "";
    input.disabled = !!owner;
    input.title = owner ? tr("emergency.managed_field", { env: owner }) : "";
  });
  $("#history-postgres-clear").disabled = !!managed.postgres_url;
  const owners = Object.entries(managed);
  $("#history-env-notice").classList.toggle("hidden", owners.length === 0);
  $("#history-env-notice").textContent = owners.length
    ? tr("history.managed_notice", { fields: owners.map(([field, env]) => `${field} (${env})`).join(", ") })
    : "";
  window.applyReadOnlyViewerMode?.(window.klaxondCurrentUser || {});
}

async function saveHistoryConfig() {
  const payload = {};
  const backend = $("#history-backend");
  const postgres = $("#history-postgres-url");
  const retention = $("#history-retention");
  const defaultLimit = $("#history-default-limit");
  if (!backend.disabled) payload.backend = backend.value;
  if (!postgres.disabled) {
    if ($("#history-postgres-clear").checked) payload.postgres_url = "";
    else if (postgres.value.trim()) payload.postgres_url = postgres.value.trim();
  }
  if (!retention.disabled) payload.retention = Number(retention.value);
  if (!defaultLimit.disabled) payload.default_limit = Number(defaultLimit.value);
  for (const input of [retention, defaultLimit]) {
    if (!input.disabled && (!input.checkValidity() || !Number.isInteger(Number(input.value)))) {
      input.focus();
      notifyValidationError("history-config", tr("history.invalid_number"), "#history-status");
      return;
    }
  }
  const existing = historyConfig.settings || {};
  if ((payload.backend || existing.backend) === "postgres"
      && !(payload.postgres_url || existing.postgres_url_configured)) {
    notifyValidationError("history-config", tr("history.postgres_required"), "#history-status");
    postgres.focus();
    return;
  }
  if (payload.backend && payload.backend !== existing.backend
      && !await confirmDialog(tr("history.switch_confirm", {
        from: existing.backend || "—", to: payload.backend,
      }), { title: tr("history.switch_title"), confirmLabel: tr("common.save_changes") })) return;
  setInlineStatus("#history-status", tr("status.saving"));
  try {
    const response = await apiFetch("/api/history-config", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    if (!response.ok) throw new Error(await response.text());
    const result = await response.json();
    renderHistoryConfig(result.config || historyConfig);
    markTabDirty("setup", false);
    notifySuccess(tr("history.saved"), { status: "#history-status", clearMs: 4000 });
  } catch (error) {
    notifyError("history-config", error, { status: "#history-status" });
  }
}

function statusBadge(status) {
  const label = status || "info";
  const cls = label === "ok" ? "info" : label === "error" ? "error" : "warn";
  const key = `setup.status.${label}`;
  const translated = tr(key);
  return `<span class="log-level ${cls}">${escapeHtml(translated === key ? label : translated)}</span>`;
}

function renderSetupChecklist(payload) {
  const box = $("#setup-checklist"); if (!box) return;
  const items = payload.items || [];
  const summary = payload.summary || {};
  $("#setup-summary").textContent = tr("setup.summary", {
    errors: payload.summary?.errors || 0,
    warnings: payload.summary?.warnings || 0,
    blocking: summary.blocking || 0,
  });
  $("#setup-progress").textContent = tr("setup.progress", {
    complete: summary.complete || 0,
    required: summary.required || 0,
  });
  $("#setup-ready-label").textContent = payload.ready ? tr("setup.ready") : tr("setup.action_required");
  $("#setup-readiness").classList.toggle("ready", !!payload.ready);
  $("#setup-readiness").classList.toggle("blocked", !payload.ready);
  const next = $("#setup-next");
  const nextAction = payload.next_action || null;
  next.classList.toggle("hidden", !nextAction);
  if (nextAction) {
    next.href = nextAction.path || "/setup";
    next.textContent = setupActionLabel(nextAction);
  }
  window.setTabBadge?.("setup", summary.blocking || 0, summary.blocking ? "warn" : "");
  const required = items.filter(item => item.required !== false);
  const optional = items.filter(item => item.required === false);
  const renderItems = (group, isOptional) => group.map((item, index) => `
    <div class="setup-item">
      ${isOptional
        ? `<div class="setup-step-label">${escapeHtml(tr("setup.recommended_badge"))}</div>`
        : `<div class="setup-step-number" aria-hidden="true">${index + 1}</div>`}
      <div>
        <div class="setup-item-heading"><strong>${escapeHtml(setupItemLabel(item))}</strong>${statusBadge(item.status)}</div>
        <p class="muted">${escapeHtml(setupItemDetail(item))}</p>
        ${item.action?.path ? `<a class="btn setup-item-action" href="${escapeHtml(item.action.path)}">${escapeHtml(setupActionLabel(item.action))}</a>` : ""}
      </div>
    </div>`).join("");
  const renderGroup = (key, group, isOptional) => group.length ? `
    <section class="setup-group" data-setup-group="${key}">
      <h3 class="setup-group-heading">${escapeHtml(tr(`setup.${key}_title`))}</h3>
      <p class="muted setup-group-description">${escapeHtml(tr(`setup.${key}_desc`))}</p>
      <div class="setup-items">${renderItems(group, isOptional)}</div>
    </section>` : "";
  box.innerHTML = renderGroup("required", required, false) + renderGroup("recommended", optional, true);
}

function setupActionLabel(action) {
  const key = action?.key ? `setup.action.${action.key}` : "setup.configure";
  const translated = tr(key);
  return translated === key ? (action?.label || tr("setup.configure")) : translated;
}

function setupItemLabel(item) {
  const key = `setup.item.${item.key}`;
  const translated = tr(key);
  return translated === key ? (item.label || item.key || "") : translated;
}

function setupItemDetail(item) {
  const key = `setup.detail.${item.key}.${item.status || "info"}`;
  const values = item.values || {};
  const translated = tr(key, { ...values, detail: item.detail || "" });
  return translated === key ? (item.detail || "") : translated;
}

function renderChannelMatrix(payload) {
  const tb = $("#t-channel-matrix tbody"); if (!tb) return;
  tb.innerHTML = "";
  for (const channel of (payload.channels || [])) {
    const row = document.createElement("tr");
    row.innerHTML = `
      <td><code>${escapeHtml(channel.name || "")}</code></td>
      <td>${channel.configured ? escapeHtml(tr("common.configured")) : escapeHtml(tr("common.missing"))}</td>
      <td>${channel.reachable ? escapeHtml(tr("channel.up")) : escapeHtml(tr("channel.down"))}</td>
      <td><code>${escapeHtml(channel.endpoint || "—")}</code></td>
      <td>${(channel.checks || []).map(x => `<code>${escapeHtml(x)}</code>`).join(" ")}</td>`;
    tb.appendChild(row);
  }
  if (!(payload.channels || []).length) {
    tb.innerHTML = `<tr><td colspan="5" class="muted">${escapeHtml(tr("matrix.empty"))}</td></tr>`;
  }
  applyTablePager("t-channel-matrix", { reset: true });
}

onReady(() => {
  $("#setup-refresh")?.addEventListener("click", () => loadSetup({ force: true }));
  $("#history-save")?.addEventListener("click", saveHistoryConfig);
});

// ---- Policy simulator ----
function parseLabelLines(raw) {
  const labels = {};
  String(raw || "").split(/\r?\n/).forEach(line => {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) return;
    const idx = trimmed.indexOf("=");
    if (idx <= 0) return;
    labels[trimmed.slice(0, idx).trim()] = trimmed.slice(idx + 1).trim();
  });
  return labels;
}

export async function runPolicySimulation(opts = {}) {
  const status = $("#policy-sim-status");
  if (!opts.silent) setInlineStatus(status, tr("status.testing"));
  try {
    const payload = {
      source: $("#policy-sim-source")?.value || "grafana",
      severity: $("#policy-sim-severity")?.value || "warning",
      labels: parseLabelLines($("#policy-sim-labels")?.value || ""),
    };
    const result = await J("/api/policy-simulate", {
      method: "POST",
      body: JSON.stringify(payload),
      headers: {"Content-Type": "application/json"},
    });
    $("#policy-sim-output").textContent = JSON.stringify(result, null, 2);
    setInlineStatus(status, tr("sim.done"));
  } catch (e) {
    if (!opts.silent) notifyError("policy-simulate", e, { status });
    $("#policy-sim-output").textContent = `${tr("common.error")}: ${errorText(e)}`;
  }
}

onReady(() => {
  $("#policy-sim-run")?.addEventListener("click", () => runPolicySimulation());
});
