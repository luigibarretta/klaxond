import {
  $, apiFetch, confirmDialog, escapeHtml, markTabDirty, notifyError, notifySuccess,
  notifyValidationError, setInlineStatus, tr,
} from "./app.js";
import { setTabBadge } from "./app-status.js";

let incidents = [];
let policyDirty = false;

const POLICY_FIELDS = {
  enabled: ["#em-enabled", "bool"],
  severities: ["#em-severities", "list"],
  retry_seconds: ["#em-retry", "number"],
  expire_seconds: ["#em-expire", "number"],
  max_attempts: ["#em-max-attempts", "number"],
  lease_seconds: ["#em-lease", "number"],
  telegram_after_attempts: ["#em-telegram-after", "number"],
  smtp_after_attempts: ["#em-smtp-after", "number"],
  notify_on_expiry: ["#em-notify-expiry", "bool"],
  auto_resolve: ["#em-auto-resolve", "bool"],
  exclude_sources: ["#em-exclude-sources", "list"],
  allow_insecure_public_url: ["#em-allow-insecure", "bool"],
  allow_ntfy_only: ["#em-allow-ntfy-only", "bool"],
};

function when(value) {
  if (!value) return "—";
  const date = new Date(Number(value) * 1000);
  return Number.isNaN(date.getTime()) ? "—" : date.toLocaleString();
}

function remaining(value) {
  if (!value) return "—";
  const seconds = Math.round(Number(value) - Date.now() / 1000);
  if (seconds <= 0) return tr("emergency.due_now");
  if (seconds < 120) return `${seconds}s`;
  return `${Math.round(seconds / 60)}m`;
}

function renderRows() {
  const body = $("#t-emergencies tbody");
  if (!body) return;
  body.innerHTML = incidents.map(item => {
    const active = item.state === "active";
    const buttons = active ? `<div class="row">
      <button class="btn primary" data-emergency-action="ack" data-id="${escapeHtml(item.receipt_id)}">${escapeHtml(tr("emergency.ack"))}</button>
      <button class="btn" data-emergency-action="retry" data-id="${escapeHtml(item.receipt_id)}">${escapeHtml(tr("emergency.retry"))}</button>
      <button class="btn danger" data-emergency-action="cancel" data-id="${escapeHtml(item.receipt_id)}">${escapeHtml(tr("emergency.cancel"))}</button>
    </div>` : `<span class="muted">${escapeHtml(item.terminal_by || "—")}</span>`;
    const escalation = [item.telegram_escalated_at ? "TG" : "", item.smtp_escalated_at ? "SMTP" : ""].filter(Boolean).join("+");
    return `<tr>
      <td title="${escapeHtml(item.receipt_id)}">${escapeHtml(when(item.created_at))}<br><code>${escapeHtml(item.receipt_id.slice(0, 10))}</code></td>
      <td><span class="badge sev-${escapeHtml(item.state)}">${escapeHtml(item.state)}</span></td>
      <td>${escapeHtml(item.title)}${item.last_error ? `<br><small class="ch-suppressed">${escapeHtml(item.last_error)}</small>` : ""}</td>
      <td>${escapeHtml(item.source)}<br><small>${escapeHtml(item.severity)}</small></td>
      <td>${Number(item.attempts)}/${Number(item.max_attempts)}${escalation ? `<br><small>${escalation}</small>` : ""}</td>
      <td>${active ? `${escapeHtml(remaining(item.next_retry_at))}<br><small>${escapeHtml(tr("emergency.expires"))}: ${escapeHtml(remaining(item.expires_at))}</small>` : escapeHtml(when(item.terminal_at))}</td>
      <td>${buttons}</td>
    </tr>`;
  }).join("") || `<tr><td colspan="7" class="muted">${escapeHtml(tr("emergency.none"))}</td></tr>`;
  body.querySelectorAll("button[data-emergency-action]").forEach(button => button.addEventListener("click", () => transition(button)));
  $("#emergency-count").textContent = `${incidents.length}`;
  const active = incidents.filter(item => item.state === "active").length;
  setTabBadge("emergencies", active, active ? "crit" : "");
  window.applyReadOnlyViewerMode?.(window.klaxondCurrentUser || {});
}

async function transition(button) {
  const action = button.dataset.emergencyAction;
  const id = button.dataset.id;
  if (action === "cancel" && !await confirmDialog(tr("emergency.cancel_confirm"), {
    title: tr("emergency.cancel"), confirmLabel: tr("emergency.cancel"), danger: true,
  })) return;
  button.disabled = true;
  try {
    const response = await apiFetch(`/api/emergencies/${encodeURIComponent(id)}/${action}`, { method: "POST", body: "{}", headers: { "Content-Type": "application/json" } });
    if (!response.ok) throw new Error(await response.text());
    notifySuccess(tr(`emergency.${action}_ok`));
    await loadEmergencies({ force: true });
  } catch (error) {
    notifyError("emergency-transition", error);
    button.disabled = false;
  }
}

function setPolicyValue(field, value) {
  const [selector, type] = POLICY_FIELDS[field];
  const input = $(selector);
  if (!input) return;
  if (type === "bool") input.checked = !!value;
  else if (type === "list") input.value = Array.isArray(value) ? value.join(", ") : "";
  else input.value = value ?? "";
}

function renderPolicyConfig(config, force = false) {
  const settings = config.settings || {};
  if (!policyDirty || force) {
    for (const field of Object.keys(POLICY_FIELDS)) setPolicyValue(field, settings[field]);
    policyDirty = false;
    markTabDirty("emergencies", false);
  }
  const managed = config.managed_fields || {};
  for (const [field, [selector]] of Object.entries(POLICY_FIELDS)) {
    const input = $(selector);
    if (!input) continue;
    const owner = managed[field] || "";
    input.disabled = !!owner;
    input.title = owner ? tr("emergency.managed_field", { env: owner }) : "";
  }
  const notice = $("#emergency-env-notice");
  const owners = Object.entries(managed);
  notice.classList.toggle("hidden", owners.length === 0);
  notice.textContent = owners.length
    ? tr("emergency.managed_notice", { fields: owners.map(([field, env]) => `${field} (${env})`).join(", ") })
    : "";
  window.applyReadOnlyViewerMode?.(window.klaxondCurrentUser || {});
}

function policyPayload() {
  const payload = {};
  for (const [field, [selector, type]] of Object.entries(POLICY_FIELDS)) {
    const input = $(selector);
    if (!input || input.disabled) continue;
    if (type === "bool") payload[field] = input.checked;
    else if (type === "number") payload[field] = Number(input.value);
    else payload[field] = input.value.split(",").map(value => value.trim().toLowerCase()).filter(Boolean);
  }
  return payload;
}

function validatePolicy(payload) {
  for (const [field, [selector, type]] of Object.entries(POLICY_FIELDS)) {
    const input = $(selector);
    if (!input || input.disabled || type === "bool" || type === "list") continue;
    if (!input.checkValidity() || !Number.isInteger(payload[field])) {
      input.focus();
      return tr("emergency.invalid_number", { field });
    }
  }
  if (payload.severities && payload.severities.length === 0) return tr("emergency.severity_required");
  const max = payload.max_attempts ?? Number($("#em-max-attempts").value);
  if ((payload.telegram_after_attempts ?? 1) > max || (payload.smtp_after_attempts ?? 1) > max) {
    return tr("emergency.escalation_invalid");
  }
  const retry = payload.retry_seconds ?? Number($("#em-retry").value);
  const expiry = payload.expire_seconds ?? Number($("#em-expire").value);
  if (expiry < retry) return tr("emergency.expiry_invalid");
  return "";
}

async function savePolicy() {
  const payload = policyPayload();
  const invalid = validatePolicy(payload);
  if (invalid) {
    notifyValidationError("emergency-policy", invalid, "#emergency-policy-status");
    return;
  }
  if ((payload.allow_insecure_public_url || payload.allow_ntfy_only)
      && !await confirmDialog(tr("emergency.unsafe_confirm"), {
        title: tr("emergency.unsafe_options"),
        confirmLabel: tr("common.save_changes"),
        danger: true,
      })) return;
  setInlineStatus("#emergency-policy-status", tr("status.saving"));
  try {
    const response = await apiFetch("/api/emergency-config", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    if (!response.ok) throw new Error(await response.text());
    policyDirty = false;
    markTabDirty("emergencies", false);
    notifySuccess(tr("emergency.saved"), { status: "#emergency-policy-status", clearMs: 4000 });
    await loadEmergencies({ force: true });
  } catch (error) {
    notifyError("emergency-policy", error, { status: "#emergency-policy-status" });
  }
}

export async function loadEmergencies(options = {}) {
  try {
    const filter = $("#emergency-filter")?.value || "all";
    const [listResponse, configResponse] = await Promise.all([
      apiFetch(`/api/emergencies?state=${encodeURIComponent(filter)}&limit=500`),
      apiFetch("/api/emergency-config"),
    ]);
    if (!listResponse.ok) throw new Error(await listResponse.text());
    if (!configResponse.ok) throw new Error(await configResponse.text());
    const list = await listResponse.json();
    const config = await configResponse.json();
    incidents = Array.isArray(list.incidents) ? list.incidents : [];
    const settings = config.settings || {};
    $("#emergency-policy").textContent = settings.enabled
      ? `${settings.retry_seconds}s × ${settings.max_attempts}; ${Math.round(Number(settings.expire_seconds || 0) / 60)}m`
      : tr("emergency.disabled");
    const active = incidents.filter(item => item.state === "active").length;
    $("#emergency-active").textContent = String(active);
    $("#emergency-escalation").textContent = `Telegram #${settings.telegram_after_attempts ?? "—"} · SMTP #${settings.smtp_after_attempts ?? "—"}`;
    renderPolicyConfig(config, !!options.force);
    renderRows();
  } catch (error) {
    notifyError("emergencies", error);
  }
}

$("#emergency-filter")?.addEventListener("change", () => loadEmergencies());
$("#emergency-refresh")?.addEventListener("click", () => loadEmergencies({ force: !policyDirty }));
$("#emergency-policy-editor")?.addEventListener("input", event => {
  if (!event.target.closest("[data-emergency-field]")) return;
  policyDirty = true;
});
$("#emergency-policy-save")?.addEventListener("click", savePolicy);
