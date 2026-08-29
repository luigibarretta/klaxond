import { $, apiFetch, escapeHtml, notifyError, notifySuccess, tr } from "./app.js";
import { setTabBadge } from "./app-status.js";

let incidents = [];

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
  if (action === "cancel" && !confirm(tr("emergency.cancel_confirm"))) return;
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

export async function loadEmergencies() {
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
    renderRows();
  } catch (error) {
    notifyError("emergencies", error);
  }
}

$("#emergency-filter")?.addEventListener("change", () => loadEmergencies());
$("#emergency-refresh")?.addEventListener("click", () => loadEmergencies());
