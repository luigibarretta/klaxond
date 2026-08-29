import {
  $, apiFetch, applyTablePager, confirmDialog, errorText, escapeHtml, fetchError, notifyError,
  notifyResponseError, notifySuccess, queryGet, setInlineStatus, tr,
} from "./app.js";
import { loadStatusActivity } from "./app-status.js";
// ---- Inhibitions (active suppressions) ----
export async function loadInhib() {
  try {
    const rows = await queryGet("inhibitions", "/api/inhibitions");
    const tb = $("#t-inhib tbody"); tb.innerHTML = "";
    if (!rows.length) {
      tb.innerHTML = `<tr><td colspan="5" class="muted">${escapeHtml(tr("inhib.no_active"))}</td></tr>`;
      applyTablePager("t-inhib", { reset: true });
      return;
    }
    for (const r of rows) {
      const row = document.createElement("tr");
      const scope = Array.isArray(r.applies_to) ? r.applies_to.join(", ") : "*";
      row.innerHTML = `<td><code>${escapeHtml(r.source)}</code></td><td>${escapeHtml(r.anchor)}</td><td><code>${escapeHtml(scope)}</code></td><td>${fmtSecs(r.expires_in_seconds)}</td><td><button class="btn" data-clear-suppression title="${escapeHtml(tr("inhib.clear_one_title"))}" style="color:var(--red); padding:2px 8px">✕</button></td>`;
      row.querySelector("[data-clear-suppression]").addEventListener("click", () => clearSuppression(r.source, r.anchor));
      tb.appendChild(row);
    }
    applyTablePager("t-inhib");
  } catch (e) { fetchError("inhibitions", e); }
}

async function clearSuppression(source, anchor) {
  const status = $("#inhib-clear-status");
  try {
    const res = await apiFetch("/api/inhibitions/clear", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({source, anchor}),
    });
    if (!res.ok) {
      notifyResponseError("inhibition-clear", res, await res.text(), status);
      return;
    }
    const r = await res.json();
    notifySuccess(tr("inhib.cleared_for_source", { count: r.cleared, source }), { status, clearMs: 3000 });
    await loadInhib();
    loadStatusActivity();
  } catch (e) {
    notifyError("inhibition-clear", e, { status, inlineText: "❌ " + errorText(e) });
  }
}


// ---- Ack-snoozes (active, 0.9.20+) ----
export async function loadAcks() {
  const tb = $("#t-acks tbody"); if (!tb) return;
  try {
    const acks = await queryGet("acks", "/api/acks");
    tb.innerHTML = "";
    if (!acks.length) {
      tb.innerHTML = `<tr><td colspan="3" class="muted">${escapeHtml(tr("inhib.no_acks"))}</td></tr>`;
      applyTablePager("t-acks", { reset: true });
      return;
    }
    for (const a of acks) {
      const row = document.createElement("tr");
      row.innerHTML = `<td><code>${escapeHtml(a.alertname)}</code></td><td>${fmtSecs(a.expires_in_seconds)}</td><td>
        <button class="btn" data-clear-ack="${escapeHtml(a.alertname)}" title="${escapeHtml(tr("inhib.clear_ack_title"))}" style="color:var(--red); padding:2px 8px">✕</button>
      </td>`;
      row.querySelector("[data-clear-ack]").addEventListener("click", () => clearAck(a.alertname));
      tb.appendChild(row);
    }
    applyTablePager("t-acks");
  } catch (e) { fetchError("acks", e); }
}

async function clearAck(alertname) {
  if (!await confirmDialog(
    `Force-clear the ACK snooze for "${alertname}"? Future alerts will resume normal delivery.`,
    { title: tr("inhib.clear_ack_title"), confirmLabel: tr("common.clear"), danger: true }
  )) return;
  try {
    const res = await apiFetch("/api/acks/clear", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({alertname}),
    });
    if (!res.ok) {
      notifyResponseError("ack-clear", res, await res.text());
      return;
    }
    const r = await res.json();
    notifySuccess(tr("inhib.ack_cleared", { count: r.cleared }), { durationMs: 3000 });
    loadAcks();
  } catch (e) {
    notifyError("ack-clear", e);
  }
}




export async function clearAllSuppressions() {
  const status = $("#inhib-clear-status");
  if (!await confirmDialog(
    "Force-clear all active suppressions? They will re-arm on the next source alert.",
    { title: tr("inhib.clear_all"), confirmLabel: tr("common.clear"), danger: true }
  )) return;
  try {
    const res = await apiFetch("/api/inhibitions/clear", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({all: true}),
    });
    if (!res.ok) {
      notifyResponseError("inhibitions-clear-all", res, await res.text(), status);
      return;
    }
    const r = await res.json();
    notifySuccess(tr("inhib.cleared_all", { count: r.cleared }), { status, clearMs: 3000 });
    await loadInhib();
    loadStatusActivity();
  } catch (e) {
    notifyError("inhibitions-clear-all", e, { status, inlineText: "❌ " + errorText(e) });
  }
}


function fmtSecs(s) {
  if (s < 60) return s + "s";
  if (s < 3600) return Math.round(s/60) + "m";
  return Math.round(s/3600 * 10) / 10 + "h";
}
