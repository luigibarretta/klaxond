import {
  $, J, applyTablePager, escapeHtml, notifyError, notifySuccess, setInlineStatus, tr,
} from "./app.js";
import { webauthnCreateOptions, webauthnCreatePayload } from "./app-auth-webauthn.js";

let authReload = async () => {};

export function setPasskeyReload(fn) {
  authReload = fn || authReload;
}

function fmtAuthTs(ts) {
  return ts ? new Date(ts * 1000).toLocaleString() : "—";
}

export function renderPasskeys(passkeys = []) {
  const body = $("#t-passkeys tbody");
  if (!body) return;
  const readOnly = document.body.classList.contains("viewer-readonly");
  body.innerHTML = "";
  if (!passkeys.length) {
    body.innerHTML = `<tr><td colspan="5" class="muted">${escapeHtml(tr("auth.no_passkeys"))}</td></tr>`;
    applyTablePager("t-passkeys", { reset: true });
    return;
  }
  for (const key of passkeys) {
    const row = document.createElement("tr");
    row.innerHTML = `
      <td>${escapeHtml(key.name || "")}</td>
      <td>${escapeHtml(key.user_name || key.user_email || key.user_sub || "")}</td>
      <td>${escapeHtml(fmtAuthTs(key.created_at))}</td>
      <td>${escapeHtml(fmtAuthTs(key.last_used_at))}</td>
      <td><button class="danger" data-passkey-del="${escapeHtml(key.id)}" ${readOnly ? "disabled" : ""}>${escapeHtml(tr("auth.delete"))}</button></td>`;
    row.querySelector("[data-passkey-del]")?.addEventListener("click", () => deletePasskey(key.id));
    body.appendChild(row);
  }
  applyTablePager("t-passkeys", { reset: true });
}

export async function registerPasskey() {
  if (!window.PublicKeyCredential || !navigator.credentials?.create) {
    notifyError("passkey-register", new Error(tr("auth.passkey_unsupported")), { status: "#passkey-status" });
    return;
  }
  const status = $("#passkey-status");
  setInlineStatus(status, tr("status.saving"));
  try {
    const start = await J("/api/auth/passkey/register/options", {
      method: "POST",
      body: JSON.stringify({ name: $("#passkey-name").value.trim() || "passkey" }),
      headers: {"Content-Type": "application/json"},
    });
    const credential = await navigator.credentials.create({ publicKey: webauthnCreateOptions(start.publicKey) });
    await J("/api/auth/passkey/register/verify", {
      method: "POST",
      body: JSON.stringify({ request_id: start.request_id, credential: webauthnCreatePayload(credential) }),
      headers: {"Content-Type": "application/json"},
    });
    await authReload();
    notifySuccess(tr("auth.passkey_registered"), { status });
  } catch (e) {
    notifyError("passkey-register", e, { status });
  }
}

async function deletePasskey(id) {
  if (!confirm(tr("auth.passkey_delete_confirm"))) return;
  try {
    await J(`/api/auth/passkey/credentials/${encodeURIComponent(id)}`, { method: "DELETE" });
    await authReload();
    notifySuccess(tr("auth.passkey_deleted"), { status: "#passkey-status", clearMs: 3000 });
  } catch (e) {
    notifyError("passkey-delete", e, { status: "#passkey-status" });
  }
}
