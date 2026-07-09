import {
  $, J, notifyError, notifySuccess, setInlineStatus, setLocalTotpEnabled, tr,
} from "./app.js";

let authReload = async () => {};
let pendingTotpSecret = "";

export function setTotpReload(fn) {
  authReload = fn || authReload;
}

export function renderTotp(basic = {}) {
  const enabled = !!basic.totp_enabled;
  setLocalTotpEnabled(enabled);
  const status = $("#auth-totp-status");
  if (status) status.textContent = enabled ? tr("auth.totp_enabled") : tr("auth.totp_disabled");
  $("#totp-disable")?.toggleAttribute("disabled", !enabled || document.body.classList.contains("viewer-readonly"));
  if (!enabled) $("#totp-setup")?.classList.add("hidden");
  if (!enabled) pendingTotpSecret = "";
}

export async function startTotpSetup() {
  const status = $("#totp-status");
  setInlineStatus(status, tr("status.loading"));
  try {
    const response = await J("/api/auth/totp/setup/start", {
      method: "POST",
      body: JSON.stringify({}),
      headers: { "Content-Type": "application/json" },
    });
    pendingTotpSecret = response.secret || "";
    $("#totp-secret").value = pendingTotpSecret;
    $("#totp-uri").value = response.otpauth_uri || "";
    $("#totp-code").value = "";
    $("#totp-setup")?.classList.remove("hidden");
    setInlineStatus(status, tr("auth.totp_scan"), { clearMs: 6000 });
  } catch (e) {
    notifyError("totp-start", e, { status });
  }
}

export async function enableTotp() {
  const status = $("#totp-status");
  const secret = pendingTotpSecret || $("#totp-secret")?.value || "";
  const code = $("#totp-code")?.value || "";
  try {
    await J("/api/auth/totp/setup/confirm", {
      method: "POST",
      body: JSON.stringify({ secret, code }),
      headers: { "Content-Type": "application/json" },
    });
    $("#totp-setup")?.classList.add("hidden");
    await authReload();
    notifySuccess(tr("auth.totp_enabled_ok"), { status });
  } catch (e) {
    notifyError("totp-enable", e, { status });
  }
}

export async function disableTotp() {
  if (!confirm(tr("auth.totp_disable_confirm"))) return;
  const status = $("#totp-status");
  try {
    await J("/api/auth/totp/disable", {
      method: "POST",
      body: JSON.stringify({}),
      headers: { "Content-Type": "application/json" },
    });
    await authReload();
    notifySuccess(tr("auth.totp_disabled_ok"), { status });
  } catch (e) {
    notifyError("totp-disable", e, { status });
  }
}
