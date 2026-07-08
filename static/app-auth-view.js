import {
  $, $$, APP_META, J, SEARCH_DEBOUNCE_MS, apiFetch, applyTablePager, debounce, errorText,
  escapeHtml, fetchError, fetchOk, getAuthPasswordPolicy, getCurrentUser, isAbortError, isPublicInfoPage,
  markTabDirty, notifyError, notifyResponseError, notifySuccess, notifyValidationError, onReady,
  queryGet, refreshTablePagers, setAuthPasswordPolicy, setInlineStatus, setLocalTotpEnabled,
  showTableRowPage, syncTabFromPath, tr, updateAllTabAccessibleLabels, updatePublicLoginLinksText,
} from "./app.js";
import { updateCurrentUserUI } from "./app-status.js";
import { loadNtfyTopics } from "./app-routing.js";
import {
  authTokens, createAuthToken, renderScopePicker, renderTokens, selectedTokenScopes,
  setAuthReload, setTokenKind,
} from "./app-auth-tokens.js";
export { authTokens, renderTokens } from "./app-auth-tokens.js";

// ---- Authentication tab ----
let authData = { settings: {}, current_user: {} };
let _pendingTotpSecret = "";

const OIDC_ISSUER_HINTS = {
  authentik: "https://idp.example.com/application/o/klaxond/",
  keycloak:  "https://idp.example.com/realms/<realm>",
  authelia:  "https://idp.example.com",
  google:    "https://accounts.google.com",
  other:     "",
};

function fmtAuthTs(ts) {
  return ts ? new Date(ts * 1000).toLocaleString() : "—";
}


function renderAuthGuard(settings) {
  const guard = $("#auth-guard");
  if (!guard) return;
  const mode = settings.mode || "none";
  const warnings = [];
  if (mode === "basic") {
    const b = settings.basic || {};
    if (!b.username || b.password_hash !== "***SET***") warnings.push(tr("auth.guard_basic"));
  } else if (mode === "ldap") {
    const ldap = settings.ldap || {};
    if (!ldap.url || (!ldap.bind_dn_template && (!ldap.service_bind_dn || ldap.service_bind_password !== "***SET***"))) warnings.push(tr("auth.guard_ldap"));
  } else if (mode === "oidc") {
    const o = settings.oidc || {};
    if (!o.issuer || !o.client_id) warnings.push(tr("auth.guard_oidc"));
  } else if (mode === "trusted-proxy") {
    const tp = settings.trusted_proxy || {};
    if (!tp.user_header || !(tp.trusted_cidrs || []).length) warnings.push(tr("auth.guard_proxy"));
  }
  guard.classList.toggle("hidden", warnings.length === 0);
  guard.textContent = warnings.join(" ");
}


function renderPasskeys(passkeys = []) {
  const tb = $("#t-passkeys tbody"); if (!tb) return;
  const readOnly = document.body.classList.contains("viewer-readonly");
  tb.innerHTML = "";
  if (!passkeys.length) {
    tb.innerHTML = `<tr><td colspan="5" class="muted">${escapeHtml(tr("auth.no_passkeys"))}</td></tr>`;
    applyTablePager("t-passkeys", { reset: true });
    return;
  }
  for (const key of passkeys) {
    const trEl = document.createElement("tr");
    trEl.innerHTML = `
      <td>${escapeHtml(key.name || "")}</td>
      <td>${escapeHtml(key.user_name || key.user_email || key.user_sub || "")}</td>
      <td>${escapeHtml(fmtAuthTs(key.created_at))}</td>
      <td>${escapeHtml(fmtAuthTs(key.last_used_at))}</td>
      <td><button class="danger" data-passkey-del="${escapeHtml(key.id)}" ${readOnly ? "disabled" : ""}>${escapeHtml(tr("auth.delete"))}</button></td>`;
    trEl.querySelector("[data-passkey-del]")?.addEventListener("click", () => deletePasskey(key.id));
    tb.appendChild(trEl);
  }
  applyTablePager("t-passkeys", { reset: true });
}

function renderTotp(basic = {}) {
  const enabled = !!basic.totp_enabled;
  setLocalTotpEnabled(enabled);
  const status = $("#auth-totp-status");
  if (status) status.textContent = enabled ? tr("auth.totp_enabled") : tr("auth.totp_disabled");
  $("#totp-disable")?.toggleAttribute("disabled", !enabled || document.body.classList.contains("viewer-readonly"));
  if (!enabled) $("#totp-setup")?.classList.add("hidden");
  if (!enabled) _pendingTotpSecret = "";
}

async function startTotpSetup() {
  const status = $("#totp-status");
  setInlineStatus(status, tr("status.loading"));
  try {
    const r = await J("/api/auth/totp/setup/start", {
      method: "POST",
      body: JSON.stringify({}),
      headers: { "Content-Type": "application/json" },
    });
    _pendingTotpSecret = r.secret || "";
    $("#totp-secret").value = _pendingTotpSecret;
    $("#totp-uri").value = r.otpauth_uri || "";
    $("#totp-code").value = "";
    $("#totp-setup")?.classList.remove("hidden");
    setInlineStatus(status, tr("auth.totp_scan"), { clearMs: 6000 });
  } catch (e) {
    notifyError("totp-start", e, { status });
  }
}

async function enableTotp() {
  const status = $("#totp-status");
  const secret = _pendingTotpSecret || $("#totp-secret")?.value || "";
  const code = $("#totp-code")?.value || "";
  try {
    await J("/api/auth/totp/setup/confirm", {
      method: "POST",
      body: JSON.stringify({ secret, code }),
      headers: { "Content-Type": "application/json" },
    });
    $("#totp-setup")?.classList.add("hidden");
    await loadAuth();
    notifySuccess(tr("auth.totp_enabled_ok"), { status });
  } catch (e) {
    notifyError("totp-enable", e, { status });
  }
}

async function disableTotp() {
  if (!confirm(tr("auth.totp_disable_confirm"))) return;
  const status = $("#totp-status");
  try {
    await J("/api/auth/totp/disable", {
      method: "POST",
      body: JSON.stringify({}),
      headers: { "Content-Type": "application/json" },
    });
    await loadAuth();
    notifySuccess(tr("auth.totp_disabled_ok"), { status });
  } catch (e) {
    notifyError("totp-disable", e, { status });
  }
}

function b64urlToBuffer(s) {
  s = String(s).replace(/-/g, "+").replace(/_/g, "/");
  s += "===".slice((s.length + 3) % 4);
  const raw = atob(s);
  const out = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
  return out.buffer;
}

function bufferToB64url(buffer) {
  return btoa(String.fromCharCode(...new Uint8Array(buffer)))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function webauthnCreateOptions(publicKey) {
  publicKey.challenge = b64urlToBuffer(publicKey.challenge);
  publicKey.user.id = b64urlToBuffer(publicKey.user.id);
  (publicKey.excludeCredentials || []).forEach(cred => { cred.id = b64urlToBuffer(cred.id); });
  return publicKey;
}

function webauthnCreatePayload(credential) {
  return {
    id: credential.id,
    rawId: bufferToB64url(credential.rawId),
    type: credential.type,
    response: {
      attestationObject: bufferToB64url(credential.response.attestationObject),
      clientDataJSON: bufferToB64url(credential.response.clientDataJSON),
      transports: credential.response.getTransports ? credential.response.getTransports() : undefined,
    },
    extensions: credential.getClientExtensionResults ? credential.getClientExtensionResults() : {},
  };
}

function webauthnGetOptions(publicKey) {
  publicKey.challenge = b64urlToBuffer(publicKey.challenge);
  (publicKey.allowCredentials || []).forEach(cred => { cred.id = b64urlToBuffer(cred.id); });
  return publicKey;
}

function webauthnGetPayload(credential) {
  return {
    id: credential.id,
    rawId: bufferToB64url(credential.rawId),
    type: credential.type,
    response: {
      authenticatorData: bufferToB64url(credential.response.authenticatorData),
      clientDataJSON: bufferToB64url(credential.response.clientDataJSON),
      signature: bufferToB64url(credential.response.signature),
      userHandle: credential.response.userHandle ? bufferToB64url(credential.response.userHandle) : null,
    },
    extensions: credential.getClientExtensionResults ? credential.getClientExtensionResults() : {},
  };
}

async function loadAuthPasswordPolicy() {
  try {
    const policy = await J("/api/auth/password-policy");
    const min = Number(policy?.min_length);
    const max = Number(policy?.max_length);
    setAuthPasswordPolicy({
      min_length: Number.isFinite(min) && min > 0 ? min : 12,
      max_length: Number.isFinite(max) && max >= min ? max : 1024,
    });
  } catch (e) {
    setAuthPasswordPolicy({ min_length: 12, max_length: 1024 });
  }
  applyAuthPasswordPolicy();
}

function applyAuthPasswordPolicy() {
  const input = $("#auth-basic-pwd");
  if (!input) return;
  const policy = getAuthPasswordPolicy();
  input.minLength = policy.min_length;
  input.maxLength = policy.max_length;
  const hint = $("#auth-basic-pwd-policy");
  if (hint) hint.textContent = tr("auth.password_min_hint", { min: policy.min_length });
}

function _showSubcard(mode) {
  const map = {
    none: [],
    basic: ["auth-basic-h", "auth-basic-card"],
    ldap: ["auth-ldap-h", "auth-ldap-card"],
    oidc:  ["auth-oidc-h", "auth-oidc-card"],
    "trusted-proxy": ["auth-tp-h", "auth-tp-card"],
  };
  for (const id of ["auth-basic-h","auth-basic-card","auth-ldap-h","auth-ldap-card","auth-oidc-h","auth-oidc-card","auth-tp-h","auth-tp-card"]) {
    document.getElementById(id)?.classList.add("hidden");
  }
  for (const id of (map[mode] || [])) {
    document.getElementById(id)?.classList.remove("hidden");
  }
}

export async function loadAuth() {
  try {
    await loadAuthPasswordPolicy();
    const j = await J("/api/auth/config");
    authData = j;
    const s = j.settings || {};
    document.querySelectorAll('input[name="auth-mode"]').forEach(r => {
      r.checked = (r.value === (s.mode || "none"));
    });
    _showSubcard(s.mode || "none");
    $("#auth-jwt-warn")?.classList.toggle("hidden", !!j.jwt_available);
    $("#auth-session-h").value = s.session_timeout_hours || 8;
    const cu = j.current_user || {};
    updateCurrentUserUI(cu);
    // basic
    const b = s.basic || {};
    $("#auth-basic-user").value = b.username || "";
    $("#auth-basic-realm").value = b.realm || "klaxond";
    $("#auth-basic-pwd").value = "";
    $("#auth-basic-status").textContent = b.password_hash === "***SET***" ? tr("auth.set") : tr("auth.not_set");
    renderTotp(b);
    // ldap
    const ldap = s.ldap || {};
    $("#auth-ldap-url").value = ldap.url || "";
    $("#auth-ldap-bind-template").value = ldap.bind_dn_template || "";
    $("#auth-ldap-service-dn").value = ldap.service_bind_dn || "";
    $("#auth-ldap-service-password").value = "";
    $("#auth-ldap-service-status").textContent = ldap.service_bind_password === "***SET***" ? tr("auth.set") : tr("auth.not_set");
    $("#auth-ldap-base-dn").value = ldap.base_dn || "";
    $("#auth-ldap-user-filter").value = ldap.user_filter || "(|(uid={username})(sAMAccountName={username})(mail={username}))";
    $("#auth-ldap-scope").value = ldap.scope || "subtree";
    $("#auth-ldap-timeout").value = ldap.timeout_secs || 5;
    $("#auth-ldap-username-attr").value = ldap.username_attr || "uid";
    $("#auth-ldap-email-attr").value = ldap.email_attr || "mail";
    $("#auth-ldap-name-attr").value = ldap.name_attr || "cn";
    $("#auth-ldap-groups-attr").value = ldap.groups_attr || "memberOf";
    // oidc
    const o = s.oidc || {};
    $("#auth-oidc-provider").value = o.provider || "authentik";
    $("#auth-oidc-issuer").value = o.issuer || "";
    $("#auth-oidc-cid").value = o.client_id || "";
    $("#auth-oidc-csec").value = "";
    $("#auth-oidc-csec-status").textContent = o.client_secret === "***SET***" ? tr("auth.set") : tr("auth.not_set");
    $("#auth-oidc-scopes").value = o.scopes || "openid profile email";
    $("#auth-oidc-group").value = o.required_group || "";
    $("#auth-oidc-redirect").value = o.redirect_path || "/api/auth/callback";
    $("#auth-oidc-full-redirect").textContent = `${location.protocol}//${location.host}${o.redirect_path || "/api/auth/callback"}`;
    // trusted-proxy
    const tp = s.trusted_proxy || {};
    $("#auth-tp-uheader").value = tp.user_header || "X-Forwarded-User";
    $("#auth-tp-eheader").value = tp.email_header || "X-Forwarded-Email";
    $("#auth-tp-gheader").value = tp.groups_header || "X-Forwarded-Groups";
    $("#auth-tp-cidrs").value = (tp.trusted_cidrs || []).join(", ");
    const w = s.webauthn || {};
    $("#auth-webauthn-enabled").checked = w.enabled !== false;
    $("#auth-webauthn-origin").value = w.origin || "";
    $("#auth-webauthn-rp-id").value = w.rp_id || "";
    renderAuthGuard(s);
    renderScopePicker(j.available_token_scopes || [], selectedTokenScopes().length ? selectedTokenScopes() : ["admin:read"]);
    renderTokens(s.api_keys || []);
    renderPasskeys(s.passkeys || []);
  } catch (e) {
    notifyError("auth", e, { status: "#auth-status", inlineText: tr("auth.error_loading", { message: errorText(e) }) });
  }
}

setAuthReload(loadAuth);

document.querySelectorAll('input[name="auth-mode"]').forEach(r => {
  r.addEventListener("change", () => _showSubcard(r.value));
});
document.getElementById("auth-oidc-provider")?.addEventListener("change", e => {
  const hint = OIDC_ISSUER_HINTS[e.target.value] || "";
  if (hint) $("#auth-oidc-issuer").placeholder = hint;
});
document.querySelectorAll("[data-token-kind-option]").forEach(btn => {
  btn.addEventListener("click", () => setTokenKind(btn.dataset.tokenKindOption));
});

$("#auth-save")?.addEventListener("click", async () => {
  const mode = document.querySelector('input[name="auth-mode"]:checked')?.value || "none";
  const basicPassword = $("#auth-basic-pwd").value;
  const passwordPolicy = getAuthPasswordPolicy();
  if (basicPassword && basicPassword.length < passwordPolicy.min_length) {
    notifyError(
      "auth-save",
      new Error(tr("auth.password_min_hint", { min: passwordPolicy.min_length })),
      { status: "#auth-status" },
    );
    return;
  }
  const out = {
    mode,
    session_timeout_hours: parseInt($("#auth-session-h").value, 10) || 8,
    basic: {
      username: $("#auth-basic-user").value.trim(),
      realm:    $("#auth-basic-realm").value.trim(),
      password: basicPassword,  // empty = keep
    },
    oidc: {
      provider:       $("#auth-oidc-provider").value,
      issuer:         $("#auth-oidc-issuer").value.trim(),
      client_id:      $("#auth-oidc-cid").value.trim(),
      client_secret:  $("#auth-oidc-csec").value,  // empty = keep
      scopes:         $("#auth-oidc-scopes").value.trim(),
      required_group: $("#auth-oidc-group").value.trim(),
      redirect_path:  $("#auth-oidc-redirect").value.trim() || "/api/auth/callback",
    },
    ldap: {
      url: $("#auth-ldap-url").value.trim(),
      bind_dn_template: $("#auth-ldap-bind-template").value.trim(),
      service_bind_dn: $("#auth-ldap-service-dn").value.trim(),
      service_bind_password: $("#auth-ldap-service-password").value,
      base_dn: $("#auth-ldap-base-dn").value.trim(),
      user_filter: $("#auth-ldap-user-filter").value.trim(),
      scope: $("#auth-ldap-scope").value,
      timeout_secs: parseInt($("#auth-ldap-timeout").value, 10) || 5,
      username_attr: $("#auth-ldap-username-attr").value.trim(),
      email_attr: $("#auth-ldap-email-attr").value.trim(),
      name_attr: $("#auth-ldap-name-attr").value.trim(),
      groups_attr: $("#auth-ldap-groups-attr").value.trim(),
    },
    trusted_proxy: {
      user_header:   $("#auth-tp-uheader").value.trim(),
      email_header:  $("#auth-tp-eheader").value.trim(),
      groups_header: $("#auth-tp-gheader").value.trim(),
      trusted_cidrs: $("#auth-tp-cidrs").value.split(",").map(x => x.trim()).filter(Boolean),
    },
    webauthn: {
      enabled: $("#auth-webauthn-enabled").checked,
      origin: $("#auth-webauthn-origin").value.trim(),
      rp_id: $("#auth-webauthn-rp-id").value.trim(),
    },
  };
  setInlineStatus("#auth-status", tr("status.saving"));
  try {
    const r = await J("/api/auth/config", {
      method: "POST",
      body: JSON.stringify({ settings: out }),
      headers: { "Content-Type": "application/json" },
    });
    if (r.ok) {
      notifySuccess(tr("auth.saved", { mode: r.settings.mode }), { status: "#auth-status" });
      markTabDirty("auth", false);
      authData.settings = r.settings;
      _showSubcard(r.settings.mode);
      renderAuthGuard(r.settings);
    } else {
      notifyError("auth-save", new Error(r.error || "unknown"), { status: "#auth-status" });
    }
  } catch (e) {
    notifyError("auth-save", e, { status: "#auth-status" });
  }
});


async function registerPasskey() {
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
    await loadAuth();
    notifySuccess(tr("auth.passkey_registered"), { status });
  } catch (e) {
    notifyError("passkey-register", e, { status });
  }
}

async function deletePasskey(id) {
  if (!confirm(tr("auth.passkey_delete_confirm"))) return;
  try {
    await J(`/api/auth/passkey/credentials/${encodeURIComponent(id)}`, { method: "DELETE" });
    await loadAuth();
    notifySuccess(tr("auth.passkey_deleted"), { status: "#passkey-status", clearMs: 3000 });
  } catch (e) {
    notifyError("passkey-delete", e, { status: "#passkey-status" });
  }
}

$("#token-create")?.addEventListener("click", createAuthToken);
$("#passkey-register")?.addEventListener("click", registerPasskey);
$("#totp-start")?.addEventListener("click", startTotpSetup);
$("#totp-enable")?.addEventListener("click", enableTotp);
$("#totp-disable")?.addEventListener("click", disableTotp);

document.querySelectorAll('[data-tab="auth"]').forEach(btn => {
  btn.addEventListener("click", () => { loadAuth(); });
});
document.querySelectorAll('[data-tab="routing"]').forEach(btn => {
  btn.addEventListener("click", () => { loadNtfyTopics(); });
});


// ---- Flow tab ----
// Dynamic Mermaid diagram from all configs. Click nodes → switch tab.
// Stats overlay reads /api/deliveries (24h window).
