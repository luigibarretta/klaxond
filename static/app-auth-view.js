import {
  $, $$, APP_META, J, SEARCH_DEBOUNCE_MS, apiFetch, applyTablePager, debounce, errorText,
  escapeHtml, fetchError, fetchOk, getAuthPasswordPolicy, getCurrentUser, isAbortError, isPublicInfoPage,
  markTabDirty, notifyError, notifyResponseError, notifySuccess, notifyValidationError, onReady,
  queryGet, refreshTablePagers, setAuthPasswordPolicy, setInlineStatus, setLocalTotpEnabled,
  showTableRowPage, syncTabFromPath, tr, updateAllTabAccessibleLabels, updatePublicLoginLinksText,
} from "./app.js";
import { updateCurrentUserUI } from "./app-status.js";
import { loadNtfyTopics } from "./app-routing.js";
import { renderPasskeys, registerPasskey, setPasskeyReload } from "./app-auth-passkeys.js";
import { disableTotp, enableTotp, renderTotp, setTotpReload, startTotpSetup } from "./app-auth-totp.js";
import {
  authTokens, createAuthToken, renderScopePicker, renderTokens, selectedTokenScopes,
  setAuthReload, setTokenKind,
} from "./app-auth-tokens.js";
export { authTokens, renderTokens } from "./app-auth-tokens.js";

// ---- Authentication tab ----
let authData = { settings: {}, current_user: {} };

const OIDC_ISSUER_HINTS = {
  authentik: "https://idp.example.com/application/o/klaxond/",
  keycloak:  "https://idp.example.com/realms/<realm>",
  authelia:  "https://idp.example.com",
  google:    "https://accounts.google.com",
  other:     "",
};

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
  const stepUp = settings.step_up || {};
  if (stepUp.required_after_primary && ["passkey", "hardware_key"].includes(stepUp.factor || "passkey")) {
    const webauthn = settings.webauthn || {};
    if (webauthn.enabled === false) warnings.push(tr("auth.guard_step_up_webauthn"));
  }
  guard.classList.toggle("hidden", warnings.length === 0);
  guard.textContent = warnings.join(" ");
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

function applyBasicSettings(settings) {
  const basic = settings.basic || {};
  $("#auth-basic-user").value = basic.username || "";
  $("#auth-basic-realm").value = basic.realm || "klaxond";
  $("#auth-basic-pwd").value = "";
  $("#auth-basic-status").textContent = basic.password_hash === "***SET***" ? tr("auth.set") : tr("auth.not_set");
  renderTotp(basic);
}

function applyLdapSettings(settings) {
  const ldap = settings.ldap || {};
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
}

function applyOidcSettings(settings) {
  const oidc = settings.oidc || {};
  $("#auth-oidc-provider").value = oidc.provider || "authentik";
  $("#auth-oidc-issuer").value = oidc.issuer || "";
  $("#auth-oidc-cid").value = oidc.client_id || "";
  $("#auth-oidc-csec").value = "";
  $("#auth-oidc-csec-status").textContent = oidc.client_secret === "***SET***" ? tr("auth.set") : tr("auth.not_set");
  $("#auth-oidc-scopes").value = oidc.scopes || "openid profile email";
  $("#auth-oidc-group").value = oidc.required_group || "";
  $("#auth-oidc-redirect").value = oidc.redirect_path || "/api/auth/callback";
  $("#auth-oidc-full-redirect").textContent = `${location.protocol}//${location.host}${oidc.redirect_path || "/api/auth/callback"}`;
}

function applyTrustedProxySettings(settings) {
  const trustedProxy = settings.trusted_proxy || {};
  $("#auth-tp-uheader").value = trustedProxy.user_header || "X-Forwarded-User";
  $("#auth-tp-eheader").value = trustedProxy.email_header || "X-Forwarded-Email";
  $("#auth-tp-gheader").value = trustedProxy.groups_header || "X-Forwarded-Groups";
  $("#auth-tp-cidrs").value = (trustedProxy.trusted_cidrs || []).join(", ");
}

function applyWebauthnSettings(settings) {
  const webauthn = settings.webauthn || {};
  $("#auth-webauthn-enabled").checked = webauthn.enabled !== false;
  $("#auth-webauthn-origin").value = webauthn.origin || "";
  $("#auth-webauthn-rp-id").value = webauthn.rp_id || "";
  const stepUp = settings.step_up || {};
  $("#auth-step-up-required").checked = !!stepUp.required_after_primary;
  $("#auth-step-up-factor").value = stepUp.factor || "passkey";
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
    applyBasicSettings(s);
    applyLdapSettings(s);
    applyOidcSettings(s);
    applyTrustedProxySettings(s);
    applyWebauthnSettings(s);
    renderAuthGuard(s);
    renderScopePicker(j.available_token_scopes || [], selectedTokenScopes().length ? selectedTokenScopes() : ["admin:read"]);
    renderTokens(s.api_keys || []);
    renderPasskeys(s.passkeys || []);
  } catch (e) {
    notifyError("auth", e, { status: "#auth-status", inlineText: tr("auth.error_loading", { message: errorText(e) }) });
  }
}

setAuthReload(loadAuth);
setPasskeyReload(loadAuth);
setTotpReload(loadAuth);

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
    step_up: {
      required_after_primary: $("#auth-step-up-required").checked,
      factor: $("#auth-step-up-factor").value || "passkey",
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
      applyWebauthnSettings(r.settings);
      renderAuthGuard(r.settings);
    } else {
      notifyError("auth-save", new Error(r.error || "unknown"), { status: "#auth-status" });
    }
  } catch (e) {
    notifyError("auth-save", e, { status: "#auth-status" });
  }
});

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
