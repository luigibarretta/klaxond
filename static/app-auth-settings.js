import { $, J, getAuthPasswordPolicy, setAuthPasswordPolicy, tr } from "./app.js";
import { renderTotp } from "./app-auth-totp.js";
export const OIDC_ISSUER_HINTS = {
  authentik: "https://idp.example.com/application/o/klaxond/",
  keycloak: "https://idp.example.com/realms/<realm>",
  authelia: "https://idp.example.com",
  google: "https://accounts.google.com",
  other: "",
};
export function renderAuthGuard(settings) {
  const guard = $("#auth-guard");
  if (!guard) return;
  const mode = settings.mode || "none";
  const warnings = [];
  if (mode === "basic") {
    const b = settings.basic || {};
    if (!b.username || b.password_hash !== "***SET***")
      warnings.push(tr("auth.guard_basic"));
  } else if (mode === "ldap") {
    const ldap = settings.ldap || {};
    if (
      !ldap.url ||
      (!ldap.bind_dn_template &&
        (!ldap.service_bind_dn || ldap.service_bind_password !== "***SET***"))
    )
      warnings.push(tr("auth.guard_ldap"));
  } else if (mode === "oidc") {
    const o = settings.oidc || {};
    if (!o.issuer || !o.client_id) warnings.push(tr("auth.guard_oidc"));
  } else if (mode === "trusted-proxy") {
    const tp = settings.trusted_proxy || {};
    if (!tp.user_header || !(tp.trusted_cidrs || []).length)
      warnings.push(tr("auth.guard_proxy"));
  }
  const stepUp = settings.step_up || {};
  if (
    stepUp.required_after_primary &&
    ["passkey", "hardware_key"].includes(stepUp.factor || "passkey")
  ) {
    const webauthn = settings.webauthn || {};
    if (webauthn.enabled === false)
      warnings.push(tr("auth.guard_step_up_webauthn"));
  }
  guard.classList.toggle("hidden", warnings.length === 0);
  guard.textContent = warnings.join(" ");
}
export async function loadAuthPasswordPolicy() {
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
export function applyAuthPasswordPolicy() {
  const input = $("#auth-basic-pwd");
  if (!input) return;
  const policy = getAuthPasswordPolicy();
  input.minLength = policy.min_length;
  input.maxLength = policy.max_length;
  const hint = $("#auth-basic-pwd-policy");
  if (hint)
    hint.textContent = tr("auth.password_min_hint", { min: policy.min_length });
}
export function showAuthSubcard(mode) {
  const map = {
    none: [],
    basic: ["auth-basic-h", "auth-basic-card"],
    ldap: ["auth-ldap-h", "auth-ldap-card"],
    oidc: ["auth-oidc-h", "auth-oidc-card"],
    "trusted-proxy": ["auth-tp-h", "auth-tp-card"],
  };
  for (const id of [
    "auth-basic-h",
    "auth-basic-card",
    "auth-ldap-h",
    "auth-ldap-card",
    "auth-oidc-h",
    "auth-oidc-card",
    "auth-tp-h",
    "auth-tp-card",
  ]) {
    document.getElementById(id)?.classList.add("hidden");
  }
  for (const id of map[mode] || []) {
    document.getElementById(id)?.classList.remove("hidden");
  }
}
function applyBasicSettings(settings) {
  const basic = settings.basic || {};
  $("#auth-basic-user").value = basic.username || "";
  $("#auth-basic-realm").value = basic.realm || "klaxond";
  $("#auth-basic-pwd").value = "";
  $("#auth-basic-status").textContent =
    basic.password_hash === "***SET***" ? tr("auth.set") : tr("auth.not_set");
  renderTotp(basic);
}
function applyLdapSettings(settings) {
  const ldap = settings.ldap || {};
  $("#auth-ldap-url").value = ldap.url || "";
  $("#auth-ldap-bind-template").value = ldap.bind_dn_template || "";
  $("#auth-ldap-service-dn").value = ldap.service_bind_dn || "";
  $("#auth-ldap-service-password").value = "";
  $("#auth-ldap-service-status").textContent =
    ldap.service_bind_password === "***SET***"
      ? tr("auth.set")
      : tr("auth.not_set");
  $("#auth-ldap-base-dn").value = ldap.base_dn || "";
  $("#auth-ldap-user-filter").value =
    ldap.user_filter ||
    "(|(uid={username})(sAMAccountName={username})(mail={username}))";
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
  $("#auth-oidc-csec-status").textContent =
    oidc.client_secret === "***SET***" ? tr("auth.set") : tr("auth.not_set");
  $("#auth-oidc-scopes").value = oidc.scopes || "openid profile email";
  $("#auth-oidc-group").value = oidc.required_group || "";
  $("#auth-oidc-redirect").value = oidc.redirect_path || "/api/auth/callback";
  $("#auth-oidc-full-redirect").textContent =
    `${location.protocol}//${location.host}${oidc.redirect_path || "/api/auth/callback"}`;
}
function applyTrustedProxySettings(settings) {
  const trustedProxy = settings.trusted_proxy || {};
  $("#auth-tp-uheader").value = trustedProxy.user_header || "X-Forwarded-User";
  $("#auth-tp-eheader").value =
    trustedProxy.email_header || "X-Forwarded-Email";
  $("#auth-tp-gheader").value =
    trustedProxy.groups_header || "X-Forwarded-Groups";
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
export function applyAuthConfiguration(settings) {
  document.querySelectorAll('input[name="auth-mode"]').forEach((radio) => {
    radio.checked = radio.value === (settings.mode || "none");
  });
  showAuthSubcard(settings.mode || "none");
  $("#auth-session-h").value = settings.session_timeout_hours || 8;
  applyBasicSettings(settings);
  applyLdapSettings(settings);
  applyOidcSettings(settings);
  applyTrustedProxySettings(settings);
  applyWebauthnSettings(settings);
  renderAuthGuard(settings);
}
