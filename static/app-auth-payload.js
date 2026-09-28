import { $ } from "./app.js";
export function collectAuthSettings() {
  const mode = document.querySelector('input[name="auth-mode"]:checked')?.value || "none";
  const basicPassword = $("#auth-basic-pwd").value;
  const settings = {
    mode: mode,
    session_timeout_hours: parseInt($("#auth-session-h").value, 10) || 8,
    basic: {
      username: $("#auth-basic-user").value.trim(),
      realm: $("#auth-basic-realm").value.trim(),
      password: basicPassword,
    },
    oidc: {
      provider: $("#auth-oidc-provider").value,
      issuer: $("#auth-oidc-issuer").value.trim(),
      client_id: $("#auth-oidc-cid").value.trim(),
      client_secret: $("#auth-oidc-csec").value,
      scopes: $("#auth-oidc-scopes").value.trim(),
      required_group: $("#auth-oidc-group").value.trim(),
      redirect_path:
        $("#auth-oidc-redirect").value.trim() || "/api/auth/callback",
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
      user_header: $("#auth-tp-uheader").value.trim(),
      email_header: $("#auth-tp-eheader").value.trim(),
      groups_header: $("#auth-tp-gheader").value.trim(),
      trusted_cidrs: $("#auth-tp-cidrs")
        .value.split(",")
        .map((x) => x.trim())
        .filter(Boolean),
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
  settings.mode = mode;
  settings.session_timeout_hours = parseInt($("#auth-session-h").value, 10) || 8;
  return settings;
}
