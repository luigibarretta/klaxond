import {
  AuthRedirectError, isAuthRedirectStarted, setAuthRedirectStarted, tr,
} from "./app-core.js";
import { requestDialog } from "./app-dialog.js";
import {
  notifyError, notifyResponseError, notifySuccess, showToast,
} from "./app-toast.js";

let _currentUser = { sub: "anonymous", mode: "none", groups: [] };
let _csrfToken = "";
let _reauthInFlight = null;
let _localTotpEnabled = null;
let _publicLegalSessionValid = false;
let _authPasswordPolicy = { min_length: 12, max_length: 1024 };
const _mutationSuccessHandlers = new Set();

export function getCurrentUser() {
  return _currentUser;
}

export function setCurrentUser(user = {}) {
  _currentUser = user || { sub: "anonymous", mode: "none", groups: [] };
  window.klaxondCurrentUser = _currentUser;
  if (_currentUser.csrf) _csrfToken = _currentUser.csrf;
  return _currentUser;
}

export function setLocalTotpEnabled(enabled) {
  _localTotpEnabled = enabled;
}

export function getAuthPasswordPolicy() {
  return _authPasswordPolicy;
}

export function setAuthPasswordPolicy(policy = {}) {
  _authPasswordPolicy = {
    min_length: Number(policy.min_length || 12),
    max_length: Number(policy.max_length || 1024),
  };
  return _authPasswordPolicy;
}

export function onApiMutationSuccess(handler) {
  if (typeof handler !== "function") return () => {};
  _mutationSuccessHandlers.add(handler);
  return () => _mutationSuccessHandlers.delete(handler);
}

export function currentReturnToPath() {
  const path = `${location.pathname || "/"}${location.search || ""}`;
  if (
    !path
    || path === "/"
    || path === "/api/auth"
    || path.startsWith("/api/auth/")
  ) return "/status";
  return path;
}

export function loginStartUrl(returnTo = "/status") {
  const url = new URL("/api/auth/login", location.origin);
  url.searchParams.set("start", "1");
  url.searchParams.set("return_to", returnTo);
  return url.pathname + url.search;
}

export function updatePublicLoginLinksText() {
  const key = _publicLegalSessionValid ? "auth.back_to_app" : "auth.sign_in";
  const href = _publicLegalSessionValid ? "/status" : loginStartUrl("/status");
  document.querySelectorAll(".public-login-link").forEach(link => {
    link.dataset.i18n = key;
    link.textContent = tr(key);
    link.setAttribute("href", href);
  });
}

export function setupPublicLoginLinks() {
  const target = "/status";
  const fallback = loginStartUrl(target);
  const links = Array.from(document.querySelectorAll(".public-login-link"));
  if (!links.length) return;
  updatePublicLoginLinksText();
  fetch("/api/auth/me", {
    headers: { "X-Klaxond-Request": "fetch" },
    redirect: "manual",
  }).then(res => {
    _publicLegalSessionValid = res.ok;
    updatePublicLoginLinksText();
  }).catch(() => {
    _publicLegalSessionValid = false;
    updatePublicLoginLinksText();
  });
  links.forEach(link => {
    link.addEventListener("click", async e => {
      e.preventDefault();
      // This link owns an authentication-aware full navigation. Do not let
      // the delegated SPA router also handle the same click and race the
      // later location.assign() with a history-only route transition.
      e.stopPropagation();
      try {
        const res = await fetch("/api/auth/me", {
          headers: { "X-Klaxond-Request": "fetch" },
          redirect: "manual",
        });
        if (res.ok) {
          location.assign(target);
          return;
        }
      } catch (err) {}
      _publicLegalSessionValid = false;
      updatePublicLoginLinksText();
      location.assign(fallback);
    });
  });
}

export function setupLogoutLinks() {
  document.querySelectorAll("[data-auth-logout]").forEach(link => {
    link.addEventListener("click", async e => {
      e.preventDefault();
      if (isAuthRedirectStarted()) return;
      // Own the navigation before invalidating the session. Background API
      // requests can otherwise observe the logout first and race this redirect.
      setAuthRedirectStarted(true);
      link.setAttribute("aria-disabled", "true");
      try {
        await fetch("/api/auth/logout", {
          method: "POST",
          credentials: "same-origin",
          headers: { "X-Klaxond-Request": "fetch" },
          redirect: "manual",
        });
      } catch (err) {}
      location.assign("/api/auth/login?logged_out=1");
    });
  });
}

export function loginUrlForCurrentPage(loginHint = "") {
  const fallback = new URL("/api/auth/login", location.origin);
  fallback.searchParams.set("return_to", currentReturnToPath());
  if (!loginHint) return fallback.pathname + fallback.search;
  try {
    const hinted = new URL(loginHint, location.origin);
    if (hinted.origin !== location.origin || hinted.pathname !== "/api/auth/login") {
      return fallback.pathname + fallback.search;
    }
    hinted.searchParams.set("return_to", currentReturnToPath());
    return hinted.pathname + hinted.search;
  } catch (e) {
    return fallback.pathname + fallback.search;
  }
}

export function beginAuthRedirect(loginHint = "") {
  if (isAuthRedirectStarted()) return;
  setAuthRedirectStarted(true);
  try { showToast(tr("auth.session_expired"), "warn", 2500); } catch (e) {}
  setTimeout(() => {
    location.assign(loginUrlForCurrentPage(loginHint));
  }, 0);
}

export function shouldApiFetch(url) {
  try {
    const u = new URL(url, location.origin);
    return u.origin === location.origin;
  } catch (e) {
    return false;
  }
}

export async function apiFetch(url, opts = {}) {
  if (!shouldApiFetch(url)) return fetch(url, opts);
  const headers = new Headers(opts.headers || {});
  const method = String(opts.method || "GET").toUpperCase();
  headers.set("X-Klaxond-Request", "fetch");
  if (_csrfToken && !["GET", "HEAD", "OPTIONS"].includes(method)) {
    headers.set("X-Klaxond-CSRF", _csrfToken);
  }
  const res = await fetch(url, { ...opts, headers, redirect: "manual" });
  const loginHint = res.headers.get("X-Klaxond-Login") || res.headers.get("Location") || "";
  const isLoginRedirect = res.status >= 300 && res.status < 400 && loginHint.includes("/api/auth/login");
  if ((res.status === 401 && loginHint) || isLoginRedirect || res.type === "opaqueredirect") {
    beginAuthRedirect(loginHint);
    throw new AuthRedirectError();
  }
  if (res.status === 428 && res.headers.get("X-Klaxond-Reauth") === "required" && !opts.__sudoRetry && !String(url).includes("/api/auth/reauth")) {
    const ok = await requestSudoReauth();
    if (ok) return apiFetch(url, { ...opts, __sudoRetry: true });
  }
  if (res.ok && !["GET", "HEAD", "OPTIONS"].includes(method)) {
    _mutationSuccessHandlers.forEach(handler => handler(method, url, opts));
  }
  return res;
}

export async function requestSudoReauth() {
  if (_reauthInFlight) return _reauthInFlight;
  _reauthInFlight = (async () => {
    if ((_currentUser?.mode || "") === "passkey") {
      return requestPasskeyReauth();
    }
    const fields = [{
      name: "password", label: tr("auth.password"), type: "password",
      required: true, autocomplete: "current-password",
    }];
    if (_localTotpEnabled !== false) fields.push({
      name: "totp", label: tr("auth.reauth_totp"), type: "text",
      required: false, autocomplete: "one-time-code", inputMode: "numeric",
    });
    const credentials = await requestDialog({
      title: tr("auth.reauth_title"),
      message: tr("auth.reauth_password"),
      fields,
      confirmLabel: tr("auth.reauth_confirm"),
    });
    if (!credentials) return false;
    const password = credentials.password;
    const totp = credentials.totp || "";
    const res = await apiFetch("/api/auth/reauth", {
      method: "POST",
      body: JSON.stringify({ password, totp }),
      headers: { "Content-Type": "application/json" },
      __sudoRetry: true,
    });
    if (!res.ok) {
      notifyResponseError("auth-reauth", res, await res.text(), null);
      return false;
    }
    const body = await res.json().catch(() => ({}));
    if (body.csrf) _csrfToken = body.csrf;
    notifySuccess(tr("auth.reauth_ok"));
    return true;
  })().finally(() => {
    _reauthInFlight = null;
  });
  return _reauthInFlight;
}

function b64urlToBuffer(s) {
  const b64 = String(s).replace(/-/g, "+").replace(/_/g, "/") + "===".slice((String(s).length + 3) % 4);
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out.buffer;
}

function bufferToB64url(buffer) {
  const bytes = new Uint8Array(buffer);
  let bin = "";
  bytes.forEach(b => bin += String.fromCharCode(b));
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function webauthnGetOptions(publicKey) {
  const opts = { ...publicKey };
  opts.challenge = b64urlToBuffer(opts.challenge);
  if (opts.allowCredentials) {
    opts.allowCredentials = opts.allowCredentials.map(c => ({ ...c, id: b64urlToBuffer(c.id) }));
  }
  return opts;
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
  };
}

export async function requestPasskeyReauth() {
  if (!window.PublicKeyCredential || !navigator.credentials?.get) {
    notifyError("auth-reauth", new Error(tr("auth.passkey_unsupported")));
    return false;
  }
  const user = _currentUser?.sub || _currentUser?.email || _currentUser?.name || "";
  const start = await apiFetch("/api/auth/passkey/login/options", {
    method: "POST",
    body: JSON.stringify({ user }),
    headers: { "Content-Type": "application/json" },
    __sudoRetry: true,
  });
  if (!start.ok) {
    notifyResponseError("auth-reauth", start, await start.text(), null);
    return false;
  }
  const challenge = await start.json();
  const credential = await navigator.credentials.get({ publicKey: webauthnGetOptions(challenge.publicKey) });
  const finish = await apiFetch("/api/auth/passkey/login/verify", {
    method: "POST",
    body: JSON.stringify({ request_id: challenge.request_id, credential: webauthnGetPayload(credential) }),
    headers: { "Content-Type": "application/json" },
    __sudoRetry: true,
  });
  if (!finish.ok) {
    notifyResponseError("auth-reauth", finish, await finish.text(), null);
    return false;
  }
  const body = await finish.json().catch(() => ({}));
  if (body.user) setCurrentUser(body.user);
  notifySuccess(tr("auth.reauth_ok"));
  return true;
}

export const J = async (url, opts) => {
  const r = await apiFetch(url, opts);
  if (!r.ok) throw new Error(`${r.status} ${r.statusText}`);
  const ct = r.headers.get("content-type") || "";
  return ct.includes("json") ? r.json() : r.text();
};
