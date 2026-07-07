// klaxond admin UI — vanilla JS, no framework.

const $ = sel => document.querySelector(sel);
const $$ = sel => document.querySelectorAll(sel);

let _authRedirectStarted = false;
let _currentUser = { sub: "anonymous", mode: "none", groups: [] };
let _csrfToken = "";
let _reauthInFlight = null;
let _localTotpEnabled = null;
let _publicLegalSessionValid = false;
let _authPasswordPolicy = { min_length: 12, max_length: 1024 };

class AuthRedirectError extends Error {
  constructor() {
    super("auth redirect");
    this.name = "AuthRedirectError";
    this.silent = true;
  }
}

function isAuthRedirectError(e) {
  return e?.silent === true || e?.name === "AuthRedirectError";
}

function currentReturnToPath() {
  const path = `${location.pathname || "/"}${location.search || ""}`;
  if (
    !path
    || path === "/"
    || path === "/api/auth"
    || path.startsWith("/api/auth/")
  ) return "/status";
  return path;
}

function loginStartUrl(returnTo = "/status") {
  const url = new URL("/api/auth/login", location.origin);
  url.searchParams.set("start", "1");
  url.searchParams.set("return_to", returnTo);
  return url.pathname + url.search;
}

function updatePublicLoginLinksText() {
  const key = _publicLegalSessionValid ? "auth.back_to_app" : "auth.sign_in";
  const href = _publicLegalSessionValid ? "/status" : loginStartUrl("/status");
  document.querySelectorAll(".public-login-link").forEach(link => {
    link.dataset.i18n = key;
    link.textContent = tr(key);
    link.setAttribute("href", href);
  });
}

function setupPublicLoginLinks() {
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

function setupLogoutLinks() {
  document.querySelectorAll("[data-auth-logout]").forEach(link => {
    link.addEventListener("click", async e => {
      e.preventDefault();
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

function loginUrlForCurrentPage(loginHint = "") {
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

function beginAuthRedirect(loginHint = "") {
  if (_authRedirectStarted) return;
  _authRedirectStarted = true;
  try { showToast(tr("auth.session_expired"), "warn", 2500); } catch (e) {}
  setTimeout(() => {
    location.assign(loginUrlForCurrentPage(loginHint));
  }, 0);
}

function shouldApiFetch(url) {
  try {
    const u = new URL(url, location.origin);
    return u.origin === location.origin;
  } catch (e) {
    return false;
  }
}

async function apiFetch(url, opts = {}) {
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
  if (res.ok && shouldInvalidateQueryCache(method, url, opts)) invalidateQueryCache();
  return res;
}

async function requestSudoReauth() {
  if (_reauthInFlight) return _reauthInFlight;
  _reauthInFlight = (async () => {
    if ((_currentUser?.mode || "") === "passkey") {
      return requestPasskeyReauth();
    }
    const password = window.prompt(tr("auth.reauth_password"));
    if (password === null) return false;
    const totp = _localTotpEnabled === false ? "" : (window.prompt(tr("auth.reauth_totp")) || "");
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

async function requestPasskeyReauth() {
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
  if (body.user) updateCurrentUserUI(body.user);
  notifySuccess(tr("auth.reauth_ok"));
  return true;
}

const J = async (url, opts) => {
  const r = await apiFetch(url, opts);
  if (!r.ok) throw new Error(`${r.status} ${r.statusText}`);
  const ct = r.headers.get("content-type") || "";
  return ct.includes("json") ? r.json() : r.text();
};
const tr = (key, vars = {}) => window.klaxondI18n?.t ? window.klaxondI18n.t(key, vars) : key;
const APP_META = window.KLAXOND_META || {};

const SEARCH_DEBOUNCE_MS = 300;
const QUERY_TTL_RULES = [
  ["/api/status", 3000],
  ["/api/logs", 5000],
  ["/api/audit", 10000],
  ["/api/deliveries", 10000],
  ["/api/inhibitions", 5000],
  ["/api/acks", 5000],
  ["/api/schedules", 30000],
  ["/api/inhibition-rules", 30000],
  ["/api/config/backups", 30000],
  ["/api/setup-status", 30000],
  ["/api/channel-test-matrix", 30000],
  ["/api/render-config", 30000],
  ["/api/channel-config", 30000],
  ["/api/ntfy-topics", 30000],
  ["/api/ingest-auth", 30000],
  ["/api/cascade-config", 30000],
  ["/api/delivery-config", 30000],
  ["/api/dedup-config", 10000],
];
const QUERY_CACHE_BYPASS_PATHS = new Set(["/api/auth/me", "/api/auth/config"]);
const QUERY_CACHE_MUTATION_BYPASS_PATHS = new Set([
  "/api/config/import-preview",
  "/api/inhibition-rules/test",
  "/api/policy-simulate",
  "/api/render-preview",
]);
const _queryCache = new Map();
const _queryInflight = new Map();
const _queryPendingByKey = new Map();

function isAbortError(e) {
  return e?.name === "AbortError" || (typeof DOMException !== "undefined" && e?.code === DOMException.ABORT_ERR);
}

function urlPath(url) {
  try {
    return new URL(url, location.origin).pathname;
  } catch (e) {
    return String(url || "").split("?")[0];
  }
}

function queryCacheKey(url) {
  try {
    const parsed = new URL(url, location.origin);
    return parsed.pathname + parsed.search;
  } catch (e) {
    return String(url || "");
  }
}

function queryTtlFor(url) {
  const path = urlPath(url);
  if (QUERY_CACHE_BYPASS_PATHS.has(path)) return 0;
  const match = QUERY_TTL_RULES.find(([prefix]) => path === prefix || path.startsWith(prefix + "/"));
  return match ? match[1] : 0;
}

function cloneQueryValue(value) {
  if (value == null || typeof value !== "object") return value;
  if (typeof structuredClone === "function") return structuredClone(value);
  return JSON.parse(JSON.stringify(value));
}

function shouldInvalidateQueryCache(method, url, opts = {}) {
  if (opts.__skipQueryInvalidation) return false;
  if (["GET", "HEAD", "OPTIONS"].includes(String(method || "GET").toUpperCase())) return false;
  return !QUERY_CACHE_MUTATION_BYPASS_PATHS.has(urlPath(url));
}

function invalidateQueryCache(match = null) {
  if (!match) {
    _queryCache.clear();
    return;
  }
  const patterns = Array.isArray(match) ? match : [match];
  for (const key of Array.from(_queryCache.keys())) {
    if (patterns.some(pattern => key.startsWith(pattern) || key.includes(pattern))) _queryCache.delete(key);
  }
}

function debounce(fn, delayMs = SEARCH_DEBOUNCE_MS) {
  let timer = null;
  const wrapped = (...args) => {
    clearTimeout(timer);
    timer = setTimeout(() => {
      timer = null;
      fn(...args);
    }, delayMs);
  };
  wrapped.cancel = () => {
    clearTimeout(timer);
    timer = null;
  };
  return wrapped;
}

async function queryGet(scope, url, opts = {}) {
  const ttlMs = opts.ttlMs ?? queryTtlFor(url);
  const key = queryCacheKey(url);
  const now = Date.now();
  if (ttlMs > 0 && !opts.force) {
    const cached = _queryCache.get(key);
    if (cached && cached.expiresAt > now) return cloneQueryValue(cached.value);
    const pending = _queryPendingByKey.get(key);
    if (pending && opts.joinInflight !== false) return cloneQueryValue(await pending);
  }
  if (opts.cancelPrevious !== false) {
    const prev = _queryInflight.get(scope);
    if (prev) prev.abort();
  }
  const controller = new AbortController();
  _queryInflight.set(scope, controller);
  const requestPromise = J(url, {
    ...(opts.fetchOptions || {}),
    signal: controller.signal,
  }).then(payload => {
    if (ttlMs > 0) {
      _queryCache.set(key, {
        expiresAt: Date.now() + ttlMs,
        value: cloneQueryValue(payload),
      });
    }
    return payload;
  });
  if (ttlMs > 0 && !opts.force) _queryPendingByKey.set(key, requestPromise);
  try {
    return await requestPromise;
  } finally {
    if (_queryInflight.get(scope) === controller) _queryInflight.delete(scope);
    if (_queryPendingByKey.get(key) === requestPromise) _queryPendingByKey.delete(key);
  }
}

window.KlaxondQuery = Object.freeze({
  invalidate: invalidateQueryCache,
  cacheSize: () => _queryCache.size,
  debounceMs: SEARCH_DEBOUNCE_MS,
});

// ---- Tab switching (with URL path routing) ----
const UI_TABS = new Set(Array.from(document.querySelectorAll(".tab[data-tab]"), t => t.dataset.tab));
const UI_PAGES = new Set(Array.from(document.querySelectorAll(".tabpane[id^='tab-']"), p => p.id.replace(/^tab-/, "")));
const PUBLIC_INFO_PAGES = new Set(["privacy", "accessibility", "terms", "cookies", "legal"]);
const LEGAL_ROUTE_TO_TAB = new Map([
  ["privacy", "privacy"],
  ["accessibility", "accessibility"],
  ["terms", "terms"],
  ["cookies", "cookies"],
  ["notice", "legal"],
]);
const LEGAL_TAB_TO_ROUTE = new Map(Array.from(LEGAL_ROUTE_TO_TAB, ([route, tab]) => [tab, route]));
const UI_ROUTE_TO_TAB = new Map([
  ["status", "status"],
  ["flow", "flow"],
  ["inhibitions", "inhibitions"],
  ["deliveries", "deliveries"],
  ["logs", "logs"],
  ["audit", "audit"],
  ["setup", "setup"],
  ["render", "render"],
  ["routing", "routing"],
  ["cascade", "cascade"],
  ["delivery", "delivery"],
  ["grouping", "grouping"],
  ["authentication", "auth"],
  ["preview", "preview"],
  ["simulator", "simulator"],
  ["test", "test"],
]);
const UI_TAB_TO_ROUTE = new Map(Array.from(UI_ROUTE_TO_TAB, ([route, tab]) => [tab, route]));
const DEFAULT_TAB = "status";

function isKnownTab(tabId) {
  return UI_PAGES.has(tabId);
}

function isPublicInfoPage(tabId = tabFromLocation().tabId) {
  return PUBLIC_INFO_PAGES.has(tabId);
}

function legalContextSearch(search = location.search) {
  try {
    return new URLSearchParams(search).get("from") === "login" ? "?from=login" : "";
  } catch (e) {
    return "";
  }
}

function isLegalFromLogin() {
  return legalContextSearch() === "?from=login";
}

function canonicalUrl(tabId, { search = location.search } = {}) {
  const path = canonicalPath(tabId);
  if (!PUBLIC_INFO_PAGES.has(tabId)) return path;
  return path + legalContextSearch(search);
}

function updatePublicLegalContextLinks() {
  const fromLogin = isLegalFromLogin();
  document.querySelectorAll("[data-public-language-control]").forEach(el => {
    el.hidden = !fromLogin;
  });
  document.querySelectorAll('.public-legal-brand, .footer-links a[href^="/legal/"]').forEach(link => {
    try {
      const url = new URL(link.getAttribute("href"), location.origin);
      if (url.origin === location.origin && url.pathname.startsWith("/legal/")) {
        link.setAttribute("href", url.pathname + (fromLogin ? "?from=login" : ""));
      }
    } catch (e) {}
  });
}

function updatePublicChrome(tabId) {
  const isPublic = PUBLIC_INFO_PAGES.has(tabId);
  document.body.classList.toggle("public-info-route", isPublic);
  const publicBar = $("#public-legal-bar");
  if (publicBar) publicBar.hidden = !isPublic;
  if (isPublic) updatePublicLegalContextLinks();
}

function canonicalPath(tabId) {
  const safeTab = isKnownTab(tabId) ? tabId : DEFAULT_TAB;
  if (PUBLIC_INFO_PAGES.has(safeTab)) return `/legal/${LEGAL_TAB_TO_ROUTE.get(safeTab) || safeTab}`;
  return `/${UI_TAB_TO_ROUTE.get(safeTab) || safeTab}`;
}

function activateTab(tabId) {
  $$(".tab").forEach(x => x.classList.remove("active"));
  $$(".tabpane").forEach(x => x.classList.remove("active"));
  const btn = document.querySelector(`.tab[data-tab="${tabId}"]`);
  const pane = $("#tab-" + tabId);
  if (pane) {
    if (btn) btn.classList.add("active");
    pane.classList.add("active");
    updatePublicChrome(tabId);
    _onTabActivated(tabId);
    return true;
  }
  return false;
}

// Per-tab initializer hook — called on EVERY activation (click OR path route).
// Loaders are idempotent (re-fetching is cheap). Add `case` here for new tabs.
function _onTabActivated(tabId) {
  try {
    switch (tabId) {
      case "flow":        if (typeof loadFlow === "function")       { loadFlow(); if (typeof _setupFlowAutorefresh === "function") _setupFlowAutorefresh(); } break;
      case "status":      if (typeof loadStatus === "function")     loadStatus(); break;
      case "auth":        if (typeof loadAuth === "function")        loadAuth(); break;
      case "deliveries":  if (typeof loadDeliv === "function")       loadDeliv(); break;
      case "routing":     if (typeof loadNtfyTopics === "function") loadNtfyTopics(); if (typeof loadIngestAuth === "function") loadIngestAuth(); break;
      case "render":      if (typeof loadRC === "function")          loadRC(); break;
      case "cascade":     if (typeof loadCascade === "function")     loadCascade(); break;
      case "delivery":    if (typeof loadDelivery === "function")    loadDelivery(); break;
      case "grouping":    if (typeof loadDedup === "function")       loadDedup(); break;
      case "inhibitions": if (typeof loadInhibRules === "function") loadInhibRules(); if (typeof loadSchedules === "function") loadSchedules(); if (typeof loadAcks === "function") loadAcks(); break;
      case "logs":        if (typeof loadLogs === "function")        loadLogs(); break;
      case "audit":       if (typeof loadAudit === "function")       loadAudit({ reset: true }); break;
      case "setup":       if (typeof loadSetup === "function")       loadSetup(); break;
      case "simulator":   if (typeof runPolicySimulation === "function") runPolicySimulation({ silent: true }); break;
    }
  } catch (e) { setTimeout(() => notifyError(`tab-${tabId}`, e), 0); }
}

function tabBaseLabel(tab) {
  const key = tab?.dataset?.i18nTitle;
  if (key) return tr(key);
  return tab?.querySelector(".tab-label")?.textContent?.trim() || tab?.textContent?.trim() || "";
}

function updateTabAccessibleLabel(tab) {
  if (!tab) return;
  const parts = [tabBaseLabel(tab)];
  const badge = tab.querySelector(".tab-badge");
  if (badge?.textContent?.trim()) {
    parts.push(tr("tab.badge_count", { count: badge.textContent.trim() }));
  }
  if (tab.querySelector(".tab-dirty")) parts.push(tr("shortcut.unsaved"));
  tab.setAttribute("aria-label", parts.filter(Boolean).join(", "));
}

function updateAllTabAccessibleLabels() {
  document.querySelectorAll(".tab").forEach(updateTabAccessibleLabel);
}

function tabFromLocation() {
  const legacyHash = (location.hash || "").replace(/^#/, "");
  if (isKnownTab(legacyHash)) return { tabId: legacyHash, canonicalize: true };

  const pathname = location.pathname.replace(/\/+$/, "") || "/";
  if (pathname === "/" || pathname === "/ui" || pathname === "/ui/index.html") {
    return { tabId: DEFAULT_TAB, canonicalize: true };
  }
  if (pathname === "/legal") {
    return { tabId: "privacy", canonicalize: true };
  }

  const legalMatch = pathname.match(/^\/legal\/([^/]+)$/);
  if (legalMatch) {
    const tabId = LEGAL_ROUTE_TO_TAB.get(legalMatch[1]);
    if (tabId) return { tabId, canonicalize: pathname !== canonicalPath(tabId) || !!location.hash };
  }

  const match = pathname.match(/^\/ui\/([^/]+)$/);
  if (match && isKnownTab(match[1])) {
    return { tabId: match[1], canonicalize: pathname !== canonicalPath(match[1]) || !!location.hash };
  }

  const rootMatch = pathname.match(/^\/([^/]+)$/);
  if (rootMatch) {
    const tabId = UI_ROUTE_TO_TAB.get(rootMatch[1]);
    if (tabId) return { tabId, canonicalize: pathname !== canonicalPath(tabId) || !!location.hash };
  }

  return { tabId: DEFAULT_TAB, canonicalize: true };
}

function syncTabFromPath({ replace = false } = {}) {
  const { tabId, canonicalize } = tabFromLocation();
  const ok = (window.activateTab || activateTab)(tabId);
  if (!ok) {
    const active = document.querySelector(".tabpane.active");
    const activeId = active ? active.id.replace(/^tab-/, "") : DEFAULT_TAB;
    history.replaceState({ tabId: activeId }, "", canonicalPath(activeId));
    return false;
  }
  if (ok && (replace || canonicalize)) {
    history.replaceState({ tabId }, "", canonicalUrl(tabId));
  }
  return ok;
}

function navigateToTab(tabId, { replace = false, search = "" } = {}) {
  if (!isKnownTab(tabId)) return false;
  if (!(window.activateTab || activateTab)(tabId)) return false;
  const url = canonicalUrl(tabId, { search });
  if (`${location.pathname}${location.search}` !== url || location.hash) {
    history[replace ? "replaceState" : "pushState"]({ tabId }, "", url);
  }
  if (PUBLIC_INFO_PAGES.has(tabId)) updatePublicLegalContextLinks();
  return true;
}

$$(".tab").forEach(t => {
  t.addEventListener("click", e => {
    e.preventDefault();
    navigateToTab(t.dataset.tab);
  });
});

document.addEventListener("click", e => {
  const link = e.target.closest?.('a[href^="/"]');
  if (!link || link.target || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return;
  const url = new URL(link.href);
  if (url.origin !== location.origin) return;
  const legalMatch = url.pathname.match(/^\/legal\/([^/]+)\/?$/);
  const legacyMatch = url.pathname.match(/^\/ui\/([^/]+)\/?$/);
  const rootMatch = url.pathname.match(/^\/([^/]+)\/?$/);
  const tabId = legalMatch
    ? LEGAL_ROUTE_TO_TAB.get(legalMatch[1])
    : legacyMatch
      ? legacyMatch[1]
      : rootMatch
        ? UI_ROUTE_TO_TAB.get(rootMatch[1])
        : "";
  if (!isKnownTab(tabId)) return;
  e.preventDefault();
  navigateToTab(tabId, { search: legalMatch ? url.search : "" });
});

window.addEventListener("popstate", () => syncTabFromPath());
if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", updateAllTabAccessibleLabels);
} else {
  updateAllTabAccessibleLabels();
}
setupPublicLoginLinks();
setupLogoutLinks();


// Shared HTML escaping helper used by feature scripts.
function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, c => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;",
  }[c]));
}

// ---- Toast notifications (non-blocking error / info banner) ----
// Replaces the silent console.warn pattern in load* functions. Toasts stack
// in the top-right and auto-dismiss after 10s; click X to dismiss manually.
function showToast(msg, kind = "error", durationMs = 10000) {
  let container = document.getElementById("toast-container");
  if (!container) {
    container = document.createElement("div");
    container.id = "toast-container";
    document.body.appendChild(container);
  }
  const toast = document.createElement("div");
  toast.className = "toast toast-" + kind;
  toast.innerHTML = `<span class="toast-msg"></span><button class="toast-close" title="Dismiss">✕</button>`;
  toast.querySelector(".toast-msg").textContent = msg;
  toast.querySelector(".toast-close").addEventListener("click", () => toast.remove());
  container.appendChild(toast);
  setTimeout(() => { if (toast.isConnected) toast.remove(); }, durationMs);
  return toast;
}

// Per-key dedup so polling loops don't flood the screen with the same error
// every 10s. The first failure shows a toast; subsequent failures with the
// same key within DEDUP_MS are silent (logged to console only).
const _TOAST_DEDUP_MS = 60000;
const _toastErrLast = new Map();
function errorText(e) {
  if (!e) return "unknown";
  if (typeof e === "string") return e;
  return e.message || String(e);
}

function statusElement(target) {
  return typeof target === "string" ? $(target) : target;
}

function setInlineStatus(target, text, opts = {}) {
  const el = statusElement(target);
  if (!el) return;
  const options = typeof opts === "string" ? { kind: opts } : opts;
  const kind = options.kind || "";
  el.textContent = text;
  if (options.color !== undefined) el.style.color = options.color;
  else if (kind === "error") el.style.color = "var(--red)";
  else if (kind === "success") el.style.color = "var(--green)";
  else el.style.color = "";
  if (options.clearMs) {
    setTimeout(() => {
      if (el.textContent === text) el.textContent = "";
    }, options.clearMs);
  }
}

function notifySuccess(message, opts = {}) {
  const text = message || tr("status.saved");
  if (opts.status) {
    setInlineStatus(opts.status, opts.inlineText || text, {
      kind: "success",
      clearMs: opts.clearMs,
      color: opts.color,
    });
  }
  showToast(text, "success", opts.durationMs || 4000);
}

function notifyError(key, e, opts = {}) {
  if (isAbortError(e) || isAuthRedirectError(e) || _authRedirectStarted) return;
  console.warn(key + ":", e);
  const msg = errorText(e);
  if (opts.status) {
    setInlineStatus(opts.status, opts.inlineText || `${tr("common.error")}: ${msg}`, "error");
  }
  if (!opts.dedup) {
    reportClientError(key, e, "error");
    showToast(`${key}: ${msg}`, "error", opts.durationMs || 10000);
    return;
  }
  const now = Date.now();
  const last = _toastErrLast.get(key) || 0;
  if (now - last < _TOAST_DEDUP_MS) return;
  _toastErrLast.set(key, now);
  reportClientError(key, e, "error");
  showToast(`${key}: ${msg}`, "error");
}

function reportClientError(key, e, level = "error") {
  const payload = {
    level,
    key: String(key || "ui"),
    message: errorText(e),
    path: `${location.pathname || "/"}${location.search || ""}`,
    stack: e && e.stack ? String(e.stack) : "",
    userAgent: navigator.userAgent || "",
  };
  try {
    fetch("/api/client-log", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Klaxond-Request": "fetch",
      },
      body: JSON.stringify(payload),
      redirect: "manual",
      keepalive: true,
    }).catch(() => {});
  } catch (err) {}
}

function notifyResponseError(key, res, bodyText = "", statusTarget = null) {
  const body = (bodyText || "").trim();
  const msg = `${res.status} ${body || res.statusText}`;
  notifyError(key, new Error(msg), { status: statusTarget });
}

function notifyValidationError(key, message, statusTarget = null) {
  notifyError(key, new Error(message), { status: statusTarget, inlineText: "❌ " + message });
}

function fetchError(key, e) {
  if (isAbortError(e) || isAuthRedirectError(e) || _authRedirectStarted) return;
  notifyError(key, e, { dedup: true });
}
function fetchOk(key) { _toastErrLast.delete(key); }
