import { J, onApiMutationSuccess } from "./app-http.js";

export const SEARCH_DEBOUNCE_MS = 300;

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

export function invalidateQueryCache(match = null) {
  if (!match) {
    _queryCache.clear();
    return;
  }
  const patterns = Array.isArray(match) ? match : [match];
  for (const key of Array.from(_queryCache.keys())) {
    if (patterns.some(pattern => key.startsWith(pattern) || key.includes(pattern))) _queryCache.delete(key);
  }
}

export function debounce(fn, delayMs = SEARCH_DEBOUNCE_MS) {
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

export async function queryGet(scope, url, opts = {}) {
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

onApiMutationSuccess((method, url, opts) => {
  if (shouldInvalidateQueryCache(method, url, opts)) invalidateQueryCache();
});

window.KlaxondQuery = Object.freeze({
  invalidate: invalidateQueryCache,
  cacheSize: () => _queryCache.size,
  debounceMs: SEARCH_DEBOUNCE_MS,
});
