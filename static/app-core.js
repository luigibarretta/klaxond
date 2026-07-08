// Shared browser primitives for the klaxond admin UI.

export const $ = sel => document.querySelector(sel);
export const $$ = sel => document.querySelectorAll(sel);

export const tr = (key, vars = {}) => window.klaxondI18n?.t ? window.klaxondI18n.t(key, vars) : key;
export const APP_META = window.KLAXOND_META || {};

let _authRedirectStarted = false;

export function isAuthRedirectStarted() {
  return _authRedirectStarted;
}

export function setAuthRedirectStarted(started) {
  _authRedirectStarted = !!started;
}

export class AuthRedirectError extends Error {
  constructor() {
    super("auth redirect");
    this.name = "AuthRedirectError";
    this.silent = true;
  }
}

export function isAuthRedirectError(e) {
  return e?.silent === true || e?.name === "AuthRedirectError";
}

export function isAbortError(e) {
  return e?.name === "AbortError" || (typeof DOMException !== "undefined" && e?.code === DOMException.ABORT_ERR);
}

export function onReady(fn) {
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", fn, { once: true });
  } else {
    fn();
  }
}

export const applyTablePager = (...args) => window.KlaxondTablePager?.applyTablePager(...args);
export const refreshTablePagers = (...args) => window.KlaxondTablePager?.refreshTablePagers(...args);
export const showTableRowPage = (...args) => window.KlaxondTablePager?.showTableRowPage(...args);

export function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, c => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;",
  }[c]));
}
