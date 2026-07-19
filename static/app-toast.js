import {
  $, isAbortError, isAuthRedirectError, isAuthRedirectStarted, tr,
} from "./app-core.js";

// ---- Toast notifications (non-blocking error / info banner) ----
export function showToast(msg, kind = "error", durationMs = 10000) {
  let container = document.getElementById("toast-container");
  if (!container) {
    container = document.createElement("div");
    container.id = "toast-container";
    document.body.appendChild(container);
  }
  const toast = document.createElement("div");
  toast.className = "toast toast-" + kind;
  toast.setAttribute("role", kind === "error" ? "alert" : "status");
  toast.setAttribute("aria-live", kind === "error" ? "assertive" : "polite");
  toast.innerHTML = `<span class="toast-msg"></span><button class="toast-close" title="Dismiss">✕</button>`;
  toast.querySelector(".toast-msg").textContent = msg;
  toast.querySelector(".toast-close").addEventListener("click", () => toast.remove());
  container.appendChild(toast);
  setTimeout(() => { if (toast.isConnected) toast.remove(); }, durationMs);
  return toast;
}

const _TOAST_DEDUP_MS = 60000;
const _toastErrLast = new Map();

export function errorText(e) {
  if (!e) return "unknown";
  if (typeof e === "string") return e;
  return e.message || String(e);
}

export function statusElement(target) {
  return typeof target === "string" ? $(target) : target;
}

export function setInlineStatus(target, text, opts = {}) {
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

export function notifySuccess(message, opts = {}) {
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

export function notifyError(key, e, opts = {}) {
  if (isAbortError(e) || isAuthRedirectError(e) || isAuthRedirectStarted()) return;
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

export function reportClientError(key, e, level = "error") {
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

export function notifyResponseError(key, res, bodyText = "", statusTarget = null) {
  const body = (bodyText || "").trim();
  const msg = `${res.status} ${body || res.statusText}`;
  notifyError(key, new Error(msg), { status: statusTarget });
}

export function notifyValidationError(key, message, statusTarget = null) {
  notifyError(key, new Error(message), { status: statusTarget, inlineText: "❌ " + message });
}

export function fetchError(key, e) {
  if (isAbortError(e) || isAuthRedirectError(e) || isAuthRedirectStarted()) return;
  notifyError(key, e, { dedup: true });
}

export function fetchOk(key) {
  _toastErrLast.delete(key);
}
