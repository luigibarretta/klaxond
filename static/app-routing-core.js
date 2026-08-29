import { $, $$, tr } from "./app-core.js";
import { setupLogoutLinks, setupPublicLoginLinks } from "./app-http.js";
import { notifyError } from "./app-toast.js";

export const dirtyTabs = new Set();

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
  ["emergencies", "emergencies"],
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
const _tabActivationHandlers = new Map();

export function isKnownTab(tabId) {
  return UI_PAGES.has(tabId);
}

export function isPublicInfoPage(tabId = tabFromLocation().tabId) {
  return PUBLIC_INFO_PAGES.has(tabId);
}

function legalContextSearch(search = location.search) {
  try {
    return new URLSearchParams(search).get("from") === "login" ? "?from=login" : "";
  } catch (e) {
    return "";
  }
}

export function isLegalFromLogin() {
  return legalContextSearch() === "?from=login";
}

export function canonicalUrl(tabId, { search = location.search } = {}) {
  const path = canonicalPath(tabId);
  if (!PUBLIC_INFO_PAGES.has(tabId)) return path;
  return path + legalContextSearch(search);
}

export function updatePublicLegalContextLinks() {
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

export function updatePublicChrome(tabId) {
  const isPublic = PUBLIC_INFO_PAGES.has(tabId);
  document.body.classList.toggle("public-info-route", isPublic);
  const publicBar = $("#public-legal-bar");
  if (publicBar) publicBar.hidden = !isPublic;
  if (isPublic) updatePublicLegalContextLinks();
}

export function canonicalPath(tabId) {
  const safeTab = isKnownTab(tabId) ? tabId : DEFAULT_TAB;
  if (PUBLIC_INFO_PAGES.has(safeTab)) return `/legal/${LEGAL_TAB_TO_ROUTE.get(safeTab) || safeTab}`;
  return `/${UI_TAB_TO_ROUTE.get(safeTab) || safeTab}`;
}

export function setTabActivationHandlers(handlers = {}) {
  _tabActivationHandlers.clear();
  for (const [tabId, handler] of Object.entries(handlers)) {
    if (typeof handler === "function") _tabActivationHandlers.set(tabId, handler);
  }
}

export function activateTab(tabId) {
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

function _onTabActivated(tabId) {
  const handler = _tabActivationHandlers.get(tabId);
  if (!handler) return;
  try {
    handler();
  } catch (e) {
    setTimeout(() => notifyError(`tab-${tabId}`, e), 0);
  }
}

function tabBaseLabel(tab) {
  const key = tab?.dataset?.i18nTitle;
  if (key) return tr(key);
  return tab?.querySelector(".tab-label")?.textContent?.trim() || tab?.textContent?.trim() || "";
}

export function updateTabAccessibleLabel(tab) {
  if (!tab) return;
  const parts = [tabBaseLabel(tab)];
  const badge = tab.querySelector(".tab-badge");
  if (badge?.textContent?.trim()) {
    parts.push(tr("tab.badge_count", { count: badge.textContent.trim() }));
  }
  if (tab.querySelector(".tab-dirty")) parts.push(tr("shortcut.unsaved"));
  tab.setAttribute("aria-label", parts.filter(Boolean).join(", "));
}

export function markTabDirty(tabId, dirty = true) {
  if (dirty) dirtyTabs.add(tabId); else dirtyTabs.delete(tabId);
  const readOnly = document.body.classList.contains("viewer-readonly");
  document.querySelectorAll(`[data-enable-when-dirty="${tabId}"]`).forEach(button => {
    button.disabled = !dirty || readOnly;
  });
  const tab = document.querySelector(`.tab[data-tab="${tabId}"]`);
  if (!tab) return;
  let dot = tab.querySelector(".tab-dirty");
  if (dirty && !dot) {
    dot = document.createElement("span");
    dot.className = "tab-dirty";
    dot.title = tr("shortcut.unsaved");
    tab.appendChild(dot);
  } else if (!dirty && dot) {
    dot.remove();
  }
  updateTabAccessibleLabel(tab);
}

export function updateAllTabAccessibleLabels() {
  document.querySelectorAll(".tab").forEach(updateTabAccessibleLabel);
}

export function tabFromLocation() {
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

export function syncTabFromPath({ replace = false } = {}) {
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

export function navigateToTab(tabId, { replace = false, search = "" } = {}) {
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

window.activateTab = activateTab;
window.addEventListener("popstate", () => syncTabFromPath());
if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", updateAllTabAccessibleLabels);
} else {
  updateAllTabAccessibleLabels();
}
setupPublicLoginLinks();
setupLogoutLinks();
