import {
  $, $$, activateTab, confirmDialog, dirtyTabs, escapeHtml, isPublicInfoPage, markTabDirty,
  navigateToTab, refreshTablePagers, syncTabFromPath, tr, updateAllTabAccessibleLabels,
  updatePublicLoginLinksText,
} from "./app.js";
import { loadAuth, renderTokens, authTokens } from "./app-auth-view.js";
import { loadDeliv, loadLogs, renderDeliv } from "./app-deliveries-logs.js";
import {
  loadCascade, loadDedup, loadDelivery, renderCascadeTable, renderDedupCards,
  renderDeliveryDefault, renderPoliciesTable, renderRulesTable,
} from "./app-delivery-grouping.js";
import { loadFlow } from "./app-flow.js";
import { loadAcks, loadInhib, loadInhibRules, loadSchedules } from "./app-inhibitions.js";
import { populateTestComponentSelect, renderRCTable, loadRC } from "./app-render-preview.js";
import { loadIngestAuth, loadNtfyTopics, loadRouting, renderNtfyTopicsEditor } from "./app-routing.js";
import { loadCurrentUser, loadConfigBackups, loadStatus } from "./app-status.js";
import { loadEmergencies } from "./app-emergencies.js";
import { loadSetup } from "./app-setup-simulator.js";

// ---- Polling ----
export async function refreshAll() {
  if (isPublicInfoPage()) return;
  await Promise.all([loadStatus(), loadCurrentUser(), loadInhib(), loadInhibRules(), loadDeliv(), loadEmergencies(), loadRC(), loadCascade(), loadRouting(), loadNtfyTopics(), loadDelivery(), loadDedup(), loadAuth(), loadIngestAuth(), loadSchedules(), loadAcks()]);
}
document.addEventListener("klaxond:languagechange", () => {
  updateAllTabAccessibleLabels();
  updatePublicLoginLinksText();
  if (isPublicInfoPage()) return;
  loadStatus();
  loadConfigBackups();
  renderDeliv();
  if (!dirtyTabs.has("inhibitions")) { loadInhib(); loadInhibRules(); loadSchedules(); loadAcks(); }
  if (!dirtyTabs.has("render")) { renderRCTable(); populateTestComponentSelect(); }
  if (!dirtyTabs.has("routing")) { renderNtfyTopicsEditor(); loadRouting(); loadIngestAuth(); }
  if (!dirtyTabs.has("cascade")) renderCascadeTable();
  if (!dirtyTabs.has("delivery")) { renderDeliveryDefault(); renderPoliciesTable(); renderRulesTable(); }
  if (!dirtyTabs.has("grouping")) renderDedupCards();
  if (!dirtyTabs.has("auth")) loadAuth();
  else renderTokens(authTokens, { preserveSource: true });
  refreshTablePagers();
  if (document.querySelector("#tab-flow.active")) loadFlow();
  if (document.querySelector("#tab-logs.active")) loadLogs();
  if (document.querySelector("#tab-setup.active")) loadSetup({ force: true });
});


// ---- Theme toggle (light / dark) ----
// Bootstrap happens inline in <head> (avoids flash of wrong theme). This
// just wires the button click to flip and persist.
(function setupThemeToggle() {
  const btn = document.getElementById("theme-toggle");
  if (!btn) return;
  const updateGlyph = () => {
    const cur = document.documentElement.getAttribute("data-theme") || "dark";
    btn.textContent = cur === "light" ? "🌞" : "🌙";
    btn.title = `Switch to ${cur === "light" ? "dark" : "light"} mode`;
  };
  updateGlyph();
  btn.addEventListener("click", () => {
    const cur = document.documentElement.getAttribute("data-theme") || "dark";
    const next = cur === "light" ? "dark" : "light";
    document.documentElement.setAttribute("data-theme", next);
    try { localStorage.setItem("klaxond.theme", next); } catch (e) {}
    updateGlyph();
  });
})();

// ---- Dirty-state tracking (unsaved changes warning) ----
// Bind change/input listeners to every form field inside each tabpane so
// edits flip the dirty flag. Excludes search/filter inputs (they're not
// "edits" the user expects to persist).
function _wireDirtyTracking() {
  document.querySelectorAll(".tabpane").forEach(pane => {
    const tabId = pane.id.replace(/^tab-/, "");
    if (!tabId) return;
    if (tabId === "logs") return;
    pane.addEventListener("input", e => {
      const t = e.target;
      if (!t || ["BUTTON"].includes(t.tagName)) return;
      if (t.closest(".table-pager")) return;
      // Skip search/filter fields — those aren't edits
      if (t.type === "search" || t.id === "deliv-filter" || t.id === "inhib-test-labels" || t.id === "emergency-filter") return;
      markTabDirty(tabId, true);
    });
    pane.addEventListener("change", e => {
      const t = e.target;
      if (!t || ["BUTTON"].includes(t.tagName)) return;
      if (t.closest(".table-pager")) return;
      if (t.id === "deliv-show-suppressed" || t.id === "inhib-test-source" || t.id === "emergency-filter") return;
      markTabDirty(tabId, true);
    });
  });
}

// Warn on page unload if any tab is dirty
window.addEventListener("beforeunload", e => {
  if (dirtyTabs.size === 0) return;
  e.preventDefault();
  e.returnValue = "";
  return "";
});

// Wrap activateTab so we warn on tab switch when the current tab is dirty.
// The user gets a chance to abort or proceed; proceed clears dirty for the
// active tab (since we assume they're abandoning the edit).
const _origActivateTab = activateTab;
let _dirtyNavigationPending = false;
function activateTabWithDirtyGuard(tabId) {
  const active = document.querySelector(".tabpane.active");
  const activeId = active ? active.id.replace(/^tab-/, "") : null;
  if (activeId && dirtyTabs.has(activeId) && activeId !== tabId) {
    if (!_dirtyNavigationPending) {
      _dirtyNavigationPending = true;
      confirmDialog(tr("shortcut.discard_confirm", { from: activeId, to: tabId }), {
        title: tr("shortcut.unsaved"),
        confirmLabel: tr("shortcut.discard"),
        danger: true,
      }).then(confirmed => {
        _dirtyNavigationPending = false;
        if (!confirmed) return;
        markTabDirty(activeId, false);
        navigateToTab(tabId);
      });
    }
    return false;
  }
  return _origActivateTab(tabId);
}
window.activateTab = activateTabWithDirtyGuard;


// ---- Keyboard shortcuts ----
// Cmd/Ctrl+S → click primary save button on the active tab
// Esc        → blur active input; if it was a search input, clear it too
// ?          → toggle the shortcut overlay (when not typing in an input)
const _SHORTCUT_HELP = [
  ["Ctrl/Cmd + S", "shortcut.save"],
  ["Esc",          "shortcut.esc"],
  ["?",            "shortcut.help"],
  ["1..9 / 0",     "shortcut.jump"],
];

function _activeTabPane() {
  return document.querySelector(".tabpane.active");
}

function _clickPrimarySaveOnActiveTab() {
  const pane = _activeTabPane();
  if (!pane) return false;
  // Find the most likely "save" button — class=primary takes precedence,
  // then look for any button whose text starts with "Save".
  const primary = pane.querySelector("button.primary:not(:disabled)");
  if (primary) { primary.click(); return true; }
  for (const b of pane.querySelectorAll("button:not(:disabled)")) {
    if ((b.textContent || "").trim().toLowerCase().startsWith("save")) {
      b.click(); return true;
    }
  }
  return false;
}

function _showShortcutHelp() {
  let box = document.getElementById("shortcut-help");
  if (box) { box.remove(); return; }
  box = document.createElement("div");
  box.id = "shortcut-help";
  box.innerHTML = `
    <div class="shortcut-help-inner">
      <h3 style="margin-top:0; text-transform:none; color:var(--text); letter-spacing:0; font-size:1.1em">${escapeHtml(tr("shortcut.title"))}</h3>
      <table style="border:none">
        ${_SHORTCUT_HELP.map(([k, d]) => `<tr><td style="border:none;padding:4px 12px 4px 0"><code>${escapeHtml(k)}</code></td><td style="border:none;padding:4px 0">${escapeHtml(tr(d))}</td></tr>`).join("")}
      </table>
      <p class="muted" style="margin-top:1em; font-size:11px">${tr("shortcut.close")}</p>
    </div>`;
  box.addEventListener("click", e => { if (e.target === box) box.remove(); });
  document.body.appendChild(box);
}

document.addEventListener("keydown", e => {
  // Cmd/Ctrl + S
  if ((e.metaKey || e.ctrlKey) && e.key === "s") {
    e.preventDefault();
    _clickPrimarySaveOnActiveTab();
    return;
  }
  // Don't intercept other shortcuts while typing
  const inInput = ["INPUT", "TEXTAREA", "SELECT"].includes(document.activeElement?.tagName);
  if (e.key === "Escape") {
    if (inInput) {
      const a = document.activeElement;
      if (a.type === "search" || a.id === "deliv-filter") { a.value = ""; a.dispatchEvent(new Event("input")); }
      a.blur();
    }
    const help = document.getElementById("shortcut-help"); if (help) help.remove();
    return;
  }
  if (inInput) return;  // remaining shortcuts only when not typing
  if (e.key === "?") { e.preventDefault(); _showShortcutHelp(); return; }
  // Number keys 1..9, 0 → tab by position
  if (/^[0-9]$/.test(e.key)) {
    const idx = e.key === "0" ? 9 : parseInt(e.key, 10) - 1;
    const tabs = document.querySelectorAll(".tab");
    if (tabs[idx]) tabs[idx].click();
  }
});

export function startApp() {
  window.activateTab = activateTabWithDirtyGuard;
  syncTabFromPath({ replace: true });
  _wireDirtyTracking();
  refreshAll();
  setInterval(() => {
    if (isPublicInfoPage()) return;
    loadStatus();
    loadInhib();
    loadDeliv();
    loadEmergencies();
  }, 10000);
}
