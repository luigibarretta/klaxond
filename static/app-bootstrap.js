// ---- Polling ----
async function refreshAll() {
  if (isPublicInfoPage()) return;
  await Promise.all([loadStatus(), loadCurrentUser(), loadInhib(), loadInhibRules(), loadDeliv(), loadRC(), loadCascade(), loadRouting(), loadNtfyTopics(), loadDelivery(), loadDedup(), loadAuth(), loadIngestAuth(), loadSchedules(), loadAcks()]);
}
refreshAll();
setInterval(() => {
  if (isPublicInfoPage()) return;
  loadStatus();
  loadInhib();
  loadDeliv();
}, 10000);

document.addEventListener("klaxond:languagechange", () => {
  updateAllTabAccessibleLabels();
  updatePublicLoginLinksText();
  if (isPublicInfoPage()) return;
  loadStatus();
  loadConfigBackups();
  renderDeliv();
  if (!_dirtyTabs.has("inhibitions")) { loadInhib(); loadInhibRules(); loadSchedules(); loadAcks(); }
  if (!_dirtyTabs.has("render")) { renderRCTable(); populateTestComponentSelect(); }
  if (!_dirtyTabs.has("routing")) { renderNtfyTopicsEditor(); loadRouting(); loadIngestAuth(); }
  if (!_dirtyTabs.has("cascade")) renderCascadeTable();
  if (!_dirtyTabs.has("delivery")) { renderDeliveryDefault(); renderPoliciesTable(); renderRulesTable(); }
  if (!_dirtyTabs.has("grouping")) renderDedupCards();
  if (!_dirtyTabs.has("auth")) loadAuth();
  else renderTokens(_authTokens, { preserveSource: true });
  refreshTablePagers();
  if (document.querySelector("#tab-flow.active")) loadFlow();
  if (document.querySelector("#tab-logs.active")) loadLogs();
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
// Track which tab panes have unsaved edits. A pane becomes dirty when any
// input/select/textarea inside it changes; cleared when load*/save* runs.
const _dirtyTabs = new Set();

function _markTabDirty(tabId, dirty = true) {
  if (dirty) _dirtyTabs.add(tabId); else _dirtyTabs.delete(tabId);
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
      if (t.type === "search" || t.id === "deliv-filter" || t.id === "inhib-test-labels") return;
      _markTabDirty(tabId, true);
    });
    pane.addEventListener("change", e => {
      const t = e.target;
      if (!t || ["BUTTON"].includes(t.tagName)) return;
      if (t.closest(".table-pager")) return;
      if (t.id === "deliv-show-suppressed" || t.id === "inhib-test-source") return;
      _markTabDirty(tabId, true);
    });
  });
}

// Warn on page unload if any tab is dirty
window.addEventListener("beforeunload", e => {
  if (_dirtyTabs.size === 0) return;
  e.preventDefault();
  e.returnValue = "";
  return "";
});

// Wrap activateTab so we warn on tab switch when the current tab is dirty.
// The user gets a chance to abort or proceed; proceed clears dirty for the
// active tab (since we assume they're abandoning the edit).
const _origActivateTab = window.activateTab || activateTab;
function activateTabWithDirtyGuard(tabId) {
  const active = document.querySelector(".tabpane.active");
  const activeId = active ? active.id.replace(/^tab-/, "") : null;
  if (activeId && _dirtyTabs.has(activeId) && activeId !== tabId) {
    if (!confirm(tr("shortcut.discard_confirm", { from: activeId, to: tabId }))) return false;
    _markTabDirty(activeId, false);
  }
  return _origActivateTab(tabId);
}
window.activateTab = activateTabWithDirtyGuard;
syncTabFromPath({ replace: true });

document.addEventListener("DOMContentLoaded", _wireDirtyTracking);

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
  const primary = pane.querySelector("button.primary");
  if (primary) { primary.click(); return true; }
  for (const b of pane.querySelectorAll("button")) {
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
