const MOBILE_SIDEBAR_QUERY = "(max-width: 760px)";
const GROUP_STORAGE_KEY = "klaxond.navGroupsCollapsed";
function desktopCollapsedPreference() {
  try {
    const saved = localStorage.getItem("klaxond.sidebarCollapsed");
    if (saved === "1" || saved === "0") return saved === "1";
  } catch (error) {}
  return false;
}
function collapsedGroupsPreference() {
  try {
    const saved = localStorage.getItem(GROUP_STORAGE_KEY);
    const value = JSON.parse(saved || "[]");
    return {
      groups: new Set(Array.isArray(value) ? value : []),
      initialized: saved !== null,
    };
  } catch (error) {
    return { groups: new Set(), initialized: false };
  }
}
function focusableElements(root) {
  return Array.from(
    root.querySelectorAll(
      'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])',
    ),
  ).filter((element) => !element.hidden && element.getClientRects().length > 0);
}
function renderIcons() {
  window.lucide?.createIcons({ attrs: { "stroke-width": 1.8 } });
}
function syncSidebarToggleIcon(toggle, mobile, collapsed) {
  const iconName = mobile
    ? "menu"
    : collapsed
      ? "panel-left-open"
      : "panel-left-close";
  if (toggle.dataset.icon === iconName) return;
  toggle.dataset.icon = iconName;
  const icon = document.createElement("i");
  icon.dataset.lucide = iconName;
  icon.setAttribute("aria-hidden", "true");
  toggle.replaceChildren(icon);
  renderIcons();
}
function translate(key, fallback, vars = {}) {
  return window.klaxondI18n?.t?.(key, vars) || fallback;
}
function syncGroupIndicator(group) {
  const button = group.querySelector(".tab-group-toggle");
  if (!button) return;
  const badges = Array.from(
    group.querySelectorAll(".tab-group-items .tab-badge"),
  );
  const count = badges.reduce((total, badge) => {
    const value = Number.parseInt(badge.textContent || "0", 10);
    return total + (Number.isFinite(value) ? value : 0);
  }, 0);
  let indicator = button.querySelector(".group-indicator");
  if (!count) {
    indicator?.remove();
  } else {
    if (!indicator) {
      indicator = document.createElement("span");
      indicator.className = "group-indicator";
      button.insertBefore(indicator, button.lastElementChild);
    }
    const severity = badges.some((badge) => badge.classList.contains("crit"))
      ? "crit"
      : badges.some((badge) => badge.classList.contains("warn"))
        ? "warn"
        : "";
    const className = `group-indicator${severity ? ` ${severity}` : ""}`;
    const text = count > 99 ? "99+" : String(count);
    if (indicator.className !== className) indicator.className = className;
    if (indicator.textContent !== text) indicator.textContent = text;
  }
  const label = button.querySelector("[data-i18n]")?.textContent?.trim() || "";
  const badgeLabel = count
    ? `, ${translate("tab.badge_count", `${count} active indicator(s)`, { count: count })}`
    : "";
  const accessibleLabel = `${label}${badgeLabel}`;
  if (button.getAttribute("aria-label") !== accessibleLabel) {
    button.setAttribute("aria-label", accessibleLabel);
  }
}

function bindSidebarControls({ sidebar, media, setCollapsed, setGroupCollapsed, closeAfterNavigation }) {
  setCollapsed(media?.matches ? true : desktopCollapsedPreference());
  document.getElementById("sidebar-toggle")?.addEventListener("click", () => {
    const collapsed = !document.body.classList.contains("sidebar-collapsed");
    setCollapsed(collapsed, { persist: true });
  });
  document.getElementById("sidebar-backdrop")?.addEventListener("click", () =>
    setCollapsed(true, { restoreFocus: true }),
  );
  document.querySelectorAll(".tab").forEach((tab) => {
    tab.addEventListener("click", () => {
      const group = tab.closest(".tab-group");
      if (group) setGroupCollapsed(group, false, false);
      setTimeout(() => {
        if (tab.classList.contains("active")) closeAfterNavigation();
      }, 0);
    });
  });
  document.addEventListener("keydown", (event) => {
    if (event.defaultPrevented) return;
    const openMobileDrawer =
      media?.matches && !document.body.classList.contains("sidebar-collapsed");
    if (!openMobileDrawer) return;
    if (event.key === "Escape") {
      event.preventDefault();
      setCollapsed(true, { restoreFocus: true });
      return;
    }
    if (event.key !== "Tab") return;
    const focusable = focusableElements(sidebar);
    if (!focusable.length) return;
    const first = focusable[0];
    const last = focusable[focusable.length - 1];
    if (event.shiftKey && document.activeElement === first) {
      event.preventDefault();
      last.focus();
    } else if (!event.shiftKey && document.activeElement === last) {
      event.preventDefault();
      first.focus();
    }
  });
  const handleViewportChange = (event) => {
    setCollapsed(event.matches ? true : desktopCollapsedPreference());
  };
  if (media?.addEventListener) media.addEventListener("change", handleViewportChange);
  else media?.addListener?.(handleViewportChange);
  document.addEventListener("klaxond:languagechange", () => {
    if (sidebar.getAttribute("role") === "dialog") {
      sidebar.setAttribute("aria-label", translate("nav.main", "Main navigation"));
    }
    document.querySelectorAll(".tab-group").forEach(syncGroupIndicator);
  });
  renderIcons();
}

function initializeSidebarGroups(groupPreference, setGroupCollapsed) {
  document.querySelectorAll(".tab-group").forEach((group) => {
    const hasActiveTab = Boolean(group.querySelector(".tab.active"));
    const collapseInactive =
      !groupPreference.initialized ||
      groupPreference.groups.has(group.dataset.group);
    setGroupCollapsed(group, !hasActiveTab && collapseInactive, false);
    group.querySelector(".tab-group-toggle")?.addEventListener("click", () => {
      setGroupCollapsed(group, !group.classList.contains("is-collapsed"));
    });
    syncGroupIndicator(group);
  });
  if (!groupPreference.initialized) {
    document.querySelectorAll(".tab-group.is-collapsed").forEach((group) => {
      groupPreference.groups.add(group.dataset.group);
    });
  }
}

function observeSidebarNavigation({ sidebar, setGroupCollapsed, closeAfterNavigation }) {
  const nav = sidebar.querySelector("nav.tabs");
  const badgeObserver = new MutationObserver(() => {
    document.querySelectorAll(".tab-group").forEach(syncGroupIndicator);
  });
  if (nav)
    badgeObserver.observe(nav, {
      childList: true,
      subtree: true,
      attributes: true,
      attributeFilter: ["class"],
    });
  const activeTabObserver = new MutationObserver((mutations) => {
    for (const mutation of mutations) {
      const tab = mutation.target;
      if (!(tab instanceof HTMLElement) || !tab.matches(".tab.active")) continue;
      const group = tab.closest(".tab-group");
      if (group) setGroupCollapsed(group, false, false);
      closeAfterNavigation();
    }
  });
  document.querySelectorAll(".tab").forEach((tab) => {
    activeTabObserver.observe(tab, { attributes: true, attributeFilter: ["class"] });
  });
}

function createSidebarCollapseHandler({ sidebar, toggle, backdrop, appMain, media, setGroupCollapsed }) {
  return (collapsed, { persist = false, restoreFocus = false } = {}) => {
    const mobile = Boolean(media?.matches);
    document.body.classList.toggle("sidebar-collapsed", collapsed);
    document.body.classList.toggle("mobile-nav-open", mobile && !collapsed);
    toggle.setAttribute("aria-expanded", String(!collapsed));
    syncSidebarToggleIcon(toggle, mobile, collapsed);
    if (appMain) appMain.inert = mobile && !collapsed;
    if (mobile && !collapsed) {
      sidebar.setAttribute("role", "dialog");
      sidebar.setAttribute("aria-modal", "true");
      sidebar.setAttribute("aria-label", translate("nav.main", "Main navigation"));
    } else {
      sidebar.removeAttribute("role");
      sidebar.removeAttribute("aria-modal");
      sidebar.removeAttribute("aria-label");
    }
    if (backdrop) backdrop.hidden = !mobile || collapsed;
    if (persist && !mobile) {
      try {
        localStorage.setItem("klaxond.sidebarCollapsed", collapsed ? "1" : "0");
      } catch (error) {}
    }
    if (mobile && !collapsed) {
      const activeGroup = sidebar.querySelector(".tab.active")?.closest(".tab-group");
      if (activeGroup) setGroupCollapsed(activeGroup, false, false);
      requestAnimationFrame(() => sidebar.querySelector(".tab.active")?.focus());
    } else if (restoreFocus) {
      requestAnimationFrame(() => toggle.focus());
    }
  };
}

export function setupSidebar() {
  const sidebar = document.getElementById("sidebar");
  const toggle = document.getElementById("sidebar-toggle");
  const backdrop = document.getElementById("sidebar-backdrop");
  const media = window.matchMedia?.(MOBILE_SIDEBAR_QUERY);
  if (!sidebar || !toggle) return;
  const groupPreference = collapsedGroupsPreference();
  const setGroupCollapsed = (group, collapsed, persist = true) => {
    const button = group.querySelector(".tab-group-toggle");
    group.classList.toggle("is-collapsed", collapsed);
    button?.setAttribute("aria-expanded", String(!collapsed));
    if (!persist) return;
    const name = group.dataset.group;
    if (collapsed) groupPreference.groups.add(name);
    else groupPreference.groups.delete(name);
    groupPreference.initialized = true;
    try {
      localStorage.setItem(
        GROUP_STORAGE_KEY,
        JSON.stringify([...groupPreference.groups]),
      );
    } catch (error) {}
  };
  initializeSidebarGroups(groupPreference, setGroupCollapsed);
  const appMain = document.querySelector(".app-main");
  const focusMain = () =>
    requestAnimationFrame(() =>
      document.getElementById("main-content")?.focus(),
    );
  const closeAfterNavigation = () => {
    if (
      !media?.matches ||
      document.body.classList.contains("sidebar-collapsed")
    )
      return;
    setCollapsed(true);
    focusMain();
  };
  const setCollapsed = createSidebarCollapseHandler({
    sidebar, toggle, backdrop, appMain, media, setGroupCollapsed,
  });
  observeSidebarNavigation({ sidebar, setGroupCollapsed, closeAfterNavigation });
  bindSidebarControls({ sidebar, media, setCollapsed, setGroupCollapsed, closeAfterNavigation });
}
