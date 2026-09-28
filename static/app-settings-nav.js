export function setupSettingsNavigation() {
  document.querySelectorAll(".settings-index").forEach(navigation => {
    const pane = navigation.closest(".tabpane");
    const actions = pane?.querySelector(".settings-actions");
    const updateSectionOffset = () => {
      if (!pane || !actions) return;
      const stickyTop = parseFloat(getComputedStyle(actions).top) || 0;
      pane.style.setProperty(
        "--settings-section-offset",
        `${Math.ceil(stickyTop + actions.getBoundingClientRect().height + 12)}px`,
      );
    };
    updateSectionOffset();
    window.addEventListener("resize", updateSectionOffset, { passive: true });
    if (typeof ResizeObserver !== "undefined" && actions) {
      new ResizeObserver(updateSectionOffset).observe(actions);
    }
  });
  document.querySelectorAll("[data-settings-target]").forEach(button => {
    button.addEventListener("click", () => {
      const target = document.getElementById(button.dataset.settingsTarget);
      if (!target) return;
      target.scrollIntoView({ block: "start", behavior: "smooth" });
      target.focus({ preventScroll: true });
    });
  });
}
