import { buildEnglishMessages } from "./i18n-en.js";
import { buildItalianMessages } from "./i18n-it.js";

// klaxond UI preferences: i18n + theme mode.
// No build step and no framework: this file is loaded before app.js.

(function () {
  const LANG_KEY = "klaxond.lang";
  const THEME_MODE_KEY = "klaxond.themeMode";
  const LEGACY_THEME_KEY = "klaxond.theme";
  const LANGS = ["en", "it"];
  const THEME_MODES = ["system", "light", "dark"];
  const APP_META = window.KLAXOND_META || {};
  const AUTHOR_NAME = String(APP_META.authorName || "Author");
  const AUTHOR_URL = String(APP_META.authorUrl || "");
  const htmlEscape = value => String(value || "").replace(/[&<>"']/g, ch => (
    {"&": "&amp;", "<": "&lt;", ">": "&gt;", "\"": "&quot;", "'": "&#39;"}[ch]
  ));
  const authorLink = () => AUTHOR_URL
    ? `<a href="${htmlEscape(AUTHOR_URL)}" target="_blank" rel="noopener">${htmlEscape(AUTHOR_NAME)}</a>`
    : htmlEscape(AUTHOR_NAME);

  const M = {
    en: buildEnglishMessages({ authorLink }),
    it: buildItalianMessages({ authorLink })
  };


  function normalizeLang(value) {
    const lang = String(value || "").toLowerCase().slice(0, 2);
    return LANGS.includes(lang) ? lang : "en";
  }

  function browserLang() {
    return normalizeLang((navigator.language || "en").toLowerCase().startsWith("it") ? "it" : "en");
  }

  function currentLanguage() {
    try {
      const stored = localStorage.getItem(LANG_KEY);
      if (stored) return normalizeLang(stored);
    } catch (e) {}
    return normalizeLang(document.documentElement.getAttribute("data-lang") || browserLang());
  }

  function interpolate(text, vars) {
    return String(text).replace(/\{([a-zA-Z0-9_]+)\}/g, (_, key) => {
      const value = vars && Object.prototype.hasOwnProperty.call(vars, key) ? vars[key] : "";
      return value == null ? "" : String(value);
    });
  }

  function t(key, vars) {
    const lang = currentLanguage();
    const text = (M[lang] && M[lang][key]) || M.en[key] || key;
    return interpolate(text, vars || {});
  }

  function setText(el, text) {
    if (el && el.textContent !== text) el.textContent = text;
  }

  function setHtml(el, html) {
    if (el && el.innerHTML !== html) el.innerHTML = html;
  }

  function languageOptionButtons() {
    return document.querySelectorAll("[data-language-option], [data-public-language-option]");
  }

  function buttonLanguage(btn) {
    return btn.dataset.languageOption || btn.dataset.publicLanguageOption || "";
  }

  function applyI18n(lang) {
    const next = normalizeLang(lang || currentLanguage());
    document.documentElement.lang = next;
    document.documentElement.setAttribute("data-lang", next);
    document.title = t("app.title");

    document.querySelectorAll("[data-i18n-html]").forEach(el => setHtml(el, t(el.dataset.i18nHtml)));
    document.querySelectorAll("[data-i18n]").forEach(el => {
      if (!el.closest("[data-i18n-html]")) setText(el, t(el.dataset.i18n));
    });
    document.querySelectorAll("[data-i18n-placeholder]").forEach(el => {
      el.setAttribute("placeholder", t(el.dataset.i18nPlaceholder));
    });
    document.querySelectorAll("[data-i18n-title]").forEach(el => {
      const text = t(el.dataset.i18nTitle);
      el.setAttribute("title", text);
      if (el.hasAttribute("aria-label")) el.setAttribute("aria-label", text);
    });
    document.querySelectorAll("[data-i18n-aria-label]").forEach(el => {
      el.setAttribute("aria-label", t(el.dataset.i18nAriaLabel));
    });

    const select = document.getElementById("language-select");
    if (select) select.value = next;
    languageOptionButtons().forEach(btn => {
      const active = normalizeLang(buttonLanguage(btn)) === next;
      btn.classList.toggle("active", active);
      btn.setAttribute("aria-pressed", active ? "true" : "false");
    });
  }

  function setLanguage(lang) {
    const next = normalizeLang(lang);
    try { localStorage.setItem(LANG_KEY, next); } catch (e) {}
    applyI18n(next);
    document.dispatchEvent(new CustomEvent("klaxond:languagechange", { detail: { lang: next } }));
  }

  function normalizeThemeMode(mode) {
    return THEME_MODES.includes(mode) ? mode : "system";
  }

  function storedThemeMode() {
    try {
      const mode = localStorage.getItem(THEME_MODE_KEY);
      if (mode) return normalizeThemeMode(mode);
      const legacy = localStorage.getItem(LEGACY_THEME_KEY);
      if (legacy === "light" || legacy === "dark") return legacy;
    } catch (e) {}
    return normalizeThemeMode(document.documentElement.getAttribute("data-theme-mode") || "system");
  }

  function resolveTheme(mode) {
    const m = normalizeThemeMode(mode);
    if (m !== "system") return m;
    try {
      if (window.matchMedia && window.matchMedia("(prefers-color-scheme: light)").matches) return "light";
    } catch (e) {}
    return "dark";
  }

  function applyThemeMode(mode) {
    const next = normalizeThemeMode(mode);
    const theme = resolveTheme(next);
    document.documentElement.setAttribute("data-theme-mode", next);
    document.documentElement.setAttribute("data-theme", theme);
    document.documentElement.style.colorScheme = theme;
    const select = document.getElementById("theme-mode");
    if (select) select.value = next;
    document.querySelectorAll("[data-theme-mode-option]").forEach(btn => {
      const active = normalizeThemeMode(btn.dataset.themeModeOption) === next;
      btn.classList.toggle("active", active);
      btn.setAttribute("aria-pressed", active ? "true" : "false");
    });
  }

  function setThemeMode(mode) {
    const next = normalizeThemeMode(mode);
    try {
      localStorage.setItem(THEME_MODE_KEY, next);
      localStorage.removeItem(LEGACY_THEME_KEY);
    } catch (e) {}
    applyThemeMode(next);
    document.dispatchEvent(new CustomEvent("klaxond:themechange", {
      detail: { mode: next, theme: resolveTheme(next) }
    }));
  }

  function initPreferences() {
    applyI18n(currentLanguage());
    applyThemeMode(storedThemeMode());

    document.getElementById("language-select")?.addEventListener("change", e => setLanguage(e.target.value));
    document.getElementById("theme-mode")?.addEventListener("change", e => setThemeMode(e.target.value));
    languageOptionButtons().forEach(btn => {
      btn.addEventListener("click", () => setLanguage(buttonLanguage(btn)));
    });
    document.querySelectorAll("[data-theme-mode-option]").forEach(btn => {
      btn.addEventListener("click", () => setThemeMode(btn.dataset.themeModeOption));
    });

    try {
      const media = window.matchMedia("(prefers-color-scheme: light)");
      media.addEventListener("change", () => {
        if (storedThemeMode() === "system") applyThemeMode("system");
      });
    } catch (e) {}
  }

  window.klaxondI18n = {
    applyI18n,
    applyThemeMode,
    currentLanguage,
    setLanguage,
    setThemeMode,
    storedThemeMode,
    t
  };
  window.t = t;

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", initPreferences);
  } else {
    initPreferences();
  }
})();
