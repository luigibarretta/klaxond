import { $, APP_META, onReady } from "./app.js";

const VERSION_EASTER_EGG_CLICKS = 7;
let _appVersion = "";
let _versionEggClicks = 0;
let _versionEggTimer = null;
let _versionEggLastFocus = null;

const VERSION_EASTER_EGGS = {
  "0": {
    title: "bootstrap signal",
    lines: [
      "cascade path: armed",
      "inhibition matrix: warm",
      "dedup buffer: quiet",
      "renderer: standing by"
    ]
  }
};

function majorVersion(version) {
  const match = String(version || "").match(/^v?(\d+)/);
  return match ? match[1] : "0";
}

function fallbackEasterEggForMajor(major) {
  const variants = [
    ["signal window", ["routes aligned", "alerts normalized", "channels watching", "operator calm"]],
    ["relay chamber", ["webhooks primed", "policies loaded", "tokens scoped", "handoff clean"]],
    ["control plane", ["guards awake", "logs retained", "config sealed", "status green"]]
  ];
  const seed = Array.from(String(major)).reduce((acc, ch) => acc + ch.charCodeAt(0), 0);
  const chosen = variants[seed % variants.length];
  return { title: chosen[0], lines: chosen[1] };
}

function easterEggForMajor(major) {
  return VERSION_EASTER_EGGS[major] || fallbackEasterEggForMajor(major);
}

export function updateAppVersion(version) {
  if (!version) return;
  _appVersion = String(version).replace(/^v/, "");
  const footerVersion = $("#footer-version");
  if (!footerVersion) return;
  footerVersion.textContent = `v${_appVersion}`;
  footerVersion.dataset.version = _appVersion;
  footerVersion.dataset.major = majorVersion(_appVersion);
  footerVersion.setAttribute("role", "button");
  footerVersion.setAttribute("tabindex", "0");
  footerVersion.setAttribute("aria-label", `klaxond v${_appVersion}`);
}

updateAppVersion(APP_META.version);

function showVersionEasterEgg() {
  const major = majorVersion(_appVersion || $("#footer-version")?.textContent || "0");
  const egg = easterEggForMajor(major);
  const panel = $("#version-easter-egg");
  if (!panel) return;
  _versionEggLastFocus = document.activeElement instanceof HTMLElement ? document.activeElement : null;
  $("#version-egg-major").textContent = `major v${major}`;
  $("#version-egg-title").textContent = egg.title;
  $("#version-egg-body").textContent = egg.lines.join("\n");
  panel.dataset.major = major;
  panel.classList.remove("hidden");
  requestAnimationFrame(() => $("#version-egg-close")?.focus());
}

function closeVersionEasterEgg() {
  const panel = $("#version-easter-egg");
  if (!panel || panel.classList.contains("hidden")) return;
  panel.classList.add("hidden");
  if (_versionEggLastFocus && document.contains(_versionEggLastFocus)) {
    _versionEggLastFocus.focus();
  }
}

function countVersionClick() {
  clearTimeout(_versionEggTimer);
  _versionEggClicks += 1;
  if (_versionEggClicks >= VERSION_EASTER_EGG_CLICKS) {
    _versionEggClicks = 0;
    showVersionEasterEgg();
    return;
  }
  _versionEggTimer = setTimeout(() => { _versionEggClicks = 0; }, 2500);
}

function setupVersionEasterEgg() {
  const footerVersion = $("#footer-version");
  if (!footerVersion) return;
  updateAppVersion(footerVersion.textContent || "0");
  footerVersion.addEventListener("click", countVersionClick);
  footerVersion.addEventListener("keydown", e => {
    if (e.key !== "Enter" && e.key !== " ") return;
    e.preventDefault();
    countVersionClick();
  });
  $("#version-egg-close")?.addEventListener("click", closeVersionEasterEgg);
  document.addEventListener("keydown", e => {
    if (e.key === "Escape") closeVersionEasterEgg();
  });
}

onReady(setupVersionEasterEgg);

