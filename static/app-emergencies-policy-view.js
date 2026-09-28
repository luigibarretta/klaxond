import {
  $,
  escapeHtml,
  markTabDirty,
  notifyValidationError,
  tr,
} from "./app.js";
import { emergencyState, markPolicyDirty } from "./app-emergencies-state.js";
import {
  profileManaged,
  profileMarkup,
  renderChipEditor,
  renderDiagnostics,
  renderTimeline,
  syncProfilesFromDom,
} from "./app-emergencies-core.js";
function renderPolicyControls(settings, managed) {
  $("#em-enabled").checked = !!settings.enabled;
  $("#em-allow-insecure").checked = !!settings.allow_insecure_public_url;
  $("#em-allow-ntfy-only").checked = !!settings.allow_ntfy_only;
  for (const [field, selector] of [
    ["enabled", "#em-enabled"],
    ["allow_insecure_public_url", "#em-allow-insecure"],
    ["allow_ntfy_only", "#em-allow-ntfy-only"],
  ]) {
    $(selector).disabled = !!managed[field];
    $(selector).title = managed[field]
      ? tr("emergency.managed_field", { env: managed[field] })
      : "";
  }
  const owner = emergencyState.policyConfig.source_of_truth || "ui";
  $("#emergency-owner").textContent = tr(`emergency.owner_${owner}`);
  const owners = Object.entries(managed);
  $("#emergency-env-notice").classList.toggle("hidden", owners.length === 0);
  $("#emergency-env-notice").textContent = owners.length
    ? tr("emergency.managed_notice_compact", { count: owners.length })
    : "";
  const fallback = $("#em-fallback");
  fallback.innerHTML = settings.profiles
    .map(
      (profile) =>
        `<option value="${escapeHtml(profile.id)}" ${profile.id === settings.fallback_profile ? "selected" : ""}>${escapeHtml(profile.name)} · ${escapeHtml(profile.id)}</option>`,
    )
    .join("");
  fallback.disabled =
    !!managed.fallback_profile ||
    settings.profiles.some((profile) => profileManaged(profile.id));
  $("#emergency-policy-save").disabled = settings.profiles.some((profile) =>
    profileManaged(profile.id),
  );
  $("#emergency-policy-save").title = $("#emergency-policy-save").disabled
    ? tr("emergency.profile_managed")
    : "";
}

function renderProfileEditors(settings, managed) {
  $("#emergency-profiles").innerHTML = settings.profiles
    .map((profile, index) =>
      profileMarkup(profile, index, profileManaged(profile.id)),
    )
    .join("");
  settings.profiles.forEach((profile, index) => {
    renderChipEditor($(`#profile-severities-${index}`), {
      label: tr("emergency.severities"),
      values: profile.severities,
      suggestions: emergencyState.policyConfig.known_severities,
      placeholder: tr("emergency.add_severity"),
      disabled: profileManaged(profile.id),
      onChange: () =>
        renderTimeline($(`[data-profile-index="${index}"]`), profile),
    });
    renderChipEditor($(`#profile-sources-${index}`), {
      label: tr("emergency.sources"),
      values: profile.sources,
      suggestions: emergencyState.policyConfig.known_sources,
      placeholder: tr("emergency.add_source"),
      disabled: profileManaged(profile.id),
      onChange: () =>
        renderTimeline($(`[data-profile-index="${index}"]`), profile),
    });
    const card = $(`[data-profile-index="${index}"]`);
    renderTimeline(card, profile);
    card
      .querySelectorAll("[data-profile-action]")
      .forEach((button) =>
        button.addEventListener("click", () =>
          profileAction(index, button.dataset.profileAction),
        ),
      );
  });
  renderChipEditor($("#em-excluded-sources"), {
    label: tr("emergency.exclude_sources"),
    values: settings.exclude_sources,
    suggestions: emergencyState.policyConfig.known_sources,
    placeholder: tr("emergency.add_source"),
    disabled: !!managed.exclude_sources,
  });
}

export function renderPolicyConfig(config, force = false) {
  if (!emergencyState.policyDirty || force) {
    emergencyState.policyConfig = JSON.parse(
      JSON.stringify(config || emergencyState.policyConfig),
    );
  }
  const settings = emergencyState.policyConfig.settings || {};
  settings.profiles ||= [];
  settings.exclude_sources ||= [];
  const managed = emergencyState.policyConfig.managed_fields || {};
  renderPolicyControls(settings, managed);
  renderProfileEditors(settings, managed);
  renderDiagnostics();
  if (!emergencyState.policyDirty || force) {
    emergencyState.policyDirty = false;
    markTabDirty("emergencies", false);
  }
  hydrateSimulatorOptions();
  window.applyReadOnlyViewerMode?.(window.klaxondCurrentUser || {});
}
export function hydrateSimulatorOptions() {
  const set = (selector, values) => {
    const node = $(selector);
    if (node)
      node.innerHTML = (values || [])
        .map((value) => `<option value="${escapeHtml(value)}"></option>`)
        .join("");
  };
  set("#policy-sim-sources", emergencyState.policyConfig.known_sources);
  set("#policy-sim-severities", emergencyState.policyConfig.known_severities);
}
export function profileAction(index, action) {
  syncProfilesFromDom();
  const profiles = emergencyState.policyConfig.settings.profiles;
  if (action === "delete") {
    const removed = profiles[index];
    profiles.splice(index, 1);
    if (emergencyState.policyConfig.settings.fallback_profile === removed.id)
      emergencyState.policyConfig.settings.fallback_profile = profiles[0]?.id || "";
  } else if (action === "up" && index > 0)
    [profiles[index - 1], profiles[index]] = [
      profiles[index],
      profiles[index - 1],
    ];
  else if (action === "down" && index < profiles.length - 1)
    [profiles[index + 1], profiles[index]] = [
      profiles[index],
      profiles[index + 1],
    ];
  markPolicyDirty();
  renderPolicyConfig(emergencyState.policyConfig, false);
}
export function addProfile() {
  try {
    syncProfilesFromDom();
  } catch (error) {
    notifyValidationError(
      "emergency-policy",
      error.message,
      "#emergency-policy-status",
    );
    return;
  }
  const suffix = Date.now().toString(36).slice(-5);
  emergencyState.policyConfig.settings.profiles.push({
    id: `profile-${suffix}`,
    name: tr("emergency.new_profile"),
    enabled: true,
    priority: 50,
    severities: ["warning"],
    sources: [],
    match: {},
    retry_seconds: 300,
    expire_seconds: 3600,
    max_attempts: 12,
    lease_seconds: 60,
    telegram: { enabled: true, after_attempts: 3 },
    smtp: { enabled: false, after_attempts: 5 },
    notify_on_expiry: true,
    auto_resolve: true,
  });
  markPolicyDirty();
  renderPolicyConfig(emergencyState.policyConfig, false);
  $(
    "#emergency-profiles article:last-child input[data-profile-field='name']",
  )?.focus();
}
