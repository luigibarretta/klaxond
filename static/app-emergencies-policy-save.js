import {
  $,
  apiFetch,
  confirmDialog,
  markTabDirty,
  notifyError,
  notifySuccess,
  notifyValidationError,
  setInlineStatus,
  tr,
} from "./app.js";
import { emergencyState, reloadEmergencyData } from "./app-emergencies-state.js";
import { profileManaged, syncProfilesFromDom } from "./app-emergencies-core.js";
function setDirty() {
  emergencyState.policyDirty = true;
  markTabDirty("emergencies", true);
}
export function policyPayload() {
  syncProfilesFromDom();
  const managed = emergencyState.policyConfig.managed_fields || {};
  const payload = {};
  if (!managed.enabled) payload.enabled = $("#em-enabled").checked;
  if (!managed.fallback_profile)
    payload.fallback_profile = $("#em-fallback").value;
  if (
    !emergencyState.policyConfig.settings.profiles.some((profile) =>
      profileManaged(profile.id),
    )
  )
    payload.profiles = emergencyState.policyConfig.settings.profiles;
  if (!managed.exclude_sources)
    payload.exclude_sources = emergencyState.policyConfig.settings.exclude_sources;
  if (!managed.allow_insecure_public_url)
    payload.allow_insecure_public_url = $("#em-allow-insecure").checked;
  if (!managed.allow_ntfy_only)
    payload.allow_ntfy_only = $("#em-allow-ntfy-only").checked;
  return payload;
}
export function validatePolicy(payload) {
  const ids = new Set();
  for (const profile of payload.profiles || emergencyState.policyConfig.settings.profiles) {
    if (!/^[a-z0-9._-]{1,64}$/.test(profile.id) || ids.has(profile.id))
      return tr("emergency.profile_id_invalid");
    ids.add(profile.id);
    if (!profile.name || profile.name.length > 80)
      return tr("emergency.profile_name_invalid");
    if (
      !profile.severities.length &&
      !profile.sources.length &&
      !Object.keys(profile.match || {}).length
    )
      return tr("emergency.matcher_required", { profile: profile.name });
    for (const field of [
      "retry_seconds",
      "expire_seconds",
      "max_attempts",
      "lease_seconds",
    ])
      if (!Number.isInteger(profile[field]))
        return tr("emergency.invalid_number", { field: field });
    if (profile.expire_seconds < profile.retry_seconds)
      return tr("emergency.expiry_invalid");
    if (
      profile.telegram.after_attempts > profile.max_attempts ||
      profile.smtp.after_attempts > profile.max_attempts
    )
      return tr("emergency.escalation_invalid");
    const timeouts = emergencyState.policyConfig.channel_timeouts || {};
    const required =
      Number(timeouts.ntfy || 15) +
      (profile.telegram.enabled ? Number(timeouts.telegram || 8) : 0) +
      (profile.smtp.enabled ? Number(timeouts.smtp || 10) : 0) +
      Number(timeouts.lease_margin || 5);
    if (profile.lease_seconds < required)
      return tr("emergency.lease_impossible_profile", {
        profile: profile.name,
        required: required,
      });
  }
  if (
    !ids.has(payload.fallback_profile || emergencyState.policyConfig.settings.fallback_profile)
  )
    return tr("emergency.fallback_invalid");
  return "";
}
export async function savePolicy() {
  let payload;
  try {
    payload = policyPayload();
  } catch (error) {
    notifyValidationError(
      "emergency-policy",
      error.message,
      "#emergency-policy-status",
    );
    return;
  }
  const invalid = validatePolicy(payload);
  if (invalid) {
    notifyValidationError(
      "emergency-policy",
      invalid,
      "#emergency-policy-status",
    );
    return;
  }
  const current = emergencyState.policyConfig.settings || {};
  const unsafeRaised =
    (payload.allow_insecure_public_url && !current.allow_insecure_public_url) ||
    (payload.allow_ntfy_only && !current.allow_ntfy_only);
  if (
    unsafeRaised &&
    !(await confirmDialog(tr("emergency.unsafe_confirm"), {
      title: tr("emergency.unsafe_options"),
      confirmLabel: tr("common.save_changes"),
      danger: true,
    }))
  )
    return;
  setInlineStatus("#emergency-policy-status", tr("status.saving"));
  try {
    const response = await apiFetch("/api/emergency-config", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    if (!response.ok) throw new Error(await response.text());
    emergencyState.policyDirty = false;
    markTabDirty("emergencies", false);
    notifySuccess(tr("emergency.saved"), {
      status: "#emergency-policy-status",
      clearMs: 4e3,
    });
    await reloadEmergencyData({ force: true });
  } catch (error) {
    notifyError("emergency-policy", error, {
      status: "#emergency-policy-status",
    });
  }
}
