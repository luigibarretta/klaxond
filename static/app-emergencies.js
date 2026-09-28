import { $, apiFetch, notifyError, tr } from "./app.js";
import { renderRows, renderTimeline, syncProfilesFromDom } from "./app-emergencies-core.js";
import { addProfile, renderPolicyConfig } from "./app-emergencies-policy-view.js";
import { savePolicy } from "./app-emergencies-policy-save.js";
import {
  emergencyState,
  markPolicyDirty,
  setEmergencyReload,
} from "./app-emergencies-state.js";

export async function loadEmergencies(options = {}) {
  try {
    const filter = $("#emergency-filter")?.value || "all";
    const [listResponse, configResponse] = await Promise.all([
      apiFetch(`/api/emergencies?state=${encodeURIComponent(filter)}&limit=500`),
      apiFetch("/api/emergency-config"),
    ]);
    if (!listResponse.ok) throw new Error(await listResponse.text());
    if (!configResponse.ok) throw new Error(await configResponse.text());
    const list = await listResponse.json();
    const config = await configResponse.json();
    emergencyState.incidents = Array.isArray(list.incidents)
      ? list.incidents
      : [];
    const profiles = (config.settings?.profiles || []).filter(
      (profile) => profile.enabled,
    );
    $("#emergency-policy").textContent = config.settings?.enabled
      ? tr("emergency.profile_count", { count: profiles.length })
      : tr("emergency.disabled");
    $("#emergency-active").textContent = String(
      emergencyState.incidents.filter((item) => item.state === "active").length,
    );
    $("#emergency-escalation").textContent = profiles.length
      ? profiles
          .map(
            (profile) =>
              `${profile.name}: ${[
                profile.telegram.enabled
                  ? `TG #${profile.telegram.after_attempts}`
                  : "",
                profile.smtp.enabled
                  ? `SMTP #${profile.smtp.after_attempts}`
                  : "",
              ].filter(Boolean).join(" · ") || "ntfy"}`,
          )
          .join(" | ")
      : "—";
    renderPolicyConfig(config, !!options.force);
    renderRows();
  } catch (error) {
    notifyError("emergencies", error);
  }
}

setEmergencyReload(loadEmergencies);

$("#emergency-filter")?.addEventListener("change", () => loadEmergencies());
$("#emergency-refresh")?.addEventListener("click", () =>
  loadEmergencies({ force: !emergencyState.policyDirty }),
);
$("#emergency-policy-editor")?.addEventListener("input", (event) => {
  if (!event.target.closest("[data-emergency-field], [data-profile-field]"))
    return;
  markPolicyDirty();
  const card = event.target.closest("[data-profile-index]");
  if (!card) return;
  try {
    syncProfilesFromDom();
    renderTimeline(
      card,
      emergencyState.policyConfig.settings.profiles[
        Number(card.dataset.profileIndex)
      ],
    );
  } catch {}
});
$("#emergency-profile-add")?.addEventListener("click", addProfile);
$("#emergency-policy-save")?.addEventListener("click", savePolicy);
