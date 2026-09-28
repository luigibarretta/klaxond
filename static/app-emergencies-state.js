import { markTabDirty } from "./app.js";

export const emergencyState = {
  incidents: [],
  policyDirty: false,
  policyConfig: {
    settings: { profiles: [], exclude_sources: [] },
    managed_fields: {},
  },
};

let reloadEmergencies = async () => {};

export function setEmergencyReload(callback) {
  reloadEmergencies = callback;
}

export function reloadEmergencyData(options) {
  return reloadEmergencies(options);
}

export function markPolicyDirty(dirty = true) {
  emergencyState.policyDirty = dirty;
  markTabDirty("emergencies", dirty);
}
