import { markTabDirty } from "./app.js";

const dirtySections = new Set();
const sectionRevisions = new Map();

export function markDeliverySectionDirty(section, dirty = true) {
  if (dirty) {
    dirtySections.add(section);
    sectionRevisions.set(section, (sectionRevisions.get(section) || 0) + 1);
  } else {
    dirtySections.delete(section);
  }
  markTabDirty("delivery", dirtySections.size > 0);
}

export function deliverySectionRevision(section) {
  return sectionRevisions.get(section) || 0;
}

export function resetDeliveryDirtyState() {
  dirtySections.clear();
  markTabDirty("delivery", false);
}

document.addEventListener("klaxond:tabdiscard", event => {
  if (event.detail?.tabId === "delivery") resetDeliveryDirtyState();
});
