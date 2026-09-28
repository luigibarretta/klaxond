import {
  $,
  J,
  apiFetch,
  confirmDialog,
  escapeHtml,
  fetchError,
  markTabDirty,
  notifyError,
  notifyResponseError,
  notifySuccess,
  queryGet,
  setInlineStatus,
  tr,
} from "./app.js";
import { loadStatus } from "./app-status.js";
export { loadIngestAuth } from "./app-routing-ingest.js";
let ntfyTopicsData = {
  topics: [],
  known_severities: [],
  note: "",
  writeable: false,
};
export const routingDirtySections = new Set();
export const routingEditRevisions = new Map([
  ["channels", 0],
  ["topics", 0],
]);
export const routingLoadGenerations = new Map([
  ["channels", 0],
  ["topics", 0],
]);
export const routingSavingSections = new Set();
export const routingForceReloadSections = new Set();
export let routingBatchGeneration = 0;
export let routingBatchActive = false;
export function updateRoutingDirtyState() {
  const dirty = routingDirtySections.size > 0;
  markTabDirty("routing", dirty);
  const readOnly = document.body.classList.contains("viewer-readonly");
  const saveAll = $("#routing-save-all");
  if (saveAll)
    saveAll.disabled =
      !dirty ||
      readOnly ||
      routingSavingSections.size > 0 ||
      routingBatchActive;
  const discard = $("#routing-discard");
  if (discard)
    discard.disabled =
      !dirty ||
      readOnly ||
      routingSavingSections.size > 0 ||
      routingBatchActive;
  for (const section of ["channels", "topics"]) {
    document
      .querySelectorAll(`[data-routing-save-section="${section}"]`)
      .forEach((button) => {
        button.disabled =
          !routingDirtySections.has(section) ||
          readOnly ||
          routingSavingSections.has(section) ||
          routingBatchActive;
      });
  }
  const status = $("#routing-dirty-status");
  if (status) {
    status.textContent = dirty
      ? tr("settings.unsaved_sections", { count: routingDirtySections.size })
      : tr("settings.no_unsaved_changes");
  }
}
export function markRoutingSectionDirty(section, dirty = true) {
  if (dirty) {
    routingDirtySections.add(section);
    routingForceReloadSections.delete(section);
    routingEditRevisions.set(
      section,
      (routingEditRevisions.get(section) || 0) + 1,
    );
  } else routingDirtySections.delete(section);
  updateRoutingDirtyState();
}
function renderNtfyTopicsSummary(data) {
  const severities = (data.known_severities || []).filter(
    (severity) => severity !== "resolved",
  );
  const severityList = severities.length
    ? severities
        .map((severity) => `<code>${escapeHtml(severity)}</code>`)
        .join(", ")
    : `<em>${escapeHtml(tr("routing.none"))}</em>`;
  $("#ntfy-topics-summary").innerHTML =
    `<small>${tr("routing.summary", { count: (data.topics || []).length, severities: severityList })}</small>`;
  $("#ntfy-topics-note").textContent = data.note || "";
}
export async function loadNtfyTopics(options = {}) {
  const force = options.force || routingForceReloadSections.has("topics");
  if (routingSavingSections.has("topics")) {
    if (force) routingForceReloadSections.add("topics");
    return true;
  }
  if (!force && routingDirtySections.has("topics")) return true;
  const requestedRevision = routingEditRevisions.get("topics");
  const loadGeneration = (routingLoadGenerations.get("topics") || 0) + 1;
  routingLoadGenerations.set("topics", loadGeneration);
  try {
    const j = await queryGet("ntfy-topics", "/api/ntfy-topics", {
      force: force,
    });
    if (routingLoadGenerations.get("topics") !== loadGeneration) return true;
    if (routingEditRevisions.get("topics") !== requestedRevision) return true;
    ntfyTopicsData = j;
    renderNtfyTopicsEditor();
    renderNtfyTopicsSummary(j);
    routingForceReloadSections.delete("topics");
    markRoutingSectionDirty("topics", false);
    return true;
  } catch (e) {
    if (routingLoadGenerations.get("topics") !== loadGeneration) return true;
    fetchError("ntfy-topics", e);
    return false;
  }
}
function _renderTopicRow(t, idx) {
  const handlesStr = (t.handles || []).join(", ");
  return `\n    <div class="ntfy-topic-row" data-topic-idx="${idx}">\n      <div class="grid2">\n        <label>${escapeHtml(tr("routing.topic_name"))} <input type="text" class="ntfy-t-name" value="${escapeHtml(t.name || "")}" placeholder="${escapeHtml(tr("routing.topic_placeholder"))}"></label>\n        <label>${escapeHtml(tr("routing.token"))}\n          <input type="password" class="ntfy-t-token" value="${escapeHtml(t.token || "")}" placeholder="${escapeHtml(t.token === "***SET***" ? tr("routing.keep_existing_placeholder") : tr("routing.token_placeholder"))}">\n          <small class="muted">${t.token === "***SET***" ? `<span style="color:#2c8a47">${escapeHtml(tr("routing.token_set"))}</span> ${escapeHtml(tr("routing.clear_to_remove"))}` : `<span style="color:#c44">${escapeHtml(tr("routing.no_token"))}</span>`}</small>\n        </label>\n      </div>\n      <label>${escapeHtml(tr("routing.handles"))}\n        <input type="text" class="ntfy-t-handles" value="${escapeHtml(handlesStr)}" placeholder="info, warning, critical">\n      </label>\n      <p class="row" style="margin-top:8px">\n        <button type="button" class="ntfy-t-delete" data-idx="${idx}" style="color:#c44">${escapeHtml(tr("routing.delete_topic"))}</button>\n      </p>\n    </div>`;
}
export function renderNtfyTopicsEditor() {
  const c = $("#ntfy-topics-editor");
  if (!c) return;
  const topics = ntfyTopicsData.topics || [];
  c.innerHTML = topics.map((t, i) => _renderTopicRow(t, i)).join("");
  c.querySelectorAll(".ntfy-t-delete").forEach((b) => {
    b.addEventListener("click", () => {
      const idx = parseInt(b.dataset.idx, 10);
      syncNtfyTopicsDraft();
      ntfyTopicsData.topics.splice(idx, 1);
      renderNtfyTopicsEditor();
      markRoutingSectionDirty("topics");
    });
  });
}
export function collectNtfyTopicsDraft({ skipEmpty: skipEmpty = false } = {}) {
  const topics = [];
  $("#ntfy-topics-editor")
    ?.querySelectorAll("[data-topic-idx]")
    .forEach((card) => {
      const name = card.querySelector(".ntfy-t-name").value.trim();
      if (skipEmpty && !name) return;
      topics.push({
        name: name,
        token: card.querySelector(".ntfy-t-token").value,
        handles: card
          .querySelector(".ntfy-t-handles")
          .value.split(",")
          .map((value) => value.trim().toLowerCase())
          .filter(Boolean),
      });
    });
  return topics;
}
export function syncNtfyTopicsDraft() {
  ntfyTopicsData.topics = collectNtfyTopicsDraft();
}
$("#ntfy-topic-add")?.addEventListener("click", () => {
  syncNtfyTopicsDraft();
  if (!ntfyTopicsData.topics) ntfyTopicsData.topics = [];
  ntfyTopicsData.topics.push({ name: "", token: "", handles: ["info"] });
  renderNtfyTopicsEditor();
  markRoutingSectionDirty("topics");
});
export async function saveNtfyTopics(options = {}) {
  if (
    routingSavingSections.has("topics") ||
    (routingBatchActive && !options.batch)
  )
    return false;
  routingSavingSections.add("topics");
  routingLoadGenerations.set(
    "topics",
    (routingLoadGenerations.get("topics") || 0) + 1,
  );
  updateRoutingDirtyState();
  const submittedRevision =
    options.revision ?? routingEditRevisions.get("topics");
  const out = options.topics ?? collectNtfyTopicsDraft({ skipEmpty: true });
  setInlineStatus("#ntfy-topics-status", tr("status.saving"));
  try {
    const r = await apiFetch("/api/ntfy-topics", {
      method: "POST",
      body: JSON.stringify({ topics: out }),
      headers: { "Content-Type": "application/json" },
    });
    if (!r.ok) {
      const txt = await r.text();
      notifyResponseError(
        "ntfy-topics-save",
        r,
        txt.slice(0, 200),
        "#ntfy-topics-status",
      );
      return false;
    }
    const j = await r.json();
    if (routingEditRevisions.get("topics") === submittedRevision) {
      ntfyTopicsData = j;
      renderNtfyTopicsEditor();
      renderNtfyTopicsSummary(j);
      markRoutingSectionDirty("topics", false);
      notifySuccess(
        tr("routing.saved_topics", {
          count: j.topics.length,
          severities: (j.known_severities || [])
            .filter((s) => s !== "resolved")
            .join(", "),
        }),
        { status: "#ntfy-topics-status" },
      );
    } else {
      notifySuccess(tr("settings.saved_newer_pending"), {
        status: "#ntfy-topics-status",
      });
    }
    return true;
  } catch (e) {
    notifyError("ntfy-topics-save", e, { status: "#ntfy-topics-status" });
    return false;
  } finally {
    finishNtfyTopicSave();
  }
}
function finishNtfyTopicSave() {
  routingSavingSections.delete("topics");
  updateRoutingDirtyState();
  if (routingForceReloadSections.has("topics"))
    void loadNtfyTopics({ force: true });
}
$("#ntfy-topics-save")?.addEventListener("click", () => saveNtfyTopics());

export function beginRoutingBatch() {
  routingBatchActive = true;
  return ++routingBatchGeneration;
}

export function endRoutingBatch() {
  routingBatchActive = false;
}

export function cancelRoutingBatch() {
  routingBatchGeneration += 1;
}
