import {
  $, J, apiFetch, confirmDialog, escapeHtml, fetchError, markTabDirty, notifyError,
  notifyResponseError, notifySuccess, queryGet, setInlineStatus, tr,
} from "./app.js";
import { loadStatus } from "./app-status.js";
export { loadIngestAuth } from "./app-routing-ingest.js";

// ---- ntfy topics (0.7.1+ editor) ----
let ntfyTopicsData = { topics: [], known_severities: [], note: "", writeable: false };
const routingDirtySections = new Set();
const routingEditRevisions = new Map([["channels", 0], ["topics", 0]]);
const routingLoadGenerations = new Map([["channels", 0], ["topics", 0]]);
const routingSavingSections = new Set();
const routingForceReloadSections = new Set();
let routingBatchGeneration = 0;
let routingBatchActive = false;

function updateRoutingDirtyState() {
  const dirty = routingDirtySections.size > 0;
  markTabDirty("routing", dirty);
  const readOnly = document.body.classList.contains("viewer-readonly");
  const saveAll = $("#routing-save-all");
  if (saveAll) saveAll.disabled = !dirty || readOnly || routingSavingSections.size > 0 || routingBatchActive;
  const discard = $("#routing-discard");
  if (discard) discard.disabled = !dirty || readOnly || routingSavingSections.size > 0 || routingBatchActive;
  for (const section of ["channels", "topics"]) {
    document.querySelectorAll(`[data-routing-save-section="${section}"]`).forEach(button => {
      button.disabled = !routingDirtySections.has(section)
        || readOnly
        || routingSavingSections.has(section)
        || routingBatchActive;
    });
  }
  const status = $("#routing-dirty-status");
  if (status) {
    status.textContent = dirty
      ? tr("settings.unsaved_sections", { count: routingDirtySections.size })
      : tr("settings.no_unsaved_changes");
  }
}

function markRoutingSectionDirty(section, dirty = true) {
  if (dirty) {
    routingDirtySections.add(section);
    routingForceReloadSections.delete(section);
    routingEditRevisions.set(section, (routingEditRevisions.get(section) || 0) + 1);
  }
  else routingDirtySections.delete(section);
  updateRoutingDirtyState();
}

function renderNtfyTopicsSummary(data) {
  const severities = (data.known_severities || []).filter(severity => severity !== "resolved");
  const severityList = severities.length
    ? severities.map(severity => `<code>${escapeHtml(severity)}</code>`).join(", ")
    : `<em>${escapeHtml(tr("routing.none"))}</em>`;
  $("#ntfy-topics-summary").innerHTML = `<small>${tr("routing.summary", {
    count: (data.topics || []).length,
    severities: severityList,
  })}</small>`;
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
    const j = await queryGet("ntfy-topics", "/api/ntfy-topics", { force });
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
  return `
    <div class="ntfy-topic-row" data-topic-idx="${idx}">
      <div class="grid2">
        <label>${escapeHtml(tr("routing.topic_name"))} <input type="text" class="ntfy-t-name" value="${escapeHtml(t.name || "")}" placeholder="${escapeHtml(tr("routing.topic_placeholder"))}"></label>
        <label>${escapeHtml(tr("routing.token"))}
          <input type="password" class="ntfy-t-token" value="${escapeHtml(t.token || "")}" placeholder="${escapeHtml(t.token === '***SET***' ? tr("routing.keep_existing_placeholder") : tr("routing.token_placeholder"))}">
          <small class="muted">${t.token === '***SET***' ? `<span style="color:#2c8a47">${escapeHtml(tr("routing.token_set"))}</span> ${escapeHtml(tr("routing.clear_to_remove"))}` : `<span style="color:#c44">${escapeHtml(tr("routing.no_token"))}</span>`}</small>
        </label>
      </div>
      <label>${escapeHtml(tr("routing.handles"))}
        <input type="text" class="ntfy-t-handles" value="${escapeHtml(handlesStr)}" placeholder="info, warning, critical">
      </label>
      <p class="row" style="margin-top:8px">
        <button type="button" class="ntfy-t-delete" data-idx="${idx}" style="color:#c44">${escapeHtml(tr("routing.delete_topic"))}</button>
      </p>
    </div>`;
}

export function renderNtfyTopicsEditor() {
  const c = $("#ntfy-topics-editor");
  if (!c) return;
  const topics = ntfyTopicsData.topics || [];
  c.innerHTML = topics.map((t, i) => _renderTopicRow(t, i)).join("");
  // Wire delete buttons
  c.querySelectorAll(".ntfy-t-delete").forEach(b => {
    b.addEventListener("click", () => {
      const idx = parseInt(b.dataset.idx, 10);
      syncNtfyTopicsDraft();
      ntfyTopicsData.topics.splice(idx, 1);
      renderNtfyTopicsEditor();
      markRoutingSectionDirty("topics");
    });
  });
}

function collectNtfyTopicsDraft({ skipEmpty = false } = {}) {
  const topics = [];
  $("#ntfy-topics-editor")?.querySelectorAll("[data-topic-idx]").forEach(card => {
    const name = card.querySelector(".ntfy-t-name").value.trim();
    if (skipEmpty && !name) return;
    topics.push({
      name,
      token: card.querySelector(".ntfy-t-token").value,
      handles: card.querySelector(".ntfy-t-handles").value
        .split(",").map(value => value.trim().toLowerCase()).filter(Boolean),
    });
  });
  return topics;
}

function syncNtfyTopicsDraft() {
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
  if (routingSavingSections.has("topics") || (routingBatchActive && !options.batch)) return false;
  routingSavingSections.add("topics");
  routingLoadGenerations.set("topics", (routingLoadGenerations.get("topics") || 0) + 1);
  updateRoutingDirtyState();
  const submittedRevision = options.revision ?? routingEditRevisions.get("topics");
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
      notifyResponseError("ntfy-topics-save", r, txt.slice(0, 200), "#ntfy-topics-status");
      return false;
    }
    const j = await r.json();
    if (routingEditRevisions.get("topics") === submittedRevision) {
      ntfyTopicsData = j;
      renderNtfyTopicsEditor();
      renderNtfyTopicsSummary(j);
      markRoutingSectionDirty("topics", false);
      notifySuccess(tr("routing.saved_topics", {
        count: j.topics.length,
        severities: (j.known_severities || []).filter(s => s !== "resolved").join(", ")
      }), { status: "#ntfy-topics-status" });
    } else {
      notifySuccess(tr("settings.saved_newer_pending"), { status: "#ntfy-topics-status" });
    }
    return true;
  } catch (e) {
    notifyError("ntfy-topics-save", e, { status: "#ntfy-topics-status" });
    return false;
  } finally {
    routingSavingSections.delete("topics");
    updateRoutingDirtyState();
    if (routingForceReloadSections.has("topics")) void loadNtfyTopics({ force: true });
  }
}

$("#ntfy-topics-save")?.addEventListener("click", () => saveNtfyTopics());



// ---- Routing (channel config) ----
export async function loadRouting(options = {}) {
  const force = options.force || routingForceReloadSections.has("channels");
  if (routingSavingSections.has("channels")) {
    if (force) routingForceReloadSections.add("channels");
    return true;
  }
  if (!force && routingDirtySections.has("channels")) return true;
  const requestedRevision = routingEditRevisions.get("channels");
  const loadGeneration = (routingLoadGenerations.get("channels") || 0) + 1;
  routingLoadGenerations.set("channels", loadGeneration);
  try {
    const c = await queryGet("channel-config", "/api/channel-config", { force });
    if (routingLoadGenerations.get("channels") !== loadGeneration) return true;
    if (routingEditRevisions.get("channels") !== requestedRevision) return true;
    $("#r-ntfy-url").value = c.ntfy.url || "";
    // ntfy topics are managed by the rich-view editor below (loadNtfyTopics).
    // The "Save routing" button only persists ntfy URL + telegram + smtp.
    $("#r-ntfy-status").innerHTML = c.ntfy.url_from_env ? `<em>${escapeHtml(tr("routing.url_overridden_env"))}</em>` : "";
    $("#r-tg-chat").value = c.telegram.chat_id || "";
    $("#r-tg-api-base").value = c.telegram.api_base || "https://api.telegram.org";
    $("#r-tg-token").value = "";
    $("#r-tg-token").placeholder = c.telegram.bot_token_configured ? "***SET***" : "";
    $("#r-tg-token-clear").checked = false;
    $("#r-tg-status").innerHTML = `${escapeHtml(tr("routing.bot_token"))} ${badge(c.telegram.bot_token_configured)}` +
      (c.telegram.chat_id_from_env ? ` · <em>${escapeHtml(tr("routing.chat_overridden_env"))}</em>` : "") +
      (c.telegram.api_base_from_env ? ` · <em>${escapeHtml(tr("routing.api_base_overridden_env"))}</em>` : "") +
      (c.telegram.bot_token_from_env ? ` · <em>${escapeHtml(tr("routing.bot_token_overridden_env"))}</em>` : "");
    $("#r-smtp-host").value = c.smtp.host || "";
    $("#r-smtp-port").value = c.smtp.port || 587;
    $("#r-smtp-from").value = c.smtp.from_addr || "";
    $("#r-smtp-to").value = c.smtp.to_addr || "";
    $("#r-smtp-user").value = c.smtp.user || "";
    $("#r-smtp-password").value = "";
    $("#r-smtp-password").placeholder = c.smtp.password_configured ? "***SET***" : "";
    $("#r-smtp-starttls").checked = c.smtp.starttls !== false;
    $("#r-smtp-password-clear").checked = false;
    $("#r-smtp-status").innerHTML = `${escapeHtml(tr("routing.user"))} ${badge(c.smtp.user_configured)} ${escapeHtml(tr("routing.password"))} ${badge(c.smtp.password_configured)}` +
      (c.smtp.host_from_env ? ` · <em>${escapeHtml(tr("routing.host_overridden_env"))}</em>` : "") +
      (c.smtp.user_from_env ? ` · <em>${escapeHtml(tr("routing.user_overridden_env"))}</em>` : "") +
      (c.smtp.password_from_env ? ` · <em>${escapeHtml(tr("routing.password_overridden_env"))}</em>` : "");
    routingForceReloadSections.delete("channels");
    markRoutingSectionDirty("channels", false);
    return true;
  } catch (e) {
    if (routingLoadGenerations.get("channels") !== loadGeneration) return true;
    fetchError("routing", e);
    return false;
  }
}

const badge = ok => ok ? `<span style='color:var(--green)'>✓ ${escapeHtml(tr("common.configured"))}</span>` : `<span style='color:var(--red)'>✗ ${escapeHtml(tr("common.missing"))}</span>`;

function channelConfigDraft() {
  // ntfy topics intentionally omitted — managed by the topic editor + /api/ntfy-topics.
  const payload = {
    ntfy: { url: $("#r-ntfy-url").value.trim() },
    telegram: {
      chat_id: $("#r-tg-chat").value.trim(),
      api_base: $("#r-tg-api-base").value.trim(),
    },
    smtp: {
      host: $("#r-smtp-host").value.trim(),
      port: parseInt($("#r-smtp-port").value, 10) || 587,
      from_addr: $("#r-smtp-from").value.trim(),
      to_addr: $("#r-smtp-to").value.trim(),
      user: $("#r-smtp-user").value.trim(),
      starttls: $("#r-smtp-starttls").checked,
    }
  };
  const tgToken = $("#r-tg-token").value.trim();
  if ($("#r-tg-token-clear").checked) payload.telegram.bot_token = "";
  else if (tgToken) payload.telegram.bot_token = tgToken;
  const smtpPassword = $("#r-smtp-password").value;
  if ($("#r-smtp-password-clear").checked) payload.smtp.password = "";
  else if (smtpPassword) payload.smtp.password = smtpPassword;
  return payload;
}

export async function saveRouting(options = {}) {
  if (routingSavingSections.has("channels") || (routingBatchActive && !options.batch)) return false;
  routingSavingSections.add("channels");
  routingLoadGenerations.set("channels", (routingLoadGenerations.get("channels") || 0) + 1);
  updateRoutingDirtyState();
  const submittedRevision = options.revision ?? routingEditRevisions.get("channels");
  const payload = options.payload ?? channelConfigDraft();
  try {
    await J("/api/channel-config", { method: "POST", body: JSON.stringify(payload), headers: { "Content-Type": "application/json" } });
    if (routingEditRevisions.get("channels") === submittedRevision) {
      markRoutingSectionDirty("channels", false);
      notifySuccess(tr("routing.saved"), { status: "#routing-msg", clearMs: 4000 });
    } else {
      notifySuccess(tr("settings.saved_newer_pending"), { status: "#routing-msg" });
    }
    loadStatus();
    return true;
  } catch (e) {
    notifyError("routing-save", e, { status: "#routing-msg" });
    return false;
  } finally {
    routingSavingSections.delete("channels");
    updateRoutingDirtyState();
    if (routingForceReloadSections.has("channels")) void loadRouting({ force: true });
  }
}

$("#btn-routing-save")?.addEventListener("click", () => saveRouting());

document.querySelectorAll("[data-routing-section]").forEach(section => {
  const markDirty = event => {
    if (event.target.closest("[data-dirty-ignore]")) return;
    markRoutingSectionDirty(section.dataset.routingSection);
  };
  section.addEventListener("input", markDirty);
  section.addEventListener("change", markDirty);
});

$("#routing-save-all")?.addEventListener("click", async () => {
  if (routingSavingSections.size > 0 || routingBatchActive) return;
  routingBatchActive = true;
  updateRoutingDirtyState();
  const batchGeneration = ++routingBatchGeneration;
  const pending = [...routingDirtySections];
  const channels = pending.includes("channels") ? {
    payload: channelConfigDraft(),
    revision: routingEditRevisions.get("channels"),
  } : null;
  const topics = pending.includes("topics") ? {
    topics: collectNtfyTopicsDraft({ skipEmpty: true }),
    revision: routingEditRevisions.get("topics"),
  } : null;
  try {
    if (channels) await saveRouting({ ...channels, batch: true });
    if (batchGeneration !== routingBatchGeneration) return;
    if (topics) await saveNtfyTopics({ ...topics, batch: true });
  } finally {
    routingBatchActive = false;
    updateRoutingDirtyState();
  }
});

$("#routing-discard")?.addEventListener("click", async () => {
  if (!routingDirtySections.size) return;
  const confirmed = await confirmDialog(tr("settings.discard_confirm"), {
    title: tr("settings.discard_changes"),
    confirmLabel: tr("shortcut.discard"),
    danger: true,
  });
  if (!confirmed) return;
  routingBatchGeneration += 1;
  const [routingLoaded, topicsLoaded] = await Promise.all([
    loadRouting({ force: true }),
    loadNtfyTopics({ force: true }),
  ]);
  if (routingLoaded && topicsLoaded) {
    notifySuccess(tr("settings.changes_discarded"));
  }
});

document.addEventListener("klaxond:languagechange", updateRoutingDirtyState);
document.addEventListener("klaxond:readonlychange", updateRoutingDirtyState);
document.addEventListener("klaxond:tabdiscard", event => {
  if (event.detail?.tabId !== "routing") return;
  routingBatchGeneration += 1;
  routingDirtySections.clear();
  routingForceReloadSections.add("channels");
  routingForceReloadSections.add("topics");
  updateRoutingDirtyState();
});
updateRoutingDirtyState();
