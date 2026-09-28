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
import {
  beginRoutingBatch,
  cancelRoutingBatch,
  collectNtfyTopicsDraft,
  endRoutingBatch,
  loadNtfyTopics,
  markRoutingSectionDirty,
  routingBatchActive,
  routingDirtySections,
  routingEditRevisions,
  routingForceReloadSections,
  routingLoadGenerations,
  routingSavingSections,
  saveNtfyTopics,
  updateRoutingDirtyState,
} from "./app-routing-topics.js";
function applyRoutingChannelConfig(c) {
  $("#r-ntfy-url").value = c.ntfy.url || "";
  $("#r-ntfy-status").innerHTML = c.ntfy.url_from_env
    ? `<em>${escapeHtml(tr("routing.url_overridden_env"))}</em>`
    : "";
  $("#r-tg-chat").value = c.telegram.chat_id || "";
  $("#r-tg-api-base").value = c.telegram.api_base || "https://api.telegram.org";
  $("#r-tg-token").value = "";
  $("#r-tg-token").placeholder = c.telegram.bot_token_configured ? "***SET***" : "";
  $("#r-tg-token-clear").checked = false;
  $("#r-tg-status").innerHTML =
    `${escapeHtml(tr("routing.bot_token"))} ${badge(c.telegram.bot_token_configured)}` +
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
  $("#r-smtp-status").innerHTML =
    `${escapeHtml(tr("routing.user"))} ${badge(c.smtp.user_configured)} ${escapeHtml(tr("routing.password"))} ${badge(c.smtp.password_configured)}` +
    (c.smtp.host_from_env ? ` · <em>${escapeHtml(tr("routing.host_overridden_env"))}</em>` : "") +
    (c.smtp.user_from_env ? ` · <em>${escapeHtml(tr("routing.user_overridden_env"))}</em>` : "") +
    (c.smtp.password_from_env ? ` · <em>${escapeHtml(tr("routing.password_overridden_env"))}</em>` : "");
}

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
    const c = await queryGet("channel-config", "/api/channel-config", {
      force: force,
    });
    if (routingLoadGenerations.get("channels") !== loadGeneration) return true;
    if (routingEditRevisions.get("channels") !== requestedRevision) return true;
    applyRoutingChannelConfig(c);
    routingForceReloadSections.delete("channels");
    markRoutingSectionDirty("channels", false);
    return true;
  } catch (e) {
    if (routingLoadGenerations.get("channels") !== loadGeneration) return true;
    fetchError("routing", e);
    return false;
  }
}
const badge = (ok) =>
  ok
    ? `<span style='color:var(--green)'>✓ ${escapeHtml(tr("common.configured"))}</span>`
    : `<span style='color:var(--red)'>✗ ${escapeHtml(tr("common.missing"))}</span>`;
function channelConfigDraft() {
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
    },
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
  if (
    routingSavingSections.has("channels") ||
    (routingBatchActive && !options.batch)
  )
    return false;
  routingSavingSections.add("channels");
  routingLoadGenerations.set(
    "channels",
    (routingLoadGenerations.get("channels") || 0) + 1,
  );
  updateRoutingDirtyState();
  const submittedRevision =
    options.revision ?? routingEditRevisions.get("channels");
  const payload = options.payload ?? channelConfigDraft();
  try {
    await J("/api/channel-config", {
      method: "POST",
      body: JSON.stringify(payload),
      headers: { "Content-Type": "application/json" },
    });
    if (routingEditRevisions.get("channels") === submittedRevision) {
      markRoutingSectionDirty("channels", false);
      notifySuccess(tr("routing.saved"), {
        status: "#routing-msg",
        clearMs: 4e3,
      });
    } else {
      notifySuccess(tr("settings.saved_newer_pending"), {
        status: "#routing-msg",
      });
    }
    loadStatus();
    return true;
  } catch (e) {
    notifyError("routing-save", e, { status: "#routing-msg" });
    return false;
  } finally {
    routingSavingSections.delete("channels");
    updateRoutingDirtyState();
    if (routingForceReloadSections.has("channels"))
      void loadRouting({ force: true });
  }
}
$("#btn-routing-save")?.addEventListener("click", () => saveRouting());
document.querySelectorAll("[data-routing-section]").forEach((section) => {
  const markDirty = (event) => {
    if (event.target.closest("[data-dirty-ignore]")) return;
    markRoutingSectionDirty(section.dataset.routingSection);
  };
  section.addEventListener("input", markDirty);
  section.addEventListener("change", markDirty);
});
$("#routing-save-all")?.addEventListener("click", async () => {
  if (routingSavingSections.size > 0 || routingBatchActive) return;
  beginRoutingBatch();
  updateRoutingDirtyState();
  const batchGeneration = beginRoutingBatch();
  const pending = [...routingDirtySections];
  const channels = pending.includes("channels")
    ? {
        payload: channelConfigDraft(),
        revision: routingEditRevisions.get("channels"),
      }
    : null;
  const topics = pending.includes("topics")
    ? {
        topics: collectNtfyTopicsDraft({ skipEmpty: true }),
        revision: routingEditRevisions.get("topics"),
      }
    : null;
  try {
    if (channels) await saveRouting({ ...channels, batch: true });
    if (batchGeneration !== routingBatchGeneration) return;
    if (topics) await saveNtfyTopics({ ...topics, batch: true });
  } finally {
    endRoutingBatch();
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
  cancelRoutingBatch();
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
document.addEventListener("klaxond:tabdiscard", (event) => {
  if (event.detail?.tabId !== "routing") return;
  cancelRoutingBatch();
  routingDirtySections.clear();
  routingForceReloadSections.add("channels");
  routingForceReloadSections.add("topics");
  updateRoutingDirtyState();
});
updateRoutingDirtyState();
export { loadIngestAuth } from "./app-routing-ingest.js";
