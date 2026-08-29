import {
  $, $$, APP_META, J, SEARCH_DEBOUNCE_MS, apiFetch, applyTablePager, debounce, errorText,
  escapeHtml, fetchError, fetchOk, getAuthPasswordPolicy, getCurrentUser, isAbortError, isPublicInfoPage,
  confirmDialog, markTabDirty, notifyError, notifyResponseError, notifySuccess,
  notifyValidationError, onReady, promptDialog,
  queryGet, refreshTablePagers, setAuthPasswordPolicy, setInlineStatus, setLocalTotpEnabled,
  showSecretDialog, showTableRowPage, syncTabFromPath, tr, updateAllTabAccessibleLabels,
  updatePublicLoginLinksText,
} from "./app.js";
import { applyReadOnlyViewerMode, loadStatus } from "./app-status.js";

// ---- ntfy topics (0.7.1+ editor) ----
let ntfyTopicsData = { topics: [], known_severities: [], note: "", writeable: false };

export async function loadNtfyTopics() {
  try {
    const j = await queryGet("ntfy-topics", "/api/ntfy-topics");
    ntfyTopicsData = j;
    renderNtfyTopicsEditor();
    const sev = (j.known_severities || []).filter(s => s !== "resolved");
    const sevStr = sev.length ? sev.map(s => `<code>${escapeHtml(s)}</code>`).join(", ") : `<em>${escapeHtml(tr("routing.none"))}</em>`;
    $("#ntfy-topics-summary").innerHTML = `<small>${tr("routing.summary", { count: (j.topics || []).length, severities: sevStr })}</small>`;
    $("#ntfy-topics-note").textContent = j.note || "";
  } catch (e) {
    fetchError("ntfy-topics", e);
  }
}

function _renderTopicRow(t, idx) {
  const handlesStr = (t.handles || []).join(", ");
  return `
    <div class="card" data-topic-idx="${idx}" style="margin-bottom:8px">
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
      ntfyTopicsData.topics.splice(idx, 1);
      renderNtfyTopicsEditor();
    });
  });
}

$("#ntfy-topic-add")?.addEventListener("click", () => {
  if (!ntfyTopicsData.topics) ntfyTopicsData.topics = [];
  ntfyTopicsData.topics.push({ name: "", token: "", handles: ["info"] });
  renderNtfyTopicsEditor();
});

$("#ntfy-topics-save")?.addEventListener("click", async () => {
  // Collect from DOM
  const out = [];
  $("#ntfy-topics-editor")?.querySelectorAll("[data-topic-idx]").forEach(card => {
    const name = card.querySelector(".ntfy-t-name").value.trim();
    const tokenRaw = card.querySelector(".ntfy-t-token").value;
    const handlesStr = card.querySelector(".ntfy-t-handles").value;
    const handles = handlesStr.split(",").map(s => s.trim().toLowerCase()).filter(Boolean);
    if (!name) return;  // skip empty rows on save (use Delete instead)
    out.push({ name, token: tokenRaw, handles });
  });
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
      return;
    }
    const j = await r.json();
    notifySuccess(tr("routing.saved_topics", {
      count: j.topics.length,
      severities: (j.known_severities || []).filter(s => s !== "resolved").join(", ")
    }), { status: "#ntfy-topics-status" });
    markTabDirty("routing", false);
    // Reload to refresh badges
    setTimeout(() => loadNtfyTopics(), 500);
  } catch (e) {
    notifyError("ntfy-topics-save", e, { status: "#ntfy-topics-status" });
  }
});



// ---- Routing (channel config) ----
export async function loadRouting() {
  try {
    const c = await queryGet("channel-config", "/api/channel-config");
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
  } catch (e) { fetchError("routing", e); }
}

const badge = ok => ok ? `<span style='color:var(--green)'>✓ ${escapeHtml(tr("common.configured"))}</span>` : `<span style='color:var(--red)'>✗ ${escapeHtml(tr("common.missing"))}</span>`;

$("#btn-routing-save").addEventListener("click", async () => {
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
  try {
    await J("/api/channel-config", { method: "POST", body: JSON.stringify(payload), headers: { "Content-Type": "application/json" } });
    notifySuccess(tr("routing.saved"), { status: "#routing-msg", clearMs: 4000 });
    markTabDirty("routing", false);
    loadStatus();
  } catch (e) { notifyError("routing-save", e, { status: "#routing-msg" }); }
});


// ---- Ingest auth (per-source webhook secret, 0.9.18+) ----
export async function loadIngestAuth() {
  const tb = $("#t-ingest-auth tbody"); if (!tb) return;
  try {
    const data = await queryGet("ingest-auth", "/api/ingest-auth");
    const srcs = data.sources || {};
    tb.innerHTML = "";
    for (const src of Object.keys(srcs).sort()) {
      const info = srcs[src];
      const row = document.createElement("tr");
      const status = info.configured
        ? `<span style='color:var(--green)'>${escapeHtml(tr("ingest.secret_set"))}</span>`
        : `<span style='color:var(--muted)'>${escapeHtml(tr("ingest.disabled"))}</span>`;
      const envName = `KLAXOND_INGEST_SECRET_${src.toUpperCase().replaceAll("-", "_")}`;
      const from = info.from === "env" ? `${escapeHtml(tr("ingest.env_readonly", { name: envName }))}`
                  : info.from === "toml" ? `<code>klaxond.toml</code>`
                  : "—";
      const isEnv = info.from === "env";
      row.innerHTML = `
        <td><code>${escapeHtml(src)}</code></td>
        <td>${status}</td>
        <td><small>${from}</small></td>
        <td>
          <button class="btn primary" data-act="generate" data-src="${escapeHtml(src)}" ${isEnv ? "disabled title='env override active'" : ""}>${escapeHtml(tr("ingest.generate"))}</button>
          <button class="btn" data-act="set" data-src="${escapeHtml(src)}" ${isEnv ? "disabled" : ""}>${escapeHtml(tr("ingest.set_custom"))}</button>
          <button class="btn" data-act="clear" data-src="${escapeHtml(src)}" ${(!info.configured || isEnv) ? "disabled" : ""} style="color:var(--red)">${escapeHtml(tr("ingest.clear"))}</button>
        </td>`;
      tb.appendChild(row);
    }
    // Wire button handlers
    tb.querySelectorAll("button[data-act]").forEach(btn => {
      btn.addEventListener("click", () => _ingestAuthAction(btn.dataset.src, btn.dataset.act));
    });
    if (document.body.classList.contains("viewer-readonly")) applyReadOnlyViewerMode(getCurrentUser());
  } catch (e) { fetchError("ingest-auth", e); }
}

async function _ingestAuthAction(src, action) {
  let body = { source: src, action };
  if (action === "set") {
    const sec = await promptDialog(
      `Paste the secret to use for source "${src}". It must contain at least 16 characters.`,
      {
        title: tr("ingest.set_custom"),
        label: tr("routing.token"),
        type: "password",
        minLength: 16,
        autocomplete: "new-password",
      }
    );
    if (!sec) return;
    if (sec.length < 16) { notifyError(`ingest-auth-${action}`, new Error(tr("ingest.secret_too_short"))); return; }
    body.secret = sec;
  }
  if (action === "clear") {
    const confirmed = await confirmDialog(
      `Clear the webhook secret for "${src}"? Klaxond will disable that inbound route.`,
      { title: tr("ingest.clear"), confirmLabel: tr("ingest.clear"), danger: true }
    );
    if (!confirmed) return;
  }
  try {
    const res = await apiFetch("/api/ingest-auth", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify(body),
    });
    if (!res.ok) {
      const txt = await res.text();
      notifyResponseError(`ingest-auth-${action}`, res, txt.slice(0, 200));
      return;
    }
    const r = await res.json();
    if (r.secret) {
      await showSecretDialog(r.secret, {
        title: tr("ingest.generated", { source: src }),
        message: `Copy this secret into the "${src}" emitter now. It will not be shown again.`,
        confirmLabel: tr("dialog.done"),
      });
      notifySuccess(tr("ingest.generated", { source: src }), { durationMs: 4000 });
    } else {
      notifySuccess(tr("ingest.action_ok", { action, source: src }), { durationMs: 4000 });
    }
    loadIngestAuth();
  } catch (e) {
    notifyError(`ingest-auth-${action}`, e);
  }
}
