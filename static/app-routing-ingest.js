import {
  $, apiFetch, confirmDialog, escapeHtml, fetchError, getCurrentUser, notifyError,
  notifyResponseError, notifySuccess, notifyValidationError, promptDialog, queryGet,
  showSecretDialog, tr,
} from "./app.js";
import { applyReadOnlyViewerMode } from "./app-status.js";

export async function loadIngestAuth() {
  const tableBody = $("#t-ingest-auth tbody");
  if (!tableBody) return;
  try {
    const data = await queryGet("ingest-auth", "/api/ingest-auth");
    const sources = data.sources || {};
    tableBody.innerHTML = "";
    for (const source of Object.keys(sources).sort()) {
      tableBody.appendChild(sourceRow(source, sources[source]));
    }
    tableBody.querySelectorAll("button[data-act]").forEach(button => {
      button.addEventListener("click", () => ingestAuthAction(button.dataset.src, button.dataset.act));
    });
    if (document.body.classList.contains("viewer-readonly")) {
      applyReadOnlyViewerMode(getCurrentUser());
    }
  } catch (error) {
    fetchError("ingest-auth", error);
  }
}

function sourceRow(source, info) {
  const row = document.createElement("tr");
  const status = info.configured
    ? `<span style='color:var(--green)'>${escapeHtml(tr("ingest.secret_set"))}</span>`
    : `<span style='color:var(--muted)'>${escapeHtml(tr("ingest.disabled"))}</span>`;
  const envName = `KLAXOND_INGEST_SECRET_${source.toUpperCase().replaceAll("-", "_")}`;
  const secretSource = info.from === "env"
    ? escapeHtml(tr("ingest.env_readonly", { name: envName }))
    : info.from === "toml" ? "<code>klaxond.toml</code>" : "—";
  const isEnv = info.from === "env";
  const definitionIsEnv = info.definition_from === "env";
  const displayName = info.display_name || source;
  row.innerHTML = `
    <td><span class="ingest-source-name"><strong>${escapeHtml(displayName)}</strong><small><code>${escapeHtml(source)}</code>${info.custom ? ` · ${escapeHtml(tr("ingest.custom"))}` : ""}</small></span></td>
    <td>${status}</td>
    <td class="ingest-source-endpoint"><code>${escapeHtml(info.endpoint || `/${source}/{severity}`)}</code></td>
    <td><small>${secretSource}</small></td>
    <td><div class="ingest-source-actions">
      <button class="btn primary" data-act="generate" data-src="${escapeHtml(source)}" ${isEnv ? "disabled title='env override active'" : ""}>${escapeHtml(tr("ingest.generate"))}</button>
      <button class="btn" data-act="set" data-src="${escapeHtml(source)}" ${isEnv ? "disabled" : ""}>${escapeHtml(tr("ingest.set_custom"))}</button>
      <button class="btn" data-act="clear" data-src="${escapeHtml(source)}" ${(!info.configured || isEnv) ? "disabled" : ""} style="color:var(--red)">${escapeHtml(tr("ingest.clear"))}</button>
      ${info.custom ? `<button class="btn danger" data-act="remove" data-src="${escapeHtml(source)}" ${(isEnv || definitionIsEnv) ? "disabled" : ""}>${escapeHtml(tr("ingest.remove"))}</button>` : ""}
    </div></td>`;
  return row;
}

async function ingestAuthAction(source, action) {
  const body = { source, action };
  if (action === "set") {
    const secret = await promptDialog(
      `Paste the secret to use for source "${source}". It must contain at least 16 characters.`,
      {
        title: tr("ingest.set_custom"),
        label: tr("routing.token"),
        type: "password",
        minLength: 16,
        autocomplete: "new-password",
      },
    );
    if (!secret) return;
    if (secret.length < 16) {
      notifyError(`ingest-auth-${action}`, new Error(tr("ingest.secret_too_short")));
      return;
    }
    body.secret = secret;
  }
  if (!await confirmDestructiveAction(source, action)) return;
  try {
    const response = await apiFetch("/api/ingest-auth", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    if (!response.ok) {
      notifyResponseError(`ingest-auth-${action}`, response, (await response.text()).slice(0, 200));
      return;
    }
    await showIngestActionResult(source, action, await response.json());
    loadIngestAuth();
  } catch (error) {
    notifyError(`ingest-auth-${action}`, error);
  }
}

async function confirmDestructiveAction(source, action) {
  if (action === "clear") {
    return confirmDialog(`Clear the webhook secret for "${source}"? Klaxond will disable that inbound route.`, {
      title: tr("ingest.clear"),
      confirmLabel: tr("ingest.clear"),
      danger: true,
    });
  }
  if (action === "remove") {
    return confirmDialog(tr("ingest.remove_confirm", { source }), {
      title: tr("ingest.remove"),
      confirmLabel: tr("ingest.remove"),
      danger: true,
    });
  }
  return true;
}

async function showIngestActionResult(source, action, result) {
  if (result.secret) {
    await showSecretDialog(result.secret, {
      title: tr("ingest.generated", { source }),
      message: tr("ingest.copy_secret", { source, endpoint: result.endpoint }),
      confirmLabel: tr("dialog.done"),
    });
    notifySuccess(tr(action === "add" ? "ingest.added" : "ingest.generated", { source }), {
      durationMs: 4000,
    });
  } else if (action === "remove") {
    notifySuccess(tr("ingest.removed", { source }), { durationMs: 4000 });
  } else {
    notifySuccess(tr("ingest.action_ok", { action, source }), { durationMs: 4000 });
  }
}

$("#ingest-source-add")?.addEventListener("click", async () => {
  const source = await promptDialog(tr("ingest.source_id_help"), {
    title: tr("ingest.add_source"),
    label: tr("ingest.source_id"),
    autocomplete: "off",
  });
  if (source === null) return;
  const normalized = source.trim().toLowerCase();
  if (!/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(normalized) || normalized.length < 2 || normalized.length > 40) {
    notifyValidationError("ingest-source-add", tr("ingest.source_id_help"));
    return;
  }
  const displayName = await promptDialog(tr("ingest.display_name_help"), {
    title: tr("ingest.add_source"),
    label: tr("ingest.display_name"),
    value: normalized.split("-").map(part => part.charAt(0).toUpperCase() + part.slice(1)).join(" "),
    autocomplete: "off",
  });
  if (!displayName?.trim()) return;
  try {
    const response = await apiFetch("/api/ingest-auth", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ source: normalized, action: "add", display_name: displayName.trim() }),
    });
    if (!response.ok) {
      notifyResponseError("ingest-source-add", response, (await response.text()).slice(0, 200));
      return;
    }
    await showIngestActionResult(normalized, "add", await response.json());
    loadIngestAuth();
  } catch (error) {
    notifyError("ingest-source-add", error);
  }
});
