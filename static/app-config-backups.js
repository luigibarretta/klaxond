import {
  $, apiFetch, errorText, escapeHtml, fetchError, notifyError, notifyResponseError,
  notifySuccess, onReady, queryGet, setInlineStatus, tr,
} from "./app.js";

export async function loadConfigBackups() {
  const list = $("#cfg-backup-list");
  if (!list) return;
  try {
    const response = await queryGet("config-backups", "/api/config/backups");
    if (response.dir) $("#cfg-backup-dir").textContent = response.dir;
    if (response.keep_max) $("#cfg-backup-keep").textContent = response.keep_max;
    const items = response.backups || [];
    if (!items.length) {
      list.innerHTML = `<li>${escapeHtml(tr("status.no_backups"))}</li>`;
      return;
    }
    list.innerHTML = items.slice(0, 10).map(backup => {
      const kb = Math.round(backup.size / 1024);
      return `<li><code>${escapeHtml(backup.name)}</code> · ${kb} KB · ${escapeHtml(backup.mtime_iso)}</li>`;
    }).join("");
  } catch (e) {
    list.innerHTML = `<li class='muted'>${escapeHtml(tr("status.backups_unavailable", { message: errorText(e) }))}</li>`;
    fetchError("config-backups", e);
  }
}

let pendingConfigImport = null;

function clearConfigImportPreview(opts = {}) {
  pendingConfigImport = null;
  const box = $("#cfg-import-preview");
  if (box) {
    box.classList.add("hidden");
    box.innerHTML = "";
  }
  $("#cfg-import-apply") && ($("#cfg-import-apply").hidden = true);
  $("#cfg-import-clear") && ($("#cfg-import-clear").hidden = true);
  if (!opts.keepStatus) setInlineStatus("#cfg-restore-status", "");
}

function renderConfigImportPreview(file, preview) {
  const box = $("#cfg-import-preview");
  if (!box) return;
  const warnings = (preview.warnings || []).map(warning => `<li>${escapeHtml(warning)}</li>`).join("");
  box.classList.remove("hidden");
  box.innerHTML = `
    <strong>${escapeHtml(tr("config.import_preview_title", { name: file.name }))}</strong>
    <div class="import-preview-grid">
      <span>${escapeHtml(tr("config.import_kind"))}</span><code>${escapeHtml(preview.source_kind || "")}</code>
      <span>${escapeHtml(tr("config.import_changed"))}</span><code>${escapeHtml((preview.changed_files || []).join(", ") || tr("status.none"))}</code>
      <span>${escapeHtml(tr("config.import_unchanged"))}</span><code>${escapeHtml((preview.unchanged_files || []).join(", ") || tr("status.none"))}</code>
      <span>${escapeHtml(tr("config.import_restore"))}</span><code>${escapeHtml((preview.would_restore || []).join(", ") || tr("status.none"))}</code>
    </div>
    ${warnings ? `<ul class="muted">${warnings}</ul>` : ""}`;
  $("#cfg-import-apply") && ($("#cfg-import-apply").hidden = false);
  $("#cfg-import-clear") && ($("#cfg-import-clear").hidden = false);
}

async function previewConfigImportFile(file) {
  const status = $("#cfg-restore-status");
  clearConfigImportPreview();
  setInlineStatus(status, tr("config.previewing"));
  const raw = await file.text();
  const isJson = raw.trimStart().startsWith("{");
  const response = await apiFetch("/api/config/import-preview", {
    method: "POST",
    headers: {"Content-Type": isJson ? "application/json" : "application/toml"},
    body: raw,
  });
  if (!response.ok) {
    const text = await response.text();
    notifyResponseError("config-import-preview", response, text.slice(0, 300), status);
    return;
  }
  const preview = await response.json();
  pendingConfigImport = { file, raw, contentType: isJson ? "application/json" : "application/toml", preview };
  renderConfigImportPreview(file, preview);
  setInlineStatus(status, tr("config.preview_ready"));
}

async function applyConfigImport() {
  const pending = pendingConfigImport;
  const status = $("#cfg-restore-status");
  if (!pending) return;
  if (!confirm(tr("config.restore_confirm", { name: pending.file.name, size: pending.file.size }))) return;
  setInlineStatus(status, tr("status.uploading"));
  try {
    const response = await apiFetch("/api/config/restore", {
      method: "POST",
      headers: {"Content-Type": pending.contentType},
      body: pending.raw,
    });
    if (!response.ok) {
      const text = await response.text();
      notifyResponseError("config-restore", response, text.slice(0, 300), status);
      return;
    }
    const json = await response.json();
    notifySuccess(tr("config.restored_toast"), {
      status,
      inlineText: tr("status.restored", { bytes: json.bytes_written, backup: json.pre_restore_backup || tr("status.none") }),
      durationMs: 6000,
    });
    clearConfigImportPreview({ keepStatus: true });
    loadConfigBackups();
  } catch (err) {
    notifyError("config-restore", err, { status, inlineText: "❌ " + errorText(err) });
  }
}

onReady(() => {
  const dl = document.getElementById("cfg-backup-download");
  if (dl) dl.href = "/api/config/backup";
  const full = document.getElementById("cfg-full-export-download");
  if (full) full.href = "/api/config/export";
  $("#cfg-import-apply")?.addEventListener("click", applyConfigImport);
  $("#cfg-import-clear")?.addEventListener("click", clearConfigImportPreview);

  const fileInput = document.getElementById("cfg-restore-file");
  if (fileInput) fileInput.addEventListener("change", async event => {
    const file = event.target.files[0];
    if (!file) return;
    try {
      await previewConfigImportFile(file);
    } catch (err) {
      notifyError("config-import-preview", err, { status: "#cfg-restore-status", inlineText: "❌ " + errorText(err) });
    } finally {
      event.target.value = "";
    }
  });
});
