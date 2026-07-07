// ---- Setup / diagnostics ----
async function loadSetup(opts = {}) {
  try {
    const [setup, matrix] = await Promise.all([
      queryGet("setup-status", "/api/setup-status", { force: opts.force, cancelPrevious: false }),
      queryGet("setup-matrix", "/api/channel-test-matrix", { force: opts.force, cancelPrevious: false }),
    ]);
    renderSetupChecklist(setup);
    renderChannelMatrix(matrix);
  } catch (e) {
    fetchError("setup", e);
    const box = $("#setup-checklist");
    if (box) box.innerHTML = `<p class="muted">${escapeHtml(tr("common.error"))}: ${escapeHtml(errorText(e))}</p>`;
  }
}

function statusBadge(status) {
  const label = status || "info";
  const cls = label === "ok" ? "info" : label === "error" ? "error" : "warn";
  return `<span class="log-level ${cls}">${escapeHtml(label)}</span>`;
}

function renderSetupChecklist(payload) {
  const box = $("#setup-checklist"); if (!box) return;
  const items = payload.items || [];
  $("#setup-summary").textContent = tr("setup.summary", {
    errors: payload.summary?.errors || 0,
    warnings: payload.summary?.warnings || 0,
  });
  box.innerHTML = items.map(item => `
    <div class="setup-item">
      <div>${statusBadge(item.status)}</div>
      <div>
        <strong>${escapeHtml(setupItemLabel(item))}</strong>
        <p class="muted">${escapeHtml(setupItemDetail(item))}</p>
      </div>
    </div>`).join("");
}

function setupItemLabel(item) {
  const key = `setup.item.${item.key}`;
  const translated = tr(key);
  return translated === key ? (item.label || item.key || "") : translated;
}

function setupItemDetail(item) {
  const key = `setup.detail.${item.key}.${item.status || "info"}`;
  const values = item.values || {};
  const translated = tr(key, { ...values, detail: item.detail || "" });
  return translated === key ? (item.detail || "") : translated;
}

function renderChannelMatrix(payload) {
  const tb = $("#t-channel-matrix tbody"); if (!tb) return;
  tb.innerHTML = "";
  for (const channel of (payload.channels || [])) {
    const row = document.createElement("tr");
    row.innerHTML = `
      <td><code>${escapeHtml(channel.name || "")}</code></td>
      <td>${channel.configured ? escapeHtml(tr("common.configured")) : escapeHtml(tr("common.missing"))}</td>
      <td>${channel.reachable ? escapeHtml(tr("channel.up")) : escapeHtml(tr("channel.down"))}</td>
      <td><code>${escapeHtml(channel.endpoint || "—")}</code></td>
      <td>${(channel.checks || []).map(x => `<code>${escapeHtml(x)}</code>`).join(" ")}</td>`;
    tb.appendChild(row);
  }
  if (!(payload.channels || []).length) {
    tb.innerHTML = `<tr><td colspan="5" class="muted">${escapeHtml(tr("matrix.empty"))}</td></tr>`;
  }
  applyTablePager("t-channel-matrix", { reset: true });
}

document.addEventListener("DOMContentLoaded", () => {
  $("#setup-refresh")?.addEventListener("click", () => loadSetup({ force: true }));
});

// ---- Policy simulator ----
function parseLabelLines(raw) {
  const labels = {};
  String(raw || "").split(/\r?\n/).forEach(line => {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) return;
    const idx = trimmed.indexOf("=");
    if (idx <= 0) return;
    labels[trimmed.slice(0, idx).trim()] = trimmed.slice(idx + 1).trim();
  });
  return labels;
}

async function runPolicySimulation(opts = {}) {
  const status = $("#policy-sim-status");
  if (!opts.silent) setInlineStatus(status, tr("status.testing"));
  try {
    const payload = {
      source: $("#policy-sim-source")?.value || "grafana",
      severity: $("#policy-sim-severity")?.value || "warning",
      labels: parseLabelLines($("#policy-sim-labels")?.value || ""),
    };
    const result = await J("/api/policy-simulate", {
      method: "POST",
      body: JSON.stringify(payload),
      headers: {"Content-Type": "application/json"},
    });
    $("#policy-sim-output").textContent = JSON.stringify(result, null, 2);
    setInlineStatus(status, tr("sim.done"));
  } catch (e) {
    if (!opts.silent) notifyError("policy-simulate", e, { status });
    $("#policy-sim-output").textContent = `${tr("common.error")}: ${errorText(e)}`;
  }
}

document.addEventListener("DOMContentLoaded", () => {
  $("#policy-sim-run")?.addEventListener("click", () => runPolicySimulation());
});

