import { confirmDialog, escapeHtml, tr } from "./app.js";

export function iconButton(action, icon, label, extraClass = "") {
  const classes = extraClass ? ` class="${escapeHtml(extraClass)}"` : "";
  return `<button type="button" data-action="${action}"${classes} aria-label="${escapeHtml(label)}" title="${escapeHtml(label)}"><i data-lucide="${icon}" aria-hidden="true"></i></button>`;
}

export function refreshDeliveryIcons() {
  window.lucide?.createIcons({ attrs: { "stroke-width": 1.8 } });
}

export function tierSummary(tiers) {
  if (!tiers.length) return `<span class="muted">—</span>`;
  return `<div class="policy-tier-summary">${tiers.map((tier, index) => `
    ${index ? '<span aria-hidden="true">→</span>' : ""}
    <span><strong>${escapeHtml(tier.name)}</strong><small>${Number(tier.timeout_seconds)}s</small></span>`).join("")}</div>`;
}

export function appendPolicyTier(editor, tier, availableTiers, onDirty) {
  const row = document.createElement("div");
  row.className = "policy-tier-row";
  const options = availableTiers
    .map(name => `<option ${name === tier.name ? "selected" : ""}>${escapeHtml(name)}</option>`)
    .join("");
  row.innerHTML = `
    <select data-tier-name>${options}</select>
    <input type="number" min="1" max="60" value="${Number(tier.timeout_seconds || 15)}" data-tier-timeout>
    <span class="muted" aria-hidden="true">s</span>
    <span class="policy-tier-actions">
      ${iconButton("up", "arrow-up", tr("cascade.move_up"))}
      ${iconButton("down", "arrow-down", tr("cascade.move_down"))}
      ${iconButton("delete", "trash-2", tr("common.delete"), "danger")}
    </span>`;
  row.addEventListener("input", onDirty);
  row.addEventListener("change", () => {
    refreshPolicyTierRows(editor);
    onDirty();
  });
  bindPolicyTierActions(row, editor, onDirty);
  editor.appendChild(row);
  refreshPolicyTierRows(editor);
  refreshDeliveryIcons();
}

function bindPolicyTierActions(row, editor, onDirty) {
  row.querySelector('[data-action="up"]').addEventListener("click", event => {
    const previous = row.previousElementSibling;
    if (!previous) return;
    editor.insertBefore(row, previous);
    refreshPolicyTierRows(editor);
    onDirty();
    focusMovedTierControl(row, event.currentTarget, "down");
    announceTierMove(editor, row);
  });
  row.querySelector('[data-action="down"]').addEventListener("click", event => {
    const next = row.nextElementSibling;
    if (!next) return;
    editor.insertBefore(next, row);
    refreshPolicyTierRows(editor);
    onDirty();
    focusMovedTierControl(row, event.currentTarget, "up");
    announceTierMove(editor, row);
  });
  row.querySelector('[data-action="delete"]').addEventListener("click", async () => {
    const policy = policyName(editor);
    const position = [...editor.children].indexOf(row) + 1;
    const channel = row.querySelector("[data-tier-name]").value;
    if (!await confirmDialog(tr("delivery.delete_policy_tier_confirm", {
      policy, position, channel,
    }), {
      title: tr("delivery.delete_policy_tier_title"),
      confirmLabel: tr("common.delete"),
      danger: true,
    })) return;
    const focusTarget = row.nextElementSibling || row.previousElementSibling;
    row.remove();
    refreshPolicyTierRows(editor);
    onDirty();
    (focusTarget?.querySelector("select") || editor.parentElement?.querySelector(".policy-tier-add"))?.focus();
  });
}

function focusMovedTierControl(row, button, fallbackAction) {
  (button.disabled ? row.querySelector(`[data-action="${fallbackAction}"]`) : button)?.focus();
}

function announceTierMove(editor, row) {
  const position = [...editor.children].indexOf(row) + 1;
  const status = document.querySelector("#delivery-status");
  if (status) status.textContent = tr("delivery.policy_tier_moved", {
    policy: policyName(editor), position,
  });
}

export function refreshPolicyTierRows(editor) {
  const rows = [...editor.querySelectorAll(".policy-tier-row")];
  const policy = policyName(editor);
  rows.forEach((row, index) => {
    const position = index + 1;
    const channel = row.querySelector("[data-tier-name]");
    const timeout = row.querySelector("[data-tier-timeout]");
    const remove = row.querySelector('[data-action="delete"]');
    channel.setAttribute("aria-label", tr("delivery.tier_channel_label", { policy, position }));
    timeout.setAttribute("aria-label", tr("delivery.tier_timeout_label", { policy, position }));
    row.querySelector('[data-action="up"]').disabled = index === 0;
    row.querySelector('[data-action="down"]').disabled = index === rows.length - 1;
    remove.setAttribute("aria-label", tr("delivery.tier_remove_label", {
      policy, position, channel: channel.value,
    }));
    remove.title = remove.getAttribute("aria-label");
  });
}

function policyName(editor) {
  return editor.closest("tr")?.querySelector('[data-f="name"]')?.value.trim()
    || tr("delivery.unnamed_policy");
}

export function parseRuleMatch(raw, position) {
  const match = {};
  const lines = String(raw || "").split(/\r?\n/);
  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index].trim();
    if (!line) continue;
    const separator = line.indexOf("=");
    if (separator <= 0 || !line.slice(separator + 1).trim()) {
      return { error: tr("delivery.rule_error_line", { position, line: index + 1 }) };
    }
    const key = line.slice(0, separator).trim();
    if (Object.hasOwn(match, key)) {
      return { error: tr("delivery.rule_error_duplicate", { position, line: index + 1, key }) };
    }
    match[key] = line.slice(separator + 1).trim();
  }
  if (!Object.keys(match).length) return { error: tr("delivery.rule_error_empty", { position }) };
  return { match };
}

export function showRuleError(row, message = "") {
  const field = row.querySelector('[data-f="match"]');
  const error = row.querySelector("[data-rule-error]");
  field.setAttribute("aria-invalid", message ? "true" : "false");
  error.textContent = message;
  error.classList.toggle("hidden", !message);
}
