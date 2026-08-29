import {
  $, J, applyTablePager, confirmDialog, escapeHtml, notifyError, notifySuccess, setInlineStatus, tr,
} from "./app.js";

export let authTokens = [];
let _activeTokenKind = "api-key";
let reloadAuth = async () => {};

function fmtAuthTs(ts) {
  return ts ? new Date(ts * 1000).toLocaleString() : "—";
}

export function setAuthReload(fn) {
  reloadAuth = typeof fn === "function" ? fn : async () => {};
}

function normalizeTokenKind(kind) {
  return kind === "pat" ? "pat" : "api-key";
}

function tokenKindLabel(kind) {
  return normalizeTokenKind(kind) === "pat" ? tr("auth.pats") : tr("auth.api_keys");
}

function updateTokenKindUI() {
  const kind = normalizeTokenKind(_activeTokenKind);
  const counts = authTokens.reduce((acc, token) => {
    const tokenKind = normalizeTokenKind(token.kind);
    acc[tokenKind] = (acc[tokenKind] || 0) + 1;
    return acc;
  }, {"api-key": 0, pat: 0});
  document.querySelectorAll("[data-token-kind-option]").forEach(btn => {
    const active = normalizeTokenKind(btn.dataset.tokenKindOption) === kind;
    btn.classList.toggle("active", active);
    btn.setAttribute("aria-pressed", active ? "true" : "false");
    btn.setAttribute("aria-selected", active ? "true" : "false");
    const count = counts[normalizeTokenKind(btn.dataset.tokenKindOption)] || 0;
    btn.title = tr("auth.token_kind_count", { kind: tokenKindLabel(btn.dataset.tokenKindOption), count });
  });
  const hidden = $("#token-kind");
  if (hidden) hidden.value = kind;
  const name = $("#token-name");
  if (name) name.placeholder = kind === "pat" ? "luigi-cli" : "grafana-admin-script";
  const summary = $("#token-kind-summary");
  if (summary) summary.textContent = kind === "pat" ? tr("auth.pat_summary") : tr("auth.api_key_summary");
  const create = $("#token-create");
  if (create) create.textContent = kind === "pat" ? tr("auth.create_pat") : tr("auth.create_api_key");
  const title = $("#token-table-title");
  if (title) title.textContent = tokenKindLabel(kind);
  const count = $("#token-table-count");
  if (count) count.textContent = tr("auth.token_count", { count: counts[kind] || 0 });
}

export function setTokenKind(kind) {
  _activeTokenKind = normalizeTokenKind(kind);
  updateTokenKindUI();
  renderTokens(authTokens, { preserveSource: true });
}

export function renderScopePicker(available = [], selected = ["admin:read"]) {
  const box = $("#token-scopes");
  if (!box) return;
  const picked = new Set(selected);
  box.innerHTML = available.map(scope => `
    <label class="scope-pill">
      <input type="checkbox" value="${escapeHtml(scope)}" ${picked.has(scope) ? "checked" : ""}>
      <code>${escapeHtml(scope)}</code>
    </label>`).join("");
}

export function selectedTokenScopes() {
  return Array.from(document.querySelectorAll("#token-scopes input:checked")).map(cb => cb.value);
}

export function renderTokens(tokens = [], opts = {}) {
  if (!opts.preserveSource) authTokens = Array.isArray(tokens) ? tokens : [];
  const filtered = authTokens.filter(token => normalizeTokenKind(token.kind) === _activeTokenKind);
  const readOnly = document.body.classList.contains("viewer-readonly");
  updateTokenKindUI();
  const tb = $("#t-tokens tbody"); if (!tb) return;
  tb.innerHTML = "";
  if (!filtered.length) {
    const emptyKey = _activeTokenKind === "pat" ? "auth.no_pats" : "auth.no_api_keys";
    tb.innerHTML = `<tr><td colspan="6" class="muted">${escapeHtml(tr(emptyKey))}</td></tr>`;
    applyTablePager("t-tokens", { reset: true });
    return;
  }
  for (const token of filtered) {
    const trEl = document.createElement("tr");
    trEl.innerHTML = `
      <td>${escapeHtml(token.name || "")}<br><small class="muted">${escapeHtml(token.prefix || "")}…</small></td>
      <td>${(token.scopes || []).map(s => `<code>${escapeHtml(s)}</code>`).join(" ")}</td>
      <td>${escapeHtml(fmtAuthTs(token.created_at))}</td>
      <td>${escapeHtml(fmtAuthTs(token.last_used_at))}</td>
      <td>${token.enabled ? `<span style="color:var(--green)">${escapeHtml(tr("auth.enabled"))}</span>` : `<span class="muted">${escapeHtml(tr("auth.revoked"))}</span>`}</td>
      <td><button class="danger" data-revoke="${escapeHtml(token.id)}" ${token.enabled && !readOnly ? "" : "disabled"}>${escapeHtml(tr("auth.revoke"))}</button></td>`;
    trEl.querySelector("[data-revoke]")?.addEventListener("click", () => revokeAuthToken(token.id));
    tb.appendChild(trEl);
  }
  applyTablePager("t-tokens", { reset: true });
}

export async function createAuthToken() {
  const status = $("#token-status");
  const body = {
    name: $("#token-name").value.trim(),
    kind: $("#token-kind").value,
    expires_in_days: parseInt($("#token-expires-days").value, 10) || null,
    scopes: selectedTokenScopes(),
  };
  setInlineStatus(status, tr("status.saving"));
  try {
    const r = await J("/api/auth/tokens", {
      method: "POST",
      body: JSON.stringify(body),
      headers: {"Content-Type": "application/json"},
    });
    const once = $("#token-once");
    once.classList.remove("hidden");
    once.textContent = tr("auth.token_once") + "\n" + r.token;
    await reloadAuth();
    notifySuccess(tr("auth.token_created"), { status });
  } catch (e) {
    notifyError("auth-token-create", e, { status });
  }
}

async function revokeAuthToken(id) {
  if (!await confirmDialog(tr("auth.revoke_confirm"), {
    title: tr("auth.revoke"), confirmLabel: tr("auth.revoke"), danger: true,
  })) return;
  try {
    await J(`/api/auth/tokens/${encodeURIComponent(id)}`, { method: "DELETE" });
    await reloadAuth();
    notifySuccess(tr("auth.token_revoked"), { status: "#token-status", clearMs: 3000 });
  } catch (e) {
    notifyError("auth-token-revoke", e, { status: "#token-status" });
  }
}
