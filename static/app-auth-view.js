import { collectAuthSettings } from "./app-auth-payload.js";
import {
  OIDC_ISSUER_HINTS,
  applyAuthConfiguration,
  applyAuthPasswordPolicy,
  loadAuthPasswordPolicy,
  renderAuthGuard,
  showAuthSubcard,
} from "./app-auth-settings.js";
import {
  $,
  $$,
  APP_META,
  J,
  SEARCH_DEBOUNCE_MS,
  apiFetch,
  applyTablePager,
  confirmDialog,
  debounce,
  dirtyTabs,
  errorText,
  escapeHtml,
  fetchError,
  fetchOk,
  getAuthPasswordPolicy,
  getCurrentUser,
  isAbortError,
  isPublicInfoPage,
  markTabDirty,
  notifyError,
  notifyResponseError,
  notifySuccess,
  notifyValidationError,
  onReady,
  queryGet,
  refreshTablePagers,
  setAuthPasswordPolicy,
  setInlineStatus,
  setLocalTotpEnabled,
  showTableRowPage,
  syncTabFromPath,
  tr,
  updateAllTabAccessibleLabels,
  updatePublicLoginLinksText,
} from "./app.js";
import { updateCurrentUserUI } from "./app-status.js";
import {
  renderPasskeys,
  registerPasskey,
  setPasskeyReload,
} from "./app-auth-passkeys.js";
import {
  disableTotp,
  enableTotp,
  renderTotp,
  setTotpReload,
  startTotpSetup,
} from "./app-auth-totp.js";
import {
  authTokens,
  createAuthToken,
  renderScopePicker,
  renderTokens,
  selectedTokenScopes,
  setAuthReload,
  setTokenKind,
} from "./app-auth-tokens.js";
export { authTokens, renderTokens } from "./app-auth-tokens.js";
let authData = { settings: {}, current_user: {} };
let authEditRevision = 0;
let authLoadGeneration = 0;
let authSaving = false;
let authReloadAfterSave = false;
function updateAuthDirtyState() {
  const dirty = dirtyTabs.has("auth");
  const readOnly = document.body.classList.contains("viewer-readonly");
  document.querySelectorAll("[data-auth-save]").forEach((button) => {
    button.disabled = !dirty || readOnly || authSaving;
  });
  const discard = $("#auth-discard");
  if (discard) discard.disabled = !dirty || readOnly || authSaving;
  const status = $("#auth-dirty-status");
  if (status) {
    status.textContent = dirty
      ? tr("settings.unsaved_sections", { count: 1 })
      : tr("settings.no_unsaved_changes");
  }
}
function markAuthConfigDirty(dirty = true) {
  if (dirty) authEditRevision += 1;
  markTabDirty("auth", dirty);
  updateAuthDirtyState();
}
export async function loadAuth(options = {}) {
  if (authSaving) {
    authReloadAfterSave = true;
    return true;
  }
  const requestedRevision = authEditRevision;
  const loadGeneration = ++authLoadGeneration;
  const preserveDraftAtStart = options.preserveDraft ?? dirtyTabs.has("auth");
  try {
    await loadAuthPasswordPolicy();
    const j = await J("/api/auth/config");
    if (loadGeneration !== authLoadGeneration) return true;
    authData = j;
    const s = j.settings || {};
    $("#auth-jwt-warn")?.classList.toggle("hidden", !!j.jwt_available);
    const cu = j.current_user || {};
    updateCurrentUserUI(cu);
    const preserveDraft =
      preserveDraftAtStart ||
      authEditRevision !== requestedRevision ||
      dirtyTabs.has("auth");
    if (preserveDraft) renderTotp(s.basic || {});
    else applyAuthConfiguration(s);
    renderScopePicker(
      j.available_token_scopes || [],
      selectedTokenScopes().length ? selectedTokenScopes() : ["admin:read"],
    );
    renderTokens(s.api_keys || []);
    renderPasskeys(s.passkeys || []);
    if (!preserveDraft) markAuthConfigDirty(false);
    return true;
  } catch (e) {
    if (loadGeneration !== authLoadGeneration) return true;
    notifyError("auth", e, {
      status: "#auth-status",
      inlineText: tr("auth.error_loading", { message: errorText(e) }),
    });
    return false;
  }
}
const reloadAuthInventory = () =>
  loadAuth({ preserveDraft: dirtyTabs.has("auth") });
setAuthReload(reloadAuthInventory);
setPasskeyReload(reloadAuthInventory);
setTotpReload(reloadAuthInventory);
document.querySelectorAll('input[name="auth-mode"]').forEach((r) => {
  r.addEventListener("change", () => showAuthSubcard(r.value));
});
document
  .getElementById("auth-oidc-provider")
  ?.addEventListener("change", (e) => {
    const hint = OIDC_ISSUER_HINTS[e.target.value] || "";
    if (hint) $("#auth-oidc-issuer").placeholder = hint;
  });
document.querySelectorAll("[data-token-kind-option]").forEach((btn) => {
  btn.addEventListener("click", () =>
    setTokenKind(btn.dataset.tokenKindOption),
  );
});
async function saveAuth() {
  if (authSaving) return false;
  authSaving = true;
  authLoadGeneration += 1;
  updateAuthDirtyState();
  const submittedRevision = authEditRevision;
  const basicPassword = $("#auth-basic-pwd").value;
  const passwordPolicy = getAuthPasswordPolicy();
  if (basicPassword && basicPassword.length < passwordPolicy.min_length) {
    notifyError(
      "auth-save",
      new Error(tr("auth.password_min_hint", { min: passwordPolicy.min_length })),
      { status: "#auth-status" },
    );
    authSaving = false;
    updateAuthDirtyState();
    return false;
  }
  const out = collectAuthSettings();
  setInlineStatus("#auth-status", tr("status.saving"));
  try {
    const r = await J("/api/auth/config", {
      method: "POST",
      body: JSON.stringify({ settings: out }),
      headers: { "Content-Type": "application/json" },
    });
    if (r.ok) {
      authData.settings = r.settings;
      if (authEditRevision === submittedRevision) {
        applyAuthConfiguration(r.settings);
        markAuthConfigDirty(false);
        notifySuccess(tr("auth.saved", { mode: r.settings.mode }), {
          status: "#auth-status",
        });
      } else {
        notifySuccess(tr("settings.saved_newer_pending"), {
          status: "#auth-status",
        });
      }
      return true;
    } else {
      notifyError("auth-save", new Error(r.error || "unknown"), {
        status: "#auth-status",
      });
    }
  } catch (e) {
    notifyError("auth-save", e, { status: "#auth-status" });
  } finally {
    authSaving = false;
    updateAuthDirtyState();
    if (authReloadAfterSave) {
      authReloadAfterSave = false;
      void loadAuth({ preserveDraft: dirtyTabs.has("auth") });
    }
  }
  return false;
}
document.querySelectorAll("[data-auth-save]").forEach((button) => {
  button.addEventListener("click", saveAuth);
});
$("#tab-auth")?.addEventListener("input", (event) => {
  if (!event.target.closest("[data-dirty-ignore], .table-pager"))
    markAuthConfigDirty();
});
$("#tab-auth")?.addEventListener("change", (event) => {
  if (!event.target.closest("[data-dirty-ignore], .table-pager"))
    markAuthConfigDirty();
});
$("#auth-discard")?.addEventListener("click", async () => {
  if (!dirtyTabs.has("auth")) return;
  const confirmed = await confirmDialog(tr("settings.discard_confirm"), {
    title: tr("settings.discard_changes"),
    confirmLabel: tr("shortcut.discard"),
    danger: true,
  });
  if (!confirmed) return;
  const discardedRevision = authEditRevision;
  markAuthConfigDirty(false);
  if (await loadAuth({ preserveDraft: false })) {
    if (authEditRevision === discardedRevision)
      notifySuccess(tr("settings.changes_discarded"));
  } else if (authEditRevision === discardedRevision) {
    markAuthConfigDirty(true);
  }
});
document.addEventListener("klaxond:languagechange", updateAuthDirtyState);
document.addEventListener("klaxond:readonlychange", updateAuthDirtyState);
updateAuthDirtyState();
$("#token-create")?.addEventListener("click", createAuthToken);
$("#passkey-register")?.addEventListener("click", registerPasskey);
$("#totp-start")?.addEventListener("click", startTotpSetup);
$("#totp-enable")?.addEventListener("click", enableTotp);
$("#totp-disable")?.addEventListener("click", disableTotp);
