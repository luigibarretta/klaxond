import {
  $, apiFetch, confirmDialog, escapeHtml, markTabDirty, notifyError, notifySuccess,
  notifyValidationError, onReady, setInlineStatus, tr,
} from "./app.js";
import { acknowledgeEmergencyReceipt } from "./app-emergency-actions.js";
import { setTabBadge } from "./app-status.js";

let incidents = [];
let policyDirty = false;
let policyConfig = { settings: { profiles: [], exclude_sources: [] }, managed_fields: {} };

function when(value) {
  if (!value) return "—";
  const date = new Date(Number(value) * 1000);
  return Number.isNaN(date.getTime()) ? "—" : date.toLocaleString();
}

function remaining(value) {
  if (!value) return "—";
  const seconds = Math.round(Number(value) - Date.now() / 1000);
  if (seconds <= 0) return tr("emergency.due_now");
  if (seconds < 120) return `${seconds}s`;
  return `${Math.round(seconds / 60)}m`;
}

function renderRows() {
  const body = $("#t-emergencies tbody");
  if (!body) return;
  body.innerHTML = incidents.map(item => {
    const active = item.state === "active";
    const buttons = active ? `<div class="row">
      <button class="btn primary" data-emergency-action="ack" data-id="${escapeHtml(item.receipt_id)}">${escapeHtml(tr("emergency.ack"))}</button>
      <button class="btn" data-emergency-action="retry" data-id="${escapeHtml(item.receipt_id)}">${escapeHtml(tr("emergency.retry"))}</button>
      <button class="btn danger" data-emergency-action="cancel" data-id="${escapeHtml(item.receipt_id)}">${escapeHtml(tr("emergency.cancel"))}</button>
    </div>` : `<span class="muted">${escapeHtml(item.terminal_by || "—")}</span>`;
    const escalation = [item.telegram_escalated_at ? "TG" : "", item.smtp_escalated_at ? "SMTP" : ""].filter(Boolean).join("+");
    const policy = item.policy_name || item.policy_id || tr("emergency.legacy_policy");
    return `<tr>
      <td data-label="${escapeHtml(tr("common.time"))}" title="${escapeHtml(item.receipt_id)}">${escapeHtml(when(item.created_at))}<br><code>${escapeHtml(item.receipt_id.slice(0, 10))}</code></td>
      <td data-label="${escapeHtml(tr("common.status"))}"><span class="badge sev-${escapeHtml(item.state)}">${escapeHtml(item.state)}</span></td>
      <td data-label="${escapeHtml(tr("common.title"))}">${escapeHtml(item.title)}<br><small>${escapeHtml(policy)}</small>${item.last_error ? `<br><small class="ch-suppressed">${escapeHtml(item.last_error)}</small>` : ""}</td>
      <td data-label="${escapeHtml(tr("common.source"))}">${escapeHtml(item.source)}<br><small>${escapeHtml(item.severity)}</small></td>
      <td data-label="${escapeHtml(tr("emergency.attempts"))}">${Number(item.attempts)}/${Number(item.max_attempts)}${escalation ? `<br><small>${escalation}</small>` : ""}</td>
      <td data-label="${escapeHtml(tr("emergency.deadline"))}">${active ? `${escapeHtml(remaining(item.next_retry_at))}<br><small>${escapeHtml(tr("emergency.expires"))}: ${escapeHtml(remaining(item.expires_at))}</small>` : escapeHtml(when(item.terminal_at))}</td>
      <td data-label="${escapeHtml(tr("common.actions"))}">${buttons}</td>
    </tr>`;
  }).join("") || `<tr><td colspan="7" class="muted">${escapeHtml(tr("emergency.none"))}</td></tr>`;
  body.querySelectorAll("button[data-emergency-action]").forEach(button => button.addEventListener("click", () => transition(button)));
  $("#emergency-count").textContent = `${incidents.length}`;
  const active = incidents.filter(item => item.state === "active").length;
  setTabBadge("emergencies", active, active ? "crit" : "");
  window.applyReadOnlyViewerMode?.(window.klaxondCurrentUser || {});
}

async function transition(button) {
  const action = button.dataset.emergencyAction;
  const id = button.dataset.id;
  if (action === "ack") {
    button.disabled = true;
    if (await acknowledgeEmergencyReceipt(id)) await loadEmergencies({ force: true });
    else button.disabled = false;
    return;
  }
  if (action === "cancel" && !await confirmDialog(tr("emergency.cancel_confirm"), {
    title: tr("emergency.cancel"), confirmLabel: tr("emergency.cancel"), danger: true,
  })) return;
  button.disabled = true;
  try {
    const response = await apiFetch(`/api/emergencies/${encodeURIComponent(id)}/${action}`, { method: "POST", body: "{}", headers: { "Content-Type": "application/json" } });
    if (!response.ok) throw new Error(await response.text());
    notifySuccess(tr(`emergency.${action}_ok`));
    await loadEmergencies({ force: true });
  } catch (error) {
    notifyError("emergency-transition", error);
    button.disabled = false;
  }
}

function prioritizeEmergencyHistory() {
  const editor = $("#emergency-policy-editor");
  const tableWrap = $("#t-emergencies")?.closest(".table-scroll");
  const toolbar = tableWrap?.previousElementSibling;
  const heading = toolbar?.previousElementSibling;
  if (!editor || !tableWrap || !toolbar || !heading) return;
  editor.open = false;
  editor.parentNode.insertBefore(heading, editor);
  editor.parentNode.insertBefore(toolbar, editor);
  editor.parentNode.insertBefore(tableWrap, editor);
}

onReady(prioritizeEmergencyHistory);

function profileManaged(profileId) {
  return Object.keys(policyConfig.managed_fields || {}).some(field => field.startsWith(`profiles.${profileId}.`));
}

function renderChipEditor(container, options) {
  if (!container) return;
  const values = options.values;
  const listId = `${container.id}-suggestions`;
  container.innerHTML = `<span class="field-label">${escapeHtml(options.label)}</span>
    <div class="chip-control ${options.disabled ? "is-disabled" : ""}">
      <div class="chip-list"></div>
      <div class="chip-entry"><input type="text" autocomplete="off" ${options.disabled ? "disabled" : ""} aria-label="${escapeHtml(options.label)}" list="${escapeHtml(listId)}" placeholder="${escapeHtml(options.placeholder || "")}"><button class="btn" type="button" ${options.disabled ? "disabled" : ""}>${escapeHtml(tr("common.add"))}</button></div>
      <datalist id="${escapeHtml(listId)}">${(options.suggestions || []).map(value => `<option value="${escapeHtml(value)}"></option>`).join("")}</datalist>
    </div>`;
  const draw = () => {
    container.querySelector(".chip-list").innerHTML = values.map((value, index) => `<span class="chip"><span>${escapeHtml(value)}</span>${options.disabled ? "" : `<button type="button" data-remove="${index}" aria-label="${escapeHtml(tr("emergency.remove_value", { value }))}">${escapeHtml(tr("emergency.remove"))}</button>`}</span>`).join("") || `<span class="muted chip-empty">${escapeHtml(tr("emergency.any_value"))}</span>`;
    container.querySelectorAll("[data-remove]").forEach(button => button.addEventListener("click", () => {
      values.splice(Number(button.dataset.remove), 1);
      draw();
      setDirty();
      options.onChange?.();
    }));
  };
  const input = container.querySelector("input");
  const add = () => {
    const value = input.value.trim().toLowerCase();
    if (!value) return;
    if (!validMatcherValue(value) || values.includes(value)) {
      input.setCustomValidity(tr("emergency.invalid_match_value"));
      input.reportValidity();
      return;
    }
    input.setCustomValidity("");
    values.push(value);
    input.value = "";
    draw();
    setDirty();
    options.onChange?.();
  };
  container.querySelector("button.btn")?.addEventListener("click", add);
  input?.addEventListener("keydown", event => {
    if (event.key === "Enter" || event.key === ",") {
      event.preventDefault();
      add();
    }
  });
  draw();
}

function validMatcherValue(value) {
  if (value.startsWith("re:")) {
    try { new RegExp(value.slice(3)); return value.length <= 256; } catch { return false; }
  }
  return /^[a-z0-9._-]{1,64}$/.test(value);
}

function profileMarkup(profile, index, managed) {
  const channel = (name, value) => `<fieldset class="fallback-card"><legend>${escapeHtml(name)}</legend><label class="inline-check"><input type="checkbox" data-profile-field="${name.toLowerCase()}.enabled" ${value.enabled ? "checked" : ""} ${managed ? "disabled" : ""}> <span>${escapeHtml(tr("emergency.channel_enabled"))}</span></label><label><span>${escapeHtml(tr("emergency.escalate_attempt"))}</span><input type="number" min="1" max="50" data-profile-field="${name.toLowerCase()}.after_attempts" value="${Number(value.after_attempts)}" ${managed ? "disabled" : ""}></label></fieldset>`;
  return `<article class="emergency-profile card" data-profile-index="${index}">
    <header class="emergency-profile-header"><div><span class="profile-order">${index + 1}</span><strong>${escapeHtml(profile.name || profile.id)}</strong><code>${escapeHtml(profile.id)}</code></div><div class="row"><button class="btn" type="button" data-profile-action="up" aria-label="${escapeHtml(tr("emergency.move_up"))}" ${index === 0 || managed ? "disabled" : ""}>${escapeHtml(tr("emergency.up"))}</button><button class="btn" type="button" data-profile-action="down" aria-label="${escapeHtml(tr("emergency.move_down"))}" ${index === policyConfig.settings.profiles.length - 1 || managed ? "disabled" : ""}>${escapeHtml(tr("emergency.down"))}</button><button class="btn danger" type="button" data-profile-action="delete" ${policyConfig.settings.profiles.length === 1 || managed ? "disabled" : ""}>${escapeHtml(tr("common.delete"))}</button></div></header>
    ${managed ? `<div class="notice warn compact">${escapeHtml(tr("emergency.profile_managed"))}</div>` : ""}
    <div class="grid4"><label><span>${escapeHtml(tr("emergency.profile_id"))}</span><input type="text" data-profile-field="id" value="${escapeHtml(profile.id)}" pattern="[a-z0-9._\\x2d]{1,64}" ${managed ? "disabled" : ""}></label><label><span>${escapeHtml(tr("emergency.profile_name"))}</span><input type="text" data-profile-field="name" value="${escapeHtml(profile.name)}" maxlength="80" ${managed ? "disabled" : ""}></label><label><span>${escapeHtml(tr("emergency.priority"))}</span><input type="number" data-profile-field="priority" value="${Number(profile.priority)}" ${managed ? "disabled" : ""}></label><label class="inline-check profile-enabled"><input type="checkbox" data-profile-field="enabled" ${profile.enabled ? "checked" : ""} ${managed ? "disabled" : ""}> <span>${escapeHtml(tr("common.enabled"))}</span></label></div>
    <div class="grid2 matcher-grid"><div id="profile-severities-${index}" class="chip-editor"></div><div id="profile-sources-${index}" class="chip-editor"></div></div>
    <label><span>${escapeHtml(tr("emergency.label_matchers"))}</span><textarea rows="3" data-profile-field="match" ${managed ? "disabled" : ""} placeholder="team=platform&#10;event=re:^Host.*">${escapeHtml(Object.entries(profile.match || {}).map(([key, value]) => `${key}=${value}`).join("\n"))}</textarea><small class="muted">${escapeHtml(tr("emergency.matcher_help"))}</small></label>
    <div class="grid4"><label><span>${escapeHtml(tr("emergency.retry_seconds"))}</span><input type="number" min="30" max="3600" data-profile-field="retry_seconds" value="${Number(profile.retry_seconds)}" ${managed ? "disabled" : ""}></label><label><span>${escapeHtml(tr("emergency.expire_seconds"))}</span><input type="number" min="30" max="10800" data-profile-field="expire_seconds" value="${Number(profile.expire_seconds)}" ${managed ? "disabled" : ""}></label><label><span>${escapeHtml(tr("emergency.max_attempts"))}</span><input type="number" min="1" max="50" data-profile-field="max_attempts" value="${Number(profile.max_attempts)}" ${managed ? "disabled" : ""}></label><label><span>${escapeHtml(tr("emergency.lease_seconds"))}</span><input type="number" min="5" max="300" data-profile-field="lease_seconds" value="${Number(profile.lease_seconds)}" ${managed ? "disabled" : ""}></label></div>
    <div class="grid2">${channel("Telegram", profile.telegram)}${channel("SMTP", profile.smtp)}</div>
    <div class="grid2"><label class="inline-check"><input type="checkbox" data-profile-field="notify_on_expiry" ${profile.notify_on_expiry ? "checked" : ""} ${managed ? "disabled" : ""}> <span>${escapeHtml(tr("emergency.notify_expiry"))}</span></label><label class="inline-check"><input type="checkbox" data-profile-field="auto_resolve" ${profile.auto_resolve ? "checked" : ""} ${managed ? "disabled" : ""}> <span>${escapeHtml(tr("emergency.auto_resolve"))}</span></label></div>
    <section class="profile-timeline" aria-label="${escapeHtml(tr("emergency.timeline"))}"><h4>${escapeHtml(tr("emergency.timeline"))}</h4><div data-profile-timeline></div></section>
  </article>`;
}

function parseMatchers(value) {
  const output = {};
  for (const line of value.split("\n").map(item => item.trim()).filter(Boolean)) {
    const split = line.indexOf("=");
    if (split < 1) throw new Error(tr("emergency.matcher_invalid"));
    const key = line.slice(0, split).trim().toLowerCase();
    const expected = line.slice(split + 1).trim();
    if (!validMatcherValue(key) || !expected || expected.length > 256) throw new Error(tr("emergency.matcher_invalid"));
    if (expected.startsWith("re:")) new RegExp(expected.slice(3));
    output[key] = expected;
  }
  return output;
}

function syncProfilesFromDom() {
  document.querySelectorAll("[data-profile-index]").forEach(card => {
    const profile = policyConfig.settings.profiles[Number(card.dataset.profileIndex)];
    card.querySelectorAll("[data-profile-field]").forEach(input => {
      const field = input.dataset.profileField;
      if (field === "match") profile.match = parseMatchers(input.value);
      else if (field.includes(".")) {
        const [parent, child] = field.split(".");
        profile[parent][child] = input.type === "checkbox" ? input.checked : Number(input.value);
      } else if (input.type === "checkbox") profile[field] = input.checked;
      else if (input.type === "number") profile[field] = Number(input.value);
      else profile[field] = input.value.trim();
    });
  });
}

function duration(seconds) {
  if (seconds < 60) return `${seconds}s`;
  if (seconds % 3600 === 0) return `${seconds / 3600}h`;
  return `${Math.round(seconds / 60)}m`;
}

function renderTimeline(card, profile) {
  const target = card.querySelector("[data-profile-timeline]");
  if (!target) return;
  const retry = Number(profile.retry_seconds);
  const expiry = Number(profile.expire_seconds);
  const max = Number(profile.max_attempts);
  const possibleAttempts = Math.max(1, Math.min(max, Math.ceil(expiry / retry)));
  const points = [{ at: 0, label: tr("emergency.timeline_initial"), meta: "ntfy · #1" }];
  for (const [channel, fallback] of [["Telegram", profile.telegram], ["SMTP", profile.smtp]]) {
    if (fallback.enabled && fallback.after_attempts <= possibleAttempts) {
      points.push({ at: (fallback.after_attempts - 1) * retry, label: channel, meta: `#${fallback.after_attempts}` });
    }
  }
  if (possibleAttempts === max) points.push({ at: (max - 1) * retry, label: tr("emergency.timeline_limit"), meta: `#${max}` });
  points.push({ at: expiry, label: tr("emergency.timeline_expiry"), meta: duration(expiry) });
  points.sort((a, b) => a.at - b.at);
  const timeouts = policyConfig.channel_timeouts || { ntfy: 15, telegram: 8, smtp: 10, lease_margin: 5 };
  const requiredLease = Number(timeouts.ntfy) + (profile.telegram.enabled ? Number(timeouts.telegram) : 0) + (profile.smtp.enabled ? Number(timeouts.smtp) : 0) + Number(timeouts.lease_margin);
  const leaseInvalid = Number(profile.lease_seconds) < requiredLease;
  target.innerHTML = `<p class="timeline-summary">${escapeHtml(tr("emergency.timeline_retry", { retry: duration(retry), attempts: possibleAttempts }))}</p><ol>${points.map(point => `<li><span>${escapeHtml(duration(point.at))}</span><strong>${escapeHtml(point.label)}</strong><small>${escapeHtml(point.meta)}</small></li>`).join("")}</ol>${leaseInvalid ? `<div class="notice error compact">${escapeHtml(tr("emergency.lease_impossible", { required: requiredLease }))}</div>` : `<small class="muted">${escapeHtml(tr("emergency.lease_budget", { required: requiredLease }))}</small>`}`;
}

function renderDiagnostics() {
  const target = $("#emergency-diagnostics");
  const diagnostics = policyConfig.diagnostics || {};
  const issues = [];
  for (const item of diagnostics.shadowed_profiles || []) issues.push(tr("emergency.shadowed", item));
  if ((diagnostics.unrouted_severities || []).length) issues.push(tr("emergency.unrouted", { values: diagnostics.unrouted_severities.join(", ") }));
  if ((diagnostics.equal_priorities || []).length) issues.push(tr("emergency.equal_priorities", { values: diagnostics.equal_priorities.join(", ") }));
  target.innerHTML = issues.length ? `<div class="notice warn"><strong>${escapeHtml(tr("emergency.routing_warnings"))}</strong><ul>${issues.map(issue => `<li>${escapeHtml(issue)}</li>`).join("")}</ul></div>` : `<div class="notice success compact">${escapeHtml(tr("emergency.routing_clear"))}</div>`;
}

function renderPolicyConfig(config, force = false) {
  if (!policyDirty || force) policyConfig = JSON.parse(JSON.stringify(config || policyConfig));
  const settings = policyConfig.settings || {};
  settings.profiles ||= [];
  settings.exclude_sources ||= [];
  $("#em-enabled").checked = !!settings.enabled;
  $("#em-allow-insecure").checked = !!settings.allow_insecure_public_url;
  $("#em-allow-ntfy-only").checked = !!settings.allow_ntfy_only;
  const managed = policyConfig.managed_fields || {};
  for (const [field, selector] of [["enabled", "#em-enabled"], ["allow_insecure_public_url", "#em-allow-insecure"], ["allow_ntfy_only", "#em-allow-ntfy-only"]]) {
    $(selector).disabled = !!managed[field];
    $(selector).title = managed[field] ? tr("emergency.managed_field", { env: managed[field] }) : "";
  }
  const owner = policyConfig.source_of_truth || "ui";
  $("#emergency-owner").textContent = tr(`emergency.owner_${owner}`);
  const owners = Object.entries(managed);
  $("#emergency-env-notice").classList.toggle("hidden", owners.length === 0);
  $("#emergency-env-notice").textContent = owners.length ? tr("emergency.managed_notice_compact", { count: owners.length }) : "";
  const fallback = $("#em-fallback");
  fallback.innerHTML = settings.profiles.map(profile => `<option value="${escapeHtml(profile.id)}" ${profile.id === settings.fallback_profile ? "selected" : ""}>${escapeHtml(profile.name)} · ${escapeHtml(profile.id)}</option>`).join("");
  fallback.disabled = !!managed.fallback_profile || settings.profiles.some(profile => profileManaged(profile.id));
  $("#emergency-policy-save").disabled = settings.profiles.some(profile => profileManaged(profile.id));
  $("#emergency-policy-save").title = $("#emergency-policy-save").disabled ? tr("emergency.profile_managed") : "";
  $("#emergency-profiles").innerHTML = settings.profiles.map((profile, index) => profileMarkup(profile, index, profileManaged(profile.id))).join("");
  settings.profiles.forEach((profile, index) => {
    renderChipEditor($(`#profile-severities-${index}`), { label: tr("emergency.severities"), values: profile.severities, suggestions: policyConfig.known_severities, placeholder: tr("emergency.add_severity"), disabled: profileManaged(profile.id), onChange: () => renderTimeline($(`[data-profile-index="${index}"]`), profile) });
    renderChipEditor($(`#profile-sources-${index}`), { label: tr("emergency.sources"), values: profile.sources, suggestions: policyConfig.known_sources, placeholder: tr("emergency.add_source"), disabled: profileManaged(profile.id), onChange: () => renderTimeline($(`[data-profile-index="${index}"]`), profile) });
    const card = $(`[data-profile-index="${index}"]`);
    renderTimeline(card, profile);
    card.querySelectorAll("[data-profile-action]").forEach(button => button.addEventListener("click", () => profileAction(index, button.dataset.profileAction)));
  });
  renderChipEditor($("#em-excluded-sources"), { label: tr("emergency.exclude_sources"), values: settings.exclude_sources, suggestions: policyConfig.known_sources, placeholder: tr("emergency.add_source"), disabled: !!managed.exclude_sources });
  renderDiagnostics();
  if (!policyDirty || force) {
    policyDirty = false;
    markTabDirty("emergencies", false);
  }
  hydrateSimulatorOptions();
  window.applyReadOnlyViewerMode?.(window.klaxondCurrentUser || {});
}

function hydrateSimulatorOptions() {
  const set = (selector, values) => { const node = $(selector); if (node) node.innerHTML = (values || []).map(value => `<option value="${escapeHtml(value)}"></option>`).join(""); };
  set("#policy-sim-sources", policyConfig.known_sources);
  set("#policy-sim-severities", policyConfig.known_severities);
}

function profileAction(index, action) {
  syncProfilesFromDom();
  const profiles = policyConfig.settings.profiles;
  if (action === "delete") {
    const removed = profiles[index];
    profiles.splice(index, 1);
    if (policyConfig.settings.fallback_profile === removed.id) policyConfig.settings.fallback_profile = profiles[0]?.id || "";
  } else if (action === "up" && index > 0) [profiles[index - 1], profiles[index]] = [profiles[index], profiles[index - 1]];
  else if (action === "down" && index < profiles.length - 1) [profiles[index + 1], profiles[index]] = [profiles[index], profiles[index + 1]];
  setDirty();
  renderPolicyConfig(policyConfig, false);
}

function addProfile() {
  try { syncProfilesFromDom(); } catch (error) { notifyValidationError("emergency-policy", error.message, "#emergency-policy-status"); return; }
  const suffix = Date.now().toString(36).slice(-5);
  policyConfig.settings.profiles.push({ id: `profile-${suffix}`, name: tr("emergency.new_profile"), enabled: true, priority: 50, severities: ["warning"], sources: [], match: {}, retry_seconds: 300, expire_seconds: 3600, max_attempts: 12, lease_seconds: 60, telegram: { enabled: true, after_attempts: 3 }, smtp: { enabled: false, after_attempts: 5 }, notify_on_expiry: true, auto_resolve: true });
  setDirty();
  renderPolicyConfig(policyConfig, false);
  $("#emergency-profiles article:last-child input[data-profile-field='name']")?.focus();
}

function setDirty() {
  policyDirty = true;
  markTabDirty("emergencies", true);
}

function policyPayload() {
  syncProfilesFromDom();
  const managed = policyConfig.managed_fields || {};
  const payload = {};
  if (!managed.enabled) payload.enabled = $("#em-enabled").checked;
  if (!managed.fallback_profile) payload.fallback_profile = $("#em-fallback").value;
  if (!policyConfig.settings.profiles.some(profile => profileManaged(profile.id))) payload.profiles = policyConfig.settings.profiles;
  if (!managed.exclude_sources) payload.exclude_sources = policyConfig.settings.exclude_sources;
  if (!managed.allow_insecure_public_url) payload.allow_insecure_public_url = $("#em-allow-insecure").checked;
  if (!managed.allow_ntfy_only) payload.allow_ntfy_only = $("#em-allow-ntfy-only").checked;
  return payload;
}

function validatePolicy(payload) {
  const ids = new Set();
  for (const profile of payload.profiles || policyConfig.settings.profiles) {
    if (!/^[a-z0-9._-]{1,64}$/.test(profile.id) || ids.has(profile.id)) return tr("emergency.profile_id_invalid");
    ids.add(profile.id);
    if (!profile.name || profile.name.length > 80) return tr("emergency.profile_name_invalid");
    if (!profile.severities.length && !profile.sources.length && !Object.keys(profile.match || {}).length) return tr("emergency.matcher_required", { profile: profile.name });
    for (const field of ["retry_seconds", "expire_seconds", "max_attempts", "lease_seconds"]) if (!Number.isInteger(profile[field])) return tr("emergency.invalid_number", { field });
    if (profile.expire_seconds < profile.retry_seconds) return tr("emergency.expiry_invalid");
    if (profile.telegram.after_attempts > profile.max_attempts || profile.smtp.after_attempts > profile.max_attempts) return tr("emergency.escalation_invalid");
    const timeouts = policyConfig.channel_timeouts || {};
    const required = Number(timeouts.ntfy || 15) + (profile.telegram.enabled ? Number(timeouts.telegram || 8) : 0) + (profile.smtp.enabled ? Number(timeouts.smtp || 10) : 0) + Number(timeouts.lease_margin || 5);
    if (profile.lease_seconds < required) return tr("emergency.lease_impossible_profile", { profile: profile.name, required });
  }
  if (!ids.has(payload.fallback_profile || policyConfig.settings.fallback_profile)) return tr("emergency.fallback_invalid");
  return "";
}

async function savePolicy() {
  let payload;
  try { payload = policyPayload(); } catch (error) { notifyValidationError("emergency-policy", error.message, "#emergency-policy-status"); return; }
  const invalid = validatePolicy(payload);
  if (invalid) { notifyValidationError("emergency-policy", invalid, "#emergency-policy-status"); return; }
  const current = policyConfig.settings || {};
  const unsafeRaised = (payload.allow_insecure_public_url && !current.allow_insecure_public_url) || (payload.allow_ntfy_only && !current.allow_ntfy_only);
  if (unsafeRaised && !await confirmDialog(tr("emergency.unsafe_confirm"), { title: tr("emergency.unsafe_options"), confirmLabel: tr("common.save_changes"), danger: true })) return;
  setInlineStatus("#emergency-policy-status", tr("status.saving"));
  try {
    const response = await apiFetch("/api/emergency-config", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload) });
    if (!response.ok) throw new Error(await response.text());
    policyDirty = false;
    markTabDirty("emergencies", false);
    notifySuccess(tr("emergency.saved"), { status: "#emergency-policy-status", clearMs: 4000 });
    await loadEmergencies({ force: true });
  } catch (error) { notifyError("emergency-policy", error, { status: "#emergency-policy-status" }); }
}

export async function loadEmergencies(options = {}) {
  try {
    const filter = $("#emergency-filter")?.value || "all";
    const [listResponse, configResponse] = await Promise.all([apiFetch(`/api/emergencies?state=${encodeURIComponent(filter)}&limit=500`), apiFetch("/api/emergency-config")]);
    if (!listResponse.ok) throw new Error(await listResponse.text());
    if (!configResponse.ok) throw new Error(await configResponse.text());
    const list = await listResponse.json();
    const config = await configResponse.json();
    incidents = Array.isArray(list.incidents) ? list.incidents : [];
    const profiles = (config.settings?.profiles || []).filter(profile => profile.enabled);
    $("#emergency-policy").textContent = config.settings?.enabled ? tr("emergency.profile_count", { count: profiles.length }) : tr("emergency.disabled");
    $("#emergency-active").textContent = String(incidents.filter(item => item.state === "active").length);
    $("#emergency-escalation").textContent = profiles.length ? profiles.map(profile => `${profile.name}: ${[profile.telegram.enabled ? `TG #${profile.telegram.after_attempts}` : "", profile.smtp.enabled ? `SMTP #${profile.smtp.after_attempts}` : ""].filter(Boolean).join(" · ") || "ntfy"}`).join(" | ") : "—";
    renderPolicyConfig(config, !!options.force);
    renderRows();
  } catch (error) { notifyError("emergencies", error); }
}

$("#emergency-filter")?.addEventListener("change", () => loadEmergencies());
$("#emergency-refresh")?.addEventListener("click", () => loadEmergencies({ force: !policyDirty }));
$("#emergency-policy-editor")?.addEventListener("input", event => {
  if (!event.target.closest("[data-emergency-field], [data-profile-field]")) return;
  setDirty();
  const card = event.target.closest("[data-profile-index]");
  if (card) {
    try { syncProfilesFromDom(); renderTimeline(card, policyConfig.settings.profiles[Number(card.dataset.profileIndex)]); } catch { /* Validation is shown on save. */ }
  }
});
$("#emergency-profile-add")?.addEventListener("click", addProfile);
$("#emergency-policy-save")?.addEventListener("click", savePolicy);
