import {
  $,
  apiFetch,
  applyTablePager,
  errorText,
  escapeHtml,
  fetchError,
  markTabDirty,
  notifyError,
  notifyResponseError,
  notifySuccess,
  notifyValidationError,
  onReady,
  queryGet,
  setInlineStatus,
  tr,
} from "./app.js";
let _schedAvailableSources = [
  "grafana",
  "beszel",
  "healthchecks",
  "wud",
  "authentik",
  "shelfmark",
  "prowlarr",
  "decypharr",
];
let _schedActiveMutes = {};
function appendScheduleActions(row, schedule, nameInput) {
  const appliesCell = document.createElement("td");
  const applies = document.createElement("div");
  applies.dataset.k = "applies_to";
  applies.style.display = "flex";
  applies.style.flexWrap = "wrap";
  applies.style.gap = "0.3em";
  const selected = new Set(schedule.applies_to || []);
  for (const source of _schedAvailableSources) {
    const label = document.createElement("label");
    label.style.fontSize = "11px";
    label.style.whiteSpace = "nowrap";
    label.style.margin = "0";
    const checkbox = document.createElement("input");
    checkbox.type = "checkbox";
    checkbox.value = source;
    checkbox.checked = selected.has(source);
    label.append(checkbox, document.createTextNode(" " + source));
    applies.appendChild(label);
  }
  appliesCell.appendChild(applies);
  row.appendChild(appliesCell);
  const statusCell = document.createElement("td");
  const updateStatus = () => {
    const remain = _schedActiveMutes[nameInput.value.trim()];
    statusCell.innerHTML = remain && remain > 0
      ? `<span style="color:var(--yellow)">${escapeHtml(tr("sched.active"))}</span><br/><small>${escapeHtml(tr("sched.left_minutes", { minutes: Math.ceil(remain / 60) }))}</small>`
      : `<span class="muted">${escapeHtml(tr("sched.idle"))}</span>`;
  };
  updateStatus();
  nameInput.addEventListener("input", updateStatus);
  row.appendChild(statusCell);
  const actions = document.createElement("td");
  const remove = document.createElement("button");
  remove.className = "btn";
  remove.textContent = "✕";
  remove.title = tr("sched.delete_title");
  remove.style.color = "var(--red)";
  remove.style.padding = "2px 8px";
  remove.addEventListener("click", () => {
    row.remove();
    applyTablePager("t-schedules");
  });
  actions.appendChild(remove);
  row.appendChild(actions);
}

function _renderSchedRow(s) {
  const row = document.createElement("tr");
  row.classList.add("sched-row");
  const td = (html) => {
    const x = document.createElement("td");
    x.innerHTML = html;
    return x;
  };
  const inName = document.createElement("input");
  inName.type = "text";
  inName.value = s.name || "";
  inName.dataset.k = "name";
  inName.placeholder = "backup-window";
  inName.style.width = "100%";
  const tdN = document.createElement("td");
  tdN.appendChild(inName);
  row.appendChild(tdN);
  const inCron = document.createElement("input");
  inCron.type = "text";
  inCron.value = s.cron || "";
  inCron.dataset.k = "cron";
  inCron.placeholder = "30 4 * * 0";
  inCron.style.width = "100%";
  inCron.style.fontFamily = "ui-monospace, monospace";
  inCron.style.fontSize = "12px";
  const tdC = document.createElement("td");
  tdC.appendChild(inCron);
  row.appendChild(tdC);
  const inDur = document.createElement("input");
  inDur.type = "number";
  inDur.min = "1";
  inDur.max = "1440";
  inDur.value = s.duration_minutes || 30;
  inDur.dataset.k = "duration_minutes";
  inDur.style.width = "5em";
  const tdD = document.createElement("td");
  tdD.appendChild(inDur);
  row.appendChild(tdD);
  const matchObj = s.match || {};
  const matchTxt = Object.entries(matchObj)
    .map(([k, v]) => `${k}=${v}`)
    .join("\n");
  const taMatch = document.createElement("textarea");
  taMatch.dataset.k = "match";
  taMatch.rows = 3;
  taMatch.value = matchTxt;
  taMatch.placeholder = "component=storage\nseverity=info";
  taMatch.style.fontFamily = "ui-monospace, monospace";
  taMatch.style.fontSize = "12px";
  const tdM = document.createElement("td");
  tdM.appendChild(taMatch);
  row.appendChild(tdM);
  appendScheduleActions(row, s, inName);
  return row;
}
export async function loadSchedules() {
  const tb = $("#t-schedules tbody");
  if (!tb) return;
  try {
    const data = await queryGet("schedules", "/api/schedules");
    _schedActiveMutes = data.active_mutes || {};
    tb.innerHTML = "";
    for (const s of data.schedules || []) tb.appendChild(_renderSchedRow(s));
    $("#sched-save-status").textContent = "";
    applyTablePager("t-schedules", { reset: true });
  } catch (e) {
    fetchError("schedules", e);
  }
}
function _collectSchedules() {
  const rows = document.querySelectorAll("#t-schedules tbody tr.sched-row");
  const out = [];
  for (const tr of rows) {
    const get = (k) => tr.querySelector(`[data-k="${k}"]`);
    const name = get("name").value.trim();
    if (!name) continue;
    const cron = get("cron").value.trim();
    if (cron.split(/\s+/).filter(Boolean).length !== 5) {
      return { error: `schedule "${name}": cron must have exactly 5 fields` };
    }
    const duration = parseInt(get("duration_minutes").value || "30", 10);
    if (!(duration >= 1 && duration <= 1440)) {
      return { error: `schedule "${name}": duration_minutes 1..1440` };
    }
    const matchTxt = get("match").value.trim();
    const match = {};
    for (const line of matchTxt.split(/\r?\n/)) {
      const t = line.trim();
      if (!t) continue;
      const eq = t.indexOf("=");
      if (eq < 1)
        return {
          error: `schedule "${name}": match line must be "label=value"`,
        };
      match[t.slice(0, eq).trim()] = t.slice(eq + 1).trim();
    }
    const applies = Array.from(
      tr.querySelectorAll('[data-k="applies_to"] input[type=checkbox]'),
    )
      .filter((cb) => cb.checked)
      .map((cb) => cb.value);
    out.push({
      name: name,
      cron: cron,
      duration_minutes: duration,
      match: match,
      applies_to: applies,
    });
  }
  return { schedules: out };
}
async function saveSchedules() {
  const status = $("#sched-save-status");
  const collected = _collectSchedules();
  if (collected.error) {
    notifyValidationError("schedules", collected.error, status);
    return;
  }
  setInlineStatus(status, tr("status.saving"));
  try {
    const res = await apiFetch("/api/schedules", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ schedules: collected.schedules }),
    });
    if (!res.ok) {
      const txt = await res.text();
      notifyResponseError("schedules", res, txt, status);
      return;
    }
    const r = await res.json();
    const savedMessage = tr("sched.saved", { count: r.count });
    markTabDirty("inhibitions", false);
    await loadSchedules();
    notifySuccess(savedMessage, { status: status });
  } catch (e) {
    notifyError("schedules", e, {
      status: status,
      inlineText: "❌ " + errorText(e),
    });
  }
}
onReady(() => {
  const add = document.getElementById("sched-add");
  const save = document.getElementById("sched-save");
  if (add)
    add.addEventListener("click", () => {
      const tb = $("#t-schedules tbody");
      tb.appendChild(
        _renderSchedRow({
          name: "",
          cron: "",
          duration_minutes: 30,
          match: {},
          applies_to: [],
        }),
      );
      applyTablePager("t-schedules", { page: "last" });
    });
  if (save) save.addEventListener("click", saveSchedules);
});
