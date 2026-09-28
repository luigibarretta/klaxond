import { $, escapeHtml, tr } from "./app.js";

let selectedStepId = "";

function domId(value) {
  return String(value || "step").replace(/[^a-zA-Z0-9_-]/g, "-");
}

function ensureStructure() {
  let panel = $("#flow-structure");
  if (panel) return panel;
  const legend = document.querySelector("#tab-flow .flow-legend");
  if (!legend) return null;
  panel = document.createElement("section");
  panel.id = "flow-structure";
  panel.className = "flow-structure";
  panel.setAttribute("aria-labelledby", "flow-structure-title");
  panel.innerHTML = `
    <div class="flow-structure-heading">
      <div>
        <h3 id="flow-structure-title">${escapeHtml(tr("flow.structure_title"))}</h3>
        <p class="muted">${escapeHtml(tr("flow.structure_desc"))}</p>
      </div>
    </div>
    <div class="flow-structure-layout">
      <ol id="flow-route-list" class="flow-route-list" aria-label="${escapeHtml(tr("flow.structure_list_label"))}"></ol>
      <aside id="flow-step-inspector" class="flow-step-inspector" aria-live="polite"></aside>
    </div>`;
  legend.insertAdjacentElement("beforebegin", panel);
  return panel;
}

function renderInspector(step) {
  const inspector = $("#flow-step-inspector");
  if (!inspector || !step) return;
  const content = `
    <span class="flow-inspector-eyebrow">${escapeHtml(tr(`flow.kind_${step.kind}`))}</span>
    <h3>${escapeHtml(step.title)}</h3>
    <p>${escapeHtml(step.detail)}</p>
    ${step.meta ? `<p class="muted">${escapeHtml(step.meta)}</p>` : ""}
    <a class="btn" href="${escapeHtml(step.href)}">${escapeHtml(tr("flow.open_settings"))}</a>`;
  if (inspector.dataset.stepId === step.id && inspector.innerHTML === content) return;
  const restoreLinkFocus = inspector.contains(document.activeElement);
  inspector.dataset.kind = step.kind;
  inspector.dataset.stepId = step.id;
  inspector.innerHTML = content;
  if (restoreLinkFocus) inspector.querySelector("a")?.focus();
}

export function renderFlowStructure(steps) {
  if (!ensureStructure()) return;
  const list = $("#flow-route-list");
  if (!list) return;
  if (!steps.some(step => step.id === selectedStepId)) selectedStepId = steps[0]?.id || "";
  const focusedElement = document.activeElement;
  const focusedStepId = focusedElement?.dataset?.flowStep
    || focusedElement?.closest?.("li")?.querySelector?.("[data-flow-step]")?.dataset?.flowStep
    || "";
  const focusedControl = focusedElement?.matches?.(".flow-step-mobile-detail a") ? "mobile-link" : "step";
  list.innerHTML = steps.map((step, index) => `
    <li>
      <button type="button" class="flow-route-step" data-flow-step="${escapeHtml(step.id)}"
        data-kind="${escapeHtml(step.kind)}" data-state="${escapeHtml(step.state || "")}" aria-pressed="${step.id === selectedStepId}"
        aria-controls="flow-step-inspector flow-step-detail-${domId(step.id)}">
        <span class="flow-step-number" aria-hidden="true">${escapeHtml(step.marker || index + 1)}</span>
        <span class="flow-step-copy">
          <strong>${escapeHtml(step.title)}</strong>
          <span>${escapeHtml(step.detail)}</span>
        </span>
        ${step.meta ? `<span class="flow-step-meta">${escapeHtml(step.meta)}</span>` : ""}
      </button>
      <div id="flow-step-detail-${domId(step.id)}" class="flow-step-mobile-detail" ${step.id === selectedStepId ? "" : "hidden"}>
        ${step.meta ? `<p class="muted">${escapeHtml(step.meta)}</p>` : ""}
        <a class="btn" href="${escapeHtml(step.href)}">${escapeHtml(tr("flow.open_settings"))}</a>
      </div>
    </li>`).join("");
  const select = stepId => {
    const step = steps.find(item => item.id === stepId) || steps[0];
    if (!step) return;
    selectedStepId = step.id;
    list.querySelectorAll("[data-flow-step]").forEach(button => {
      button.setAttribute("aria-pressed", String(button.dataset.flowStep === selectedStepId));
    });
    list.querySelectorAll(".flow-step-mobile-detail").forEach(detail => {
      detail.hidden = detail.id !== `flow-step-detail-${domId(selectedStepId)}`;
    });
    renderInspector(step);
  };
  list.querySelectorAll("[data-flow-step]").forEach(button => {
    button.addEventListener("click", () => select(button.dataset.flowStep));
  });
  select(selectedStepId);
  if (focusedStepId) {
    const button = Array.from(list.querySelectorAll("[data-flow-step]"))
      .find(candidate => candidate.dataset.flowStep === focusedStepId);
    if (focusedControl === "mobile-link") button?.closest("li")?.querySelector(".flow-step-mobile-detail a")?.focus();
    else button?.focus();
  }
}
