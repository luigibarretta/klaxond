import { tr } from "./app-core.js";

let activeDialog = null;

function button(label, className = "btn") {
  const element = document.createElement("button");
  element.type = "button";
  element.className = className;
  element.textContent = label;
  return element;
}

function fieldControl(field) {
  const label = document.createElement("label");
  label.className = "app-dialog-field";
  const text = document.createElement("span");
  text.textContent = field.label || field.name;
  const input = field.multiline ? document.createElement("textarea") : document.createElement("input");
  input.name = field.name;
  input.type = field.type || "text";
  input.value = field.value || "";
  input.autocomplete = field.autocomplete || "off";
  input.required = !!field.required;
  if (field.minLength) input.minLength = field.minLength;
  if (field.maxLength) input.maxLength = field.maxLength;
  if (field.placeholder) input.placeholder = field.placeholder;
  if (field.inputMode) input.inputMode = field.inputMode;
  label.append(text, input);
  if (field.help) {
    const help = document.createElement("small");
    help.className = "muted";
    help.textContent = field.help;
    label.append(help);
  }
  return { label, input };
}

function focusableWithin(dialog) {
  return Array.from(dialog.querySelectorAll(
    'button:not(:disabled), input:not(:disabled), textarea:not(:disabled), select:not(:disabled), [href], [tabindex]:not([tabindex="-1"])'
  )).filter(element => !element.hidden);
}

export function requestDialog(options = {}) {
  activeDialog?.cancel();
  return new Promise(resolve => {
    const overlay = document.createElement("div");
    overlay.className = "app-dialog-overlay";
    const dialog = document.createElement("section");
    dialog.className = `app-dialog app-dialog-${options.kind || "default"}`;
    dialog.setAttribute("role", "dialog");
    dialog.setAttribute("aria-modal", "true");
    const titleId = `app-dialog-title-${Date.now()}`;
    dialog.setAttribute("aria-labelledby", titleId);

    const title = document.createElement("h2");
    title.id = titleId;
    title.textContent = options.title || tr("dialog.title");
    dialog.append(title);
    if (options.message) {
      const message = document.createElement("p");
      message.className = "app-dialog-message";
      message.textContent = options.message;
      dialog.append(message);
    }

    const inputs = new Map();
    for (const field of options.fields || []) {
      const control = fieldControl(field);
      inputs.set(field.name, control.input);
      dialog.append(control.label);
    }

    if (options.secret !== undefined) {
      const secretBox = document.createElement("div");
      secretBox.className = "app-dialog-secret";
      const secret = document.createElement("textarea");
      secret.readOnly = true;
      secret.rows = 3;
      secret.value = String(options.secret);
      secret.setAttribute("aria-label", options.secretLabel || tr("dialog.secret_value"));
      const copy = button(options.copyLabel || tr("dialog.copy"));
      copy.addEventListener("click", async () => {
        try {
          await navigator.clipboard.writeText(secret.value);
        } catch (error) {
          secret.select();
          document.execCommand("copy");
        }
        copy.textContent = tr("dialog.copied");
      });
      secretBox.append(secret, copy);
      dialog.append(secretBox);
    }

    const error = document.createElement("p");
    error.className = "app-dialog-error hidden";
    error.setAttribute("role", "alert");
    dialog.append(error);

    const actions = document.createElement("div");
    actions.className = "app-dialog-actions";
    const cancel = options.hideCancel ? null : button(options.cancelLabel || tr("dialog.cancel"));
    const confirm = button(
      options.confirmLabel || tr("dialog.confirm"),
      options.danger ? "btn danger" : "btn primary"
    );
    if (cancel) actions.append(cancel);
    actions.append(confirm);
    dialog.append(actions);
    overlay.append(dialog);
    document.body.append(overlay);

    const previousFocus = document.activeElement;
    let settled = false;
    const finish = result => {
      if (settled) return;
      settled = true;
      overlay.remove();
      activeDialog = null;
      if (previousFocus?.isConnected) previousFocus.focus();
      resolve(result);
    };
    const cancelDialog = () => finish(null);
    activeDialog = { cancel: cancelDialog };
    cancel?.addEventListener("click", cancelDialog);
    overlay.addEventListener("mousedown", event => {
      if (event.target === overlay && options.dismissOnBackdrop !== false) cancelDialog();
    });
    dialog.addEventListener("keydown", event => {
      if (event.key === "Escape" && options.dismissOnEscape !== false) {
        event.preventDefault();
        cancelDialog();
      }
      if (event.key === "Enter" && event.target instanceof HTMLInputElement) {
        event.preventDefault();
        confirm.click();
        return;
      }
      if (event.key !== "Tab") return;
      const focusable = focusableWithin(dialog);
      if (!focusable.length) return;
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    });
    confirm.addEventListener("click", () => {
      const values = {};
      for (const [name, input] of inputs) {
        if (!input.checkValidity()) {
          input.reportValidity();
          input.focus();
          return;
        }
        values[name] = input.value;
      }
      const validation = options.validate?.(values);
      if (validation) {
        error.textContent = validation;
        error.classList.remove("hidden");
        return;
      }
      finish(values);
    });
    (inputs.values().next().value || confirm).focus();
  });
}

export async function confirmDialog(message, options = {}) {
  const result = await requestDialog({ ...options, message });
  return result !== null;
}

export async function promptDialog(message, options = {}) {
  const result = await requestDialog({
    ...options,
    message,
    fields: [{
      name: "value",
      label: options.label || tr("dialog.value"),
      type: options.type || "text",
      value: options.value || "",
      required: options.required !== false,
      minLength: options.minLength,
      autocomplete: options.autocomplete,
    }],
  });
  return result?.value ?? null;
}

export function showSecretDialog(secret, options = {}) {
  return requestDialog({ ...options, secret, hideCancel: true });
}
