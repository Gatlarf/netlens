import { h } from "./util.js";

// A small modal form instead of window.prompt: password fields are masked, every field has a label, Escape cancels.
//   const v = await formDialog({ title: "New password", text: "…", fields: [{ key: "password", label: "New password", type: "password", min: 12 }], ok: "Change" });
//   v is { password: "…" }, or null when the person cancelled.
// field: { key, label, type: "text"|"password"|"number"|"checkbox"|"textarea"|"select" (options: [[value, text], …]), readonly, value, placeholder, hint, required, min (length for text/password) }
export function formDialog({ title, text = "", fields, ok = "Continue" }) {
  return new Promise((resolve) => {
    const dialog = h("dialog", { class: "stepup-dialog", "aria-label": title });
    const inputs = {};
    const rows = fields.map((f, i) => {
      const id = `fd-${Date.now()}-${i}`;
      const isBox = f.type === "checkbox";
      const input = f.type === "select" ? h("select", { id }, (f.options || []).map(([v, t]) => h("option", { value: String(v), selected: String(v) === String(f.value) }, t)))
        : f.type === "textarea" ? h("textarea", { id, rows: "3", class: "w-full", placeholder: f.placeholder || "" })
        : h("input", { id, type: f.type || "text", autocomplete: f.type === "password" ? "new-password" : "off", placeholder: f.placeholder || "" });
      if (f.readonly) input.readOnly = true;
      if (isBox) input.checked = !!f.value; else input.value = f.value == null ? "" : String(f.value);
      inputs[f.key] = input;
      const label = h("label", { for: id }, f.label);
      return h("div", { class: isBox ? "field field-check" : "field" }, isBox ? [input, " ", label] : [label, input], f.hint ? h("div", { class: "hint" }, f.hint) : null);
    });
    const error = h("p", { class: "error", role: "alert", hidden: true });
    const submit = h("button", { class: "btn primary", type: "submit" }, ok);
    const cancel = h("button", { class: "btn", type: "button" }, "Cancel");
    const finish = (value) => { dialog.close(); dialog.remove(); resolve(value); };
    const form = h("form", { method: "dialog" }, h("h2", {}, title), text ? h("p", {}, text) : null, ...rows, error, h("div", { class: "btn-row" }, submit, cancel));
    form.addEventListener("submit", (e) => {
      e.preventDefault();
      const out = {};
      for (const f of fields) {
        const input = inputs[f.key];
        const value = f.type === "checkbox" ? input.checked : input.value;
        if (f.type !== "checkbox" && f.required !== false && f.required && !String(value).trim()) { error.textContent = `${f.label}: fill this in.`; error.hidden = false; input.focus(); return; }
        if (f.min && String(value).length < f.min) { error.textContent = `${f.label}: at least ${f.min} characters.`; error.hidden = false; input.focus(); return; }
        out[f.key] = value;
      }
      finish(out);
    });
    cancel.addEventListener("click", () => finish(null));
    dialog.addEventListener("cancel", (e) => { e.preventDefault(); finish(null); });
    dialog.appendChild(form);
    document.body.appendChild(dialog);
    dialog.showModal();
    const first = fields.length ? inputs[fields[0].key] : submit;
    setTimeout(() => { first.focus(); if (first.readOnly) first.select(); }, 0);
  });
}
