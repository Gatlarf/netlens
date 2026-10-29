import { get } from "./api.js";
import { h } from "./util.js";

// A login that lives in the company's PAM can require a reason (a ticket number or a few words) for every use. The reason goes to the audit log and to the PAM.

let open = null;

function ask(name) {
  if (open) return open;
  open = new Promise((resolve) => {
    const dialog = h("dialog", { class: "stepup-dialog", "aria-label": "Reason for using this login" });
    const input = h("input", { type: "text", maxlength: "300", autocomplete: "off", "aria-label": "Reason", placeholder: "for example: ticket INC-1234, disk check" });
    const ok = h("button", { class: "btn primary", type: "submit" }, "Continue");
    const cancel = h("button", { class: "btn", type: "button" }, "Cancel");
    const finish = (value) => { dialog.close(); dialog.remove(); open = null; resolve(value); };
    const form = h("form", { method: "dialog" }, h("h2", {}, "Why do you need this login?"),
      h("p", {}, `“${name}” is kept in your privileged-access system, which asks for a reason. It is written to the audit log and passed on.`),
      h("div", { class: "field" }, input), h("div", { class: "btn-row" }, ok, cancel));
    form.addEventListener("submit", (e) => { e.preventDefault(); if (input.value.trim().length >= 3) finish(input.value.trim()); else input.focus(); });
    cancel.addEventListener("click", () => finish(null));
    dialog.addEventListener("cancel", (e) => { e.preventDefault(); finish(null); });
    dialog.appendChild(form);
    document.body.appendChild(dialog);
    dialog.showModal();
    setTimeout(() => input.focus(), 0);
  });
  return open;
}

// "" when the login needs no reason, the reason when it does, null when the person cancelled.
export async function reasonFor(credentialId) {
  if (!credentialId) return "";
  let entry = null;
  try { entry = (await get("/api/credentials")).credentials.find((c) => c.id === credentialId); } catch { return ""; }
  if (!entry || !entry.pam || !entry.pam.reason_required) return "";
  return ask(entry.name);
}
