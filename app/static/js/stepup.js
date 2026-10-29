import { h } from "./util.js";
import * as webauthn from "./webauthn.js";

// Step-up: a privileged action asks the person to prove who they are again (Settings → Sign-in security, Enterprise).
// The server answers 401 "step_up_required:<how>"; this asks once, confirms, and the caller repeats what it was doing.

export function isStepUp(detail) {
  return typeof detail === "string" && detail.startsWith("step_up_required");
}

let open = null;

async function confirm(body) {
  const res = await fetch("api/me/stepup", { method: "POST", credentials: "same-origin", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
  if (res.ok) return null;
  let detail = res.statusText;
  try { const j = await res.json(); if (typeof j.detail === "string") detail = j.detail; } catch { /* keep the status text */ }
  return detail;
}

// Ask how the user confirms (a code, the password, or the identity provider). Resolves true when confirmed, false when cancelled.
export function prompt(method = "password") {
  if (open) return open;
  open = new Promise((resolve) => {
    const dialog = h("dialog", { class: "stepup-dialog", "aria-label": "Confirm it is you" });
    const error = h("p", { class: "error", hidden: "hidden" });
    const form = h("form", { method: "dialog" }, h("h2", {}, "Confirm it is you"));
    const finish = (value) => { dialog.close(); dialog.remove(); open = null; resolve(value); };
    const cancel = h("button", { class: "btn", type: "button" }, "Cancel");
    cancel.addEventListener("click", () => finish(false));
    dialog.addEventListener("cancel", (e) => { e.preventDefault(); finish(false); });
    const codeForm = () => {
      form.replaceChildren(h("h2", {}, "Confirm it is you"));
      const input = h("input", { type: "text", autocomplete: "one-time-code", inputmode: "numeric", maxlength: "24", "aria-label": "Code", spellcheck: "false" });
      form.append(h("p", {}, "Enter a code from your authenticator app (or a recovery code)."), h("div", { class: "field" }, input), error);
      const ok = h("button", { class: "btn primary", type: "submit" }, "Confirm");
      form.onsubmit = async (e) => {
        e.preventDefault();
        ok.disabled = true;
        const problem = await confirm({ code: input.value.trim() });
        if (problem === null) return finish(true);
        error.textContent = problem; error.hidden = false; ok.disabled = false; input.select();
      };
      form.append(h("div", { class: "btn-row" }, ok, cancel));
      setTimeout(() => input.focus(), 0);
    };
    if (method === "webauthn") {
      form.append(h("p", {}, "This action needs a fresh confirmation. Use your security key or passkey."), error);
      const go = h("button", { class: "btn primary", type: "submit" }, "Use my security key");
      const alt = h("button", { class: "btn", type: "button", hidden: "hidden" }, "Use a code instead");
      alt.addEventListener("click", codeForm);
      form.onsubmit = async (e) => {
        e.preventDefault();
        go.disabled = true; error.hidden = true;
        try {
          const res = await fetch("api/me/stepup", { credentials: "same-origin" });
          const state = res.ok ? await res.json() : {};
          if (state.method !== "webauthn" || !state.webauthn) { if (state.method === "totp") return codeForm(); throw new Error("A security key cannot be used on this page (it needs https)."); }
          const credential = await webauthn.get(state.webauthn);
          const problem = await confirm({ credential });
          if (problem === null) return finish(true);
          throw new Error(problem);
        } catch (err) { error.textContent = err.message || "The security key could not be used."; error.hidden = false; go.disabled = false; }
      };
      fetch("api/me/stepup", { credentials: "same-origin" }).then((r) => r.json()).then((st) => { if ((st.alternatives || []).includes("totp")) alt.hidden = false; }).catch(() => {});
      form.append(h("div", { class: "btn-row" }, go, alt, cancel));
    } else if (method === "oidc") {
      form.append(h("p", {}, "This action needs a fresh sign-in. You will be taken to your identity provider and brought back."));
      const go = h("button", { class: "btn primary", type: "submit" }, "Confirm with your identity provider");
      form.addEventListener("submit", (e) => { e.preventDefault(); location.href = `api/auth/oidc/stepup?back=${encodeURIComponent(location.hash)}`; });
      form.append(h("div", { class: "btn-row" }, go, cancel));
    } else {
      const totp = method === "totp";
      const input = h("input", { type: totp ? "text" : "password", autocomplete: totp ? "one-time-code" : "current-password", inputmode: totp ? "numeric" : "text", maxlength: totp ? "24" : "200", "aria-label": totp ? "Code" : "Password", spellcheck: "false" });
      form.append(h("p", {}, totp ? "This action needs a fresh confirmation. Enter a code from your authenticator app (or a recovery code)." : "This action needs a fresh confirmation. Enter your password."),
        h("div", { class: "field" }, input), error);
      const ok = h("button", { class: "btn primary", type: "submit" }, "Confirm");
      form.addEventListener("submit", async (e) => {
        e.preventDefault();
        ok.disabled = true;
        const problem = await confirm(totp ? { code: input.value.trim() } : { password: input.value });
        if (problem === null) return finish(true);
        error.textContent = problem;
        error.hidden = false;
        ok.disabled = false;
        input.select();
      });
      form.append(h("div", { class: "btn-row" }, ok, cancel));
      setTimeout(() => input.focus(), 0);
    }
    dialog.appendChild(form);
    document.body.appendChild(dialog);
    dialog.showModal();
  });
  return open;
}

// Before something that cannot simply be repeated after a refusal (a terminal opens a WebSocket): is a confirmation needed now? Returns true to go on.
export async function ensureFresh() {
  let state;
  try {
    const res = await fetch("api/me/stepup", { credentials: "same-origin" });
    if (!res.ok) return true;
    state = await res.json();
  } catch { return true; }
  if (!state.enabled || state.fresh) return true;
  if (state.available === false) return false;
  return prompt(state.method);
}
