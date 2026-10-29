import { get, post } from "./api.js";
import { h } from "./util.js";

// Four-eyes approval (Settings -> Sign-in security): some actions need another administrator to say yes first. This asks for it (with a reason), waits, and resolves true when
// it was approved so the caller can repeat what it was doing, false when it was denied, cancelled or timed out.

const NAMES = { terminal: "open a terminal", remote: "open a remote desktop", restore: "restore a backup" };

export function isApprovalRequired(detail) {
  return typeof detail === "string" && detail.startsWith("approval_required");
}

// detail is "approval_required:<action>:<target>"
export function parse(detail) {
  const [, action, ...rest] = String(detail).split(":");
  return { action, target: rest.join(":") };
}

export function ask(action, target, label = "") {
  return new Promise((resolve) => {
    const dialog = h("dialog", { class: "stepup-dialog", "aria-label": "Approval needed" });
    const input = h("input", { type: "text", maxlength: "300", autocomplete: "off", "aria-label": "Reason", placeholder: "for example: ticket INC-1234, restart nginx" });
    const status = h("p", { class: "hint", role: "status" });
    const error = h("p", { class: "error", hidden: "hidden" });
    const go = h("button", { class: "btn primary", type: "submit" }, "Ask for approval");
    const cancel = h("button", { class: "btn", type: "button" }, "Cancel");
    const form = h("form", { method: "dialog" }, h("h2", {}, "Another administrator has to approve this"),
      h("p", {}, `To ${NAMES[action] || action}${label ? ` (${label})` : ""} a second administrator must say yes first. Say why you need it; they see your reason.`),
      h("div", { class: "field" }, input), status, error, h("div", { class: "btn-row" }, go, cancel));
    let timer = null, id = null, done = false;
    const finish = async (value) => {
      if (done) return;
      done = true;
      clearInterval(timer);
      if (!value && id) { try { await post(`/api/approvals/${id}/cancel`, {}); } catch { /* it may be decided already */ } }
      dialog.close(); dialog.remove(); resolve(value);
    };
    cancel.addEventListener("click", () => finish(false));
    dialog.addEventListener("cancel", (e) => { e.preventDefault(); finish(false); });
    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      if (id) return;
      go.disabled = true; error.hidden = true;
      try {
        const made = await post("/api/approvals", { action, target, reason: input.value });
        id = made.id;
        status.textContent = "Asked. Waiting for another administrator to approve… (this window checks every few seconds)";
        input.disabled = true;
        timer = setInterval(async () => {
          try {
            const now = await get(`/api/approvals/${id}`);
            if (now.status === "approved") { status.textContent = "Approved."; finish(true); }
            else if (now.status === "denied") { error.textContent = `Denied by ${now.decided_by}${now.comment ? `: ${now.comment}` : ""}`; error.hidden = false; status.textContent = ""; clearInterval(timer); setTimeout(() => finish(false), 2500); }
            else if (now.status !== "pending") finish(false);
          } catch { /* keep trying */ }
        }, 3000);
      } catch (err) { error.textContent = err.message || "Could not ask"; error.hidden = false; go.disabled = false; }
    });
    dialog.appendChild(form);
    document.body.appendChild(dialog);
    dialog.showModal();
    setTimeout(() => input.focus(), 0);
  });
}
