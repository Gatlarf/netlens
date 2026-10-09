import { post } from "../api.js";
import { h, toast, sessionInfo } from "../util.js";

// The signed-in account: who it is, password change (users only) and logout.
export function buildAccountCard() {
  const me = sessionInfo();
  const card = h("div", { class: "card" });
  card.appendChild(h("h2", {}, "Account"));
  if (me) {
    card.appendChild(h("p", {}, `Signed in as `, h("strong", {}, me.username), me.builtin ? " (access token, administrator)" : ` (${me.role === "admin" ? "administrator" : "viewer, read-only"})`));
  }

  if (me && !me.builtin) {
    const form = h("form", { class: "edit-form", id: "password-form" });
    const field = (label, name) => h("div", { class: "field" }, h("label", {}, label), h("input", { type: "password", name, autocomplete: name === "current" ? "current-password" : "new-password", required: true }));
    form.appendChild(field("Current password", "current"));
    form.appendChild(field("New password (at least 8 characters)", "new"));
    form.appendChild(h("button", { type: "submit", class: "btn" }, "Change password"));
    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      try {
        await post("/api/me/password", { current: form.elements.current.value, new: form.elements.new.value });
        form.reset();
        toast("Password changed. Your other logins were ended.", "success");
      } catch (err) {
        toast(err.message || "Could not change the password", "error");
      }
    });
    card.appendChild(form);
  }

  const logoutBtn = h("button", { class: "btn", type: "button" }, "Log out");
  logoutBtn.addEventListener("click", async () => {
    try {
      await post("/api/logout");
      toast("Logged out", "info");
      document.dispatchEvent(new CustomEvent("netlens:unauth"));
    } catch (err) {
      toast(err.message || "Logout failed", "error");
    }
  });
  card.appendChild(logoutBtn);
  return card;
}
