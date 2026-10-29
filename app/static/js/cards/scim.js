import { get, put, post, del } from "../api.js";
import { h, clear, toast, fmtTime } from "../util.js";

// Settings -> Provisioning (SCIM 2.0): the identity provider makes, deactivates and removes accounts by itself.
export async function buildScimCard() {
  const card = h("div", { class: "card admin-only" });
  let st = await get("/api/scim");
  let shown = null;          // a new token, shown once

  function draw() {
    clear(card);
    card.appendChild(h("h2", {}, "Provisioning (SCIM)"));
    card.appendChild(h("p", { class: "hint" }, "Let your identity provider (Entra ID, Okta, Keycloak, Authentik ...) make an account when somebody joins and deactivate it when they leave, so nobody has to remember. People still sign in with single sign-on. The provider can only change accounts it made itself, can never make an administrator, and can never touch the last one."));
    if (!st.allowed) card.appendChild(h("p", { class: "warn-text" }, "Part of the Enterprise edition and the free trial (Settings → Licence). Without it the provider can still deactivate and remove accounts, but not make new ones."));
    card.appendChild(h("table", { class: "kv" }, h("tbody", {}, [["SCIM address (tenant URL)", st.address], ["Token", st.has_token ? `${st.token_name}, made ${fmtTime(st.token_created)}${st.last_used ? `, last used ${fmtTime(st.last_used)}` : ", not used yet"}` : "none yet"], ["Accounts made by the provider", String(st.users)]]
      .map(([k, v]) => h("tr", {}, h("th", {}, k), h("td", { class: "mono", style: "overflow-wrap:anywhere" }, v))))));
    if (shown) card.appendChild(h("div", { class: "card", style: "margin:.6em 0" }, h("p", { class: "warn-text" }, "Copy this token into your identity provider now. It is shown only once."), h("pre", { class: "code-block", style: "overflow-wrap:anywhere;white-space:pre-wrap" }, shown)));
    const enabled = h("input", { type: "checkbox", checked: st.enabled, disabled: !st.has_token });
    const role = h("select", {}, [["viewer", "Viewer (can look, not change)"], ["operator", "Operator"]].map(([v, t]) => h("option", { value: v, selected: v === st.role }, t)));
    const nets = h("textarea", { rows: 2, class: "mono", placeholder: "20.50.0.0/16  (only from these addresses; empty = from anywhere)", "aria-label": "Networks" });
    nets.value = st.networks.join("\n");
    const field = (label, el, hint) => h("div", { class: "field" }, h("label", {}, label), el, hint ? h("p", { class: "hint" }, hint) : null);
    const save = h("button", { class: "btn primary", type: "button" }, "Save");
    save.addEventListener("click", async () => {
      try { st = { ...st, ...(await put("/api/scim", { enabled: enabled.checked, role: role.value, networks: nets.value.split(/[\s,]+/).filter(Boolean) })) }; toast("Saved", "success"); draw(); } catch (err) { toast(err.message || "Could not save", "error"); }
    });
    const make = h("button", { class: "btn", type: "button" }, st.has_token ? "Make a new token" : "Make a token");
    make.addEventListener("click", async () => {
      if (st.has_token && !window.confirm("The old token stops working at once. Continue?")) return;
      try { const r = await post("/api/scim/token", { name: "identity provider" }); shown = r.token; st = { ...st, ...r }; delete st.token; draw(); } catch (err) { toast(err.message || "Failed", "error"); }
    });
    card.append(h("div", { class: "btn-row" }, make, st.has_token ? h("button", { class: "btn danger", type: "button", onclick: async () => { if (!window.confirm("Revoke the token and switch provisioning off?")) return; try { st = { ...st, ...(await del("/api/scim/token")) }; shown = null; draw(); } catch (err) { toast(err.message || "Failed", "error"); } } }, "Revoke the token") : null),
      h("div", { class: "field" }, h("label", { class: "check-row" }, enabled, " Accept provisioning calls")),
      field("Role of new accounts", role, "Never administrator. A person's role at sign-in can follow their groups (Single sign-on → Group → role map)."),
      field("Allowed networks", nets, "Optional: where the provider's calls come from."), h("div", { class: "form-actions" }, save));
  }
  draw();
  return card;
}
