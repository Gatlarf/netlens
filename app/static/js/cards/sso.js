import { get, put, post } from "../api.js";
import { h, clear, toast } from "../util.js";

// Settings page: single sign-on with an OpenID Connect identity provider.
export async function buildSsoCard() {
  const card = h("div", { class: "card" });
  function draw(info) {
    clear(card);
    card.appendChild(h("h2", {}, "Single sign-on"));
    card.appendChild(h("p", { class: "hint" },
      "Let people sign in with your company account (Microsoft Entra ID, Keycloak, Authentik, Google, Okta ...). Netlens becomes an application of your identity provider: create one there (type: web, authorization code), enter the redirect address below, and copy the client id and secret here. People are recognised by the provider's own id, never by their name, so nobody can take over a local account. The first sign-in makes the Netlens user; the role follows the provider's groups at every sign-in. Part of every licence and the free trial."));
    if (!info.allowed) card.appendChild(h("p", { class: "warn-text" }, "Needs a licence or the free trial (Settings → Licence)."));
    const field = (label, input, hint) => h("div", { class: "field" }, h("label", {}, label), input, hint ? h("p", { class: "hint" }, hint) : null);
    const enabled = h("input", { type: "checkbox" });
    enabled.checked = info.enabled;
    const issuer = h("input", { type: "url", value: info.issuer, placeholder: "https://login.example.com/realms/home" });
    const clientId = h("input", { type: "text", value: info.client_id });
    const secret = h("input", { type: "password", autocomplete: "off", placeholder: info.has_secret ? "(kept, type to change)" : "client secret" });
    const scopes = h("input", { type: "text", value: info.scopes });
    const groupsClaim = h("input", { type: "text", value: info.groups_claim });
    const adminGroups = h("input", { type: "text", value: info.admin_groups, placeholder: "netlens-admins, it" });
    const role = h("select", {}, h("option", { value: "viewer", selected: info.default_role === "viewer" }, "Viewer (can look, not change)"), h("option", { value: "admin", selected: info.default_role === "admin" }, "Administrator"));
    const label = h("input", { type: "text", value: info.label });
    const base = h("input", { type: "url", value: info.redirect_base, placeholder: "https://netlens.example.com (only behind a reverse proxy that changes the address)" });
    const save = h("button", { class: "btn primary", type: "button" }, "Save");
    save.addEventListener("click", async () => {
      save.disabled = true;
      try {
        draw(await put("/api/sso", { enabled: enabled.checked, issuer: issuer.value, client_id: clientId.value, scopes: scopes.value, groups_claim: groupsClaim.value, admin_groups: adminGroups.value,
          default_role: role.value, label: label.value, redirect_base: base.value, ...(secret.value ? { client_secret: secret.value } : {}) }));
        toast("Saved", "success");
      } catch (err) { toast(err.message || "Could not save", "error"); save.disabled = false; }
    });
    const test = h("button", { class: "btn", type: "button" }, "Test the provider");
    test.addEventListener("click", async () => {
      test.disabled = true;
      try { await put("/api/sso", { issuer: issuer.value }); await post("/api/sso/test", {}); toast("The provider answers", "success"); } catch (err) { toast(err.message || "Failed", "error"); }
      test.disabled = false;
    });
    card.append(h("label", { class: "check" }, enabled, " Show “sign in with …” on the sign-in page"),
      field("Redirect address (enter this at your provider)", h("input", { type: "text", readonly: true, value: info.redirect_uri, class: "mono" })),
      field("Provider address (issuer)", issuer, "The address that has /.well-known/openid-configuration below it."), field("Client id", clientId), field("Client secret", secret),
      field("Scopes", scopes), field("Groups claim", groupsClaim, "The name of the claim that lists a person's groups."), field("Administrator groups", adminGroups, "Comma separated. Everybody else gets the default role."),
      field("Default role", role), field("Button text", label), field("Address of Netlens", base), h("div", { class: "form-actions" }, save, test));
  }
  draw(await get("/api/sso"));
  return card;
}
