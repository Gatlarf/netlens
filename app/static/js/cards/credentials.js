import { get, post, put, del } from "../api.js";
import { h, clear, toast, timeAgo } from "../util.js";
import { reasonFor } from "../reason.js";

const KINDS = [["login", "User name and password"], ["ssh_key", "SSH key"], ["pam", "In your PAM system (Enterprise)"]];

// Settings → Credentials: every login Netlens uses for a host, stored once. A secret can be set or replaced, never read back.
export async function buildCredentialsCard() {
  const card = h("div", { class: "card admin-only" });
  let data = await get("/api/credentials");
  let editing = null;            // the id being edited, "" for a new one

  function form() {
    const cur = data.credentials.find((c) => c.id === editing) || { name: "", kind: "login", username: "", domain: "", shared: false };
    const pm = cur.pam || { provider: Object.keys(data.pam.providers)[0] || "", url: "", where: "", namespace: "", kv_version: "2", auth: "approle", approle_mount: "", role_id: "", has_ca: false,
      username_field: "", password_field: "", key_field: "", passphrase_field: "", domain_field: "", reason_required: false };
    const mount = (pm.where || "").split("/")[0] || "secret";
    const path = (pm.where || "").split("/").slice(1).join("/");
    const name = h("input", { type: "text", value: cur.name, maxlength: 80, placeholder: "for example: Windows PCs (admin)" });
    const kind = h("select", { disabled: Boolean(editing) }, KINDS.filter(([v]) => v !== "pam" || data.pam.allowed || cur.kind === "pam").map(([v, t]) => h("option", { value: v, selected: v === cur.kind }, t)));
    const user = h("input", { type: "text", value: cur.username, autocomplete: "off" });
    const domain = h("input", { type: "text", value: cur.domain, autocomplete: "off", placeholder: "optional" });
    const pass = h("input", { type: "password", autocomplete: "new-password", placeholder: editing ? "(set; type to replace)" : "" });
    const key = h("textarea", { rows: 4, class: "mono", placeholder: editing ? "(set; paste to replace)" : "-----BEGIN OPENSSH PRIVATE KEY-----" });
    const phrase = h("input", { type: "password", autocomplete: "new-password", placeholder: "only if the key has one" });
    const shared = h("input", { type: "checkbox", checked: cur.shared });
    const secretRows = h("div", {});
    const text = (value, extra = {}) => h("input", { type: "text", value: value || "", autocomplete: "off", spellcheck: "false", ...extra });
    const secret = (hint) => h("input", { type: "password", autocomplete: "new-password", placeholder: editing ? "(set; type to replace)" : hint || "" });
    const pamF = {
      provider: h("select", {}, Object.entries(data.pam.providers).map(([v, t]) => h("option", { value: v, selected: v === pm.provider }, t))),
      url: text(pm.url, { placeholder: "https://vault.example.com:8200" }), namespace: text(pm.namespace, { placeholder: "optional (Vault Enterprise / OpenBao namespaces)" }),
      mount: text(mount), path: text(path, { placeholder: "netlens/linux-admin" }),
      kv: h("select", {}, [["2", "KV version 2"], ["1", "KV version 1"]].map(([v, t]) => h("option", { value: v, selected: v === String(pm.kv_version) }, t))),
      auth: h("select", {}, [["approle", "AppRole (recommended)"], ["token", "A token"]].map(([v, t]) => h("option", { value: v, selected: v === pm.auth }, t))),
      approle_mount: text(pm.approle_mount, { placeholder: "approle" }), role: text(pm.role_id), secret_id: secret(), token: secret(),
      ca: h("textarea", { rows: 3, class: "mono", placeholder: pm.has_ca ? "(set; paste to replace)" : "-----BEGIN CERTIFICATE----- (only if your PAM uses a private CA)" }),
      f_user: text(pm.username_field, { placeholder: "username" }), f_pass: text(pm.password_field, { placeholder: "password" }), f_key: text(pm.key_field, { placeholder: "private_key" }),
      f_phrase: text(pm.passphrase_field, { placeholder: "passphrase" }), f_domain: text(pm.domain_field, { placeholder: "domain" }),
      reason: h("input", { type: "checkbox", checked: pm.reason_required }),
    };
    const pamRows = h("div", {});
    const drawPam = () => {
      clear(pamRows);
      const f = (label, el, hint) => h("div", { class: "field" }, h("label", {}, label), el, hint ? h("p", { class: "hint" }, hint) : null);
      pamRows.append(f("PAM system", pamF.provider, "Netlens asks it for the password each time it is needed and keeps no copy. If it cannot be reached, the login is not used."),
        f("Address", pamF.url), f("Namespace", pamF.namespace), f("Secrets engine", pamF.mount), f("Secret path", pamF.path), f("Version", pamF.kv),
        f("Netlens signs in with", pamF.auth, "Give Netlens its own identity with a policy that may only read the secrets that hold monitoring and access accounts."));
      if (pamF.auth.value === "approle") pamRows.append(f("AppRole mount", pamF.approle_mount), f("Role id", pamF.role), f("Secret id", pamF.secret_id));
      else pamRows.append(f("Token", pamF.token));
      pamRows.append(f("CA certificate", pamF.ca), h("details", { class: "collapsible" }, h("summary", {}, "Field names in the secret (only if they differ)"),
        f("User name", pamF.f_user), f("Password", pamF.f_pass), f("Private key", pamF.f_key), f("Passphrase", pamF.f_phrase), f("Domain", pamF.f_domain)),
        h("div", { class: "field" }, h("label", { class: "check-row" }, pamF.reason, " Ask for a reason every time"),
          h("p", { class: "hint" }, "A person gives a ticket number or a few words; it goes to the audit log. Monitors and other background jobs cannot use such a login.")));
    };
    pamF.auth.addEventListener("change", drawPam);
    const fill = () => {
      clear(secretRows);
      if (kind.value === "pam") { drawPam(); secretRows.append(pamRows); return; }
      if (kind.value === "login") secretRows.append(h("div", { class: "field" }, h("label", {}, "Password"), pass), h("div", { class: "field" }, h("label", {}, "Domain"), domain));
      else secretRows.append(h("div", { class: "field" }, h("label", {}, "Private key"), key), h("div", { class: "field" }, h("label", {}, "Passphrase"), phrase));
    };
    kind.addEventListener("change", fill);
    fill();
    const save = h("button", { class: "btn primary", type: "button" }, editing ? "Save" : "Add");
    save.addEventListener("click", async () => {
      const body = { name: name.value, kind: kind.value, username: user.value, shared: shared.checked };
      if (kind.value === "login") Object.assign(body, { password: pass.value, domain: domain.value });
      else if (kind.value === "pam") {
        Object.assign(body, { provider: pamF.provider.value, url: pamF.url.value.trim(), namespace: pamF.namespace.value.trim(), mount: pamF.mount.value.trim(), path: pamF.path.value.trim(), kv_version: pamF.kv.value,
          approle_mount: pamF.approle_mount.value.trim(), role_id: pamF.auth.value === "approle" ? pamF.role.value.trim() : "", secret_id: pamF.auth.value === "approle" ? pamF.secret_id.value : "",
          token: pamF.auth.value === "token" ? pamF.token.value : "", username_field: pamF.f_user.value.trim(), password_field: pamF.f_pass.value.trim(), key_field: pamF.f_key.value.trim(),
          passphrase_field: pamF.f_phrase.value.trim(), domain_field: pamF.f_domain.value.trim(), reason_required: pamF.reason.checked });
        if (pamF.ca.value.trim()) body.ca_cert = pamF.ca.value.trim();
      } else Object.assign(body, { private_key: key.value, passphrase: phrase.value });
      try {
        if (editing) await put(`/api/credentials/${editing}`, body); else await post("/api/credentials", body);
        toast("Saved", "success");
        editing = null;
        data = await get("/api/credentials");
        draw();
      } catch (err) { toast(err.message || "Could not save", "error"); }
    });
    const cancel = h("button", { class: "btn", type: "button", onclick: () => { editing = null; draw(); } }, "Cancel");
    return h("section", { class: "probe-section" }, h("h3", {}, editing ? `Change “${cur.name}”` : "Add a login"),
      h("div", { class: "field" }, h("label", {}, "Name"), name), h("div", { class: "field" }, h("label", {}, "Kind"), kind),
      h("div", { class: "field" }, h("label", {}, "User name"), user), secretRows,
      h("div", { class: "field" }, h("label", { class: "check-row" }, shared, " Let other administrators use it"),
        h("p", { class: "hint" }, "Off: only you can use it. On: other administrators can pick it (for remote access and for setting up monitoring), but nobody can read it.")),
      h("div", { class: "form-actions" }, save, " ", cancel));
  }

  async function tryPam(c) {
    const reason = await reasonFor(c.id);
    if (reason === null) return;
    try {
      const res = await post(`/api/credentials/${c.id}/test`, { reason });
      toast(res.ok ? `${res.message}: ${res.fields.join(", ")}` : res.message, res.ok ? "success" : "error");
    } catch (err) { toast(err.message || "Could not try it", "error"); }
    data = await get("/api/credentials");
    draw();
  }

  function draw() {
    clear(card);
    card.appendChild(h("h2", {}, "Credentials"));
    card.appendChild(h("p", { class: "hint" }, "The logins Netlens uses to reach your hosts: remote desktop, SSH, health monitoring and host probes. Each is stored once, encrypted, and picked by name wherever it is needed. " +
      "A password or key can be replaced but is never shown again. Every use is in the audit log."));
    const rows = data.credentials.map((c) => h("tr", {},
      h("td", {}, c.name), h("td", {}, c.kind === "pam" ? h("span", {}, `PAM · ${c.pam.provider_name}`, h("br"), h("span", { class: "hint mono" }, c.pam.where)) : c.kind === "ssh_key" ? "SSH key" : "Password"), h("td", {}, c.username || "–"),
      h("td", {}, c.shared ? (c.mine ? "shared by you" : `shared by ${c.owner}`) : "only you"),
      h("td", { class: "hint" }, c.last_used ? `${c.used_for || "used"} · ${timeAgo(c.last_used)}` : "not used yet", c.pam && c.pam.last ? h("div", { class: c.pam.last.ok ? "hint" : "error" }, c.pam.last.ok ? "PAM: last check-out worked" : `PAM: ${c.pam.last.message}`) : null),
      h("td", {}, c.kind === "pam" ? h("span", {}, h("button", { class: "btn", type: "button", onclick: () => tryPam(c) }, "Try it"), " ") : null,
        h("button", { class: "btn", type: "button", onclick: () => { editing = c.id; draw(); } }, "Change"), " ",
        h("button", { class: "btn danger", type: "button", onclick: async () => {
          if (!window.confirm(`Delete “${c.name}”? Whatever uses it asks for a login again.`)) return;
          try { await del(`/api/credentials/${c.id}`); data = await get("/api/credentials"); draw(); } catch (err) { toast(err.message || "Could not delete", "error"); }
        } }, "Delete"))));
    card.appendChild(rows.length
      ? h("div", { class: "table-wrap" }, h("table", { class: "data" }, h("thead", {}, h("tr", {}, ["Name", "Kind", "User", "Who can use it", "Last used", ""].map((t) => h("th", {}, t)))), h("tbody", {}, rows)))
      : h("p", { class: "hint" }, "No logins stored yet."));
    if (editing === null) card.appendChild(h("div", { class: "form-actions" }, h("button", { class: "btn primary", type: "button", onclick: () => { editing = ""; draw(); } }, "Add a login")));
    else card.appendChild(form());
  }
  draw();
  return card;
}
