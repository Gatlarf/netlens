import { get, post, put, del } from "../api.js";
import { h, clear, toast, timeAgo } from "../util.js";

const KINDS = [["login", "User name and password"], ["ssh_key", "SSH key"]];

// Settings → Credentials: every login Netlens uses for a host, stored once. A secret can be set or replaced, never read back.
export async function buildCredentialsCard() {
  const card = h("div", { class: "card admin-only" });
  let data = await get("/api/credentials");
  let editing = null;            // the id being edited, "" for a new one

  function form() {
    const cur = data.credentials.find((c) => c.id === editing) || { name: "", kind: "login", username: "", domain: "", shared: false };
    const name = h("input", { type: "text", value: cur.name, maxlength: 80, placeholder: "for example: Windows PCs (admin)" });
    const kind = h("select", { disabled: Boolean(editing) }, KINDS.map(([v, t]) => h("option", { value: v, selected: v === cur.kind }, t)));
    const user = h("input", { type: "text", value: cur.username, autocomplete: "off" });
    const domain = h("input", { type: "text", value: cur.domain, autocomplete: "off", placeholder: "optional" });
    const pass = h("input", { type: "password", autocomplete: "new-password", placeholder: editing ? "(set; type to replace)" : "" });
    const key = h("textarea", { rows: 4, class: "mono", placeholder: editing ? "(set; paste to replace)" : "-----BEGIN OPENSSH PRIVATE KEY-----" });
    const phrase = h("input", { type: "password", autocomplete: "new-password", placeholder: "only if the key has one" });
    const shared = h("input", { type: "checkbox", checked: cur.shared });
    const secretRows = h("div", {});
    const fill = () => {
      clear(secretRows);
      if (kind.value === "login") secretRows.append(h("div", { class: "field" }, h("label", {}, "Password"), pass), h("div", { class: "field" }, h("label", {}, "Domain"), domain));
      else secretRows.append(h("div", { class: "field" }, h("label", {}, "Private key"), key), h("div", { class: "field" }, h("label", {}, "Passphrase"), phrase));
    };
    kind.addEventListener("change", fill);
    fill();
    const save = h("button", { class: "btn primary", type: "button" }, editing ? "Save" : "Add");
    save.addEventListener("click", async () => {
      const body = { name: name.value, kind: kind.value, username: user.value, shared: shared.checked };
      if (kind.value === "login") Object.assign(body, { password: pass.value, domain: domain.value });
      else Object.assign(body, { private_key: key.value, passphrase: phrase.value });
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

  function draw() {
    clear(card);
    card.appendChild(h("h2", {}, "Credentials"));
    card.appendChild(h("p", { class: "hint" }, "The logins Netlens uses to reach your hosts: remote desktop, SSH, health monitoring and host probes. Each is stored once, encrypted, and picked by name wherever it is needed. " +
      "A password or key can be replaced but is never shown again. Every use is in the audit log."));
    const rows = data.credentials.map((c) => h("tr", {},
      h("td", {}, c.name), h("td", {}, c.kind === "ssh_key" ? "SSH key" : "Password"), h("td", {}, c.username || "–"),
      h("td", {}, c.shared ? (c.mine ? "shared by you" : `shared by ${c.owner}`) : "only you"),
      h("td", { class: "hint" }, c.last_used ? `${c.used_for || "used"} · ${timeAgo(c.last_used)}` : "not used yet"),
      h("td", {}, h("button", { class: "btn", type: "button", onclick: () => { editing = c.id; draw(); } }, "Change"), " ",
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
