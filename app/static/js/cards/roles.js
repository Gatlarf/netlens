import { get, post, put, del } from "../api.js";
import { h, clear, toast } from "../util.js";

// Settings -> Roles: a custom role is a viewer or an operator plus a few read-only extras (the audit log, reports, backups ...). It never grants writing or any setting.
export async function buildRolesCard() {
  const card = h("div", { class: "card admin-only" });
  let data = await get("/api/roles");
  let editing = null;            // a role id, "" for a new one

  function form() {
    const cur = data.roles.find((r) => r.id === editing) || { name: "", base: "viewer", grants: [] };
    const name = h("input", { type: "text", value: cur.name, maxlength: 40, placeholder: "for example: Auditor" });
    const base = h("select", {}, [["viewer", "Viewer (reads)"], ["operator", "Operator (reads and acts on alerts)"]].map(([v, t]) => h("option", { value: v, selected: v === cur.base }, t)));
    const boxes = data.catalogue.map((c) => {
      const box = h("input", { type: "checkbox", checked: cur.grants.includes(c.id), value: c.id });
      return [box, h("label", { class: "check-row", title: c.text }, box, ` ${c.label}`, h("span", { class: "hint" }, ` — ${c.text}`))];
    });
    const save = h("button", { class: "btn primary", type: "button" }, editing ? "Save" : "Add");
    save.addEventListener("click", async () => {
      const body = { name: name.value, base: base.value, grants: boxes.filter(([b]) => b.checked).map(([b]) => b.value) };
      try {
        data = editing ? await put(`/api/roles/${editing}`, body) : await post("/api/roles", body);
        toast("Saved", "success");
        editing = null;
        draw();
      } catch (err) { toast(err.message || "Could not save", "error"); }
    });
    return h("section", { class: "probe-section" }, h("h3", {}, editing ? `Change “${cur.name}”` : "Add a role"),
      h("div", { class: "field" }, h("label", {}, "Name"), name), h("div", { class: "field" }, h("label", {}, "Based on"), base),
      h("div", { class: "field" }, h("label", {}, "May also read"), ...boxes.map(([, row]) => h("div", {}, row))),
      h("div", { class: "form-actions" }, save, " ", h("button", { class: "btn", type: "button", onclick: () => { editing = null; draw(); } }, "Cancel")));
  }

  function draw() {
    clear(card);
    card.appendChild(h("h2", {}, "Roles"));
    card.appendChild(h("p", { class: "hint" }, "A custom role is a viewer or an operator plus a few extra things to read, for example an auditor who may read the audit log and the reports. It cannot change anything and never reaches logins, users, remote access or settings: those stay with the administrator. Give a role to a user under Users & tokens."));
    if (!data.allowed) card.appendChild(h("p", { class: "hint" }, "Custom roles are part of the Enterprise edition (or the free trial). Without it, users with a custom role are simply their base role."));
    const label = (id) => (data.catalogue.find((c) => c.id === id) || {}).label || id;
    const rows = data.roles.map((r) => h("tr", {}, h("td", {}, r.name), h("td", {}, r.base), h("td", { class: "hint" }, r.grants.length ? r.grants.map(label).join(", ") : "nothing extra"), h("td", {}, `${r.users}`),
      h("td", {}, h("div", { class: "row-actions" }, h("button", { class: "btn", type: "button", onclick: () => { editing = r.id; draw(); } }, "Change"),
        h("button", { class: "btn danger", type: "button", onclick: async () => {
          if (!window.confirm(`Remove the role “${r.name}”? ${r.users ? `${r.users} user(s) keep their base role (${r.base}).` : ""}`)) return;
          try { data = await del(`/api/roles/${r.id}`); draw(); } catch (err) { toast(err.message || "Could not remove", "error"); }
        } }, "Remove")))));
    card.appendChild(rows.length ? h("div", { class: "table-wrap" }, h("table", { class: "data" }, h("thead", {}, h("tr", {}, ["Role", "Based on", "May also read", "Users", ""].map((t) => h("th", {}, t)))), h("tbody", {}, rows))) : h("p", { class: "hint" }, "No custom roles yet."));
    if (editing === null) { if (data.allowed) card.appendChild(h("div", { class: "form-actions" }, h("button", { class: "btn primary", type: "button", onclick: () => { editing = ""; draw(); } }, "Add a role"))); }
    else card.appendChild(form());
  }
  draw();
  return card;
}
