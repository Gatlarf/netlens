import { api, get } from "../api.js";
import { h, clear, toast } from "../util.js";

const PALETTE = ["#2563eb", "#16a34a", "#d97706", "#9333ea", "#dc2626", "#0891b2", "#be185d", "#65a30d", "#7c3aed", "#ea580c"];

function fill(card, groups) {
  clear(card);
  card.appendChild(h("h2", {}, "Groups"));
  card.appendChild(h("p", { class: "hint" },
    "Put devices in groups such as rooms, floors or owners. A device is in one group. The map can colour devices by group and show one group at a time, " +
    "the Devices page can filter and set groups for many devices at once, and Home Assistant uses the group as the area of a device. " +
    "Set a device's group on its page, or from the Devices page."));

  if (groups.length) {
    const table = h("table", { class: "table groups" });
    table.appendChild(h("thead", {}, h("tr", {}, ["Group", "Colour", "Devices", ""].map((t) => h("th", {}, t)))));
    const body = h("tbody");
    for (const g of groups) {
      const name = h("input", { type: "text", value: g.name, maxlength: "40", "aria-label": `Name of ${g.name}` });
      const color = h("input", { type: "color", value: g.color, "aria-label": `Colour of ${g.name}` });
      const save = h("button", { type: "button", class: "btn" }, "Save");
      const del = h("button", { type: "button", class: "btn danger" }, "Delete");
      const call = async (request, done) => {
        try {
          fill(card, (await request()).groups);
          toast(done, "success");
        } catch (err) {
          toast(err.message || "Failed", "error");
        }
      };
      save.addEventListener("click", () => call(() => api(`/api/groups/${g.id}`, { method: "PATCH", body: { name: name.value, color: color.value } }), "Saved"));
      del.addEventListener("click", () => {
        if (window.confirm(`Delete the group "${g.name}"? Its ${g.count} device(s) stay, without a group.`)) call(() => api(`/api/groups/${g.id}`, { method: "DELETE" }), "Group deleted");
      });
      body.appendChild(h("tr", {}, h("td", {}, name), h("td", {}, color), h("td", {}, String(g.count)), h("td", {}, save, " ", del)));
    }
    table.appendChild(body);
    card.appendChild(table);
  } else {
    card.appendChild(h("p", { class: "hint" }, "No groups yet."));
  }

  const form = h("form", { class: "edit-form", id: "new-group-form" });
  const name = h("input", { type: "text", name: "name", required: true, maxlength: "40", placeholder: "Living room" });
  const color = h("input", { type: "color", name: "color", value: PALETTE[groups.length % PALETTE.length] }); // a different colour for each new group
  form.appendChild(h("h3", {}, "New group"));
  form.appendChild(h("div", { class: "field" }, h("label", {}, "Name"), name));
  form.appendChild(h("div", { class: "field" }, h("label", {}, "Colour"), color));
  form.appendChild(h("button", { type: "submit", class: "btn" }, "Add group"));
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    try {
      fill(card, (await api("/api/groups", { method: "POST", body: { name: name.value, color: color.value } })).groups);
      toast("Group added", "success");
    } catch (err) {
      toast(err.message || "Could not add the group", "error");
    }
  });
  card.appendChild(form);
}

export async function buildGroupsCard() {
  const card = h("div", { class: "card" });
  fill(card, (await get("/api/groups")).groups);
  return card;
}
