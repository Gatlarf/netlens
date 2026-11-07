import { api, get } from "../api.js";
import { keepDrafts } from "../editguard.js";
import { h, clear, toast } from "../util.js";

const PALETTE = ["#2563eb", "#16a34a", "#d97706", "#9333ea", "#dc2626", "#0891b2", "#be185d", "#65a30d", "#7c3aed", "#ea580c"];

function fill(card, groups) { return keepDrafts(card, () => fillNow(card, groups)); }

function fillNow(card, groups) {
  clear(card);
  card.appendChild(h("h2", {}, "Groups"));
  card.appendChild(h("p", { class: "hint" },
    "Put devices in groups such as rooms, floors or owners. A device is in one group. The map can colour devices by group and show one group at a time, " +
    "the Devices page can filter and set groups for many devices at once, and Home Assistant uses the group as the area of a device. " +
    "Set a device's group on its page or from the Devices page, or add many devices at once with \"Add devices to a group\" below."));

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
  if (groups.length) card.appendChild(bulkSection(card, groups));
}

// Several devices into one group at once: pick the group, filter the list, tick the devices.
function bulkSection(card, groups) {
  const box = h("div", { class: "edit-form", id: "bulk-group" });
  box.appendChild(h("h3", {}, "Add devices to a group"));
  const target = h("select", { "aria-label": "Group to put the devices in" },
    ...groups.map((g) => h("option", { value: String(g.id) }, g.name)),
    h("option", { value: "" }, "(no group: take them out of their group)"));
  const search = h("input", { type: "search", placeholder: "Filter by name, address or group", "aria-label": "Filter the devices" });
  const onlyFree = h("input", { type: "checkbox", checked: true });
  const list = h("div", { class: "bulk-list", style: "max-height:22rem;overflow:auto;border:1px solid var(--border, #8884);border-radius:var(--radius-sm);padding:6px" }, h("p", { class: "hint" }, "Loading devices…"));
  const count = h("span", { class: "hint" });
  const apply = h("button", { type: "button", class: "btn primary", disabled: true }, "Add to group");
  const selectShown = h("button", { type: "button", class: "btn" }, "Select all shown");
  const clearAll = h("button", { type: "button", class: "btn" }, "Clear selection");

  let devices = [];
  const chosen = new Set();
  const shown = () => {
    const q = search.value.trim().toLowerCase();
    return devices.filter((d) => (!onlyFree.checked || d.group_id == null)
      && (!q || [d.name, d.primary_ip, d.group].some((v) => (v || "").toLowerCase().includes(q))));
  };
  const refreshCount = () => {
    count.textContent = `${chosen.size} selected`;
    apply.disabled = chosen.size === 0;
  };
  const draw = () => {
    clear(list);
    const rows = shown();
    if (!rows.length) list.appendChild(h("p", { class: "hint" }, devices.length ? "No device matches." : "No devices."));
    for (const d of rows) {
      const tick = h("input", { type: "checkbox", checked: chosen.has(d.id) });
      tick.addEventListener("change", () => { tick.checked ? chosen.add(d.id) : chosen.delete(d.id); refreshCount(); });
      list.appendChild(h("label", { style: "display:flex;gap:8px;align-items:center;padding:2px 4px" }, tick,
        h("span", {}, d.name || d.primary_ip || `#${d.id}`), h("span", { class: "hint" }, [d.primary_ip, d.group ? `in ${d.group}` : "no group"].filter(Boolean).join(" · "))));
    }
    refreshCount();
  };
  search.addEventListener("input", draw);
  onlyFree.addEventListener("change", draw);
  selectShown.addEventListener("click", () => { shown().forEach((d) => chosen.add(d.id)); draw(); });
  clearAll.addEventListener("click", () => { chosen.clear(); draw(); });
  apply.addEventListener("click", async () => {
    const group_id = target.value === "" ? null : Number(target.value);
    const name = target.selectedOptions[0].textContent;
    try {
      const res = await api("/api/devices/group", { method: "POST", body: { ids: [...chosen], group_id } });
      toast(`${res.changed} device${res.changed === 1 ? "" : "s"} ${group_id === null ? "taken out of their group" : `put in ${name}`}`, "success");
      fill(card, (await get("/api/groups")).groups);
    } catch (err) {
      toast(err.message || "Could not change the groups", "error");
    }
  });

  box.appendChild(h("div", { class: "field" }, h("label", {}, "Group"), target));
  box.appendChild(h("div", { class: "field" }, h("label", {}, "Devices"), search));
  box.appendChild(h("label", { style: "display:flex;gap:8px;align-items:center" }, onlyFree, "Only devices without a group"));
  box.appendChild(list);
  box.appendChild(h("div", { class: "btn-row" }, apply, selectShown, clearAll, count));
  get("/api/devices").then((all) => {
    devices = all.slice().sort((a, b) => (a.name || "").localeCompare(b.name || ""));
    draw();
  }).catch((err) => { clear(list); list.appendChild(h("p", { class: "hint" }, err.message || "Could not load the devices")); });
  return box;
}

export async function buildGroupsCard() {
  const card = h("div", { class: "card" });
  fill(card, (await get("/api/groups")).groups);
  return card;
}
