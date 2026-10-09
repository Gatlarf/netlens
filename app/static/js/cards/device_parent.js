import { get, patch } from "../api.js";
import { h, statusDot, typeBadge } from "../util.js";

const SOURCE_NOTE = {
  manual: "set by you",
  hypervisor: "reported by a hypervisor plugin (for example Proxmox)",
  uplink: "reported by a network plugin (for example your router)",
  guess: "a guess based on this being a virtual machine",
  route: "found by traceroute",
  gateway: "the default gateway",
};

// Section "Network position" (shown inside the Edit card): who this device sits below, who sits below it, and a way to
// choose the parent. `onSaved` is called after a successful change so the page can reload its data.
export async function buildParentCard(device, onSaved) {
  const card = h("div", { class: "parent-section" });
  card.appendChild(h("h3", {}, "Network position"));
  const info = device.parent;
  if (!info) return card;

  // ---- where it sits now
  const parentLine = h("p", {});
  if (info.effective) {
    parentLine.appendChild(document.createTextNode("Sits below "));
    parentLine.appendChild(h("a", { href: `#/device/${info.effective.id}` }, info.effective.name));
    parentLine.appendChild(h("span", { class: "hint" }, ` (${SOURCE_NOTE[info.source] || info.reason})`));
  } else {
    parentLine.appendChild(document.createTextNode("Top level: no parent. "));
    parentLine.appendChild(h("span", { class: "hint" }, info.mode === "none" ? "(set by you)" : "(nothing says what it depends on)"));
  }
  card.appendChild(parentLine);

  // ---- choose the parent
  const errorEl = h("p", { class: "error" }, "");
  const select = h("select", { name: "parent" });
  const form = h("form", { class: "edit-form" });
  const field = h("div", { class: "field" });
  field.appendChild(h("label", {}, "Parent"));
  field.appendChild(select);
  field.appendChild(h("p", { class: "hint" },
    "Automatic uses your plugins (hypervisors, routers), the traceroute path and the default gateway. Pick a device to fix the parent yourself, " +
    "for example the switch or mesh node this device is connected to. Devices below this one are not listed."));
  form.appendChild(field);
  form.appendChild(errorEl);
  const saveBtn = h("button", { type: "submit", class: "btn" }, "Save position");
  form.appendChild(saveBtn);
  card.appendChild(form);

  select.appendChild(h("option", { value: "auto" }, "Automatic"));
  select.appendChild(h("option", { value: "none" }, "None (top level)"));
  try {
    const devices = await get("/api/devices");
    const blocked = new Set([device.id, ...(info.descendants || [])]);
    const options = devices
      .filter((d) => !blocked.has(d.id))
      .map((d) => ({ id: d.id, label: `${d.name || d.primary_ip}${d.primary_ip && d.name !== d.primary_ip ? ` (${d.primary_ip})` : ""}` }))
      .sort((a, b) => a.label.toLowerCase().localeCompare(b.label.toLowerCase()));
    for (const o of options) select.appendChild(h("option", { value: `device:${o.id}` }, o.label));
  } catch (err) {
    errorEl.textContent = err.message || "Could not load the device list";
  }
  select.value = info.mode === "none" ? "none" : info.mode === "device" && info.device_id ? `device:${info.device_id}` : "auto";

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    errorEl.textContent = "";
    const value = select.value;
    const body = value === "auto" ? { parent_mode: "auto" }
      : value === "none" ? { parent_mode: "none" }
      : { parent_mode: "device", parent_device_id: Number(value.split(":")[1]) };
    saveBtn.disabled = true;
    try {
      await patch(`/api/devices/${device.id}`, body);
    } catch (err) {
      errorEl.textContent = err.message || "Could not save";
      saveBtn.disabled = false;
      return;
    }
    saveBtn.disabled = false;
    if (typeof onSaved === "function") onSaved("Network position saved");
  });

  // ---- what sits below it
  if (info.children && info.children.length > 0) {
    card.appendChild(h("h4", {}, `Devices below this one (${info.children.length}${info.descendants.length > info.children.length ? `, ${info.descendants.length} in total` : ""})`));
    const list = h("ul", { class: "children-list" });
    for (const c of info.children) {
      list.appendChild(h("li", {}, statusDot(c.online), " ", h("a", { href: `#/device/${c.id}` }, c.name), " ", typeBadge(c.type)));
    }
    card.appendChild(list);
  }
  return card;
}
