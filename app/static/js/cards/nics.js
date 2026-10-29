import { get, patch, ApiError } from "../api.js";
import { h, toast, statusDot } from "../util.js";

function describeError(err) {
  return err instanceof ApiError ? err.message : "That did not work";
}

// "Network cards": a host with more than one network card shows up as one device per MAC address. Here the owner says which devices are cards of the
// same machine. Nothing else changes: every card is still monitored by itself, but the host lists its cards and DNS registers the host's own name.
export function buildNicsCard(device, onChange) {
  const card = h("div", { class: "card nics-card" });
  card.appendChild(h("h2", {}, "Network cards"));
  const change = async (id, hostId) => {
    try {
      await patch(`/api/devices/${id}`, { nic_of: hostId });
      onChange();
    } catch (err) {
      toast(describeError(err), "error");
    }
  };

  if (device.nic_of) {
    card.appendChild(h("p", {}, "This device is another network card of ", h("a", { href: `#/device/${device.nic_of.id}` }, device.nic_of.name), "."));
    const unlink = h("button", { type: "button", class: "btn danger" }, "Unlink");
    unlink.addEventListener("click", () => change(device.id, null));
    card.appendChild(h("div", { class: "btn-row" }, unlink));
    return card;
  }

  const nics = device.nics || [];
  card.appendChild(h("p", { class: "hint" }, "A host with two network cards shows up as two devices, one per MAC address. Link the other card here: this page then lists it, and DNS registers the host's own name only. Each card is still monitored by itself, so a card that stops answering is still reported."));
  if (nics.length) {
    const online = nics.filter((n) => n.online).length + (device.online ? 1 : 0);
    card.appendChild(h("p", {}, `${online} of ${nics.length + 1} network cards answering.`));
    const list = h("ul", { class: "ip-list" });
    for (const n of nics) {
      const unlink = h("button", { type: "button", class: "btn" }, "Unlink");
      unlink.addEventListener("click", () => change(n.id, null));
      list.appendChild(h("li", {}, statusDot(n.online), " ", h("a", { href: `#/device/${n.id}` }, n.name || n.mac), " ", h("span", { class: "mono hint" }, [n.mac, n.ip].filter(Boolean).join(" · ")), " ", unlink));
    }
    card.appendChild(list);
  }

  const more = h("details", { class: "nics-add" }, h("summary", {}, "Link another network card"));
  const select = h("select", { "aria-label": "The other network card" });
  let loaded = false;
  more.addEventListener("toggle", async () => {
    if (!more.open || loaded) return;
    loaded = true;
    try {
      const taken = new Set([device.id, ...nics.map((n) => n.id)]);
      const options = (await get("/api/devices")).filter((d) => !taken.has(d.id))
        .map((d) => ({ id: d.id, label: `${d.name || d.primary_ip}${d.primary_ip && d.name !== d.primary_ip ? ` (${d.primary_ip})` : ""}${d.mac ? ` · ${d.mac}` : ""}` }))
        .sort((a, b) => a.label.toLowerCase().localeCompare(b.label.toLowerCase()));
      for (const o of options) select.appendChild(h("option", { value: String(o.id) }, o.label));
    } catch (err) {
      toast(describeError(err), "error");
    }
  });
  const add = h("button", { type: "button", class: "btn primary" }, "Link");
  add.addEventListener("click", () => { if (select.value) change(Number(select.value), device.id); });
  more.append(h("p", { class: "hint" }, "Pick the device that is the other card of this machine."), select, h("div", { class: "btn-row" }, add));
  card.appendChild(more);
  return card;
}
