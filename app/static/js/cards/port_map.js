import { get, put, del } from "../api.js";
import { h, clear, toast, statusDot, typeBadge } from "../util.js";

const SWITCHY = new Set(["switch", "router", "ap"]);
const SELECTED = new Map();      // device id -> the port that is open; kept when the page refreshes itself

function speedText(p) {
  if (p.up === null || p.up === undefined) return "";
  if (!p.up) return p.enabled === false ? "off" : "no link";
  if (!p.speed_mbps) return "link";
  return p.speed_mbps >= 1000 ? `${p.speed_mbps / 1000}G` : `${p.speed_mbps}M`;
}

function state(p) {
  if (p.up === null || p.up === undefined) return p.devices.length ? "used" : "unknown";
  if (p.enabled === false) return "disabled";
  return p.up ? "up" : "down";
}

function deviceLine(d, onRemove) {
  const line = h("li", { class: "pm-device" });
  line.appendChild(statusDot(d.online));
  line.appendChild(document.createTextNode(" "));
  line.appendChild(h("a", { href: `#/device/${d.id}` }, d.name));
  line.appendChild(document.createTextNode(" "));
  line.appendChild(typeBadge(d.type));
  if (d.manual) line.appendChild(h("span", { class: "pm-tag", title: "You set this connection by hand; a plugin never overwrites it" }, "set by you"));
  if (d.differs) {
    const where = [d.differs.node, d.differs.port ? `port ${d.differs.port}` : ""].filter(Boolean).join(" ");
    line.appendChild(h("span", { class: "pm-tag warn", title: "What the switch plugin reports differs from what you set" }, `the plugin reports ${where}`));
  }
  if (d.manual && onRemove) {
    line.appendChild(h("button", { class: "btn small admin-only", type: "button", onclick: () => onRemove(d) }, "Remove"));
  }
  if (d.behind && d.behind.length) {
    const more = d.behind_total > d.behind.length ? ` (and ${d.behind_total - d.behind.length} more)` : "";
    const sub = h("details", { class: "pm-behind" }, h("summary", {}, `${d.behind_total} device${d.behind_total === 1 ? "" : "s"} behind it`));
    const list = h("ul", {});
    for (const b of d.behind) {
      list.appendChild(h("li", {}, statusDot(b.online), " ", h("a", { href: `#/device/${b.id}` }, b.name), " ", typeBadge(b.type)));
    }
    sub.appendChild(list);
    if (more) sub.appendChild(h("p", { class: "hint" }, more));
    line.appendChild(sub);
  }
  return line;
}

// The front of the switch: one block per port with its link state, speed and the device(s) on it; a click opens the port.
// Also where the owner says which device is connected to which port (the only way for a switch that does not tell, like a TP-Link Easy Smart).
export async function buildPortMapCard(device) {
  const data = await get(`/api/devices/${device.id}/port-map`);
  const type = device.type_override || device.device_type;
  if (!data.ports.length && !data.no_port.length && !SWITCHY.has(type)) return null;

  const card = h("div", { class: "card port-map-card" });
  let selected = SELECTED.get(device.id) || null;
  let devices = null;

  async function reload() {
    const fresh = await get(`/api/devices/${device.id}/port-map`);
    Object.assign(data, fresh);
    draw();
  }

  async function remove(d) {
    try {
      await del(`/api/devices/${d.id}/connection`);
      toast("Connection removed");
      await reload();
    } catch (err) {
      toast(err.message || "Could not remove", "error");
    }
  }

  function draw() {
    clear(card);
    card.appendChild(h("h2", {}, "Connected devices"));
    const used = data.ports.filter((p) => p.devices.length).length;
    const total = data.ports.reduce((n, p) => n + p.devices.length, 0);
    card.appendChild(h("p", { class: "hint" },
      data.ports.length || total
        ? `${total} device${total === 1 ? "" : "s"} on ${used} port${used === 1 ? "" : "s"}. Click a port to see what is on it. A port that leads to another switch lists the devices behind that switch.`
        : "No device is linked to a port of this switch yet. Use the form below to say which device is connected where."));
    if (data.uplink) {
      const up = h("p", {}, "This switch is connected to ", h("a", { href: `#/device/${data.uplink.id}` }, data.uplink.name));
      if (data.uplink.port) up.appendChild(h("span", { class: "mono" }, ` · port ${data.uplink.port}`));
      if (data.uplink.manual) up.appendChild(h("span", { class: "pm-tag" }, "set by you"));
      card.appendChild(up);
    }

    if (data.ports.length) {
      const numeric = data.ports.every((p) => /^\d+$/.test(p.port));
      const plate = h("div", { class: `faceplate${numeric && data.ports.length >= 8 ? " two-rows" : ""}` });
      for (const p of data.ports) {
        const first = p.devices[0];
        const text = !first ? "" : p.devices.length > 1 ? `${p.devices.length} devices` : first.name;
        const hasNode = p.devices.some((d) => d.behind && d.behind.length);
        const block = h("button", {
          type: "button",
          class: `fp-port st-${state(p)}${selected === p.port ? " sel" : ""}${hasNode ? " node" : ""}`,
          title: [`Port ${p.port}${p.name ? ` (${p.name})` : ""}`, speedText(p), ...p.devices.map((d) => d.name)].filter(Boolean).join(" · "),
          onclick: () => { selected = selected === p.port ? null : p.port; SELECTED.set(device.id, selected); draw(); },
        },
        h("span", { class: "fp-num" }, p.port),
        h("span", { class: "fp-speed" }, speedText(p) || " "),
        h("span", { class: "fp-dev" }, text || " "));
        plate.appendChild(block);
      }
      card.appendChild(plate);
      card.appendChild(h("p", { class: "hint fp-legend" },
        h("span", { class: "fp-key st-up" }), " link ", h("span", { class: "fp-key st-down" }), " no link ", h("span", { class: "fp-key st-disabled" }), " disabled ",
        h("span", { class: "fp-key st-used" }), " no data from the switch, but devices set ", h("span", { class: "fp-key node" }), " leads to another switch"));
    }

    const port = data.ports.find((p) => p.port === selected);
    if (port) {
      const box = h("div", { class: "pm-selected" });
      box.appendChild(h("h3", {}, `Port ${port.port}${port.name ? ` (${port.name})` : ""}`));
      const facts = [speedText(port) && (port.up ? `link ${speedText(port)}${port.duplex ? ` ${port.duplex}` : ""}` : speedText(port))].filter(Boolean);
      if (facts.length) box.appendChild(h("p", { class: "hint" }, facts.join(" · ")));
      if (port.devices.length) {
        const list = h("ul", { class: "pm-devices" });
        for (const d of port.devices) list.appendChild(deviceLine(d, remove));
        box.appendChild(list);
      } else {
        box.appendChild(h("p", { class: "hint" }, "Nothing is linked to this port."));
      }
      card.appendChild(box);
    }

    if (data.no_port.length) {
      card.appendChild(h("h3", {}, `Below this switch, port unknown (${data.no_port.length})`));
      const list = h("ul", { class: "pm-devices" });
      for (const d of data.no_port) list.appendChild(deviceLine(d, remove));
      card.appendChild(list);
    }

    card.appendChild(buildForm());
  }

  function buildForm() {
    const form = h("form", { class: "pm-form admin-only" });
    form.appendChild(h("h3", {}, "Connect a device to a port"));
    const portInput = h("input", { name: "port", type: "text", placeholder: "Port (for example 5)", list: `pm-ports-${device.id}`, value: selected || "", maxlength: "60" });
    const choices = h("datalist", { id: `pm-ports-${device.id}` });
    for (const p of data.ports) choices.appendChild(h("option", { value: p.port }, p.name || ""));
    const pick = h("select", { name: "device" }, h("option", { value: "" }, "Loading devices…"));
    const err = h("p", { class: "error" }, "");
    const btn = h("button", { class: "btn", type: "submit" }, "Connect");
    form.appendChild(h("div", { class: "pm-row" }, portInput, choices, pick, btn));
    form.appendChild(h("p", { class: "hint" },
      "For a switch that cannot say what is plugged in. The device also sits below this switch in the network map. For a device behind a second switch, connect it to that switch " +
      "and connect that switch to this one. A plugin never overwrites what you set here."));
    form.appendChild(err);

    const fill = (list) => {
      clear(pick);
      pick.appendChild(h("option", { value: "" }, "Choose a device"));
      for (const d of list) pick.appendChild(h("option", { value: String(d.id) }, d.label));
    };
    const load = devices ? Promise.resolve(devices) : get("/api/devices").then((all) => {
      devices = all
        .map((d) => ({ id: d.id, label: `${d.name || d.primary_ip}${d.primary_ip && d.name !== d.primary_ip ? ` (${d.primary_ip})` : ""}` }))
        .sort((a, b) => a.label.toLowerCase().localeCompare(b.label.toLowerCase()));
      return devices;
    });
    load.then((list) => fill(list.filter((d) => d.id !== device.id))).catch(() => { err.textContent = "Could not load the device list"; });

    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      err.textContent = "";
      if (!pick.value) { err.textContent = "Choose a device"; return; }
      btn.disabled = true;
      try {
        await put(`/api/devices/${pick.value}/connection`, { node_device_id: device.id, port: portInput.value.trim() || null });
        toast("Connection saved");
        if (portInput.value.trim()) selected = data.ports.find((p) => p.port === portInput.value.trim())?.port || selected;
        await reload();
      } catch (ex) {
        err.textContent = ex.message || "Could not save";
        btn.disabled = false;
      }
    });
    return form;
  }

  draw();
  return card;
}
