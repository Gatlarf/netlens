import { get, patch, post, del, ApiError } from "../api.js";
import { h, clear, fmtTime, timeAgo, typeBadge, statusDot, toast, TYPE_LABELS, shortName, isAdmin, vendorText, vendorTitle } from "../util.js";
import { mountTerminal, isTerminalActive } from "../terminal.js";
import { buildDeviceUptimeCard } from "../cards/device_uptime.js";
import { buildDeviceWifiCard } from "../cards/device_wifi.js";
import { buildDeviceServicesCard } from "../cards/device_services.js";
import { buildParentCard } from "../cards/device_parent.js";
import { buildStabilitySection, isStabilityOpen } from "../cards/stability.js";

const WEB_PORTS = new Set([80, 443, 8080, 8443, 8006, 5000, 5001, 9000]);

function portLink(port, ip) {
  if (!WEB_PORTS.has(port)) return null;
  const secure = [443, 8443, 8006, 5001].includes(port);
  const url = `${secure ? "https" : "http"}://${ip}:${port}`;
  return h("a", { href: url, target: "_blank", rel: "noopener noreferrer" }, "Open");
}

function kvRow(label, valueNode) {
  const row = h("div", { class: "kv" });
  row.appendChild(h("span", { class: "kv-label" }, label));
  row.appendChild(valueNode);
  return row;
}

function buildDetailsCard(device) {
  const card = h("div", { class: "card" });
  card.appendChild(h("h2", {}, "Details"));

  card.appendChild(kvRow("IP", h("span", { class: "mono" }, device.primary_ip || "—")));
  card.appendChild(kvRow("MAC", h("span", { class: "mono" }, device.mac || "—")));
  card.appendChild(kvRow("Vendor", h("span", { title: vendorTitle(device) }, vendorText(device))));
  card.appendChild(kvRow("Hostname", h("span", {}, device.hostname || "—")));

  const osNode = h("span", {});
  if (device.os_name) {
    osNode.textContent = device.os_name;
    if (device.os_confidence !== null && device.os_confidence !== undefined) {
      osNode.textContent += ` (${device.os_confidence}%)`;
    }
  } else {
    osNode.textContent = "—";
  }
  card.appendChild(kvRow("OS", osNode));

  const typeNode = h("span", {});
  typeNode.textContent = device.type || "unknown";
  if (device.type_override) {
    typeNode.textContent += " (override)";
  }
  card.appendChild(kvRow("Type", typeNode));

  card.appendChild(kvRow("First seen", h("span", {}, fmtTime(device.first_seen))));

  const lastSeenNode = h("span", {});
  lastSeenNode.textContent = fmtTime(device.last_seen);
  card.appendChild(kvRow("Last seen", lastSeenNode));

  card.appendChild(kvRow("Status", statusDot(device.online)));

  // DNS: what Netlens knows about this device's record (only once the DNS feature has looked at it)
  if (device.dns && device.dns.state && device.dns.state !== "skip") {
    const label = { ok: "registered", self: "registers itself", add: "not registered yet", update: "record needs updating", wait: "waiting to register", conflict: "name conflict" }[device.dns.state] || device.dns.state;
    card.appendChild(kvRow("DNS", h("span", { id: "dns-info", title: device.dns.reason || "" }, `${device.dns.fqdn || ""} · ${label}`)));
  }

  // where it is plugged in / connected, from a router or switch plugin (SNMP, Omada, UniFi, ASUS...)
  const link = device.connection;
  if (link && (link.node_name || link.node_mac || link.port)) {
    const where = h("span", { id: "connection-info" }, link.node_name || link.node_mac || "");
    if (link.port) where.appendChild(h("span", { class: "mono" }, `${link.node_name || link.node_mac ? " · " : ""}port ${link.port}`));
    card.appendChild(kvRow("Connected to", where));
  }

  return card;
}

function buildWhyCard(device) {
  const info = device.identification;
  if (!info) return null;
  const card = h("div", { class: "card", id: "why-card" });
  card.appendChild(h("h2", {}, "Why this type?"));
  if (device.type_override) {
    card.appendChild(h("p", { class: "hint" }, `You set this device to ${TYPE_LABELS[device.type_override] || device.type_override}; that choice wins. Netlens' own guess was ${TYPE_LABELS[device.device_type] || device.device_type || "unknown"}.`));
  }
  if (!info.evidence.length) {
    card.appendChild(h("p", { class: "hint" }, "Nothing known about this device points to a type yet. A deep scan, or a name, usually helps."));
    return card;
  }
  const list = h("ul", { class: "evidence" });
  info.evidence.slice(0, 8).forEach((e, i) => {
    list.appendChild(h("li", { class: i === 0 ? "top" : "" },
      h("span", { class: "ev-type" }, TYPE_LABELS[e.type] || e.type),
      h("span", { class: "ev-bar", title: `weight ${e.weight}` }, h("i", { style: `width:${Math.min(100, e.weight)}%` })),
      h("span", { class: "ev-why" }, e.why)));
  });
  card.appendChild(list);
  card.appendChild(h("p", { class: "hint" }, "The strongest clue decides. If it is wrong, set the type by hand under Edit: after two devices of the same manufacturer you corrected the same way, Netlens applies that to the others."));
  return card;
}

// proto/port -> the containers of this Docker host that publish it
function containerPortOwners(device) {
  const owners = new Map();
  for (const g of (device.virtualization && device.virtualization.guests) || []) {
    for (const p of (g.details && g.details.ports) || []) {
      if (!p.host_port) continue;
      const key = `${p.proto || "tcp"}/${p.host_port}`;
      if (!owners.has(key)) owners.set(key, []);
      if (!owners.get(key).includes(g)) owners.get(key).push(g);
    }
  }
  return owners;
}

function buildPortsCard(device, onChanged) {
  const card = h("div", { class: "card" });
  card.appendChild(h("h2", {}, "Open ports"));

  const table = h("table", { class: "data" });
  const thead = h("thead");
  const headRow = h("tr");
  const owners = containerPortOwners(device);
  const withOwner = owners.size > 0;
  ["Port", "Proto", "Service", "Product", "Version", "State", ...(withOwner ? ["Container"] : [])].forEach((col) => {
    headRow.appendChild(h("th", {}, col));
  });
  thead.appendChild(headRow);
  table.appendChild(thead);

  const tbody = h("tbody");
  const ports = device.ports || [];
  if (ports.length === 0) {
    const emptyRow = h("tr");
    const emptyCell = h("td", { colspan: withOwner ? "7" : "6" }, "No open ports");
    emptyRow.appendChild(emptyCell);
    tbody.appendChild(emptyRow);
  } else {
    for (const p of ports) {
      const row = h("tr");
      const portCell = h("td", {});
      portCell.textContent = String(p.port);
      const link = portLink(p.port, device.primary_ip);
      if (link) {
        portCell.appendChild(h("span", {}, " "));
        portCell.appendChild(link);
      }
      row.appendChild(portCell);
      row.appendChild(h("td", {}, p.proto || ""));
      row.appendChild(h("td", {}, p.service || ""));
      row.appendChild(h("td", {}, p.product || ""));
      row.appendChild(h("td", {}, p.version || ""));
      const note = p.state && p.state !== "open" ? p.state : "";
      const stateCell = h("td", {}, note);
      if (device.baseline && device.baseline.unexpected.includes(`${p.proto}/${p.port}`)) {
        stateCell.appendChild(h("span", { class: "tag unknown-tag", title: "This port is not in the device's baseline" }, "not in baseline"));
      }
      row.appendChild(stateCell);
      if (withOwner) {
        const who = owners.get(`${p.proto}/${p.port}`) || [];
        row.appendChild(h("td", {}, ...who.map((g, i) => [i ? ", " : "", h("span", { class: "tag", title: g.details.image || "" }, g.name)]).flat()));
      }
      tbody.appendChild(row);
    }
  }
  table.appendChild(tbody);
  card.appendChild(table);

  const base = device.baseline;
  const box = h("div", { class: "baseline-box admin-only" });
  if (base) {
    box.appendChild(h("p", { class: base.unexpected.length || base.missing.length ? "error" : "hint", id: "baseline-state" },
      `Baseline from ${fmtTime(base.at)}: ${base.expected.length ? base.expected.join(", ") : "no open ports"}.` +
      (base.unexpected.length ? ` Not in baseline: ${base.unexpected.join(", ")}.` : "") +
      (base.missing.length ? ` Gone: ${base.missing.join(", ")}.` : "") +
      (base.unexpected.length || base.missing.length ? "" : " Nothing has changed.")));
  } else {
    box.appendChild(h("p", { class: "hint" }, "No baseline. Accept the current ports as normal and Netlens will warn when they change."));
  }
  const act = async (accept, done) => {
    try {
      await post("/api/devices/baseline", { ids: [device.id], accept });
      toast(done, "success");
      onChanged();
    } catch (err) {
      toast(err.message || "Failed", "error");
    }
  };
  const acceptBtn = h("button", { type: "button", class: "btn", id: "baseline-accept" }, base ? "Accept current ports" : "Accept as normal");
  acceptBtn.addEventListener("click", () => act(true, "Baseline saved"));
  box.appendChild(acceptBtn);
  if (base) {
    const removeBtn = h("button", { type: "button", class: "btn", id: "baseline-clear" }, "Remove baseline");
    removeBtn.addEventListener("click", () => act(false, "Baseline removed"));
    box.appendChild(removeBtn);
  }
  card.appendChild(box);

  return card;
}

let groupChoices = []; // the groups to pick from, read before the page is built

let editOpen = false; // the Edit card stays open (or closed) when the page refreshes itself

function buildEditCard(device, onSaved) {
  const card = h("div", { class: "card edit-card" });
  const details = h("details", { class: "edit-details", open: editOpen });
  details.appendChild(h("summary", {}, h("h2", {}, "Edit"), h("span", { class: "hint" }, "name, type, group, notes, scanning, network position")));
  details.addEventListener("toggle", () => { editOpen = details.open; });
  card.appendChild(details);

  const form = h("form", { class: "edit-form compact" });
  const grid = h("div", { class: "edit-grid" });

  const nameField = h("div", { class: "field" });
  nameField.appendChild(h("label", {}, "Custom name"));
  const nameInput = h("input", { type: "text", name: "custom_name", value: device.custom_name || "" });
  nameField.appendChild(nameInput);
  grid.appendChild(nameField);

  const typeField = h("div", { class: "field" });
  typeField.appendChild(h("label", {}, "Type override"));
  const typeSelect = h("select", { name: "type_override" });
  const autoOption = h("option", { value: "" }, "(automatic)");
  typeSelect.appendChild(autoOption);
  for (const key of Object.keys(TYPE_LABELS)) {
    const opt = h("option", { value: key }, TYPE_LABELS[key]);
    if (device.type_override === key) opt.selected = true;
    typeSelect.appendChild(opt);
  }
  typeField.appendChild(typeSelect);
  grid.appendChild(typeField);

  const groupField = h("div", { class: "field" });
  groupField.appendChild(h("label", {}, "Group (room, floor, owner...)"));
  const groupSelect = h("select", { name: "group_id" });
  groupSelect.appendChild(h("option", { value: "" }, "(none)"));
  for (const g of groupChoices) groupSelect.appendChild(h("option", { value: String(g.id) }, g.name));
  groupSelect.value = device.group_id != null ? String(device.group_id) : "";
  groupField.appendChild(groupSelect);
  groupSelect.title = groupChoices.length ? "Groups are managed under Settings → Groups." : "No groups yet: create them under Settings → Groups.";
  grid.appendChild(groupField);

  const tagsField = h("div", { class: "field" });
  tagsField.appendChild(h("label", {}, "Tags"));
  const tagsInput = h("input", { type: "text", name: "tags", value: (device.tags || []).join(", ") });
  tagsField.appendChild(tagsInput);
  grid.appendChild(tagsField);
  form.appendChild(grid);

  const notesField = h("div", { class: "field" });
  notesField.appendChild(h("label", {}, "Notes"));
  const notesTextarea = h("textarea", { name: "notes", rows: "2" });
  notesTextarea.value = device.notes || "";
  notesField.appendChild(notesTextarea);
  form.appendChild(notesField);

  const notifyField = h("div", { class: "field" });
  const notifyInput = h("input", { type: "checkbox", name: "notify_offline", checked: device.notify_offline !== false });
  notifyField.appendChild(h("label", { title: "Needs e-mail notifications to be set up under Settings." }, notifyInput, " E-mail me when it goes offline"));
  form.appendChild(notifyField);

  const gentleField = h("div", { class: "field" });
  const gentleInput = h("input", { type: "checkbox", name: "gentle", checked: device.gentle === true });
  gentleField.appendChild(h("label", { title: "Scans only check which ports are open and never connect to them to identify the service. Use it for devices that complain about it, such as a Samsung TV asking whether a smart device may connect. Service names, versions and the OS are then no longer refreshed. Applies to quick and deep scans, not to a full scan you start yourself." }, gentleInput, " Gentle scanning (don't probe its services)"));
  form.appendChild(gentleField);

  const dnsField = h("div", { class: "field" });
  const dnsMode = h("select", { name: "dns_mode", title: "Automatic follows the DNS settings. Always registers the device even when it would be skipped (a Windows machine, a unknown device). Never keeps it out of DNS." },
    h("option", { value: "auto" }, "Automatic"), h("option", { value: "always" }, "Always register"), h("option", { value: "never" }, "Never register"));
  dnsMode.value = device.dns_mode || "auto";
  const dnsName = h("input", { type: "text", name: "dns_name", value: device.dns_name || "", placeholder: "(automatic)", maxlength: "100", title: "The host name Netlens registers for this device. Leave empty for the automatic name." });
  dnsField.appendChild(h("label", {}, "DNS registration"));
  dnsField.appendChild(h("div", { class: "edit-grid" }, dnsMode, dnsName));
  form.appendChild(dnsField);

  const trustField = h("div", { class: "field" });
  const trustInput = h("input", { type: "checkbox", name: "trusted", checked: device.trusted === true });
  trustField.appendChild(h("label", { title: "Tick it for devices you recognise. Devices that appear later start as unknown, so you can spot newcomers." }, trustInput, " Known device"));
  form.appendChild(trustField);

  const saveBtn = h("button", { type: "submit" }, "Save");
  form.appendChild(saveBtn);

  let dirty = false;
  let focused = false;

  const fields = [nameInput, typeSelect, groupSelect, tagsInput, notesTextarea, notifyInput, trustInput, dnsMode, dnsName];
  for (const f of fields) {
    f.addEventListener("input", () => { dirty = true; });
    f.addEventListener("change", () => { dirty = true; });
    f.addEventListener("focus", () => { focused = true; });
    f.addEventListener("blur", () => { focused = false; });
  }

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const body = {
      custom_name: nameInput.value,
      type_override: typeSelect.value || null,
      group_id: groupSelect.value ? Number(groupSelect.value) : null,
      tags: tagsInput.value.split(",").map((s) => s.trim()).filter(Boolean),
      notes: notesTextarea.value,
      notify_offline: notifyInput.checked,
      trusted: trustInput.checked,
      gentle: gentleInput.checked,
      dns_mode: dnsMode.value,
      dns_name: dnsName.value,
    };
    try {
      await patch(`/api/devices/${device.id}`, body);
    } catch (err) {
      toast(err instanceof ApiError ? err.message : "Save failed", "error");
      return;
    }
    dirty = false;
    toast("Saved", "success");
    onSaved();
  });

  details.appendChild(form);
  const parentSlot = h("div", { class: "parent-slot" });  // "Network position", filled in by the page
  details.appendChild(parentSlot);

  return { card, parentSlot, isDirty: () => dirty, isFocused: () => focused };
}

const KIND_LABELS = { lxc: "LXC", qemu: "VM", vm: "VM", app: "App", container: "Container" };

function portText(ports) {
  const shown = (ports || []).filter((p) => p.host_port).map((p) => `${p.host_port}${p.container_port && p.container_port !== p.host_port ? "→" + p.container_port : ""}${p.proto && p.proto !== "tcp" ? "/" + p.proto : ""}${p.bind && p.bind !== "0.0.0.0" && p.bind !== "::" ? " (" + p.bind + ")" : ""}`);
  return shown.join(", ");
}

// the state of a container, with its health and restarts when they are worth a look
function containerState(g) {
  const d = g.details || {};
  const bits = [h("span", {}, g.status)];
  if (d.health && d.health !== "healthy") bits.push(h("span", { class: "tag unknown-tag", title: "Docker health check" }, d.health));
  if (d.restarts >= 3) bits.push(h("span", { class: "tag unknown-tag", title: "Restarts since the container was created" }, `${d.restarts} restarts`));
  return h("span", { class: "container-state" }, ...bits.flatMap((b, i) => (i ? [" ", b] : [b])));
}

// why a running container has no device of its own
function containerAddressNote(g) {
  const driver = (g.details && g.details.network_driver) || "";
  if (driver === "host") return "shares the host's address";
  if (driver === "macvlan" || driver === "ipvlan") return "not seen on the network";
  return "inside the host";
}

// "2 CPU · 4 GB memory · 32 GB disk"
function resourceText(d) {
  const parts = [];
  if (d.cpus) parts.push(`${d.cpus} CPU`);
  if (d.memory_mb) parts.push(d.memory_mb >= 1024 ? `${Math.round(d.memory_mb / 102.4) / 10} GB memory` : `${d.memory_mb} MB memory`);
  if (d.disk_gb) parts.push(`${d.disk_gb} GB disk`);
  return parts.join(" · ");
}

const YEAR_MS = 365 * 24 * 3600 * 1000;

function imageAge(created) {
  const ms = Date.now() - Date.parse(created);
  if (!Number.isFinite(ms) || ms < 0) return null;
  const days = Math.floor(ms / 86400000);
  return { days, text: days >= 365 ? `${Math.floor(days / 365)} year${days >= 730 ? "s" : ""} ago` : days >= 60 ? `${Math.floor(days / 30)} months ago` : `${days} days ago`, old: ms > YEAR_MS };
}

function containerRows(card, g) {
  const d = g.details || {};
  const resources = resourceText(d);
  if (resources) card.appendChild(kvRow("Resources", h("span", {}, resources)));
  if (d.os) card.appendChild(kvRow("System", h("span", {}, d.os)));
  if (d.version) card.appendChild(kvRow("Version", h("span", {}, d.version, d.update_available ? h("span", { class: "tag unknown-tag", title: "A newer version is available" }, "update available") : null)));
  else if (d.update_available) card.appendChild(kvRow("Update", h("span", { class: "tag unknown-tag" }, "update available")));
  if (d.tags) card.appendChild(kvRow("Tags", h("span", {}, d.tags)));
  if (d.autostart !== undefined) card.appendChild(kvRow("Starts at boot", h("span", {}, d.autostart ? "yes" : "no")));
  if (d.image) {
    const age = d.image_created ? imageAge(d.image_created) : null;
    card.appendChild(kvRow("Image", h("span", {}, d.image, age ? h("span", { class: age.old ? "tag unknown-tag" : "hint", title: "When the image was built" }, ` built ${age.text}`) : null)));
  }
  if (d.project) card.appendChild(kvRow("Compose", h("span", {}, d.service ? `${d.project} / ${d.service}` : d.project)));
  if (d.network) card.appendChild(kvRow("Network", h("span", {}, d.network_driver && d.network_driver !== d.network ? `${d.network} (${d.network_driver})` : d.network)));
  if (d.health) card.appendChild(kvRow("Health", h("span", {}, d.health)));
  if (d.restarts !== undefined) card.appendChild(kvRow("Restarts", h("span", {}, String(d.restarts))));
  if (d.started) card.appendChild(kvRow("Started", h("span", {}, fmtTime(d.started))));
  if (d.exit_code !== undefined) card.appendChild(kvRow("Exit code", h("span", {}, String(d.exit_code))));
  const ports = portText(d.ports);
  if (ports) card.appendChild(kvRow("Published ports", h("span", {}, ports, d.exposed ? h("span", { class: "tag unknown-tag", title: "Reachable from the whole network" }, "all interfaces") : null)));
}

function buildVirtualizationCard(device) {
  const info = device.virtualization;
  if (!info) return null;
  const card = h("div", { class: "card" });
  card.appendChild(h("h2", {}, "Virtualization"));

  if (info.guest) {
    const g = info.guest;
    const isContainer = g.kind === "container";
    const kind = isContainer ? "Container (Docker)" : g.kind === "lxc" ? "Container (LXC)" : g.kind === "app" ? "App" : "Virtual machine";
    card.appendChild(kvRow("Runs as", h("span", {}, isContainer ? `${kind} ${g.name}` : `${kind} ${g.guest_id}, ${g.name}`)));
    card.appendChild(kvRow("Status", containerState(g)));
    if (g.node && !isContainer) card.appendChild(kvRow("Node", h("span", {}, g.node)));
    if (g.host_device_id) {
      card.appendChild(kvRow("Host", h("a", { href: `#/device/${g.host_device_id}` }, g.host_name || `device ${g.host_device_id}`)));
    }
    containerRows(card, g);
    card.appendChild(kvRow("Reported by", h("span", {}, g.plugin_id)));
  }

  if (info.guests && info.guests.length > 0) {
    const docker = info.guests.some((g) => g.kind === "container");
    card.appendChild(h("p", { class: "hint" }, docker && info.guests.every((g) => g.kind === "container")
      ? `Docker host with ${info.guests.length} container${info.guests.length === 1 ? "" : "s"}:`
      : `Hypervisor host with ${info.guests.length} guest${info.guests.length === 1 ? "" : "s"}:`));
    const table = h("table", { class: "data" });
    const headRow = h("tr");
    (docker ? ["Name", "Status", "Image", "Ports", "Device"] : ["ID", "Name", "Type", "Status", ...(info.guests.some((g) => resourceText(g.details || {})) ? ["Resources"] : []), "Device"]).forEach((c) => headRow.appendChild(h("th", {}, c)));
    table.appendChild(h("thead", {}, headRow));
    const tbody = h("tbody");
    for (const g of info.guests) {
      const isContainer = g.kind === "container";
      const deviceCell = g.device_id
        ? h("td", {}, h("a", { href: `#/device/${g.device_id}` }, g.device_name || `device ${g.device_id}`))
        : h("td", { class: "hint" }, g.status !== "running" && g.status !== "restarting" ? "not running" : isContainer ? containerAddressNote(g) : "not seen on the network");
      if (docker) {
        tbody.appendChild(h("tr", {}, h("td", {}, g.name), h("td", {}, containerState(g)), h("td", {}, (g.details && g.details.image) || ""), h("td", {}, portText(g.details && g.details.ports)), deviceCell));
      } else {
        const withResources = info.guests.some((x) => resourceText(x.details || {}));
        tbody.appendChild(h("tr", {}, h("td", {}, String(g.guest_id)), h("td", {}, g.name), h("td", {}, KIND_LABELS[g.kind] || g.kind), h("td", {}, containerState(g)),
          ...(withResources ? [h("td", {}, resourceText(g.details || {}))] : []), deviceCell));
      }
    }
    table.appendChild(tbody);
    card.appendChild(table);
  }
  return card;
}

function buildNamesCard(device) {
  const card = h("div", { class: "card" });
  card.appendChild(h("h2", {}, "Names & addresses"));

  const names = device.names || [];
  if (names.length > 0) {
    const namesList = h("ul", { class: "names-list" });
    for (const n of names) {
      const li = h("li", {});
      li.appendChild(h("span", { class: "name-value" }, n.name));
      li.appendChild(h("span", { class: "source-badge" }, n.source || ""));
      namesList.appendChild(li);
    }
    card.appendChild(namesList);
  } else {
    card.appendChild(h("p", {}, "No names recorded"));
  }

  const ips = device.ips || [];
  if (ips.length > 0) {
    const ipList = h("ul", { class: "ip-list" });
    for (const ip of ips) {
      const li = h("li", {});
      li.appendChild(h("span", { class: "mono" }, ip.ip));
      li.appendChild(h("span", { class: "ip-seen" }, fmtTime(ip.last_seen)));
      ipList.appendChild(li);
    }
    card.appendChild(ipList);
  } else {
    card.appendChild(h("p", {}, "No IP history"));
  }

  return card;
}

// Delete the device. A device that is still on the network is added again by the next scan,
// so the confirmation offers to ignore it as well. `onOpenChange` tells the page not to refresh
// itself (and close the box) while the confirmation is open.
function buildDeleteCard(device, onOpenChange) {
  const card = h("div", { class: "card" });
  card.appendChild(h("h2", {}, "Delete device"));
  const name = device.name || device.primary_ip || "this device";
  card.appendChild(h("p", { class: "hint" },
    "Removes the device with its ports, names, uptime history and links. Scans add it back if it is still on the network, unless you ignore it."));

  const openBtn = h("button", { class: "btn danger", type: "button" }, "Delete device…");
  const box = h("div", { class: "confirm-box", hidden: true });
  const ignoreInput = h("input", { type: "checkbox", name: "ignore", checked: !!device.online });
  const errorEl = h("p", { class: "error" }, "");
  const confirmBtn = h("button", { class: "btn danger", type: "button" }, "Delete");
  const cancelBtn = h("button", { class: "btn", type: "button" }, "Cancel");

  box.appendChild(h("p", {}, `Delete ${name}? This cannot be undone.`));
  box.appendChild(h("label", { class: "check" }, ignoreInput, " Also ignore it in future scans"));
  box.appendChild(h("p", { class: "hint" }, device.online
    ? "It is online right now, so without this the next scan would add it again."
    : "It is offline. Tick this if it should never be added back, even when it appears again."));
  box.appendChild(errorEl);
  box.appendChild(h("div", { class: "btn-row" }, confirmBtn, cancelBtn));

  openBtn.addEventListener("click", () => {
    box.hidden = false;
    openBtn.hidden = true;
    onOpenChange(true);
  });
  cancelBtn.addEventListener("click", () => {
    box.hidden = true;
    openBtn.hidden = false;
    errorEl.textContent = "";
    onOpenChange(false);
  });
  confirmBtn.addEventListener("click", async () => {
    confirmBtn.disabled = true;
    cancelBtn.disabled = true;
    errorEl.textContent = "";
    try {
      await del(`/api/devices/${device.id}?ignore=${ignoreInput.checked}`);
    } catch (err) {
      errorEl.textContent = err.message || "Could not delete the device";
      confirmBtn.disabled = false;
      cancelBtn.disabled = false;
      return;
    }
    onOpenChange(false);
    toast(ignoreInput.checked ? `${name} deleted and ignored` : `${name} deleted`, "success");
    window.location.hash = "#/devices";
  });

  card.appendChild(openBtn);
  card.appendChild(box);
  return card;
}

function buildEventsCard(device) {
  const card = h("div", { class: "card" });
  card.appendChild(h("h2", {}, "Recent events"));

  const events = device.events || [];
  if (events.length === 0) {
    card.appendChild(h("p", {}, "No events"));
    return card;
  }

  const list = h("ul", { class: "events-list" });
  for (const ev of events) {
    const li = h("li", { class: "event" });
    li.appendChild(h("span", { class: "event-time" }, timeAgo(ev.ts)));
    li.appendChild(h("span", { class: "event-kind" }, ev.kind));
    li.appendChild(h("span", { class: "event-detail" }, ev.detail || ""));
    list.appendChild(li);
  }
  card.appendChild(list);

  return card;
}

// A heading button that runs one action and shows its answer in a toast.
function actionButton(label, title, run, id) {
  const btn = h("button", { class: "btn admin-only", type: "button", title, id: `action-${id}` }, label);
  btn.addEventListener("click", async () => {
    btn.disabled = true;
    btn.textContent = `${label}…`;
    try {
      toast(await run(), "info");
    } catch (err) {
      toast(err.message || `${label} failed`, "error");
    } finally {
      btn.disabled = false;
      btn.textContent = label;
    }
  });
  return btn;
}

function buildNotFound() {
  const card = h("div", { class: "card" });
  card.appendChild(h("h2", {}, "Device not found"));
  const link = h("a", { href: "#/devices" }, "← Devices");
  card.appendChild(link);
  return card;
}

export async function render(container, params) {
  let disposed = false;
  let loading = false;
  let failing = false;
  let editResult = null;
  let deleteOpen = false;
  let terminalSlot = null;
  let terminalHandle = null;

  const disposeTerminal = () => {
    if (terminalHandle && typeof terminalHandle.dispose === "function") {
      terminalHandle.dispose();
    }
    terminalHandle = null;
  };

  // Builds the whole page off-screen and swaps it in, so a refresh never
  // leaves half a page or two copies of it in the container.
  async function show(device) {
    const page = h("div", {});

    const heading = h("div", { class: "heading-row" });
    heading.appendChild(statusDot(device.online));
    heading.appendChild(h("h1", { title: device.name || null }, shortName(device.name) || device.primary_ip || "Unknown"));
    heading.appendChild(typeBadge(device.type));
    heading.appendChild(h("a", { href: "#/devices" }, "← Devices"));
    if (device.primary_ip) {
      const scanBtn = h("button", {
        class: "btn admin-only",
        type: "button",
        title: "All 65535 TCP ports, service versions, OS detection and traceroute for this host only. Can take a few minutes.",
        onclick: async () => {
          scanBtn.disabled = true;
          try {
            await post(`/api/devices/${device.id}/scan`);
            toast(`Full scan of ${device.primary_ip} started. Progress is shown under the top bar.`, "info");
          } catch (err) {
            toast(err instanceof ApiError && err.status === 409 ? "A scan is already running" : (err.message || "Could not start the scan"), "error");
          } finally {
            scanBtn.disabled = false;
          }
        },
      }, "Full scan");
      heading.appendChild(scanBtn);
      heading.appendChild(actionButton("Ping", "Is the device answering right now?", async () => {
        const r = await post(`/api/devices/${device.id}/ping`);
        return r.up ? `${device.primary_ip} answers${r.rtt_ms != null ? ` (${r.rtt_ms.toFixed(1)} ms)` : ""}` : `${device.primary_ip} does not answer`;
      }, "ping"));
      heading.appendChild(actionButton("Trace", "The hops between Netlens and this device", async () => {
        const r = await post(`/api/devices/${device.id}/trace`);
        if (!r.up) return `${device.primary_ip} does not answer`;
        return r.hops.length ? `Route: ${r.hops.join(" → ")} → ${device.primary_ip}` : `${device.primary_ip} is on the same network (no hops)`;
      }, "trace"));
    }
    if (device.mac) {
      heading.appendChild(actionButton("Wake", "Send a Wake-on-LAN packet to this device's MAC address", async () => {
        await post(`/api/devices/${device.id}/wake`);
        return "Wake-on-LAN packet sent. The device must have Wake-on-LAN enabled; it shows online after the next scan.";
      }, "wake"));
    }
    page.appendChild(heading);

    const grid = h("div", { class: "grid-2" });
    const left = h("div", { class: "col-left" });
    left.appendChild(buildDetailsCard(device));
    const why = buildWhyCard(device);
    if (why) left.appendChild(why);
    left.appendChild(buildPortsCard(device, () => load()));
    const newSlot = h("div", { id: "terminal-slot", class: "terminal-slot" });
    left.appendChild(newSlot);  // the console is the last card of the left column
    grid.appendChild(left);

    const right = h("div", { class: "col-right" });
    const uptimeSlot = h("div", {});
    right.appendChild(uptimeSlot);
    buildDeviceUptimeCard(device.id).then((c) => {
      if (disposed) return;
      if (isAdmin()) {
        const section = buildStabilitySection(device);
        section.classList.add("admin-only");
        c.appendChild(section);
      }
      uptimeSlot.appendChild(c);
    }).catch(() => {});
    const servicesSlot = h("div", {});
    right.appendChild(servicesSlot);
    buildDeviceServicesCard(device).then((c) => { if (!disposed) servicesSlot.appendChild(c); }).catch(() => {});
    const wifiSlot = h("div", {});
    right.appendChild(wifiSlot);
    buildDeviceWifiCard(device.id).then((c) => { if (c && !disposed) wifiSlot.appendChild(c); }).catch(() => {});
    const virtualizationCard = buildVirtualizationCard(device);
    if (virtualizationCard) right.appendChild(virtualizationCard);
    const newEdit = buildEditCard(device, () => load());
    newEdit.card.classList.add("admin-only");
    right.appendChild(newEdit.card);
    buildParentCard(device, (message) => { toast(message, "success"); load(); })
      .then((c) => { if (!disposed) newEdit.parentSlot.appendChild(c); })
      .catch(() => {});
    right.appendChild(buildNamesCard(device));
    right.appendChild(buildEventsCard(device));
    const deleteCard = buildDeleteCard(device, (open) => { deleteOpen = open; });
    deleteCard.classList.add("admin-only");
    right.appendChild(deleteCard);
    grid.appendChild(right);
    page.appendChild(grid);

    disposeTerminal();
    editResult = newEdit;
    terminalSlot = newSlot;
    clear(container);
    container.appendChild(page);

    if (!isAdmin()) return; // the terminal is for administrators
    try {
      // "Wide view" lifts the console above both columns, "Narrow view" puts it back under the details
      const placeWide = (wide) => {
        if (wide) page.insertBefore(newSlot, grid);
        else left.appendChild(newSlot);
      };
      const handle = await mountTerminal(newSlot, device, { onWideChange: placeWide });
      if (disposed || terminalSlot !== newSlot) {
        if (handle && typeof handle.dispose === "function") handle.dispose();
      } else {
        terminalHandle = handle;
        // jump straight to the console from the top of the page
        for (const p of (handle && handle.protos) || []) {
          heading.appendChild(h("button", {
            class: "btn admin-only",
            type: "button",
            id: `jump-${p.proto}`,
            title: `Open the ${p.proto.toUpperCase()} console below`,
            onclick: () => handle.open(p.proto),
          }, p.proto === "ssh" ? "SSH" : "Telnet"));
        }
      }
    } catch (err) {
      if (!disposed) toast("Terminal failed to load", "error");
    }
  }

  async function load() {
    if (loading || disposed) return;
    loading = true;
    try {
      const device = await get(`/api/devices/${params.id}`);
      try {
        groupChoices = (await get("/api/groups")).groups;
      } catch (e) {
        groupChoices = [];
      }
      if (disposed) return;
      failing = false;
      await show(device);
    } catch (err) {
      if (disposed) return;
      if (err instanceof ApiError && err.status === 404) {
        disposeTerminal();
        clear(container);
        container.appendChild(buildNotFound());
        return;
      }
      // Report a failure once, not on every refresh while it persists.
      if (!failing) toast("Failed to load device", "error");
      failing = true;
    } finally {
      loading = false;
    }
  }

  await load();

  const interval = setInterval(() => {
    if (terminalSlot && isTerminalActive(terminalSlot)) return;
    if (isStabilityOpen()) return;
    if (editResult && (editResult.isDirty() || editResult.isFocused())) return;
    if (deleteOpen) return;
    load();
  }, 20000);

  // show the result of a (full) scan as soon as it is done
  const onScanFinished = () => {
    if (deleteOpen || isStabilityOpen() || (terminalSlot && isTerminalActive(terminalSlot))) return;
    if (editResult && (editResult.isDirty() || editResult.isFocused())) return;
    load();
  };
  document.addEventListener("netlens:scan-finished", onScanFinished);

  return () => {
    disposed = true;
    clearInterval(interval);
    document.removeEventListener("netlens:scan-finished", onScanFinished);
    disposeTerminal();
  };
}
