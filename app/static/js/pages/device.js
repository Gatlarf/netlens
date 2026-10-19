import { get, patch, post, del, ApiError } from "../api.js";
import { h, clear, fmtTime, timeAgo, typeBadge, statusDot, toast, TYPE_LABELS, shortName, isAdmin, vendorText, vendorTitle } from "../util.js";
import { eventLabel } from "../event_labels.js";
import { mountTerminal, isTerminalActive } from "../terminal.js";
import { buildDeviceUptimeCard } from "../cards/device_uptime.js";
import { buildPerformanceCard } from "../cards/performance.js";
import { buildDeviceMonitorCard, isMonitorFormOpen } from "../cards/device_monitor.js";
import { buildHealthGlance } from "../cards/health_glance.js";
import { buildDevicePortsCard, PORT_METRICS } from "../cards/device_ports.js";
import { buildDeviceWifiCard } from "../cards/device_wifi.js";
import { buildDeviceServicesCard } from "../cards/device_services.js";
import { stateDot } from "./services.js";
import { buildParentCard } from "../cards/device_parent.js";
import { buildDeviceSitesCards } from "../cards/proxy_sites.js";
import { buildDeviceVulnCard } from "../cards/vulns.js";
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
  const top = info.evidence && info.evidence[0];
  const card = h("details", { class: "card", id: "why-card", open: !top });       // folded while Netlens has a clear answer
  card.appendChild(h("summary", {}, h("h2", { class: "inline-h2" }, "Why this type?"), top ? h("span", { class: "hint" }, ` ${TYPE_LABELS[top.type] || top.type}: ${top.why}`) : null));
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

// The service check that watches this port of this device, if there is one.
function checkForPort(checks, port) {
  return checks.find((c) => (c.kind === "tcp" || c.kind === "http") && c.port === port.port && (port.proto || "tcp") === "tcp") || null;
}

// What "Add" creates for an open port: a web check on the usual web ports (80, 443, 8080, 8443; the scheme follows the port), a plain port check on the rest.
function checkFor(device, p) {
  const web = [80, 443, 8080, 8443].includes(p.port) && /http|www/i.test(p.service || "http");
  const label = p.service && p.service !== "unknown" ? p.service : `port ${p.port}`;
  const name = `${device.custom_name || device.hostname || device.primary_ip} ${label}`.slice(0, 100);
  return web ? { device_id: device.id, name, kind: "http", host: device.primary_ip, port: p.port, path: "/", expect: "alive" }
    : { device_id: device.id, name, kind: "tcp", host: device.primary_ip, port: p.port };
}

function buildPortsCard(device, onChanged) {
  const card = h("div", { class: "card" });
  card.appendChild(h("h2", {}, "Open ports"));

  const table = h("table", { class: "data" });
  const thead = h("thead");
  const headRow = h("tr");
  const owners = containerPortOwners(device);
  const withOwner = owners.size > 0;
  ["Port", "Proto", "Service", "Product", "Version", "State", ...(withOwner ? ["Container"] : []), "Check"].forEach((col) => {
    headRow.appendChild(h("th", {}, col));
  });
  thead.appendChild(headRow);
  table.appendChild(thead);

  const tbody = h("tbody");
  const checkCells = [];
  const ports = device.ports || [];
  if (ports.length === 0) {
    const emptyRow = h("tr");
    const emptyCell = h("td", { colspan: withOwner ? "8" : "7" }, "No open ports");
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
      const checkCell = h("td", { class: "port-check" });
      row.appendChild(checkCell);
      checkCells.push([p, checkCell]);
      tbody.appendChild(row);
    }
  }
  table.appendChild(tbody);
  if (checkCells.length && device.primary_ip) {
    get(`/api/service-checks?device_id=${device.id}`).then((checks) => {
      for (const [p, cell] of checkCells) {
        if ((p.proto || "tcp") !== "tcp") continue;     // service checks connect over TCP
        const existing = checkForPort(checks, p);
        if (existing) {
          const remove = h("button", { type: "button", class: "btn admin-only", title: `Stop watching ${existing.target}` }, "Remove check");
          remove.addEventListener("click", async () => {
            remove.disabled = true;
            try { await del(`/api/service-checks/${existing.id}`); toast("Check removed", "success"); onChanged(); } catch (err) { toast(err.message || "Failed", "error"); remove.disabled = false; }
          });
          cell.append(stateDot(existing), " ", remove);
        } else {
          const add = h("button", { type: "button", class: "btn admin-only", title: "Watch this port with a service check" }, "Add check");
          add.addEventListener("click", async () => {
            add.disabled = true;
            try { await post("/api/service-checks", checkFor(device, p)); toast("Check added", "success"); onChanged(); } catch (err) { toast(err.message || "Failed", "error"); add.disabled = false; }
          });
          cell.appendChild(add);
        }
      }
    }).catch(() => {});
  }
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
  notifyField.appendChild(h("label", { title: "Needs an alert channel (for example e-mail) under Settings." }, notifyInput, " Alert me when it goes offline"));
  form.appendChild(notifyField);

  const alwaysField = h("div", { class: "field" });
  const alwaysInput = h("input", { type: "checkbox", name: "always_on", checked: device.always_on === true });
  alwaysField.appendChild(h("label", { title: "Tick it for devices that should be on all the time (router, switch, server, NAS, camera). The Uptime page and the dashboard can then show the availability of these core devices separately from phones, tablets and laptops that come and go." }, alwaysInput, " Always-on device (should always be online)"));
  form.appendChild(alwaysField);

  const excludeField = h("div", { class: "field" });
  const excludeInput = h("input", { type: "checkbox", name: "report_exclude", checked: device.report_exclude === true });
  excludeField.appendChild(h("label", { title: "The weekly and monthly reports leave this device out: its outages and availability do not count. Use it for a test machine or a phone that comes and goes." }, excludeInput, " Leave out of reports"));
  form.appendChild(excludeField);

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

  const fields = [nameInput, typeSelect, groupSelect, tagsInput, notesTextarea, notifyInput, alwaysInput, excludeInput, trustInput, dnsMode, dnsName];
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
      always_on: alwaysInput.checked,
      report_exclude: excludeInput.checked,
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
  else if (d.update_available && !d.image_checked) card.appendChild(kvRow("Update", h("span", { class: "tag unknown-tag" }, "update available")));
  if (d.tags) card.appendChild(kvRow("Tags", h("span", {}, d.tags)));
  if (d.autostart !== undefined) card.appendChild(kvRow("Starts at boot", h("span", {}, d.autostart ? "yes" : "no")));
  if (d.image) {
    const age = d.image_created ? imageAge(d.image_created) : null;
    card.appendChild(kvRow("Image", h("span", {}, d.image, age ? h("span", { class: age.old ? "tag unknown-tag" : "hint", title: "When the image was built" }, ` built ${age.text}`) : null,
      d.image_checked ? (d.update_available ? h("span", { class: "tag unknown-tag", title: "The registry now serves a different image for this tag" }, "newer image available") : h("span", { class: "hint", title: "Same as what the registry serves for this tag" }, " · up to date")) : null)));
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

// The newest backup of this guest, from a backup plugin (Proxmox Backup Server ...)
function buildBackupCard(device) {
  const b = device.guest_backup;
  if (!b) return null;
  const card = h("div", { class: "card" }, h("h2", {}, "Backup"));
  const days = b.age_s === null ? "never" : b.age_s < 3600 ? `${Math.max(1, Math.round(b.age_s / 60))} min ago` : b.age_s < 172800 ? `${Math.round(b.age_s / 3600)} h ago` : `${Math.round(b.age_s / 86400)} days ago`;
  const state = b.last_state === "failed" ? h("span", { class: "error" }, "last backup failed") : b.late ? h("span", { class: "warn-text" }, "late") : h("span", { class: "run-ok" }, "up to date");
  card.appendChild(kvRow("State", state));
  card.appendChild(kvRow("Newest backup", h("span", { title: b.last_backup || "" }, days)));
  card.appendChild(kvRow("Copies kept", h("span", {}, String(b.count))));
  if (b.verify_state !== "none") card.appendChild(kvRow("Verified", h("span", {}, b.verify_state === "ok" ? "yes" : "failed")));
  card.appendChild(kvRow("Reported by", h("span", {}, b.plugin_id)));
  card.appendChild(h("p", { class: "hint" }, h("a", { href: "#/backups" }, "All backups")));
  return card;
}

function buildSmartHomeCard(device) {
  const d = device.smarthome;
  if (!d) return null;
  const card = h("div", { class: "card" }, h("h2", {}, "Smart home"));
  card.appendChild(kvRow("State", d.available ? h("span", { class: "run-ok" }, "available") : h("span", { class: "error" }, "unavailable")));
  if (d.manufacturer || d.model) card.appendChild(kvRow("Model", h("span", {}, [d.manufacturer, d.model].filter(Boolean).join(" "))));
  if (d.area) card.appendChild(kvRow("Area", h("span", {}, d.area)));
  if (d.sw) card.appendChild(kvRow("Firmware", h("span", {}, d.sw)));
  if (d.protocol) card.appendChild(kvRow("Protocol", h("span", {}, d.protocol)));
  if (d.battery !== null && d.battery !== undefined) card.appendChild(kvRow("Battery", h("span", { class: d.battery_low ? "warn-text" : "" }, `${d.battery}%`)));
  if (d.update) card.appendChild(kvRow("Update", h("span", { class: "warn-text" }, "available")));
  if (d.via) card.appendChild(kvRow("Paired through", h("span", {}, d.via)));
  card.appendChild(h("p", { class: "hint" }, `Reported by ${d.plugin_id}. `, h("a", { href: "#/smarthome" }, "All smart-home devices")));
  return card;
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

  const v6 = device.ipv6 || [];
  if (v6.length > 0) {
    card.appendChild(h("h3", {}, "IPv6 addresses"));
    const SCOPE = { global: "global", ula: "private (ULA)", link: "link-local" };
    const list = h("ul", { class: "ip-list" });
    for (const a of v6) {
      list.appendChild(h("li", {}, h("span", { class: "mono" }, a.ip), h("span", { class: "hint" }, ` ${SCOPE[a.scope] || a.scope}`), h("span", { class: "ip-seen" }, fmtTime(a.last_seen))));
    }
    card.appendChild(list);
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
    li.appendChild(h("span", { class: "event-kind" }, eventLabel(ev.kind)));
    if (ev.maintenance) li.appendChild(h("span", { class: "badge maint", title: "Held back by a maintenance window" }, `maintenance: ${ev.maintenance}`));
    li.appendChild(h("span", { class: "event-detail" }, ev.detail || ""));
    list.appendChild(li);
  }
  card.appendChild(list);

  return card;
}

// "Maintenance": hold back the alarms about this device (and the devices behind it) for a while, e.g. before a planned reboot.
function maintenanceButton(device, reload) {
  const select = h("select", { class: "admin-only", "aria-label": "Start maintenance for", title: "Hold back offline alarms for this device and the devices behind it" },
    h("option", { value: "" }, "Maintenance…"), h("option", { value: "30" }, "30 minutes"), h("option", { value: "60" }, "1 hour"),
    h("option", { value: "240" }, "4 hours"), h("option", { value: "1440" }, "24 hours"));
  select.addEventListener("change", async () => {
    const minutes = Number(select.value);
    select.value = "";
    if (!minutes) return;
    try {
      await post("/api/maintenance/now", { device_ids: [device.id], minutes, behind: true });
      toast(`Maintenance started for ${minutes >= 60 ? `${minutes / 60} h` : `${minutes} min`}. End it under Settings → Maintenance windows.`, "success");
      reload();
    } catch (err) {
      toast(err.message || "Could not start maintenance", "error");
    }
  });
  return select;
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
  let activeTab = "overview";
  try {      // the dashboard's health card opens the device on its Health tab
    const wanted = sessionStorage.getItem("netlens.devicetab");
    if (wanted) { activeTab = wanted; sessionStorage.removeItem("netlens.devicetab"); }
  } catch (e) { /* no storage */ }     // the chosen section stays when the page refreshes itself

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
    if (device.maintenance) heading.appendChild(h("span", { class: "badge maint", title: "Alarms about this device are held back right now" }, `In maintenance: ${device.maintenance}`));
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
    heading.appendChild(maintenanceButton(device, () => load()));
    if (device.mac) {
      heading.appendChild(actionButton("Wake", "Send a Wake-on-LAN packet to this device's MAC address", async () => {
        await post(`/api/devices/${device.id}/wake`);
        return "Wake-on-LAN packet sent. The device must have Wake-on-LAN enabled; it shows online after the next scan.";
      }, "wake"));
    }
    page.appendChild(heading);

    // The page is split into sections behind a tab bar, so the health graphs are one click away
    // instead of far down a long page. `panels` keeps every section in the page; only one is visible.
    const panels = {};
    const column = () => h("div", { class: "col-left" });
    const twoColumns = (a, b) => h("div", { class: "grid-2" }, a, b);
    const slot = () => h("div", {});

    // Overview: who it is, whether it is up, what happened lately
    const ovLeft = column();
    ovLeft.appendChild(buildDetailsCard(device));
    const why = buildWhyCard(device);
    if (why) ovLeft.appendChild(why);
    const ovRight = column();
    const uptimeSlot = slot();
    ovRight.appendChild(uptimeSlot);
    buildDeviceUptimeCard(device.id).then((c) => {
      if (disposed) return;
      if (isAdmin()) {
        const section = buildStabilitySection(device);
        section.classList.add("admin-only");
        c.appendChild(section);
      }
      uptimeSlot.appendChild(c);
    }).catch(() => {});
    const vulnSlot = slot();
    ovRight.appendChild(vulnSlot);
    buildDeviceVulnCard(device).then((c) => { if (c && !disposed) vulnSlot.appendChild(c); }).catch(() => {});
    ovRight.appendChild(buildEventsCard(device));
    panels.overview = twoColumns(ovLeft, ovRight);

    // Health: the graphs first, then how it is read and the service checks
    const health = h("div", { class: "dev-health" });
    const performanceSlot = slot();
    health.appendChild(performanceSlot);
    const portsSlot = slot();
    health.insertBefore(portsSlot, performanceSlot);
    // a switch with many ports gets a table of ports; its per-port graphs are then left out of the general graphs
    buildDevicePortsCard(device).catch(() => null).then((ports) => {
      if (ports && !disposed) portsSlot.appendChild(ports);
      return buildPerformanceCard("device", device.id, { unlessOnly: ["up", "rtt_ms"], skip: ports ? ["up", "storage_status", "service_stopped", ...PORT_METRICS] : ["up", "storage_status", "service_stopped"] });
    }).then((c) => { if (c && !disposed) performanceSlot.appendChild(c); }).catch(() => {});
    const hLeft = column();
    const hRight = column();
    if (isAdmin()) {
      const monitorSlot = slot();
      hLeft.appendChild(monitorSlot);
      buildDeviceMonitorCard(device, { onChange: () => load() }).then((c) => { if (c && !disposed) monitorSlot.appendChild(c); }).catch(() => {});
    }
    const servicesSlot = slot();
    hRight.appendChild(servicesSlot);
    buildDeviceServicesCard(device).then((c) => { if (!disposed) servicesSlot.appendChild(c); }).catch(() => {});
    health.appendChild(twoColumns(hLeft, hRight));
    panels.health = health;

    // Network: ports, names, Wi-Fi, virtual machines, proxied sites
    const nLeft = column();
    nLeft.appendChild(buildPortsCard(device, () => load()));
    const nRight = column();
    const wifiSlot = slot();
    nRight.appendChild(wifiSlot);
    buildDeviceWifiCard(device.id).then((c) => { if (c && !disposed) wifiSlot.appendChild(c); }).catch(() => {});
    const virtualizationCard = buildVirtualizationCard(device);
    if (virtualizationCard) nRight.appendChild(virtualizationCard);
    const backupCard = buildBackupCard(device);
    if (backupCard) nRight.appendChild(backupCard);
    const smartCard = buildSmartHomeCard(device);
    if (smartCard) nRight.appendChild(smartCard);
    for (const siteCard of buildDeviceSitesCards(device)) nRight.appendChild(siteCard);
    nRight.appendChild(buildNamesCard(device));
    panels.network = twoColumns(nLeft, nRight);

    // Console (administrators)
    // a console that is in use is moved into the new page as it is: a refresh must not drop the session
    const keepConsole = !!(terminalSlot && terminalHandle && isTerminalActive(terminalSlot));
    const newSlot = keepConsole ? terminalSlot : h("div", { id: "terminal-slot", class: "terminal-slot" });
    if (isAdmin()) panels.console = newSlot;

    // Settings (administrators): edit, parent, delete
    const newEdit = buildEditCard(device, () => load());
    newEdit.card.classList.add("admin-only");
    if (isAdmin()) {
      const sLeft = column();
      sLeft.appendChild(newEdit.card);
      const sRight = column();
      const deleteCard = buildDeleteCard(device, (open) => { deleteOpen = open; });
      deleteCard.classList.add("admin-only");
      sRight.appendChild(deleteCard);
      panels.settings = twoColumns(sLeft, sRight);
      buildParentCard(device, (message) => { toast(message, "success"); load(); })
        .then((c) => { if (!disposed) newEdit.parentSlot.appendChild(c); })
        .catch(() => {});
    }

    const TABS = [["overview", "Overview"], ["health", "Health"], ["network", "Network"], ["console", "Console"], ["settings", "Settings"]]
      .filter(([key]) => panels[key] && !(document.body.dataset.scoped && key !== "overview"));      // a customer view has the overview only
    if (!panels[activeTab] || document.body.dataset.scoped) activeTab = "overview";
    const tabBar = h("div", { class: "dev-tabs", role: "tablist" });
    const buttons = {};
    const select = (key) => {
      activeTab = key;
      for (const [k, el] of Object.entries(panels)) el.hidden = k !== key;
      for (const [k, b] of Object.entries(buttons)) { b.setAttribute("aria-selected", String(k === key)); b.classList.toggle("active", k === key); }
    };
    for (const [key, label] of TABS) {
      const b = h("button", { type: "button", class: "dev-tab", role: "tab", id: `tab-${key}`, onclick: () => select(key) }, label);
      buttons[key] = b;
      tabBar.appendChild(b);
    }
    page.appendChild(tabBar);
    const strip = h("div", { class: "dev-glance" });
    page.appendChild(strip);
    for (const [key, el] of Object.entries(panels)) {
      el.classList.add("dev-panel");
      page.appendChild(el);
    }
    select(activeTab);
    buildHealthGlance(device, () => select("health")).then((el) => { if (el && !disposed) strip.appendChild(el); }).catch(() => {});

    if (!keepConsole) disposeTerminal();
    editResult = newEdit;
    terminalSlot = newSlot;
    // swap the page in without the scroll position jumping: hold the old height until the cards have filled in
    const oldHeight = container.offsetHeight;
    const scrollY = window.scrollY;
    if (oldHeight) container.style.minHeight = `${oldHeight}px`;
    clear(container);
    container.appendChild(page);
    window.scrollTo(0, scrollY);
    setTimeout(() => { if (!disposed) container.style.minHeight = ""; }, 4000);

    if (!isAdmin()) return; // the terminal is for administrators
    // RDP and VNC open on the Remote access page
    for (const [proto, label] of [["rdp", "RDP"], ["vnc", "VNC"]]) {
      const open = (device.ports || []).some((p) => p.proto === "tcp" && String(p.state || "").startsWith("open")
        && (proto === "rdp" ? p.port === 3389 || ["ms-wbt-server", "rdp"].includes(p.service) : (p.port >= 5900 && p.port <= 5909) || String(p.service || "").includes("vnc")));
      if (open) heading.appendChild(h("a", { class: "btn admin-only", href: `#/remote?device=${device.id}&proto=${proto}`, id: `jump-${proto}`, title: `Open ${label} on the Remote access page` }, label));
    }
    const addConsoleButtons = (handle) => {
      for (const p of (handle && handle.protos) || []) {
        heading.appendChild(h("button", {
          class: "btn admin-only",
          type: "button",
          id: `jump-${p.proto}`,
          title: `Open the ${p.proto.toUpperCase()} console below`,
          onclick: () => { select("console"); handle.open(p.proto); },
        }, p.proto === "ssh" ? "SSH" : "Telnet"));
      }
    };
    if (keepConsole) { addConsoleButtons(terminalHandle); return; }
    try {
      const handle = await mountTerminal(newSlot, device);
      if (disposed || terminalSlot !== newSlot) {
        if (handle && typeof handle.dispose === "function") handle.dispose();
      } else {
        terminalHandle = handle;
        addConsoleButtons(handle);  // jump straight to the console from the top of the page
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
    if (document.hidden) return;
    if (terminalSlot && isTerminalActive(terminalSlot)) return;
    if (isStabilityOpen()) return;
    if (editResult && (editResult.isDirty() || editResult.isFocused())) return;
    if (deleteOpen || isMonitorFormOpen()) return;     // never wipe a form someone is filling in
    load();
  }, 20000);

  // show the result of a (full) scan as soon as it is done
  const onScanFinished = () => {
    if (deleteOpen || isMonitorFormOpen() || isStabilityOpen() || (terminalSlot && isTerminalActive(terminalSlot))) return;
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
