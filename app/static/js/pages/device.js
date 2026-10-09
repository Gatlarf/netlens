import { get, patch, post, del, ApiError } from "../api.js";
import { h, clear, fmtTime, timeAgo, typeBadge, statusDot, toast, TYPE_LABELS, shortName } from "../util.js";
import { mountTerminal, isTerminalActive } from "../terminal.js";
import { buildDeviceUptimeCard } from "../cards/device_uptime.js";
import { buildDeviceWifiCard } from "../cards/device_wifi.js";
import { buildDeviceServicesCard } from "../cards/device_services.js";
import { buildParentCard } from "../cards/device_parent.js";

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
  card.appendChild(kvRow("Vendor", h("span", {}, device.vendor || "—")));
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

  return card;
}

function buildPortsCard(device, onChanged) {
  const card = h("div", { class: "card" });
  card.appendChild(h("h2", {}, "Open ports"));

  const table = h("table", { class: "data" });
  const thead = h("thead");
  const headRow = h("tr");
  ["Port", "Proto", "Service", "Product", "Version", "State"].forEach((col) => {
    headRow.appendChild(h("th", {}, col));
  });
  thead.appendChild(headRow);
  table.appendChild(thead);

  const tbody = h("tbody");
  const ports = device.ports || [];
  if (ports.length === 0) {
    const emptyRow = h("tr");
    const emptyCell = h("td", { colspan: "6" }, "No open ports");
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
      tbody.appendChild(row);
    }
  }
  table.appendChild(tbody);
  card.appendChild(table);

  const base = device.baseline;
  const box = h("div", { class: "baseline-box" });
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

function buildEditCard(device, onSaved) {
  const card = h("div", { class: "card" });
  card.appendChild(h("h2", {}, "Edit"));

  const form = h("form", { class: "edit-form" });

  const nameField = h("div", { class: "field" });
  nameField.appendChild(h("label", {}, "Custom name"));
  const nameInput = h("input", { type: "text", name: "custom_name", value: device.custom_name || "" });
  nameField.appendChild(nameInput);
  form.appendChild(nameField);

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
  form.appendChild(typeField);

  const tagsField = h("div", { class: "field" });
  tagsField.appendChild(h("label", {}, "Tags"));
  const tagsInput = h("input", { type: "text", name: "tags", value: (device.tags || []).join(", ") });
  tagsField.appendChild(tagsInput);
  form.appendChild(tagsField);

  const notesField = h("div", { class: "field" });
  notesField.appendChild(h("label", {}, "Notes"));
  const notesTextarea = h("textarea", { name: "notes", rows: "4" });
  notesTextarea.value = device.notes || "";
  notesField.appendChild(notesTextarea);
  form.appendChild(notesField);

  const notifyField = h("div", { class: "field" });
  const notifyInput = h("input", { type: "checkbox", name: "notify_offline", checked: device.notify_offline !== false });
  notifyField.appendChild(h("label", {}, notifyInput, " Send an e-mail when this device goes offline"));
  notifyField.appendChild(h("p", { class: "hint" }, "Needs e-mail notifications to be set up under Settings."));
  form.appendChild(notifyField);

  const trustField = h("div", { class: "field" });
  const trustInput = h("input", { type: "checkbox", name: "trusted", checked: device.trusted === true });
  trustField.appendChild(h("label", {}, trustInput, " Known device"));
  trustField.appendChild(h("p", { class: "hint" }, "Tick it for devices you recognise. Devices that appear later start as unknown, so you can spot newcomers."));
  form.appendChild(trustField);

  const saveBtn = h("button", { type: "submit" }, "Save");
  form.appendChild(saveBtn);

  let dirty = false;
  let focused = false;

  const fields = [nameInput, typeSelect, tagsInput, notesTextarea, notifyInput, trustInput];
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
      tags: tagsInput.value.split(",").map((s) => s.trim()).filter(Boolean),
      notes: notesTextarea.value,
      notify_offline: notifyInput.checked,
      trusted: trustInput.checked,
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

  card.appendChild(form);

  return { card, isDirty: () => dirty, isFocused: () => focused };
}

function buildVirtualizationCard(device) {
  const info = device.virtualization;
  if (!info) return null;
  const card = h("div", { class: "card" });
  card.appendChild(h("h2", {}, "Virtualization"));

  if (info.guest) {
    const g = info.guest;
    const kind = g.kind === "lxc" ? "Container (LXC)" : "Virtual machine";
    card.appendChild(kvRow("Runs as", h("span", {}, `${kind} ${g.guest_id}, ${g.name}`)));
    card.appendChild(kvRow("Status", h("span", {}, g.status)));
    if (g.node) card.appendChild(kvRow("Node", h("span", {}, g.node)));
    if (g.host_device_id) {
      card.appendChild(kvRow("Host", h("a", { href: `#/device/${g.host_device_id}` }, g.host_name || `device ${g.host_device_id}`)));
    }
    card.appendChild(kvRow("Reported by", h("span", {}, g.plugin_id)));
  }

  if (info.guests && info.guests.length > 0) {
    card.appendChild(h("p", { class: "hint" }, `Hypervisor host with ${info.guests.length} guest${info.guests.length === 1 ? "" : "s"}:`));
    const table = h("table", { class: "data" });
    const headRow = h("tr");
    ["ID", "Name", "Type", "Status", "Device"].forEach((c) => headRow.appendChild(h("th", {}, c)));
    table.appendChild(h("thead", {}, headRow));
    const tbody = h("tbody");
    for (const g of info.guests) {
      const deviceCell = g.device_id
        ? h("td", {}, h("a", { href: `#/device/${g.device_id}` }, g.device_name || `device ${g.device_id}`))
        : h("td", { class: "hint" }, g.status === "running" ? "not seen on the network" : "not running");
      tbody.appendChild(h("tr", {},
        h("td", {}, String(g.guest_id)), h("td", {}, g.name), h("td", {}, g.kind === "lxc" ? "LXC" : g.kind === "qemu" ? "VM" : g.kind),
        h("td", {}, g.status), deviceCell));
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
        class: "btn",
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
    }
    page.appendChild(heading);

    const grid = h("div", { class: "grid-2" });
    const left = h("div", { class: "col-left" });
    left.appendChild(buildDetailsCard(device));
    left.appendChild(buildPortsCard(device, () => load()));
    grid.appendChild(left);

    const right = h("div", { class: "col-right" });
    const newEdit = buildEditCard(device, () => load());
    right.appendChild(newEdit.card);
    const parentSlot = h("div", {});
    right.appendChild(parentSlot);
    buildParentCard(device, (message) => { toast(message, "success"); load(); })
      .then((c) => { if (!disposed) parentSlot.appendChild(c); })
      .catch(() => {});
    const virtualizationCard = buildVirtualizationCard(device);
    if (virtualizationCard) right.appendChild(virtualizationCard);
    const uptimeSlot = h("div", {});
    right.appendChild(uptimeSlot);
    buildDeviceUptimeCard(device.id).then((c) => { if (!disposed) uptimeSlot.appendChild(c); }).catch(() => {});
    const servicesSlot = h("div", {});
    right.appendChild(servicesSlot);
    buildDeviceServicesCard(device).then((c) => { if (!disposed) servicesSlot.appendChild(c); }).catch(() => {});
    const wifiSlot = h("div", {});
    right.appendChild(wifiSlot);
    buildDeviceWifiCard(device.id).then((c) => { if (c && !disposed) wifiSlot.appendChild(c); }).catch(() => {});
    right.appendChild(buildNamesCard(device));
    right.appendChild(buildEventsCard(device));
    right.appendChild(buildDeleteCard(device, (open) => { deleteOpen = open; }));
    grid.appendChild(right);
    page.appendChild(grid);

    const newSlot = h("div", { id: "terminal-slot", class: "terminal-slot" });
    page.appendChild(newSlot);

    disposeTerminal();
    editResult = newEdit;
    terminalSlot = newSlot;
    clear(container);
    container.appendChild(page);

    try {
      const handle = await mountTerminal(newSlot, device);
      if (disposed || terminalSlot !== newSlot) {
        if (handle && typeof handle.dispose === "function") handle.dispose();
      } else {
        terminalHandle = handle;
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
    if (editResult && (editResult.isDirty() || editResult.isFocused())) return;
    if (deleteOpen) return;
    load();
  }, 20000);

  // show the result of a (full) scan as soon as it is done
  const onScanFinished = () => {
    if (deleteOpen || (terminalSlot && isTerminalActive(terminalSlot))) return;
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
