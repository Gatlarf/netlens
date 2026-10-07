import { get, patch, ApiError } from "../api.js";
import { h, clear, fmtTime, timeAgo, typeBadge, statusDot, toast, TYPE_LABELS } from "../util.js";
import { mountTerminal, isTerminalActive } from "../terminal.js";

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

function buildPortsCard(device) {
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
      row.appendChild(h("td", {}, p.state && p.state !== "open" ? p.state : ""));
      tbody.appendChild(row);
    }
  }
  table.appendChild(tbody);
  card.appendChild(table);

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

  const saveBtn = h("button", { type: "submit" }, "Save");
  form.appendChild(saveBtn);

  let dirty = false;
  let focused = false;

  const fields = [nameInput, typeSelect, tagsInput, notesTextarea];
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
    heading.appendChild(h("h1", {}, device.name || device.primary_ip || "Unknown"));
    heading.appendChild(typeBadge(device.type));
    heading.appendChild(h("a", { href: "#/devices" }, "← Devices"));
    page.appendChild(heading);

    const grid = h("div", { class: "grid-2" });
    const left = h("div", { class: "col-left" });
    left.appendChild(buildDetailsCard(device));
    left.appendChild(buildPortsCard(device));
    grid.appendChild(left);

    const right = h("div", { class: "col-right" });
    const newEdit = buildEditCard(device, () => load());
    right.appendChild(newEdit.card);
    right.appendChild(buildNamesCard(device));
    right.appendChild(buildEventsCard(device));
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
    load();
  }, 20000);

  return () => {
    disposed = true;
    clearInterval(interval);
    disposeTerminal();
  };
}
