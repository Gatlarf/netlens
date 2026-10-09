import { get, post } from "../api.js";
import { h, clear, toast, fmtTime, timeAgo, debounce, typeBadge, statusDot, TYPE_LABELS, shortName } from "../util.js";

const REFRESH_MS = 15000;

const SORT_KEYS = [
  { key: "online", label: "Status", sortable: true },
  { key: "name", label: "Name", sortable: true },
  { key: "primary_ip", label: "IP", sortable: true },
  { key: "mac", label: "MAC", sortable: true },
  { key: "vendor", label: "Vendor", sortable: true },
  { key: "type", label: "Type", sortable: true },
  { key: "os_name", label: "OS", sortable: true },
  { key: "open_ports", label: "Open ports", sortable: true },
  { key: "last_seen", label: "Last seen", sortable: true }
];

function ipToNum(ip) {
  if (!ip) return -1;
  const parts = String(ip).split(".");
  if (parts.length !== 4) return -1;
  let n = 0;
  for (const p of parts) {
    const v = parseInt(p, 10);
    if (Number.isNaN(v)) return -1;
    n = n * 256 + v;
  }
  return n;
}

function sortValue(device, key) {
  switch (key) {
    case "online":
      return device.online ? 1 : 0;
    case "name":
      return String(device.name || "").toLowerCase();
    case "primary_ip":
      return ipToNum(device.primary_ip);
    case "mac":
      return String(device.mac || "").toLowerCase();
    case "vendor":
      return String(device.vendor || "").toLowerCase();
    case "type":
      return String(device.type || "").toLowerCase();
    case "os_name":
      return String(device.os_name || "").toLowerCase();
    case "open_ports":
      return Number(device.open_ports) || 0;
    case "last_seen":
      return String(device.last_seen || "");
    default:
      return "";
  }
}

function compare(a, b, key, dir) {
  const va = sortValue(a, key);
  const vb = sortValue(b, key);
  let cmp;
  if (typeof va === "number" && typeof vb === "number") {
    cmp = va - vb;
  } else {
    cmp = String(va).localeCompare(String(vb));
  }
  return dir === "desc" ? -cmp : cmp;
}

function buildToolbar(state) {
  const toolbar = h("div", { class: "toolbar" });

  const search = h("input", {
    type: "search",
    placeholder: "Search name, IP, MAC, vendor…",
    value: state.q
  });
  search.addEventListener("input", debounce(() => {
    state.q = search.value;
    load();
  }, 250));
  toolbar.appendChild(search);

  const statusSel = h("select", { "aria-label": "Status filter" });
  statusSel.appendChild(h("option", { value: "" }, "All"));
  statusSel.appendChild(h("option", { value: "true" }, "Online"));
  statusSel.appendChild(h("option", { value: "false" }, "Offline"));
  statusSel.value = state.online;
  statusSel.addEventListener("change", () => {
    state.online = statusSel.value;
    load();
  });
  toolbar.appendChild(statusSel);

  const typeSel = h("select", { "aria-label": "Type filter" });
  typeSel.appendChild(h("option", { value: "" }, "All"));
  for (const key of Object.keys(TYPE_LABELS)) {
    typeSel.appendChild(h("option", { value: key }, TYPE_LABELS[key]));
  }
  typeSel.value = state.type;
  typeSel.addEventListener("change", () => {
    state.type = typeSel.value;
    load();
  });
  toolbar.appendChild(typeSel);

  const trustSel = h("select", { "aria-label": "Known or unknown devices", class: "trust-filter" });
  trustSel.appendChild(h("option", { value: "" }, "Known and unknown"));
  trustSel.appendChild(h("option", { value: "false" }, "Unknown only"));
  trustSel.appendChild(h("option", { value: "true" }, "Known only"));
  trustSel.value = state.trusted;
  trustSel.addEventListener("change", () => {
    state.trusted = trustSel.value;
    load();
  });
  toolbar.appendChild(trustSel);

  const portsSel = h("select", { "aria-label": "Ports compared with the baseline", class: "ports-filter" });
  portsSel.appendChild(h("option", { value: "" }, "Any ports"));
  portsSel.appendChild(h("option", { value: "changed" }, "Ports changed from baseline"));
  portsSel.appendChild(h("option", { value: "baseline" }, "With a baseline"));
  portsSel.appendChild(h("option", { value: "none" }, "Without a baseline"));
  portsSel.value = state.ports;
  portsSel.addEventListener("change", () => {
    state.ports = portsSel.value;
    load();
  });
  toolbar.appendChild(portsSel);

  const trustAll = h("button", { type: "button", class: "btn trust-all admin-only", title: "Mark every device on the list as known" }, "Trust all unknown");
  trustAll.addEventListener("click", async () => {
    const unknown = devices.filter((d) => !d.trusted);
    if (!unknown.length) {
      toast("Every device here is already known", "info");
      return;
    }
    if (!window.confirm(`Mark ${unknown.length} device(s) as known? New devices that appear later will still be flagged as unknown.`)) return;
    try {
      const res = await post("/api/devices/trust", { ids: unknown.map((d) => d.id) });
      toast(`${res.changed} device(s) marked as known`, "success");
      load();
    } catch (err) {
      toast(err.message || "Could not mark the devices", "error");
    }
  });
  toolbar.appendChild(trustAll);

  const baselineAll = h("button", { type: "button", class: "btn baseline-all admin-only", title: "Take the open ports of the listed devices without a baseline as their normal ones" }, "Set baselines");
  baselineAll.addEventListener("click", async () => {
    const without = devices.filter((d) => d.ports_drift === null);
    if (!without.length) {
      toast("Every device here already has a baseline", "info");
      return;
    }
    if (!window.confirm(`Take the current open ports of ${without.length} device(s) as normal? Netlens then reports ports that appear or vanish.`)) return;
    try {
      const res = await post("/api/devices/baseline", { ids: without.map((d) => d.id) });
      toast(`${res.changed} baseline(s) saved`, "success");
      load();
    } catch (err) {
      toast(err.message || "Could not save the baselines", "error");
    }
  });
  toolbar.appendChild(baselineAll);

  const count = h("span", { class: "count" }, "0 devices");
  toolbar.appendChild(count);

  const csv = h("a", { href: "/api/export/devices.csv", download: "devices.csv" }, "Export CSV");
  const json = h("a", { href: "/api/export/devices.json", download: "devices.json" }, "Export JSON");
  toolbar.appendChild(csv);
  toolbar.appendChild(json);

  return { toolbar, count };
}

function buildTable(state) {
  const table = h("table", { class: "data" });
  const thead = h("thead");
  const tr = h("tr");
  for (const col of SORT_KEYS) {
    const th = h("th", {
      class: col.sortable ? "sortable" : "",
      "data-key": col.key
    }, col.label);
    if (col.sortable) {
      th.addEventListener("click", () => {
        if (state.sortKey === col.key) {
          state.sortDir = state.sortDir === "asc" ? "desc" : "asc";
        } else {
          state.sortKey = col.key;
          state.sortDir = "asc";
        }
        renderRows();
      });
    }
    tr.appendChild(th);
  }
  thead.appendChild(tr);
  table.appendChild(thead);

  const tbody = h("tbody");
  table.appendChild(tbody);

  return { table, tbody };
}

function renderRows() {
  clear(tbody);

  const sorted = devices.slice().sort((a, b) => compare(a, b, state.sortKey, state.sortDir));

  for (const th of thead.querySelectorAll("th.sortable")) {
    th.classList.remove("sorted-asc", "sorted-desc");
    if (th.dataset.key === state.sortKey) {
      th.classList.add(state.sortDir === "asc" ? "sorted-asc" : "sorted-desc");
    }
  }

  for (const d of sorted) {
    const tr = h("tr", {
      tabindex: "0",
      role: "link",
      "aria-label": "View device " + (d.name || d.primary_ip)
    });
    tr.addEventListener("click", () => {
      location.hash = "#/device/" + d.id;
    });
    tr.addEventListener("keydown", (e) => {
      if (e.key === "Enter") {
        location.hash = "#/device/" + d.id;
      }
    });

    tr.appendChild(h("td", {}, statusDot(d.online)));

    const nameCell = h("td", {});
    nameCell.appendChild(h("span", { class: "device-name", title: d.name || null }, shortName(d.name) || "—"));
    if (!d.trusted) nameCell.appendChild(h("span", { class: "tag unknown-tag", title: "Not marked as a known device yet" }, "unknown"));
    if (Array.isArray(d.tags) && d.tags.length) {
      const chips = h("div", { class: "tags" });
      for (const t of d.tags) {
        chips.appendChild(h("span", { class: "tag" }, t));
      }
      nameCell.appendChild(chips);
    }
    tr.appendChild(nameCell);

    tr.appendChild(h("td", {}, d.primary_ip || "—"));
    tr.appendChild(h("td", { class: "mono" }, d.mac || "—"));
    tr.appendChild(h("td", {}, d.vendor || "—"));
    tr.appendChild(h("td", {}, typeBadge(d.type)));
    tr.appendChild(h("td", {}, d.os_name || "—"));
    const portsCell = h("td", {}, String(d.open_ports ?? 0));
    if (d.ports_drift > 0) portsCell.appendChild(h("span", { class: "tag unknown-tag", title: "Open ports differ from the baseline" }, `${d.ports_drift} changed`));
    tr.appendChild(portsCell);
    tr.appendChild(h("td", { title: fmtTime(d.last_seen) }, timeAgo(d.last_seen)));

    tbody.appendChild(tr);
  }

  count.textContent = sorted.length + (sorted.length === 1 ? " device" : " devices");
}

async function load() {
  const params = new URLSearchParams();
  if (state.q) params.set("q", state.q);
  if (state.online) params.set("online", state.online);
  if (state.trusted) params.set("trusted", state.trusted);

  try {
    devices = await get("/api/devices?" + params.toString());
  } catch (e) {
    devices = [];
  }

  if (state.type) {
    devices = devices.filter((d) => d.type === state.type);
  }
  if (state.ports === "changed") devices = devices.filter((d) => d.ports_drift > 0);
  else if (state.ports === "baseline") devices = devices.filter((d) => d.ports_drift !== null);
  else if (state.ports === "none") devices = devices.filter((d) => d.ports_drift === null);

  if (!devices.length) {
    clear(tbody);
    const empty = h("tr");
    const td = h("td", { class: "empty", colspan: String(SORT_KEYS.length) }, "No devices yet. Run a scan.");
    empty.appendChild(td);
    tbody.appendChild(empty);
    count.textContent = "0 devices";
    return;
  }

  renderRows();
}

let devices = [];
let tbody;
let thead;
let count;
let interval;

const state = {
  q: "",
  online: "",
  trusted: "",
  type: "",
  ports: "",
  sortKey: "primary_ip",
  sortDir: "asc"
};

export async function render(container, params) {
  clear(container);

  const built = buildToolbar(state);
  const toolbar = built.toolbar;
  count = built.count;

  const built2 = buildTable(state);
  const table = built2.table;
  tbody = built2.tbody;
  thead = table.querySelector("thead");

  const wrap = h("div", { class: "table-wrap" });
  wrap.appendChild(table);

  container.appendChild(toolbar);
  container.appendChild(wrap);

  await load();

  interval = setInterval(load, REFRESH_MS);

  const onScanFinished = () => load();
  document.addEventListener("netlens:scan-finished", onScanFinished);

  return () => {
    clearInterval(interval);
    document.removeEventListener("netlens:scan-finished", onScanFinished);
  };
}