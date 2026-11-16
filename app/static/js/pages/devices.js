import { get, post } from "../api.js";
import { h, clear, patch, toast, foldToolbarOnPhone, fmtTime, timeAgo, debounce, typeBadge, statusDot, TYPE_LABELS, shortName, vendorText, vendorTitle } from "../util.js";
import { pageHead } from "../ui.js";
import { createBulkEditor } from "./devices_bulk.js";
import { editing } from "../editguard.js";
import { createTableViews } from "../tableview.js";
import { CATALOG, BUILTIN_VIEWS } from "./devices_columns.js";

const REFRESH_MS = 15000;

let tv = null;                       // the table views (columns, order, widths, sort, saved views): tableview.js
const controls = {};                 // the filter boxes of the toolbar by name, so a view can set them

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
  controls.q = search;
  toolbar.appendChild(search);

  const statusSel = h("select", { "aria-label": "Status filter" });
  statusSel.appendChild(h("option", { value: "" }, "All"));
  statusSel.appendChild(h("option", { value: "true" }, "Online"));
  statusSel.appendChild(h("option", { value: "false" }, "Offline"));
  statusSel.value = state.online;
  statusSel.addEventListener("change", () => {
    state.online = statusSel.value;
    tv.filtersChanged();
    load();
  });
  controls.online = statusSel;
  toolbar.appendChild(statusSel);

  const typeSel = h("select", { "aria-label": "Type filter" });
  typeSel.appendChild(h("option", { value: "" }, "All"));
  for (const key of Object.keys(TYPE_LABELS)) {
    typeSel.appendChild(h("option", { value: key }, TYPE_LABELS[key]));
  }
  typeSel.value = state.type;
  typeSel.addEventListener("change", () => {
    state.type = typeSel.value;
    tv.filtersChanged();
    load();
  });
  controls.type = typeSel;
  toolbar.appendChild(typeSel);

  const trustSel = h("select", { "aria-label": "Known or unknown devices", class: "trust-filter" });
  trustSel.appendChild(h("option", { value: "" }, "Known and unknown"));
  trustSel.appendChild(h("option", { value: "false" }, "Unknown only"));
  trustSel.appendChild(h("option", { value: "true" }, "Known only"));
  const wantsTrust = /[?&]trusted=(true|false)/.exec(location.hash);          // "#/devices?trusted=false" lists the devices not marked as known yet
  if (wantsTrust) state.trusted = wantsTrust[1];
  trustSel.value = state.trusted;
  trustSel.addEventListener("change", () => {
    state.trusted = trustSel.value;
    tv.filtersChanged();
    load();
  });
  controls.trusted = trustSel;
  toolbar.appendChild(trustSel);

  const portsSel = h("select", { "aria-label": "Ports compared with the baseline", class: "ports-filter" });
  portsSel.appendChild(h("option", { value: "" }, "Any ports"));
  portsSel.appendChild(h("option", { value: "changed" }, "Ports changed from baseline"));
  portsSel.appendChild(h("option", { value: "baseline" }, "With a baseline"));
  portsSel.appendChild(h("option", { value: "none" }, "Without a baseline"));
  portsSel.value = state.ports;
  portsSel.addEventListener("change", () => {
    state.ports = portsSel.value;
    tv.filtersChanged();
    load();
  });
  controls.ports = portsSel;
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

  const groupSel = h("select", { "aria-label": "Group filter", class: "group-filter" });
  groupSel.appendChild(h("option", { value: "" }, "Any group"));
  groupSel.appendChild(h("option", { value: "none" }, "No group"));
  for (const g of groupList) groupSel.appendChild(h("option", { value: String(g.id) }, g.name));
  groupSel.value = state.group;
  groupSel.addEventListener("change", () => {
    state.group = groupSel.value;
    tv.filtersChanged();
    load();
  });
  controls.group = groupSel;
  toolbar.appendChild(groupSel);

  if (networkList.length > 1) {          // a filter by network (range, VLAN) is only useful when more than one is scanned
    const netSel = h("select", { "aria-label": "Network filter", class: "group-filter" });
    netSel.appendChild(h("option", { value: "" }, "Any network"));
    netSel.appendChild(h("option", { value: "none" }, "No network"));
    for (const n of networkList) netSel.appendChild(h("option", { value: String(n.id) }, n.label));
    netSel.value = state.network;
    netSel.addEventListener("change", () => {
      state.network = netSel.value;
      tv.filtersChanged();
      load();
    });
    controls.network = netSel;
  toolbar.appendChild(netSel);
  }

  if (groupList.length) {
    // put every device that is listed (after the filters) in one group
    const assignSel = h("select", { "aria-label": "Group for the listed devices", class: "group-assign admin-only" });
    assignSel.appendChild(h("option", { value: "" }, "Set group of listed…"));
    for (const g of groupList) assignSel.appendChild(h("option", { value: String(g.id) }, g.name));
    assignSel.appendChild(h("option", { value: "none" }, "(remove from group)"));
    assignSel.addEventListener("change", async () => {
      const value = assignSel.value;
      assignSel.value = "";
      if (!value || !devices.length) return;
      const target = value === "none" ? null : Number(value);
      const label = value === "none" ? "no group" : groupList.find((g) => g.id === target).name;
      if (!window.confirm(`Put the ${devices.length} listed device(s) in: ${label}?`)) return;
      try {
        const res = await post("/api/devices/group", { ids: devices.map((d) => d.id), group_id: target });
        toast(`${res.changed} device(s) updated`, "success");
        load();
      } catch (err) {
        toast(err.message || "Could not set the group", "error");
      }
    });
    toolbar.appendChild(assignSel);
  }

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

  const bulkBtn = h("button", { type: "button", class: "btn bulk-toggle admin-only keep", title: "Change the name, type, group and the on/off settings of many devices at once" }, "Edit many");
  bulkBtn.addEventListener("click", () => setBulk(true));
  toolbar.appendChild(bulkBtn);

  const count = h("span", { class: "count keep" }, "0 devices");
  toolbar.appendChild(count);

  const csv = h("a", { href: "/api/export/devices.csv", download: "devices.csv" }, "Export CSV");
  const json = h("a", { href: "/api/export/devices.json", download: "devices.json" }, "Export JSON");
  toolbar.appendChild(csv);
  toolbar.appendChild(json);

  toolbar.appendChild(tv.controls);

  // phones show the list without column headers: this picks the sort order instead
  const sortSel = h("select", { "aria-label": "Sort by" });
  const dirBtn = h("button", { class: "btn", type: "button", "aria-label": "Reverse the order" });
  const syncPhoneSort = () => {
    sortSel.replaceChildren(...tv.columns().filter((k) => CATALOG.find((c) => c.key === k).sort && CATALOG.find((c) => c.key === k).label).map((k) => h("option", { value: k }, "Sort: " + CATALOG.find((c) => c.key === k).label)));
    const sort = tv.sortedBy();
    if (sort) sortSel.value = sort.key;
    dirBtn.textContent = !sort || sort.dir === "asc" ? "↑" : "↓";
  };
  syncPhoneSort();
  tv.onSortChange = syncPhoneSort;
  sortSel.addEventListener("change", () => tv.setSort(sortSel.value, (tv.sortedBy() || {}).dir || "asc"));
  dirBtn.addEventListener("click", () => tv.setSort((tv.sortedBy() || { key: sortSel.value }).key, (tv.sortedBy() || {}).dir === "asc" ? "desc" : "asc"));
  toolbar.appendChild(h("div", { class: "sort-phone keep" }, sortSel, dirBtn));
  foldToolbarOnPhone(toolbar, "Filters");

  return { toolbar, count };
}

function renderRows() {
  const sorted = tv.sorted(devices);
  const rows = [];
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
      if (e.key === "Enter" && e.target === tr) {
        location.hash = "#/device/" + d.id;
      }
    });
    tr.append(...tv.rowCells(d));
    rows.push(tr);
  }
  patch(tbody, rows);

  count.textContent = sorted.length + (sorted.length === 1 ? " device" : " devices");
}

let loadTicket = 0;                  // a slow answer for an older filter must not replace the answer for the newer one
async function load() {
  const params = new URLSearchParams();
  if (state.q) params.set("q", state.q);
  if (state.online) params.set("online", state.online);
  if (state.trusted) params.set("trusted", state.trusted);
  const extra = tv.needs();
  if (extra.length) params.set("extra", extra.join(","));        // what the chosen columns need beyond the device itself

  const mine = ++loadTicket;
  try {
    const got = await get("/api/devices?" + params.toString());
    if (mine !== loadTicket) return;
    devices = got;
  } catch (e) {
    if (mine !== loadTicket) return;
    if (!Array.isArray(devices)) devices = [];        // a failed refresh keeps the list that is on screen
    else if (!devices.length) devices = [];
    else return;
  }

  if (state.type) {
    devices = devices.filter((d) => d.type === state.type);
  }
  if (state.group === "none") devices = devices.filter((d) => d.group_id == null);
  else if (state.group) devices = devices.filter((d) => String(d.group_id) === state.group);
  if (state.network === "none") devices = devices.filter((d) => !d.network);
  else if (state.network) devices = devices.filter((d) => d.network && String(d.network.id) === state.network);
  if (state.ports === "changed") devices = devices.filter((d) => d.ports_drift > 0);
  else if (state.ports === "baseline") devices = devices.filter((d) => d.ports_drift !== null);
  else if (state.ports === "none") devices = devices.filter((d) => d.ports_drift === null);

  if (bulkMode) {                      // the editor is on screen: rebuild it only when other devices are listed, and never under the hands of the user
    const listed = devices.map((d) => d.id).join(",");
    if (listed !== bulkListed && !editing(bulk && bulk.el)) { bulkListed = listed; bulk.refresh(); }
    count.textContent = devices.length + (devices.length === 1 ? " device" : " devices");
    return;
  }

  if (!devices.length) {
    const empty = h("tr");
    const td = h("td", { class: "empty", colspan: String(tv.columns().length) }, "No devices yet. Run a scan.");
    empty.appendChild(td);
    patch(tbody, empty);
    count.textContent = "0 devices";
    return;
  }

  renderRows();
}

let devices = [];
let bulk = null;                     // the mass edit (devices_bulk.js), made when the page is drawn
let bulkMode = false;
let bulkListed = "";
let tableWrap;

function setBulk(on) {
  bulkMode = on;
  tableWrap.hidden = on;
  bulk.el.hidden = !on;
  if (on) { bulkListed = devices.map((d) => d.id).join(","); bulk.refresh(); }
  else { bulk.reset(); renderRows(); }
}

let groupList = [];
let networkList = [];
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
  group: "",
  network: ""
};

export async function render(container, params) {
  clear(container);
  try {
    groupList = (await get("/api/groups")).groups;
  } catch (e) {
    groupList = [];
  }
  try {
    networkList = (await get("/api/networks")).networks;
  } catch (e) {
    networkList = [];
  }

  const filterKeys = ["online", "type", "trusted", "ports", "group", "network"];
  tv = await createTableViews({
    table: "devices", catalog: CATALOG, builtins: BUILTIN_VIEWS, locked: ["status", "name"], tableClass: "data devices-table",
    getFilters: () => Object.fromEntries(filterKeys.map((k) => [k, state[k]])),
    setFilters: (f) => {                                          // a view brings its own filters (the ones it does not name are cleared)
      for (const k of filterKeys) { state[k] = (f && f[k]) || ""; if (controls[k]) controls[k].value = state[k]; }
    },
    onChange: (reason) => {
      if (tv.onSortChange) tv.onSortChange();
      if (reason === "columns" || reason === "view") load(); else if (reason === "sort") renderRows();
    },
  });
  tv.useRows(() => devices);
  const built = buildToolbar(state);
  const toolbar = built.toolbar;
  count = built.count;

  const table = tv.table;
  tbody = tv.tbody;
  thead = table.querySelector("thead");

  const wrap = h("div", { class: "table-wrap" });
  wrap.appendChild(table);
  tableWrap = wrap;
  bulkMode = false;
  bulk = createBulkEditor({
    getDevices: () => devices,
    getGroups: () => groupList,
    onSaved: async (allDone) => { await load(); if (allDone) setBulk(false); else bulk.refresh(); },
    onLeave: () => setBulk(false)
  });
  bulk.el.hidden = true;

  container.appendChild(pageHead("Devices", "Everything Netlens has found on your network. Click a device for its page; use the filters to narrow the list."));
  container.appendChild(toolbar);
  container.appendChild(wrap);
  container.appendChild(bulk.el);

  await load();

  interval = setInterval(() => { if (!document.hidden) load(); }, REFRESH_MS);

  const onScanFinished = () => load();
  document.addEventListener("netlens:scan-finished", onScanFinished);

  return () => {
    clearInterval(interval);
    document.removeEventListener("netlens:scan-finished", onScanFinished);
  };
}