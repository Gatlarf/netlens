// Overview (beta): tabs of widgets, a period switch and a right-hand drawer to add, remove, resize and drag widgets.
// It reads /api/stats; the layout is kept in this browser (localStorage) for now.
import { get } from "../api.js";
import { h, timeAgo } from "../util.js";
import { fmtDuration } from "../charts.js";
import { barList, columnChart, donut, emptyNote, fmtBytes, fmtNumber, fmtPct, lineChart, tile } from "../charts.js";

const PERIODS = [["1D", "24h"], ["1W", "7d"], ["1M", "30d"]];
const KEY = "netlens.overview.v1";


const devLink = (r) => h("a", { href: `#/device/${r.id}` }, r.name || String(r.id));
function tbl(headers, rows) {
  if (!rows.length) return emptyNote();
  return h("table", { class: "mk-table" }, h("thead", {}, h("tr", {}, ...headers.map((x) => h("th", {}, x)))), h("tbody", {}, ...rows.map((r) => h("tr", {}, ...r.map((c) => h("td", {}, c))))));
}
const relTable = (list) => tbl(["Device", "Uptime", "Outages"], list.map((r) => [devLink(r), fmtPct(r.uptime), String(r.outages)]));

// every widget: id, title, a hint for the preview in the drawer (line/bars/donut/tiles/table), and how to draw it from /api/stats
const WIDGETS = [
  { id: "overview", title: "Devices at a glance", kind: "tiles", span: 3, draw: (s) => h("div", { class: "tiles inline" },
    tile(fmtNumber(s.overview.total), "devices"), tile(fmtNumber(s.overview.online), "online", { tone: "good" }), tile(fmtNumber(s.overview.offline), "offline", { tone: s.overview.offline ? "warn" : "" }),
    tile(fmtNumber(s.overview.new_7d), "new in 7 days"), tile(fmtPct(s.overview.online_pct), "online now")) },
  { id: "online", title: "Devices online over time", kind: "line", span: 3, draw: (s) => lineChart(s.history.online_series.map((r) => ({ x: r.t.replace("T", " ").slice(5, s.history.bucket === "hour" ? 16 : 10), online: r.online, monitored: r.monitored })), [{ key: "online", label: "online" }, { key: "monitored", label: "monitored" }]) },
  { id: "events", title: "Events per day", kind: "bars", span: 2, draw: (s) => columnChart(s.history.events_series.map((r) => ({ x: r.day.slice(5), v: r.total }))) },
  { id: "type", title: "Devices by type", kind: "donut", span: 1, draw: (s) => donut(s.composition.by_type.map((t) => ({ label: t.label, count: t.count }))) },
  { id: "vendor", title: "Top vendors", kind: "list", span: 1, draw: (s) => barList(s.composition.by_vendor) },
  { id: "os", title: "Operating systems", kind: "list", span: 1, draw: (s) => barList(s.composition.by_os) },
  { id: "subnet", title: "Subnets", kind: "list", span: 1, draw: (s) => barList(s.composition.by_subnet) },
  { id: "conn", title: "Wired and Wi-Fi clients", kind: "donut", span: 1, draw: (s) => {
    const c = s.composition.connection;
    const items = [["Wired", c.wired], ["Wi-Fi", c.wifi], ["Unknown", c.unknown]].filter((x) => x[1]).map(([label, count]) => ({ label, count }));
    return items.length ? donut(items) : emptyNote("Turn on a router plugin to see this."); } },
  { id: "bands", title: "Wi-Fi bands", kind: "donut", span: 1, draw: (s) => (s.composition.wifi_bands.length ? donut(s.composition.wifi_bands.map((b) => ({ label: b.label, count: b.count }))) : emptyNote()) },
  { id: "nodes", title: "Clients per network node", kind: "list", span: 1, draw: (s) => (s.composition.clients_per_node.length ? barList(s.composition.clients_per_node) : emptyNote()) },
  { id: "signal", title: "Signal quality", kind: "donut", span: 1, draw: (s) => (s.wifi.clients ? donut(s.wifi.quality) : emptyNote("No Wi-Fi clients reported.")) },
  { id: "weakest", title: "Weakest Wi-Fi clients", kind: "table", span: 2, draw: (s) => {
    if (!s.wifi.clients) return emptyNote();
    const t = h("table", { class: "mk-table" }, h("thead", {}, h("tr", {}, ...["Device", "Signal", "Node", "Band"].map((x) => h("th", {}, x)))));
    t.appendChild(h("tbody", {}, ...s.wifi.weakest.map((r) => h("tr", {}, h("td", {}, h("a", { href: `#/device/${r.id}` }, r.name || String(r.id))), h("td", {}, `${r.rssi} dBm`), h("td", {}, r.node || ""), h("td", {}, r.band || ""))))); return t; } },
  { id: "app-tiles", title: "Traffic totals", kind: "tiles", span: 3, draw: (s) => (s.applications && s.applications.available
    ? h("div", { class: "tiles inline" }, tile(fmtBytes(s.applications.rx), "downloaded"), tile(fmtBytes(s.applications.tx), "uploaded"), tile(fmtNumber(s.applications.applications_total), "applications seen"))
    : emptyNote(s.applications && s.applications.enabled === false ? "Traffic statistics are switched off (Settings > Traffic statistics)." : "No router reports applications.")) },
  { id: "apps", title: "Top applications (traffic)", kind: "list", span: 2, draw: (s) => (s.applications && s.applications.available ? barList(s.applications.applications.map((r) => ({ label: r.name, count: r.rx + r.tx, text: fmtBytes(r.rx + r.tx) }))) : emptyNote()) },
  { id: "app-devices", title: "Top devices by traffic", kind: "list", span: 1, draw: (s) => (s.applications && s.applications.available ? barList(s.applications.clients.map((r) => ({ label: r.name, count: r.rx + r.tx, text: fmtBytes(r.rx + r.tx), href: `#/device/${r.id}` }))) : emptyNote()) },
  { id: "traffic-day", title: "Traffic per day", kind: "bars", span: 2, draw: (s) => (s.applications && s.applications.available && s.applications.per_day.length > 1 ? columnChart(s.applications.per_day.map((r) => ({ x: r.day, v: r.rx + r.tx }))) : emptyNote()) },
  { id: "uptime-tiles", title: "Availability", kind: "tiles", span: 3, draw: (s) => h("div", { class: "tiles inline" }, tile(fmtPct(s.availability.uptime_24h), "24 hours"), tile(fmtPct(s.availability.uptime_7d), "7 days"), tile(fmtPct(s.availability.uptime_30d), "30 days"),
    tile(s.availability.avg_rtt_ms === null ? "\u2013" : `${s.availability.avg_rtt_ms} ms`, "average response")) },
  { id: "least", title: "Least reliable (7 days)", kind: "table", span: 1, draw: (s) => relTable(s.availability.least_reliable) },
  { id: "most", title: "Most reliable (7 days)", kind: "table", span: 1, draw: (s) => relTable(s.availability.most_reliable) },
  { id: "flapping", title: "Flapping devices (24 h)", kind: "table", span: 1, draw: (s) => tbl(["Device", "Changes"], s.availability.flapping.map((r) => [devLink(r), String(r.flaps_24h)])) },
  { id: "longest", title: "Offline the longest", kind: "table", span: 1, draw: (s) => tbl(["Device", "Offline for"], s.availability.longest_outages.map((r) => [devLink(r), fmtDuration(r.seconds)])) },
  { id: "slowest", title: "Slowest to answer (24 h)", kind: "table", span: 1, draw: (s) => tbl(["Device", "Response"], s.availability.slowest.map((r) => [devLink(r), `${r.rtt_ms} ms`])) },
  { id: "ports", title: "Most common open ports", kind: "list", span: 1, draw: (s) => barList(s.ports.top_ports) },
  { id: "services", title: "Most common services", kind: "list", span: 1, draw: (s) => barList(s.ports.top_services) },
  { id: "most-open", title: "Devices with the most open ports", kind: "list", span: 1, draw: (s) => barList(s.ports.most_open.map((r) => ({ id: r.id, label: r.name, count: r.count, href: `#/device/${r.id}` }))) },
  { id: "parents", title: "Busiest parents", kind: "list", span: 1, draw: (s) => barList(s.structure.busiest_parents.map((r) => ({ label: r.name, count: r.children, href: `#/device/${r.id}` }))) },
  { id: "speed-tiles", title: "Internet speed", kind: "tiles", span: 3, draw: (s) => {
    const sp = s.speed; if (!sp || !sp.tests) return emptyNote("No speed tests in this period.");
    const rate = (v) => (v === null || v === undefined ? "\u2013" : v >= 1000 ? `${(v / 1000).toFixed(2)} Gbps` : `${Math.round(v)} Mbps`);
    return h("div", { class: "tiles inline" }, tile(rate(sp.down.avg), "download"), tile(rate(sp.up.avg), "upload"), tile(sp.latency.avg == null ? "\u2013" : `${sp.latency.avg.toFixed(1)} ms`, "ping"), tile(fmtNumber(sp.tests), "tests")); } },
  { id: "speed-line", title: "Internet speed over time", kind: "line", span: 2, draw: (s) => (s.speed && s.speed.series.length > 1
    ? lineChart(s.speed.series.map((r) => ({ x: r.ts.slice(5, 10), down: r.down, up: r.up })), [{ key: "down", label: "Download (Mbps)" }, { key: "up", label: "Upload (Mbps)" }]) : emptyNote("Needs two tests in this period.")) },
  { id: "guests", title: "Virtual machines and containers", kind: "tiles", span: 3, draw: (s) => (s.guests && s.guests.total
    ? h("div", { class: "tiles inline" }, tile(fmtNumber(s.guests.running), "running"), tile(fmtNumber(s.guests.stopped), "stopped"), tile(fmtNumber(s.guests.hosts), "hosts"), tile(fmtNumber(s.guests.update_available), "update available", { tone: s.guests.update_available ? "warn" : "" }))
    : emptyNote("No hypervisor or Docker plugin reports guests.")) },
  { id: "scans", title: "Scans", kind: "tiles", span: 3, draw: (s) => (s.scans ? h("div", { class: "tiles inline" }, ...Object.entries({ total: "scans", ok: "completed", failed: "failed" }).filter(([k]) => s.scans[k] !== undefined).map(([k, l]) => tile(fmtNumber(s.scans[k]), l))) : emptyNote())},
];
const BY_ID = Object.fromEntries(WIDGETS.map((w) => [w.id, w]));

const DEFAULT_TABS = [
  { id: "summary", name: "Summary", widgets: ["overview", "online", "type", "events", "conn"] },
  { id: "network", name: "Network", widgets: ["subnet", "vendor", "os", "nodes"] },
  { id: "wireless", name: "Wireless", widgets: ["signal", "bands", "weakest"] },
  { id: "apps", name: "Applications", widgets: ["app-tiles", "apps", "app-devices", "traffic-day"] },
];

function load() {
  try {
    const v = JSON.parse(localStorage.getItem(KEY) || "null");
    if (v && Array.isArray(v.tabs) && v.tabs.length) return v;
  } catch (e) { /* private window */ }
  return { tabs: DEFAULT_TABS.map((t) => ({ ...t, widgets: [...t.widgets] })), active: "summary", period: "1W" };
}
function save(state) {
  try { localStorage.setItem(KEY, JSON.stringify(state)); } catch (e) { /* ignore */ }
}

// a tiny sketch of a widget for the drawer, so the choice is visual
function thumb(kind) {
  const bars = (n) => h("div", { class: "mk-th mk-th-bars" }, ...Array.from({ length: n }, (_, i) => h("i", { style: `height:${25 + ((i * 37) % 60)}%` })));
  if (kind === "donut") return h("div", { class: "mk-th mk-th-donut" }, h("i", {}), h("b", {}));
  if (kind === "list") return h("div", { class: "mk-th mk-th-list" }, ...[90, 70, 45, 30].map((w) => h("i", { style: `width:${w}%` })));
  if (kind === "table") return h("div", { class: "mk-th mk-th-table" }, ...Array.from({ length: 4 }, () => h("i", {})));
  if (kind === "tiles") return h("div", { class: "mk-th mk-th-tiles" }, ...Array.from({ length: 4 }, () => h("i", {})));
  return kind === "line" ? h("div", { class: "mk-th mk-th-line" }, h("i", {})) : bars(14);
}

export async function render(container) {
  if (!document.getElementById("overview-css")) {
    document.head.appendChild(h("link", { id: "overview-css", rel: "stylesheet", href: "css/overview.css" }));
  }
  const state = load();
  let stats = null, drawerOpen = false, loadedPeriod = null;
  const shell = h("div", { class: "mk" });
  container.appendChild(shell);
  const tab = () => state.tabs.find((t) => t.id === state.active) || state.tabs[0];

  async function fetchStats() {
    const range = PERIODS.find(([k]) => k === state.period)[1];
    if (loadedPeriod === range && stats) return;
    stats = await get(`/api/stats?range=${range}`);
    loadedPeriod = range;
  }

  const spanOf = (w) => (tab().sizes && tab().sizes[w.id]) || w.span;

  function widgetBox(w) {
    const body = h("div", { class: "mk-body" });
    try { body.appendChild(w.draw(stats)); } catch (e) { body.appendChild(emptyNote("Nothing to show yet.")); }
    const remove = h("button", { class: "mk-x", type: "button", title: "Remove from this tab", "aria-label": "Remove", onclick: () => { tab().widgets = tab().widgets.filter((i) => i !== w.id); save(state); paint(); } }, "\u00d7");
    const size = h("button", { class: "mk-x", type: "button", title: "Change the width (1, 2 or 3 columns)", "aria-label": "Change the width", onclick: () => {
      const t = tab(); t.sizes = t.sizes || {}; t.sizes[w.id] = (spanOf(w) % 3) + 1; save(state); paintGrid(); } }, "\u2194");
    const handle = h("span", { class: "mk-handle", title: "Drag to move", "aria-label": "Drag to move" }, "\u22ee\u22ee");
    const box = h("section", { class: `mk-card span${spanOf(w)}`, dataset: { id: w.id } }, h("header", {}, handle, h("h3", {}, w.title), size, remove), body);
    handle.addEventListener("pointerdown", (e) => startDrag(e, box));
    return box;
  }

  // drag a widget by its handle (mouse and touch): it follows the pointer, the others make room, the order is saved on release
  function startDrag(e, box) {
    if (e.button !== undefined && e.button !== 0) return;
    e.preventDefault();
    const rect = box.getBoundingClientRect();
    const offX = e.clientX - rect.left, offY = e.clientY - rect.top;
    const ghost = box.cloneNode(true);
    ghost.classList.add("mk-ghost");
    ghost.style.width = `${rect.width}px`; ghost.style.height = `${rect.height}px`;
    document.body.appendChild(ghost);
    box.classList.add("mk-moving");
    const place = (x, y) => { ghost.style.left = `${x - offX}px`; ghost.style.top = `${y - offY}px`; };
    place(e.clientX, e.clientY);
    const move = (ev) => {
      place(ev.clientX, ev.clientY);
      if (ev.clientY < 70) window.scrollBy(0, -18); else if (ev.clientY > innerHeight - 70) window.scrollBy(0, 18);
      ghost.style.display = "none";
      const under = document.elementFromPoint(ev.clientX, ev.clientY);
      ghost.style.display = "";
      const over = under && under.closest(".mk-card");
      if (!over || over === box || !grid.contains(over)) return;
      const kids = [...grid.children];
      if (kids.indexOf(box) < kids.indexOf(over)) over.after(box); else over.before(box);   // swap places with the widget under the pointer
    };
    const up = () => {
      window.removeEventListener("pointermove", move); window.removeEventListener("pointerup", up); window.removeEventListener("pointercancel", up);
      ghost.remove(); box.classList.remove("mk-moving");
      const ids = [...grid.querySelectorAll(".mk-card")].map((c) => c.dataset.id);
      const rest = tab().widgets.filter((i) => !ids.includes(i));
      tab().widgets = [...ids, ...rest]; save(state);
    };
    window.addEventListener("pointermove", move); window.addEventListener("pointerup", up); window.addEventListener("pointercancel", up);
  }

  function drawer() {
    const t = tab();
    const close = () => { drawerOpen = false; paint(); };
    const rows = [...WIDGETS].sort((a, b) => Number(t.widgets.includes(b.id)) - Number(t.widgets.includes(a.id))).map((w) => {
      const box = h("input", { type: "checkbox", id: `mk-w-${w.id}` });
      box.checked = t.widgets.includes(w.id);
      box.addEventListener("change", () => {
        t.widgets = box.checked ? [...t.widgets.filter((i) => i !== w.id), w.id] : t.widgets.filter((i) => i !== w.id);
        save(state); paintGrid();
      });
      return h("label", { class: "mk-opt", for: `mk-w-${w.id}` }, h("span", { class: "mk-opt-title" }, box, w.title), thumb(w.kind));
    });
    const del = state.tabs.length > 1 ? h("button", { class: "btn", type: "button", onclick: () => {
      state.tabs = state.tabs.filter((x) => x.id !== t.id); state.active = state.tabs[0].id; drawerOpen = false; save(state); paint(); } }, "Delete this tab") : null;
    const reset = h("button", { class: "btn", type: "button", onclick: () => { const d = DEFAULT_TABS.find((x) => x.id === t.id); if (d) { t.widgets = [...d.widgets]; save(state); paint(); } } }, "Defaults");
    return h("aside", { class: "mk-drawer", "aria-label": "Edit tab" },
      h("header", {}, h("h2", {}, `Edit ${t.name}`), h("button", { class: "mk-x", type: "button", "aria-label": "Close", onclick: close }, "×")),
      h("div", { class: "mk-opts" }, ...rows), h("footer", {}, h("button", { class: "btn primary", type: "button", onclick: close }, "Done"), reset, del));
  }

  let grid = null;
  function paintGrid() {
    if (!grid || !stats) return;
    const ids = tab().widgets.filter((i) => BY_ID[i]);
    grid.replaceChildren(...(ids.length ? ids.map((i) => widgetBox(BY_ID[i])) : [h("p", { class: "hint mk-empty" }, "This tab is empty. Open the gear and tick the widgets you want.")]));
  }

  function paint() {
    const tabs = h("div", { class: "mk-tabs", role: "tablist" }, ...state.tabs.map((t) => h("button", { class: `mk-tab${t.id === state.active ? " on" : ""}`, role: "tab", type: "button", onclick: () => { state.active = t.id; save(state); paint(); } }, t.name)),
      h("button", { class: "mk-icon", type: "button", title: "Add a tab", "aria-label": "Add a tab", onclick: () => {
        const name = (prompt("Name of the new tab") || "").trim(); if (!name) return;
        const id = `t${Date.now()}`; state.tabs.push({ id, name: name.slice(0, 24), widgets: [] }); state.active = id; drawerOpen = true; save(state); paint(); } }, "+"),
      h("button", { class: "mk-icon", type: "button", title: "Choose the widgets of this tab", "aria-label": "Edit tab", onclick: () => { drawerOpen = !drawerOpen; paint(); } }, "⚙"));
    const period = h("div", { class: "mk-period", role: "group", "aria-label": "Period" }, ...PERIODS.map(([k]) => h("button", { class: k === state.period ? "on" : "", type: "button", onclick: async () => { state.period = k; save(state); await fetchStats().catch(() => {}); paint(); } }, k)));

    grid = h("div", { class: "mk-grid" });
    const main = h("div", { class: "mk-main" }, h("div", { class: "mk-bar" }, tabs, period), h("p", { class: "mk-note" }, "Beta: drag the grip of a widget to move it, use \u2194 to change its width. Your tabs and widgets are kept in this browser only."), grid);
    shell.className = `mk${drawerOpen ? " with-drawer" : ""}`;
    shell.replaceChildren(main, ...(drawerOpen ? [drawer()] : []));
    paintGrid();
  }

  shell.appendChild(h("p", { class: "hint" }, "Loading…"));
  try { await fetchStats(); } catch (e) { shell.replaceChildren(h("p", { class: "error" }, e.message || "Could not load")); return; }
  paint();
}
