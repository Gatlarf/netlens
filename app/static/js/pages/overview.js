// The statistic widgets of the former Overview page: the dashboard offers each of them as a card (ids "ov-<id>"). They draw from /api/stats.
import { h, timeAgo } from "../util.js";
import { fmtDuration } from "../charts.js";
import { barList, columnChart, donut, emptyNote, fmtBytes, fmtNumber, fmtPct, lineChart, tile } from "../charts.js";



const devLink = (r) => h("a", { href: `#/device/${r.id}` }, r.name || String(r.id));
function tbl(headers, rows) {
  if (!rows.length) return emptyNote();
  return h("table", { class: "mk-table" }, h("thead", {}, h("tr", {}, ...headers.map((x) => h("th", {}, x)))), h("tbody", {}, ...rows.map((r) => h("tr", {}, ...r.map((c) => h("td", {}, c))))));
}
const relTable = (list) => tbl(["Device", "Uptime", "Outages"], list.map((r) => [devLink(r), fmtPct(r.uptime), String(r.outages)]));

// every widget: id, title, a hint for the preview in the drawer (line/bars/donut/tiles/table), and how to draw it from /api/stats
export const WIDGETS = [
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
