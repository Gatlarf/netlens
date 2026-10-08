import { get } from "../api.js";
import { h, clear, toast, timeAgo, TYPE_LABELS } from "../util.js";
import { barList, columnChart, donut, emptyNote, fmtBytes, fmtDuration, fmtNumber, fmtPct, lineChart, tile } from "../charts.js";

const RANGES = [["24h", "24 hours"], ["7d", "7 days"], ["30d", "30 days"], ["90d", "90 days"]];
const EVENT_LABELS = {
  device_new: "New device", device_offline: "Went offline", device_online: "Came online", ip_changed: "IP changed",
  os_changed: "OS changed", port_opened: "Port opened", host_timeout: "Host timeout", device_deleted: "Deleted",
};

const dev = (item) => ({ ...item, href: `#/device/${item.id}` });

function card(title, ...children) {
  return h("div", { class: "card stat-card" }, h("h2", {}, title), ...children);
}

function table(headers, rows) {
  if (!rows.length) return emptyNote();
  return h("div", { class: "table-wrap" }, h("table", { class: "data" },
    h("thead", {}, h("tr", {}, headers.map((t) => h("th", {}, t)))),
    h("tbody", {}, rows.map((r) => h("tr", {}, r.map((c) => h("td", {}, c)))))));
}

function link(item, text) {
  return h("a", { href: `#/device/${item.id}` }, text ?? item.name);
}

function section(title, ...cards) {
  return h("section", { class: "stat-section" }, h("h3", {}, title), h("div", { class: "stat-grid" }, ...cards));
}

function labelType(label) {
  return TYPE_LABELS[label] || label;
}

function build(s) {
  const o = s.overview;
  const c = s.composition;
  const a = s.availability;
  const p = s.ports;
  const st = s.structure;
  const sc = s.scans;
  const ev = s.events;
  const sys = s.system;
  const hist = s.history;
  const root = h("div", { class: "stats" });

  // ------------------------------------------------------------------ overview
  root.appendChild(h("div", { class: "tiles" },
    tile(fmtNumber(o.total), "devices"), tile(fmtNumber(o.online), "online", { tone: "good" }),
    tile(fmtNumber(o.offline), "offline", { tone: o.offline ? "warn" : "" }), tile(fmtPct(o.online_pct), "online now"),
    tile(fmtNumber(o.new_24h), "new in 24 h"), tile(fmtNumber(o.new_7d), "new in 7 days"), tile(fmtNumber(o.new_30d), "new in 30 days"),
    tile(fmtNumber(o.stale_30d), "not seen for 30 days", { tone: o.stale_30d ? "warn" : "" }), tile(fmtNumber(o.ignored), "ignored")));

  // ------------------------------------------------------------------ history
  const online = hist.online_series.map((r) => ({ x: r.t.replace("T", " ").slice(5, hist.bucket === "hour" ? 16 : 10), online: r.online, monitored: r.monitored }));
  const daily = hist.daily.map((r) => ({ x: r.day.slice(5), devices: r.devices, online: r.online }));
  root.appendChild(section("History",
    card(`Devices online (per ${hist.bucket})`, lineChart(online, [{ key: "online", label: "online" }, { key: "monitored", label: "monitored" }])),
    card("Devices over time (daily)", daily.length < 2 ? emptyNote("The daily history builds up with every day Netlens runs.") : lineChart(daily, [{ key: "devices", label: "known devices" }, { key: "online", label: "online" }])),
    card("Events per day", columnChart(hist.events_series.map((r) => ({ x: r.day.slice(5), v: r.total }))))));

  // ------------------------------------------------------------------ composition
  const conn = [["Wired", c.connection.wired], ["Wi-Fi", c.connection.wifi], ["Unknown", c.connection.unknown]].filter((x) => x[1]).map(([label, count]) => ({ label, count }));
  root.appendChild(section("What is on the network",
    card("By type", donut(c.by_type.map((t) => ({ label: labelType(t.label), count: t.count })))),
    card("Top vendors", barList(c.by_vendor)), card("Operating systems", barList(c.by_os)), card("Subnets", barList(c.by_subnet)),
    card("Wired and Wi-Fi", conn.length ? donut(conn) : emptyNote("Turn on a router plugin to see this."), c.wifi_bands.length ? h("h4", {}, "Wi-Fi bands") : null, c.wifi_bands.length ? barList(c.wifi_bands) : null),
    card("Clients per network node", c.clients_per_node.length ? barList(c.clients_per_node) : emptyNote("Turn on a router plugin to see this."))));

  // ------------------------------------------------------------------ availability
  const rel = (list) => table(["Device", "Uptime (7 d)", "Outages"], list.map((r) => [link(r), fmtPct(r.uptime), String(r.outages)]));
  root.appendChild(section("Availability",
    h("div", { class: "tiles inline" }, tile(fmtPct(a.uptime_24h), "network uptime, 24 h"), tile(fmtPct(a.uptime_7d), "7 days"), tile(fmtPct(a.uptime_30d), "30 days"), tile(a.avg_rtt_ms === null ? "–" : `${a.avg_rtt_ms} ms`, "average response")),
    card("Least reliable (7 days)", rel(a.least_reliable)), card("Most reliable (7 days)", rel(a.most_reliable)),
    card("Flapping (many changes in 24 h)", table(["Device", "Changes"], a.flapping.map((r) => [link(r), String(r.flaps_24h)]))),
    card("Offline the longest", table(["Device", "Offline for"], a.longest_outages.map((r) => [link(r), fmtDuration(r.seconds)]))),
    card("Slowest to answer (24 h)", table(["Device", "Response"], a.slowest.map((r) => [link(r), `${r.rtt_ms} ms`])))));

  // ------------------------------------------------------------------ ports
  root.appendChild(section("Ports and services",
    h("div", { class: "tiles inline" }, tile(fmtNumber(p.open_total), "open ports"), tile(fmtNumber(p.devices_with_open), "devices with open ports"), tile(fmtNumber(p.devices_without_open), "devices with none found"), tile(fmtNumber(p.opened_7d), "newly opened, 7 days")),
    card("Most common open ports", barList(p.top_ports)), card("Most common services", barList(p.top_services)),
    card("Devices with the most open ports", barList(p.most_open.map((r) => dev({ id: r.id, label: r.name, count: r.count }))))));

  // ------------------------------------------------------------------ structure
  root.appendChild(section("Network structure",
    h("div", { class: "tiles inline" }, tile(fmtNumber(st.max_depth), "levels deep"), tile(fmtNumber(c.top_level), "top-level devices"), tile(fmtNumber(c.with_parent), "devices with a parent")),
    card("Busiest parents", barList(st.busiest_parents.map((r) => dev({ id: r.id, label: r.name, count: r.children })))),
    card("Where the hierarchy comes from", barList(st.sources.map((r) => ({ label: r.label, count: r.count })))),
    card("Hypervisor hosts", table(["Host", "Plugin", "Guests", "Running"], st.hypervisor_hosts.map((r) => [r.host, r.plugin, String(r.guests), String(r.running)])))));

  // ------------------------------------------------------------------ scans
  const kinds = Object.entries(sc.by_kind);
  root.appendChild(section("Scans",
    card(`Scans in the last ${RANGES.find((r) => r[0] === s.range)[1]}`, table(["Kind", "Total", "Done", "Failed", "Cancelled", "Median", "95th pct", "Longest"],
      kinds.map(([k, v]) => [k, String(v.total), String(v.done), String(v.failed), String(v.cancelled), fmtDuration(v.median_s), fmtDuration(v.p95_s), fmtDuration(v.max_s)])),
    h("p", { class: "hint" }, `${sc.host_timeouts} host timeout${sc.host_timeouts === 1 ? "" : "s"}.`)),
    card("Hosts found per scan", lineChart(sc.hosts_trend.map((r, i) => ({ x: `#${r.id}`, hosts: r.hosts })), [{ key: "hosts", label: "hosts" }]))));

  // ------------------------------------------------------------------ events
  root.appendChild(section("Events",
    card("By kind", barList(ev.by_kind.map((r) => ({ label: EVENT_LABELS[r.label] || r.label, count: r.count })))),
    card("Most active devices", barList(ev.most_active.map((r) => dev({ id: r.id, label: r.name, count: r.count })))),
    card("Latest events", table(["When", "What", "Device"], ev.recent.map((r) => [timeAgo(r.ts), `${EVENT_LABELS[r.kind] || r.kind}${r.detail ? `: ${r.detail}` : ""}`, r.device_id ? h("a", { href: `#/device/${r.device_id}` }, r.device || `device ${r.device_id}`) : ""])))));

  // ------------------------------------------------------------------ system
  root.appendChild(section("System",
    card("Netlens", table(["", ""], [["Version", sys.version], ["Database size", fmtBytes(sys.db_bytes)], ["Oldest uptime record", sys.oldest_check ? timeAgo(sys.oldest_check) : "–"], ["Oldest event", sys.oldest_event ? timeAgo(sys.oldest_event) : "–"]])),
    card("Stored rows", barList(Object.entries(sys.rows).map(([label, count]) => ({ label, count })))),
    card("Plugins", table(["Plugin", "State", "Last sync"], sys.plugins.map((r) => [r.id, r.enabled ? "on" : "off", r.enabled ? (r.ok === null ? "waiting" : r.ok ? `ok, ${timeAgo(r.ts)}` : `failed: ${r.error}`) : ""])))));
  return root;
}

export async function render(container) {
  let destroyed = false;
  let range = "7d";
  try {
    range = RANGES.map((r) => r[0]).includes(localStorage.getItem("netlens.stats.range")) ? localStorage.getItem("netlens.stats.range") : "7d";
  } catch (e) {
    // storage unavailable: use the default
  }
  const bar = h("div", { class: "toolbar" }, h("strong", {}, "Statistics"), h("span", { class: "hint" }, "Period for the history, scan and event groups:"));
  const buttons = {};
  for (const [key, label] of RANGES) {
    buttons[key] = h("button", { class: "btn", type: "button", "data-range": key }, label);
    buttons[key].addEventListener("click", () => {
      range = key;
      try {
        localStorage.setItem("netlens.stats.range", key);
      } catch (e) {
        // not remembered
      }
      load();
    });
    bar.appendChild(buttons[key]);
  }
  const stamp = h("span", { class: "hint stats-stamp" }, "");
  bar.appendChild(stamp);
  const body = h("div", { class: "stats-body" }, h("p", { class: "hint" }, "Loading..."));
  container.appendChild(bar);
  container.appendChild(body);

  async function load() {
    for (const [key, btn] of Object.entries(buttons)) btn.classList.toggle("active", key === range);
    try {
      const data = await get(`/api/stats?range=${range}`);
      if (destroyed) return;
      clear(body);
      body.appendChild(build(data));
      stamp.textContent = `Updated ${timeAgo(data.generated)}`;
    } catch (err) {
      if (destroyed) return;
      clear(body);
      body.appendChild(h("p", { class: "error" }, err.message || "Failed to load the statistics"));
      toast(err.message || "Failed to load the statistics", "error");
    }
  }

  load();
  const timer = setInterval(() => { if (!destroyed) load(); }, 60000);
  return () => {
    destroyed = true;
    clearInterval(timer);
  };
}
