// The start page: a grid of cards. Which cards, in what order and the cards a user made are a per-user choice kept on the server.
import { get, put, del } from "../api.js";
import { h, clear, timeAgo, shortName, isAdmin, sessionInfo, toast } from "../util.js";
import { barList, columnChart, emptyNote, fmtPct, lineChart } from "../charts.js";
import { cssVar } from "../theme.js";
import { big, customCard, linkList, pluginCard, plural, rows, sparkline, toneUp } from "../dashboard_cards.js";
import { openEditor } from "../dashboard_editor.js";
import { layoutHorizontal } from "../layout_horizontal.js";

const REFRESH_MS = 30000;
const KINDS = {
  device_new: "New device", device_online: "Came online", device_offline: "Went offline", device_changed: "Changed", port_opened: "Port opened",
  port_closed: "Port closed", wifi_roamed: "Roamed", login_failed: "Failed sign-ins", cert_expiring: "Certificate", service_down: "Service down", service_up: "Service up",
  metric_warning: "Health warning", metric_critical: "Health critical", metric_ok: "Health normal",
};
const kindText = (k) => KINDS[k] || k.replace(/_/g, " ");
// ---------- the cards ----------
// size: s = one column, w = two, f = the whole row. show(d): has this installation anything for the card? `def` = on the default dashboard.

const CARDS = [
  { id: "devices", title: "Devices online", href: "#/devices", size: "s", def: true, about: "How many devices answer right now, with the 14-day trend.",
    tone: (d) => (d.summary.devices.offline === 0 ? "ok" : ""),
    build: ({ summary: s, trend }) => big(`${s.devices.online} / ${s.devices.total}`, `${s.devices.offline} offline · ${s.devices.new_24h} new today`, { spark: sparkline(trend.map((t) => t.online)) }) },
  { id: "uptime", title: "Uptime", href: "#/uptime", size: "s", def: true, about: "Share of device checks that succeeded: the always-on (core) devices and all devices, over 24 hours, 7 days and 30 days.",
    tone: (d) => toneUp(d.summary.core && d.summary.core.devices ? d.summary.core.uptime["24h"] : d.summary.uptime["24h"]),
    build: ({ summary: s, trend }) => {
      const core = s.core && s.core.devices ? s.core : null, all = s.uptime;
      const pair = (u) => h("div", { class: "d-three" }, [["7 days", u["7d"]], ["30 days", u["30d"]]].map(([label, v]) => h("div", {}, h("small", {}, label), h("strong", { class: `d-${toneUp(v) || "ok"}` }, fmtPct(v)))));
      if (!core) {   // nothing marked yet: all devices, with a nudge
        return big(fmtPct(all["24h"]), "all devices, last 24 hours", { spark: sparkline(trend.map((t) => (t.devices ? (t.online / t.devices) * 100 : null))), extra: [pair(all),
          h("div", { class: "d-mini" }, h("a", { href: "#/uptime" }, "Mark your always-on devices"), " to see them apart from phones and tablets.")] });
      }
      return big(fmtPct(core.uptime["24h"]), `${plural(core.devices, "always-on device")} · last 24 hours`, { extra: [
        pair(core.uptime),
        h("div", { class: "d-mini" }, `All devices: ${fmtPct(all["24h"])} · ${fmtPct(all["7d"])} · ${fmtPct(all["30d"])}`)] });
    } },
  { id: "speed", title: "Internet speed", href: "#/speedtest", size: "s", def: true, about: "The latest internet speed test: download, upload and delay.", show: (d) => !!d.speed,
    build: ({ speed: s }) => big(s.down_mbps >= 1000 ? `${(s.down_mbps / 1000).toFixed(2)} Gbps` : `${Math.round(s.down_mbps)} Mbps`, `down · up ${Math.round(s.up_mbps)} Mbps · ping ${Math.round(s.latency_ms)} ms`, { extra: h("div", { class: "d-mini" }, timeAgo(s.ts)) }) },
  { id: "flapping", title: "Unstable devices", href: "#/uptime", size: "s", def: true, about: "Devices that keep going up and down: the always-on ones and the others apart, and the least reliable ones.",
    tone: (d) => ((d.summary.core && d.summary.core.devices ? d.summary.core.flapping : d.summary.devices.flapping) ? "warn" : "ok"),
    build: ({ summary: s, worst }) => {
      const core = s.core && s.core.devices ? s.core : null, others = s.devices.flapping - (core ? core.flapping : 0);
      const lowest = worst.length ? h("div", { class: "d-mini" }, "Lowest 7 days: ", worst.slice(0, 2).map((w, i) => [i ? ", " : "", h("a", { href: `#/device/${w.id}` }, shortName(w.name)), ` ${fmtPct(w.pct)}`])) : null;
      if (!core) return big(s.devices.flapping, s.devices.flapping === 1 ? "device flaps (24 hours)" : "devices flap (24 hours)", { extra: lowest });
      return big(core.flapping, core.flapping === 1 ? "always-on device flaps (24 hours)" : "always-on devices flap (24 hours)", { extra: [
        h("div", { class: "d-mini" }, `${others} other ${others === 1 ? "device flaps" : "devices flap"}`), lowest] });
    } },
  { id: "services", title: "Services", href: "#/services", size: "s", def: true, about: "Your HTTP, port and DNS checks.",
    show: (d) => d.summary.services.total > 0, tone: (d) => (d.summary.services.down ? "bad" : "ok"),
    build: ({ summary: s, services_down: down }) => big(`${s.services.up} / ${s.services.up + s.services.down}`, s.services.down ? `down: ${down.slice(0, 2).join(", ")}${down.length > 2 ? "…" : ""}` : "all up") },
  { id: "containers", title: "Containers & guests", href: "#/devices", size: "s", def: true, about: "Docker containers and virtual machines on your hosts.",
    show: (d) => d.summary.containers.total + d.summary.guests.total > 0,
    tone: (d) => (d.summary.containers.unhealthy || d.summary.containers.restarting ? "warn" : "ok"),
    build: ({ summary: s }) => big(`${s.guests.running} / ${s.guests.total}`, `running on ${plural(s.guests.hosts, "host")}`, {
      extra: s.containers.unhealthy || s.containers.restarting ? h("div", { class: "d-mini d-warn" }, `${s.containers.unhealthy} unhealthy · ${s.containers.restarting} restarting`) : null }) },
  { id: "sites", title: "Sites & certificates", href: "#/stats", size: "s", def: true, about: "Reverse-proxy sites and when their certificates end.",
    show: (d) => d.summary.sites.total > 0,
    tone: (d) => (d.summary.sites.down || d.summary.sites.certificates_expired ? "bad" : d.summary.sites.certificates_expiring ? "warn" : "ok"),
    build: ({ summary: s }) => big(s.sites.total, s.sites.next_expiry_days === null ? "sites" : `sites · next certificate ends in ${plural(s.sites.next_expiry_days, "day")}`) },
  { id: "plugins", title: "Plugins", href: "#/settings/plugins", size: "s", def: true, about: "Plugins that are switched on, and whether they work.",
    show: (d) => d.summary.plugins.some((p) => p.enabled),
    tone: (d) => (d.summary.plugins.some((p) => p.enabled && p.ok === false) ? "bad" : "ok"),
    build: ({ summary: s }) => {
      const on = s.plugins.filter((p) => p.enabled), failing = on.filter((p) => p.ok === false);
      return big(`${on.length - failing.length} / ${on.length}`, failing.length ? `failing: ${failing.map((p) => p.id).join(", ")}` : "working", {
        extra: s.update.plugin_updates ? h("div", { class: "d-mini" }, plural(s.update.plugin_updates, "update"), " available") : null });
    } },
  { id: "backup", title: "Backup & scans", href: "#/scans", size: "s", def: true, about: "When the last backup and the last scan finished.",
    tone: (d) => (d.summary.backup.last_ok === false || d.summary.scans.last?.status === "failed" ? "bad" : "ok"),
    build: ({ summary: s }) => {
      const last = s.scans.last;
      return rows([
        ["Backup", s.backup.last_at ? timeAgo(s.backup.last_at) : s.backup.enabled ? "not yet" : "off", s.backup.last_ok === false ? "bad" : ""],
        ["Last scan", last ? `${last.kind} · ${timeAgo(last.finished)}` : "never", last?.status === "failed" ? "bad" : ""],
        ["Found", last ? plural(last.hosts_found, "host") : "–"],
      ]);
    } },
  { id: "dns", title: "DNS & network checks", href: "#/settings/dns", size: "s", def: true, about: "Names registered in your DNS server and the DHCP server check.",
    show: (d) => d.summary.dns.registered + d.summary.dns.pending + d.summary.dns.conflicts > 0 || d.summary.netchecks.enabled,
    tone: (d) => (d.summary.dns.conflicts || d.summary.netchecks.untrusted ? "warn" : "ok"),
    build: ({ summary: s }) => rows([
      ["Registered", s.dns.registered], ["Waiting to register", s.dns.pending, s.dns.pending ? "warn" : ""], ["Conflicts", s.dns.conflicts, s.dns.conflicts ? "warn" : ""],
      ["DHCP servers", !s.netchecks.enabled ? "check is off" : !s.netchecks.last_run ? "not checked yet" : `${s.netchecks.dhcp_servers}${s.netchecks.untrusted ? ` (${s.netchecks.untrusted} untrusted)` : ""}`, s.netchecks.untrusted ? "bad" : ""],
    ]) },
  { id: "security", title: "Security", href: "#/scans", size: "s", def: true, about: "Failed sign-ins, devices you have not approved and new versions.",
    tone: (d) => (d.login_failed_24h ? "warn" : "ok"),
    build: ({ summary: s, login_failed_24h: lf }) => rows([
      ["Failed sign-in bursts (24 h)", lf, lf ? "warn" : ""], ["Unknown devices", s.devices.unknown, s.devices.unknown ? "warn" : ""],
      ["New devices (7 days)", s.devices.new_7d], ["Update", s.update.available ? s.update.latest : "up to date", s.update.available ? "warn" : ""],
    ]) },
  { id: "attention", title: "Needs attention", size: "w", def: true, about: "Everything that is wrong or worth a look, worst first.",
    tone: (d) => (d.attention.some((a) => a.level === "bad") ? "bad" : d.attention.some((a) => a.level === "warn") ? "warn" : "ok"),
    build: ({ attention }) => (attention.length
      ? h("ul", { class: "d-attention" }, attention.map((a) => h("li", { class: `d-${a.level}` }, h("a", { href: a.href }, a.text))))
      : h("p", { class: "d-quiet" }, "All quiet. Nothing needs your attention.")) },
  { id: "events", title: "Recent events", href: "#/scans", size: "w", def: true, about: "The latest things that happened on the network.",
    build: ({ events }) => (events.length ? h("ul", { class: "d-events" }, events.slice(0, 8).map((e) => h("li", {},
      h("span", { class: "d-time" }, timeAgo(e.ts)), h("span", { class: "d-kind" }, kindText(e.kind)),
      e.device_id ? h("a", { href: `#/device/${e.device_id}` }, shortName(e.device) || `device ${e.device_id}`) : null))) : emptyNote("No events yet.")) },
  { id: "minimap", title: "Map", href: "#/map", size: "w", def: true, about: "A small picture of your network. Click it to open the full map.", tall: true, build: null },

  // not on the default dashboard, added by the user
  { id: "worst", title: "Least reliable devices", href: "#/uptime", size: "s", about: "The five devices that were down most in the last 7 days.",
    build: ({ worst }) => (worst.length ? barList(worst.map((w) => ({ label: shortName(w.name), count: Math.round(100 - w.pct), href: `#/device/${w.id}` })), { unit: "% down" }) : emptyNote("Every device was up all week.")) },
  { id: "trend", title: "Devices online, 14 days", href: "#/stats", size: "w", about: "How many devices were online, day by day.",
    build: ({ trend }) => lineChart(trend.map((t) => ({ x: t.day.slice(5), online: t.online, total: t.devices })), [{ key: "online", label: "Online" }, { key: "total", label: "Known" }], { height: 130 }) },
  { id: "eventsday", title: "Events per day", href: "#/scans", size: "w", about: "How busy the network was, 14 days.",
    build: ({ trend }) => (trend.length ? columnChart(trend.map((t) => ({ x: t.day.slice(5), v: t.events })), { height: 90 }) : emptyNote()) },
  { id: "types", title: "Device types", href: "#/devices", size: "s", about: "What kinds of devices you have.",
    build: ({ summary: s }) => {
      const counts = {};
      s.device_list.forEach((d) => { counts[d.type || "unknown"] = (counts[d.type || "unknown"] || 0) + 1; });
      return barList(Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 6).map(([label, count]) => ({ label, count })));
    } },
  { id: "groups", title: "Groups", href: "#/devices", size: "s", about: "Online devices per group.", show: (d) => d.summary.device_list.some((x) => x.group),
    build: ({ summary: s }) => {
      const g = {};
      s.device_list.forEach((d) => { const k = d.group || "(no group)"; g[k] = g[k] || [0, 0]; g[k][1] += 1; if (d.online) g[k][0] += 1; });
      return rows(Object.entries(g).sort((a, b) => b[1][1] - a[1][1]).slice(0, 6).map(([k, [on, all]]) => [k, `${on} / ${all}`, on < all ? "" : "ok"]));
    } },
  { id: "wifi", title: "Wi-Fi", href: "#/stats", size: "s", about: "Wi-Fi clients and signal strength.", show: (d) => d.summary.wifi.clients > 0,
    build: ({ summary: s }) => big(s.wifi.clients, `clients · average ${s.wifi.avg_rssi ?? "–"} dBm${s.wifi.weak ? ` · ${s.wifi.weak} weak` : ""}`) },
  { id: "newdevices", title: "New devices", href: "#/devices", size: "s", about: "Devices first seen in the last 7 days.",
    build: ({ new_devices: n }) => (n.length ? linkList(n.map((x) => ({ text: shortName(x.name), href: `#/device/${x.id}`, note: timeAgo(x.first_seen) }))) : emptyNote("Nothing new this week.")) },
  { id: "certs", title: "Certificates", href: "#/stats", size: "s", about: "The certificates that end first.", show: (d) => d.certificates.length > 0,
    build: ({ certificates: c }) => linkList(c.map((x) => ({ text: x.name, note: x.days < 0 ? "expired" : `${x.days} d`, tone: x.days < 0 ? "bad" : x.days <= 14 ? "warn" : "" }))) },
  { id: "updates", title: "Updates available", href: "#/settings/about", size: "s", about: "Newer container images and Netlens or plugin versions.",
    build: ({ summary: s }) => rows([
      ["Container images", s.guests.image_updates || 0, s.guests.image_updates ? "warn" : ""], ["Hosts with updates", s.guests.update_available || 0],
      ["Netlens", s.update.available ? s.update.latest : "up to date", s.update.available ? "warn" : ""], ["Plugins", s.update.plugin_updates, s.update.plugin_updates ? "warn" : ""],
    ]) },
  { id: "actions", title: "Quick actions", size: "s", admin: true, about: "Start a scan with one tap.",
    build: () => h("div", { class: "d-actions" },
      h("button", { class: "btn primary", type: "button", onclick: () => document.getElementById("scan-quick")?.click() }, "Quick scan"),
      h("button", { class: "btn", type: "button", onclick: () => document.getElementById("scan-deep")?.click() }, "Deep scan")) },
];
const TYPE_ABOUT = { value: "A value from your data", device: "A device", group: "A group of devices", service: "A service check", notes: "Notes and links" };
const DEFAULT_ORDER = CARDS.filter((c) => c.def).map((c) => c.id);

// ---------- the chosen layout (per user, kept on the server so every browser and device shows the same dashboard) ----------
// The browser's own storage is only the fallback (and where an older version kept the layout): it is moved to the server once.

const storageKey = () => `netlens.dashboard.${sessionInfo()?.username || "default"}`;
const EMPTY = { order: null, custom: [] };

function localLayout() {
  try {
    const saved = JSON.parse(localStorage.getItem(storageKey()) || "null");
    if (Array.isArray(saved)) return { order: saved, custom: [] };           // how an older version stored it
    if (saved && Array.isArray(saved.order)) return { order: saved.order, custom: Array.isArray(saved.custom) ? saved.custom : [] };
  } catch (e) {
    // no storage or damaged
  }
  return null;
}

function setLocal(layout) {
  try {
    if (layout) localStorage.setItem(storageKey(), JSON.stringify(layout));
    else localStorage.removeItem(storageKey());
  } catch (e) {
    // the choice then lasts until the page is closed
  }
}

// The administrator's dashboard for everybody (null while there is none). Whoever has not arranged their own sees this one.
async function loadDefault() {
  try {
    const d = await get("/api/dashboard/default");
    if (Array.isArray(d.order)) return { order: d.order, custom: d.custom || [] };
  } catch (e) {
    // an older server: the built-in cards
  }
  return null;
}

// The cards an administrator shared with everybody (they are added from the pool like the built-in ones)
async function loadLibrary() {
  try {
    return (await get("/api/dashboard/shared")).cards || [];
  } catch (e) {
    return [];
  }
}

async function loadLayout(shared) {
  let server = EMPTY, reachable = true;
  try {
    server = await get("/api/dashboard/layout");
  } catch (e) {
    reachable = false;
  }
  if (Array.isArray(server.order)) return { order: server.order, custom: server.custom || [], own: true };
  const local = localLayout();
  if (local) {
    if (reachable) {  // a layout from before it was kept on the server: move it there
      try { await put("/api/dashboard/layout", local); setLocal(null); } catch (e) { /* stays in the browser */ }
    }
    return { ...local, own: true };
  }
  return shared ? { order: [...shared.order], custom: [...shared.custom], own: false } : { order: [...DEFAULT_ORDER], custom: [], own: false };
}

// reset: go back to what the administrator set (or the built-in cards); the layout of this user is then removed
async function saveLayout(layout, reset) {
  try {
    if (reset) await del("/api/dashboard/layout");
    else await put("/api/dashboard/layout", layout);
    setLocal(null);
  } catch (e) {
    if (e && e.status === 422) throw e;   // the server refused the layout itself: nothing is kept, the window shows why
    setLocal(reset ? null : layout);      // for example the demo, where nothing may be saved on the server
  }
}

// ---------- the mini map ----------

function loadVis() {
  if (window.vis) return Promise.resolve();
  return new Promise((resolve, reject) => {
    const script = document.querySelector('script[src="vendor/vis-network.min.js"]') || Object.assign(document.createElement("script"), { src: "vendor/vis-network.min.js" });
    script.addEventListener("load", () => resolve());
    script.addEventListener("error", () => reject(new Error("The map library could not be loaded.")));
    if (!script.parentNode) document.head.appendChild(script);
  });
}

// the Map page spaces its cards far apart; the small map packs the same layout tighter so it fills the card
const squeeze = (p) => (p ? { x: p.x * 1.3, y: p.y * 0.34 } : {});

function miniMap() {
  const box = h("div", { class: "d-map", "aria-label": "Map of the network" });
  let network = null, nodes = null;
  const colors = () => ({ on: cssVar("--ok", "#16a34a"), off: cssVar("--muted", "#94a3b8"), edge: cssVar("--border", "#cbd5e1") });
  const paint = (device) => { const c = colors(); return { color: { background: device.online ? c.on : c.off, border: device.online ? c.on : c.off } }; };

  async function load() {
    try {
      const [data] = await Promise.all([get("/api/map"), loadVis()]);
      // the same left-to-right layout as the Map page: the top device on the left, every level a column to its right
      const parents = data.edges.filter((e) => e.kind === "parent");
      const parentOf = new Map(parents.map((e) => [e.to, e.from]));
      const ids = new Set(data.nodes.map((n) => n.id));
      const where = layoutHorizontal(data.nodes.map((n) => ({ id: n.id, parent_id: ids.has(parentOf.get(n.id)) ? parentOf.get(n.id) : null }))).positions;
      const list = data.nodes.map((n) => ({ id: n.id, title: `${shortName(n.label)}${n.online ? "" : " (offline)"}`, shape: "dot", size: n.online ? 9 : 7, ...paint(n), ...squeeze(where.get(n.id)) }));
      const edges = parents.map((e) => ({ from: e.from, to: e.to, color: { color: colors().edge } }));
      if (!network) {
        nodes = new window.vis.DataSet(list);
        network = new window.vis.Network(box, { nodes, edges: new window.vis.DataSet(edges) }, {
          physics: false, interaction: { dragNodes: false, dragView: false, zoomView: false, hover: true },
          edges: { smooth: { type: "cubicBezier", forceDirection: "horizontal", roundness: 0.5 }, width: 1 }, nodes: { borderWidth: 0 },
        });
        network.on("click", (p) => { location.hash = p.nodes.length && Number.isInteger(p.nodes[0]) ? `#/device/${p.nodes[0]}` : "#/map"; });
        network.once("afterDrawing", () => network.fit({ animation: false }));
      } else {
        nodes.update(list.map((n) => ({ id: n.id, size: n.size, color: n.color, title: n.title, x: n.x, y: n.y })));
        network.redraw();
        network.fit({ animation: false });
      }
    } catch (err) {
      box.replaceChildren(h("p", { class: "hint" }, err.message || "The map could not be loaded."));
    }
  }
  return { box, load, destroy: () => { if (network) network.destroy(); network = null; } };
}

// ---------- the page ----------

export async function render(container) {
  const shared = await loadDefault();
  const layout = await loadLayout(shared);
  let library = await loadLibrary();
  const base = () => (shared ? { order: shared.order, custom: shared.custom } : { order: DEFAULT_ORDER, custom: [] });
  let data = null, order = layout.order, custom = layout.custom, own = layout.own, editing = false, disposed = false, timer = null;
  const map = miniMap();
  let mapStarted = false;
  const header = h("div", { class: "dash-head" });
  const grid = h("div", { class: "dash-grid" });
  const pool = h("div", { class: "dash-pool" });
  const nudge = h("div", {});
  container.append(nudge, header, grid, pool);
  // administrators who have not been through the getting-started guide (or closed it halfway) get a one-line invitation
  if (isAdmin()) {
    get("/api/wizard").then((w) => {
      if (disposed || !w || w.status === "done" || w.status === "dismissed") return;
      nudge.append(h("div", { class: "card wiz-banner", id: "wizard-nudge" },
        h("p", {}, h("strong", {}, "Finish setting up Netlens. "), "A short guide walks through the settings that matter: networks, alerts, always-on devices and checks."),
        h("span", { class: "wiz-nav-end" },
          h("a", { class: "btn primary", href: "#/wizard" }, w.status === "pending" ? "Continue the guide" : "Open the guide"),
          h("button", { class: "btn", type: "button", onclick: async () => {
            try { await put("/api/wizard", { status: "dismissed" }); } catch (err) { /* hidden anyway */ }
            clear(nudge);
          } }, "Not now"))));
    }).catch(() => {});
  }

  const visible = (card) => !card.admin || isAdmin();
  const hasData = (card) => !card.show || card.show(data);
  // every card there can be right now: the built-in ones, those of the enabled plugins and the ones this user made
  const registry = () => {
    const all = new Map(CARDS.map((c) => [c.id, c]));
    for (const pc of data ? data.plugin_cards || [] : []) { const c = pluginCard(pc); all.set(c.id, c); }
    for (const def of library) { const c = customCard(def, data); c.shared = true; all.set(c.id, c); }
    for (const def of custom) { const c = customCard(def, data); all.set(c.id, c); }        // your own copy wins over a shared one
    return all;
  };
  const byId = (id) => registry().get(id);

  async function persist() {
    const known = registry();
    order = order.filter((id) => known.has(id) || !data);                      // a card of a plugin that is switched off is dropped
    try {
      const b = base();
      own = !(!custom.length && !b.custom.length && order.length === b.order.length && order.every((id, i) => id === b.order[i]));
      await saveLayout({ order, custom }, !own);
    } catch (e) {
      toast(e.message || "Could not save the dashboard", "error");
    }
  }
  function move(id, delta) {
    const i = order.indexOf(id), j = i + delta;
    if (i < 0 || j < 0 || j >= order.length) return;
    [order[i], order[j]] = [order[j], order[i]];
    persist();
    draw();
  }
  const isShared = (id) => library.some((c) => c.id === id) && !custom.some((c) => c.id === id);
  async function saveLibrary(next) {
    await put("/api/dashboard/shared", { cards: next });
    library = next;
  }
  function edit(def) {
    if (def && isShared(def.id)) {                                               // a shared card: changing it changes it for everybody
      if (!isAdmin()) return;
      openEditor({ def, data, onSave: async (saved) => {
        await saveLibrary(library.map((c) => (c.id === saved.id ? saved : c)));
        draw();
      } });
      return;
    }
    openEditor({ def, data, onSave: async (saved) => {
      const next = custom.some((c) => c.id === saved.id) ? custom.map((c) => (c.id === saved.id ? saved : c)) : [...custom, saved];
      const placed = order.includes(saved.id) ? order : [...order, saved.id];
      await saveLayout({ order: placed, custom: next }, false);   // the server checks the card; a mistake shows in the window
      custom = next; order = placed; own = true;
      draw();
    } });
  }
  function deleteCard(id) {
    custom = custom.filter((c) => c.id !== id);
    order = order.filter((x) => x !== id);
    persist();
    draw();
  }
  // administrators: move one of their own cards into the shared library (everybody can then add it) and back
  async function shareCard(def) {
    try {
      await saveLibrary([...library, def]);
      custom = custom.filter((c) => c.id !== def.id);
      await persist();
      toast("Everybody can now add this card from their card pool", "success");
    } catch (e) {
      toast(e.message || "Could not share the card", "error");
    }
    draw();
  }
  async function unshareCard(def) {
    try {
      await saveLibrary(library.filter((c) => c.id !== def.id));
      custom = [...custom, def];
      await persist();
    } catch (e) {
      toast(e.message || "Could not stop sharing the card", "error");
    }
    draw();
  }
  async function deleteShared(def) {
    try {
      await saveLibrary(library.filter((c) => c.id !== def.id));
      order = order.filter((x) => x !== def.id);
      await persist();
    } catch (e) {
      toast(e.message || "Could not delete the card", "error");
    }
    draw();
  }

  function cardEl(card) {
    const tone = card.tone ? card.tone(data) : "";
    const empty = !hasData(card);
    const title = h("h2", { class: "d-title" }, card.href && !editing ? h("a", { href: card.href }, card.title) : card.title);
    const head = h("div", { class: "d-head" }, title);
    if (editing) {
      const i = order.indexOf(card.id);
      head.append(h("span", { class: "d-tools" },
        card.custom && (!card.shared || isAdmin()) ? h("button", { class: "btn d-tool", type: "button", "aria-label": `Change ${card.title}`, title: "Change", onclick: () => edit(card.custom) }, "✎") : null,
        card.custom && !card.shared && isAdmin() ? h("button", { class: "btn d-tool", type: "button", "aria-label": `Share ${card.title} with everyone`, title: "Share with everyone", onclick: () => shareCard(card.custom) }, "⇪") : null,
        h("button", { class: "btn d-tool", type: "button", disabled: i === 0, "aria-label": `Move ${card.title} earlier`, title: "Earlier", onclick: () => move(card.id, -1) }, "◀"),
        h("button", { class: "btn d-tool", type: "button", disabled: i === order.length - 1, "aria-label": `Move ${card.title} later`, title: "Later", onclick: () => move(card.id, 1) }, "▶"),
        h("button", { class: "btn d-tool", type: "button", "aria-label": `Remove ${card.title}`, title: "Remove", onclick: () => { order = order.filter((x) => x !== card.id); persist(); draw(); } }, "✕")));
    }
    const body = card.id === "minimap" ? map.box : empty ? h("p", { class: "hint" }, "Nothing to show here yet: this card appears when it has something to report.") : card.build(data);
    const node = h("section", { class: `dcard size-${card.size} ${tone ? `tone-${tone}` : ""} ${card.href && !editing ? "linked" : ""} ${card.tall ? "tall" : ""} ${editing ? "editing" : ""}`, dataset: { card: card.id }, draggable: editing }, head, body);
    if (editing) {
      node.addEventListener("dragstart", (e) => { e.dataTransfer.setData("text/plain", card.id); e.dataTransfer.effectAllowed = "move"; node.classList.add("dragging"); });
      node.addEventListener("dragend", () => node.classList.remove("dragging"));
      node.addEventListener("dragover", (e) => { e.preventDefault(); e.dataTransfer.dropEffect = "move"; });
      node.addEventListener("drop", (e) => {
        e.preventDefault();
        const from = e.dataTransfer.getData("text/plain");
        if (!byId(from) || from === card.id) return;
        order = order.filter((x) => x !== from);
        order.splice(order.indexOf(card.id), 0, from);
        persist();
        draw();
      });
    }
    return node;
  }

  function drawHeader() {
    const a = data.attention, bad = a.filter((x) => x.level !== "info").length;
    const status = bad ? `${plural(bad, "thing")} need${bad === 1 ? "s" : ""} attention` : "Everything looks fine";
    clear(header);
    header.append(
      h("div", {}, h("h1", {}, "Dashboard"), h("p", { class: `dash-status ${bad ? "d-warn" : "d-ok"}` }, status, h("span", { class: "hint" }, ` · updated ${timeAgo(data.summary.generated)}`)),
        shared && !own ? h("p", { class: "hint" }, "This is the starting dashboard set by your administrator. Press Customize to make it your own.") : null),
      h("div", { class: "dash-tools" },
        editing && isAdmin() ? h("button", { class: "btn", type: "button", title: "Everybody who has not arranged their own dashboard will see this one", onclick: setForEveryone }, "Use as default for everyone") : null,
        editing && isAdmin() && shared ? h("button", { class: "btn", type: "button", title: "Back to the built-in default for everybody who has not arranged their own", onclick: clearForEveryone }, "Remove the default") : null,
        editing ? h("button", { class: "btn", type: "button", onclick: resetMine }, shared ? "Back to the default" : "Reset to default") : null,
        h("button", { class: `btn ${editing ? "primary" : ""}`, type: "button", "aria-pressed": String(editing), onclick: () => { editing = !editing; draw(); } }, editing ? "Done" : "Customize")));
  }

  async function setForEveryone() {
    try {
      await put("/api/dashboard/default", { order, custom });
      toast("Saved. Everybody who has not arranged their own dashboard now sees this one.");
      location.reload();
    } catch (e) {
      toast(e.message || "Could not save the default dashboard", "error");
    }
  }
  async function clearForEveryone() {
    try {
      await del("/api/dashboard/default");
      toast("The built-in default is used again.");
      location.reload();
    } catch (e) {
      toast(e.message || "Could not remove the default dashboard", "error");
    }
  }
  async function resetMine() {
    const b = base();
    order = [...b.order]; custom = b.custom.map((c) => ({ ...c })); own = false;
    try { await saveLayout(null, true); } catch (e) { toast(e.message || "Could not reset the dashboard", "error"); }
    draw();
  }

  function poolItem(c, extra) {
    const placed = order.includes(c.id);
    return h("div", { class: "pool-item" }, h("div", {}, h("strong", {}, c.title), h("p", { class: "hint" }, placed ? `${c.about} On your dashboard.` : c.about)),
      h("div", { class: "pool-buttons" }, extra, placed ? null : h("button", { class: "btn", type: "button", onclick: () => { order.push(c.id); persist(); draw(); } }, "Add")));
  }

  function drawPool() {
    clear(pool);
    if (!editing) return;
    const all = [...registry().values()];
    const free = all.filter((c) => !order.includes(c.id) && visible(c) && !c.custom && !c.plugin);
    const mine = all.filter((c) => c.custom && !c.shared);                          // also the ones already on the dashboard
    const sharedFree = all.filter((c) => c.shared && (isAdmin() || !order.includes(c.id)));    // an administrator also sees the ones already on the dashboard, to change or unshare them
    const plugins = all.filter((c) => c.plugin && !order.includes(c.id));
    pool.append(h("div", { class: "toolbar" }, h("h2", {}, "Your own cards"), h("button", { class: "btn primary", type: "button", onclick: () => edit(null) }, "Create a card")),
      mine.length ? h("div", { class: "pool-list" }, mine.map((c) => poolItem({ ...c, about: TYPE_ABOUT[c.custom.type] || c.about }, [
        h("button", { class: "btn", type: "button", onclick: () => edit(c.custom) }, "Change"),
        isAdmin() ? h("button", { class: "btn", type: "button", title: "Let every user add this card to their dashboard", onclick: () => shareCard(c.custom) }, "Share") : null,
        h("button", { class: "btn danger", type: "button", onclick: () => deleteCard(c.id) }, "Delete")])))
        : h("p", { class: "hint" }, "Make a card that shows any value, a device, a group, a service check, or notes and links."));
    if (sharedFree.length) {
      pool.append(h("h2", {}, "Shared by your administrator"), h("div", { class: "pool-list" }, sharedFree.map((c) => poolItem({ ...c, about: TYPE_ABOUT[c.custom.type] || c.about }, isAdmin() ? [
        h("button", { class: "btn", type: "button", onclick: () => edit(c.custom) }, "Change"),
        h("button", { class: "btn", type: "button", title: "Take it out of the shared cards; it stays in your own cards", onclick: () => unshareCard(c.custom) }, "Stop sharing"),
        h("button", { class: "btn danger", type: "button", title: "Delete it for everybody", onclick: () => deleteShared(c.custom) }, "Delete")] : []))));
    }
    if (plugins.length) pool.append(h("h2", {}, "Cards from your plugins"), h("div", { class: "pool-list" }, plugins.map((c) => poolItem(c))));
    pool.append(h("h2", {}, "Add a card"), free.length ? h("div", { class: "pool-list" }, free.map((c) => poolItem(c))) : h("p", { class: "hint" }, "All cards are on your dashboard."));
  }

  function draw() {
    if (!data) return;
    drawHeader();
    clear(grid);
    grid.classList.toggle("editing", editing);
    const known = registry();
    for (const id of order) {
      const card = known.get(id);
      if (!card || !visible(card) || (!editing && !hasData(card))) continue;
      grid.append(cardEl(card));
    }
    if (!grid.children.length) grid.append(h("p", { class: "hint" }, "Your dashboard is empty. Press Customize to add cards."));
    drawPool();
    if (order.includes("minimap") && !mapStarted) { mapStarted = true; map.load(); }
    else if (order.includes("minimap")) map.load();
  }

  async function refresh() {
    try {
      data = await get("/api/dashboard");
      if (!disposed && !(editing && grid.children.length)) draw();
    } catch (err) {
      if (!data && !disposed) clear(grid), grid.append(h("p", { class: "error" }, err.message || "The dashboard could not be loaded."));
    }
  }

  grid.append(h("p", { class: "hint" }, "Loading…"));
  await refresh();
  timer = setInterval(() => { if (!editing && !document.hidden) refresh(); }, REFRESH_MS);
  return () => { disposed = true; clearInterval(timer); map.destroy(); };
}
