import { get } from "../api.js";
import { h, clear, patch } from "../util.js";

// EXPERIMENT: a full-screen command-centre view. It looks "streamed": the event list takes new events the moment the poll sees them (every 4 s), the gauges
// and radar refresh every 15 s, and the ticker runs along the bottom. Nothing is stored; it is read-only and uses the same API as the other pages.
const NS = "http://www.w3.org/2000/svg";
const svg = (tag, attrs = {}) => { const n = document.createElementNS(NS, tag); for (const [k, v] of Object.entries(attrs)) n.setAttribute(k, String(v)); return n; };
const COLOUR = { ok: "#00ffa3", warn: "#ffb020", bad: "#ff3b5c", cyan: "#00e5ff" };
const hash = (n) => { let x = (Number(n) * 2654435761) >>> 0; x ^= x >>> 15; x = Math.imul(x, 2246822519) >>> 0; return (x ^ (x >>> 13)) >>> 0; };
const pad = (n) => String(n).padStart(2, "0");
const BAD = new Set(["device_offline", "service_down", "metric_critical", "probe_offline", "remote_service_down", "capacity_critical", "dhcp_rogue", "gateway_changed"]);
const WARN = new Set(["metric_warning", "device_new", "container_restarting", "capacity_warning"]);
const GOOD = new Set(["device_online", "service_up", "metric_ok", "probe_online"]);
// where a click on an event goes: the device it is about, or the page that shows that kind of problem
function eventHref(e) {
  if (/^(service_|certificate_)/.test(e.kind)) return "#/services";
  if (/^(probe_|remote_)/.test(e.kind)) return "#/remote-sites";
  if (/^(backup_|guest_backup_)/.test(e.kind)) return "#/backups";
  if (/^(storage_|capacity_)/.test(e.kind) && e.device_id == null) return "#/storage";
  if (e.device_id != null) return `#/device/${e.device_id}`;
  return "#/changes";
}
const level = (kind) => (BAD.has(kind) ? "bad" : WARN.has(kind) ? "warn" : GOOD.has(kind) ? "ok" : "");

// A gauge is built once and then only its numbers change, so the ring slides to the new value instead of being redrawn.
function gauge(label, href) {
  const r = 38, c = 2 * Math.PI * r;
  const box = h("a", { class: "hud-gauge", href, title: `Open ${href.replace("#/", "")}` });
  const s = svg("svg", { viewBox: "0 0 100 100" });
  const arc = svg("circle", { class: "arc", cx: 50, cy: 50, r, "stroke-width": 7, "stroke-dasharray": c, "stroke-dashoffset": c, transform: "rotate(-90 50 50)" });
  const num = svg("text", { class: "num", x: 50, y: 51 });
  s.append(svg("circle", { class: "track", cx: 50, cy: 50, r, "stroke-width": 7 }), arc, num);
  box.append(s, h("div", { class: "cap" }, label));
  box.set = (pct, colour, text) => {
    const p = Math.max(0, Math.min(100, pct ?? 0));
    s.style.color = colour;
    arc.setAttribute("stroke", colour);
    arc.setAttribute("stroke-dashoffset", String(c * (1 - p / 100)));
    num.textContent = text ?? (pct == null ? "–" : `${Math.round(p)}%`);
  };
  return box;
}

// ---- the radar -----------------------------------------------------------------------------------------------------------------------------------
// The frame and the sweep are built once. Every refresh (and every change of view) only moves, resizes or recolours the blips, which glide to their new place.
// Four views decide where a blip sits:
//   hash      a steady scatter: the distance follows the importance (critical in the middle), the direction is arbitrary
//   depth     the network as a tree: the top device in the middle, every level a ring further out, a branch keeps its own slice
//   group     one slice per device group, the distance follows the importance
//   response  the distance is the response time right now (log scale), the direction is arbitrary; offline devices sit on the rim
const VIEWS = [["hash", "Hash"], ["depth", "Depth"], ["group", "Group"], ["response", "Response"]];
const CAPTION = {
  hash: "Distance: importance (critical in the middle) · direction: arbitrary but steady",
  depth: "Distance: levels below the top device · each branch has its own slice",
  group: "One slice per device group · distance: importance",
  response: "Distance: response time now (log scale) · offline on the rim",
};
const R = 230, C = 250;
const RESPONSE_RINGS = [[5, 60], [20, 120], [80, 180], [300, 235]];       // the ms written on each ring
const rttRadius = (ms) => Math.min(0.98, Math.log10(Math.max(1, ms)) / Math.log10(300) * 0.98);
const polar = (ang, frac) => ({ x: C + Math.cos(ang) * R * frac, y: C + Math.sin(ang) * R * frac });
const importance = (d, hh) => (d.tier === "critical" ? 0.18 + (hh >>> 12) % 30 / 100 : d.always_on ? 0.3 + (hh >>> 12) % 35 / 100 : 0.5 + (hh >>> 12) % 45 / 100);
const hashAngle = (id) => (hash(id) % 3600) / 10 * Math.PI / 180;

function layoutHash(devices) {
  const at = new Map();
  for (const d of devices) at.set(d.id, polar(hashAngle(d.id), importance(d, hash(d.id))));
  return { at, legend: [] };
}

function layoutResponse(devices, rtt) {
  const at = new Map();
  for (const d of devices) {
    const r = rtt.get(d.id);
    let frac, dim = false;
    if (!d.online || (r && r.up === false)) frac = 0.97;
    else if (r && r.rtt_ms != null) frac = rttRadius(r.rtt_ms);
    else { frac = 0.93; dim = true; }                                      // nothing measured lately
    at.set(d.id, { ...polar(hashAngle(d.id), frac), dim });
  }
  return { at, legend: RESPONSE_RINGS.map(([ms, r]) => ({ kind: "ring-label", r, text: `${ms} ms` })) };
}

function layoutDepth(devices, tree) {
  const nodes = new Map((tree || []).map((n) => [n.id, n]));
  const kids = new Map();
  for (const n of nodes.values()) { const p = nodes.has(n.parent_id) ? n.parent_id : null; if (!kids.has(p)) kids.set(p, []); kids.get(p).push(n.id); }
  const leaves = new Map();
  const count = (id) => { const k = kids.get(id) || []; const v = k.length ? k.reduce((a, c) => a + count(c), 0) : 1; leaves.set(id, v); return v; };
  const roots = (kids.get(null) || []).slice().sort((a, b) => a - b);
  roots.forEach(count);
  const maxDepth = Math.max(1, ...[...nodes.values()].map((n) => n.depth || 0));
  const ring = (depth) => (depth === 0 ? 0.03 : 0.1 + 0.85 * depth / maxDepth);
  const place = new Map();
  const walk = (ids, a0, a1, depth) => {
    const total = ids.reduce((a, id) => a + leaves.get(id), 0);
    let from = a0;
    for (const id of ids) {
      const span = (a1 - a0) * leaves.get(id) / total;
      place.set(id, { ang: from + span / 2, depth });
      walk((kids.get(id) || []).slice().sort((a, b) => a - b), from, from + span, depth + 1);
      from += span;
    }
  };
  walk(roots, -Math.PI / 2, Math.PI * 1.5, 0);
  const at = new Map();
  for (const d of devices) {
    const pl = place.get(d.id);
    if (pl) {
      const jitter = pl.depth ? ((hash(d.id) % 100) / 100 - 0.5) * 0.03 : 0;      // a hair of spread so siblings do not sit on one line
      at.set(d.id, polar(pl.ang, Math.max(0.03, ring(pl.depth) + jitter)));
    } else at.set(d.id, { ...polar(hashAngle(d.id), 0.97), dim: true });          // not in the tree (yet): out on the rim
  }
  const legend = [];
  for (let k = 1; k <= maxDepth; k++) legend.push({ kind: "ring", r: ring(k) * R }, { kind: "ring-label", r: ring(k) * R, text: `level ${k}` });
  return { at, legend };
}

function layoutGroup(devices, all) {
  const groups = new Map();
  for (const d of all) { const key = d.group_id ?? "none"; if (!groups.has(key)) groups.set(key, { key, name: d.group || "No group", colour: d.group_color || "#6d9db6", members: [] }); groups.get(key).members.push(d); }
  const list = [...groups.values()].sort((a, b) => (a.key === "none") - (b.key === "none") || a.name.localeCompare(b.name));
  const weight = (g) => Math.max(3, g.members.length);
  const total = list.reduce((a, g) => a + weight(g), 0);
  const at = new Map(), legend = [];
  let from = -Math.PI / 2;
  for (const g of list) {
    const span = Math.PI * 2 * weight(g) / total;
    const members = g.members.slice().sort((a, b) => (a.tier === "critical" ? 0 : 1) - (b.tier === "critical" ? 0 : 1) || a.id - b.id);
    members.forEach((d, i) => { at.set(d.id, polar(from + span * (i + 0.5) / members.length, importance(d, hash(d.id)))); });
    legend.push({ kind: "spoke", ang: from }, { kind: "slice-label", ang: from + span / 2, text: g.name, colour: g.colour });
    from += span;
  }
  return { at, legend };
}

function radar() {
  const s = svg("svg", { viewBox: "-80 0 660 500", role: "img", "aria-label": "Radar of all devices; red blips are offline" });
  const defs = svg("defs");
  const grad = svg("linearGradient", { id: "hudsweep", x1: 0, y1: 0, x2: 1, y2: 0 });
  grad.append(svg("stop", { offset: "0", "stop-color": COLOUR.cyan, "stop-opacity": 0 }), svg("stop", { offset: "1", "stop-color": COLOUR.cyan, "stop-opacity": 0.55 }));
  defs.appendChild(grad);
  s.appendChild(defs);
  const frame = svg("g", { class: "frame" });
  for (const r of [60, 120, 180, 235]) frame.appendChild(svg("circle", { class: "ring", cx: C, cy: C, r }));
  for (const a of [0, 45, 90, 135]) frame.appendChild(svg("line", { class: "axis", x1: C - 240 * Math.cos(a * Math.PI / 180), y1: C - 240 * Math.sin(a * Math.PI / 180), x2: C + 240 * Math.cos(a * Math.PI / 180), y2: C + 240 * Math.sin(a * Math.PI / 180) }));
  s.appendChild(frame);
  const legend = svg("g", { class: "legend" });
  s.appendChild(legend);
  const sweep = svg("g", { class: "sweep" });
  sweep.appendChild(svg("path", { d: "M250 250 L250 12 A238 238 0 0 1 418 82 Z", fill: "url(#hudsweep)", transform: "rotate(-45 250 250)" }));
  s.appendChild(sweep);
  const blips = svg("g");
  s.appendChild(blips);
  s.appendChild(svg("circle", { cx: C, cy: C, r: 4, fill: COLOUR.cyan }));
  const dots = new Map();
  let legendKey = "";

  function drawLegend(items, mode) {
    const key = mode + JSON.stringify(items);
    if (key === legendKey) return;
    legendKey = key;
    frame.classList.toggle("quiet", mode === "depth" || mode === "group");               // the fixed rings give way to the ones of the view
    clear(legend);
    for (const it of items) {
      if (it.kind === "ring") legend.appendChild(svg("circle", { class: "lring", cx: C, cy: C, r: it.r }));
      else if (it.kind === "ring-label") legend.appendChild(Object.assign(svg("text", { class: "lbl", x: C + 4, y: C - it.r - 3 }), { textContent: it.text }));
      else if (it.kind === "spoke") legend.appendChild(svg("line", { class: "axis spoke", x1: C, y1: C, x2: C + Math.cos(it.ang) * 240, y2: C + Math.sin(it.ang) * 240 }));
      else if (it.kind === "slice-label") {
        const x = C + Math.cos(it.ang) * 246, y = C + Math.sin(it.ang) * 246 + 3;
        const t = svg("text", { class: "lbl slice", x, y, "text-anchor": Math.cos(it.ang) < -0.2 ? "end" : Math.cos(it.ang) > 0.2 ? "start" : "middle", fill: it.colour });
        t.textContent = it.text.length > 16 ? `${it.text.slice(0, 15)}…` : it.text;
        legend.appendChild(t);
      }
    }
  }

  // devices: those to show; ctx: { mode, all (every device, so a view keeps its layout when the filter changes), tree (the hierarchy), rtt (Map id -> latest response) }
  s.update = (devices, ctx) => {
    const mode = ctx.mode;
    const { at, legend: items } = mode === "depth" ? layoutDepth(devices, ctx.tree) : mode === "group" ? layoutGroup(devices, ctx.all) : mode === "response" ? layoutResponse(devices, ctx.rtt) : layoutHash(devices);
    drawLegend(items, mode);
    const seen = new Set();
    for (const d of devices) {
      seen.add(d.id);
      const pos = at.get(d.id) || polar(hashAngle(d.id), 0.9);
      let dot = dots.get(d.id);
      const born = !dot;
      if (born) {
        dot = svg("circle", { cx: 0, cy: 0, tabindex: 0, role: "link" });
        const open = () => { location.hash = `#/device/${d.id}`; };
        dot.addEventListener("click", open);
        dot.addEventListener("keydown", (e) => { if (e.key === "Enter") open(); });
        dot.style.transition = "none"; dot.appendChild(svg("title")); dots.set(d.id, dot); blips.appendChild(dot);
      }
      const cls = `blip ${d.online ? "on" : "off"}${d.tier === "critical" ? " crit" : ""}${pos.dim ? " dim" : ""}`;
      if (dot.getAttribute("class") !== cls) {
        dot.setAttribute("class", cls);
        dot.setAttribute("r", d.tier === "critical" ? 6 : 4);
        dot.setAttribute("fill", d.online ? COLOUR.ok : COLOUR.bad);
        dot.style.filter = `drop-shadow(0 0 5px ${d.online ? COLOUR.ok : COLOUR.bad})`;
      }
      const move = `translate(${pos.x.toFixed(1)}px, ${pos.y.toFixed(1)}px)`;
      if (dot.style.transform !== move) dot.style.transform = move;
      if (born) requestAnimationFrame(() => requestAnimationFrame(() => { dot.style.transition = ""; }));      // a new blip appears in place; only later moves glide
      const r = ctx.rtt && ctx.rtt.get(d.id);
      dot.setAttribute("aria-label", `Open ${d.custom_name || d.hostname || d.primary_ip}`);
      dot.firstChild.textContent = `${d.custom_name || d.hostname || d.primary_ip}${d.online ? "" : " (offline)"}${mode === "response" && r && r.rtt_ms != null ? ` · ${r.rtt_ms} ms` : ""}`;
    }
    for (const [id, dot] of dots) if (!seen.has(id)) { dot.remove(); dots.delete(id); }
  };
  return s;
}

export async function render(container) {
  let disposed = false, lastId = 0;
  let scope = "all", coreIds = new Set();            // "core": only the always-on devices
  try { scope = localStorage.getItem("netlens.hud.scope") === "core" ? "core" : "all"; } catch (e) { /* not remembered */ }
  let lastList = null, lastDash = null, lastRel = null, tree = [], rtt = new Map();
  let view = "hash";
  try { const v = localStorage.getItem("netlens.hud.radar"); if (VIEWS.some(([k]) => k === v)) view = v; } catch (e) { /* not remembered */ }
  const viewBtns = {};
  const caption = h("p", { class: "hud-cap" }, CAPTION[view]);
  const viewSwitch = h("div", { class: "hud-scope hud-views", role: "group", "aria-label": "How the radar places the devices" },
    ...VIEWS.map(([key, label]) => (viewBtns[key] = h("button", { type: "button", "aria-pressed": String(key === view), onclick: () => {
      view = key;
      try { localStorage.setItem("netlens.hud.radar", key); } catch (e) { /* only this page remembers it */ }
      for (const [k, b] of Object.entries(viewBtns)) b.setAttribute("aria-pressed", String(k === view));
      caption.textContent = CAPTION[view];
      if (lastList) drawRadar();
    } }, label))));
  const clock = h("span", { class: "hud-clock" });
  const scopeBtns = {};
  const scopeSwitch = h("div", { class: "hud-scope", role: "group", "aria-label": "Which devices" },
    ...[["all", "All devices"], ["core", "Always-on"]].map(([key, label]) => (scopeBtns[key] = h("button", { type: "button", "aria-pressed": String(key === scope), onclick: () => {
      scope = key;
      try { localStorage.setItem("netlens.hud.scope", key); } catch (e) { /* only this page remembers it */ }
      for (const [k, b] of Object.entries(scopeBtns)) b.setAttribute("aria-pressed", String(k === scope));
      if (lastDash) paint();
    } }, label))));
  const gauges = h("div", { class: "hud-gauges" });
  const attn = h("ol", { class: "hud-attn" });
  const radarBox = h("div", { class: "hud-radar" });
  const radarSvg = radar();
  radarBox.appendChild(radarSvg);
  const gDevices = gauge("Devices online", "#/devices"), gServices = gauge("Services up", "#/services"), gAvail = gauge("Availability 30d", "#/uptime");
  gauges.append(gDevices, gServices, gAvail);
  let tickerText = "";
  const stats = h("div", { class: "hud-stats" });
  const feed = h("ol", {});
  const ticker = h("div", { class: "hud-ticker" });

  const root = h("div", { class: "hud" },
    h("div", { class: "hud-top" }, h("span", { class: "hud-title" }, h("i", { class: "hud-live" }), "Netlens // situation"), scopeSwitch, clock),
    h("div", { class: "hud-left" }, h("section", { class: "hud-panel" }, h("h3", {}, "Vitals"), gauges), h("section", { class: "hud-panel", style: "flex:1" }, h("h3", {}, "Needs attention"), attn)),
    h("div", { class: "hud-mid" }, h("section", { class: "hud-panel hud-radar-panel", style: "flex:1;display:flex;flex-direction:column" }, h("div", { class: "hud-panel-head" }, h("h3", {}, "Network scope"), viewSwitch), caption, radarBox), h("section", { class: "hud-panel" }, stats)),
    h("div", { class: "hud-right" }, h("section", { class: "hud-panel hud-feed", style: "flex:1" }, h("h3", {}, "Live event stream"), feed)),
    h("div", { class: "hud-bottom" }, ticker));
  clear(container);
  container.appendChild(root);

  // The ticker shows the text as many times as needed to be wider than the screen and scrolls by exactly one copy, so it loops without a gap.
  function fillTicker(spans) {
    const group = () => h("div", {}, ...spans.map((x) => x.cloneNode(true)));
    ticker.replaceChildren(group());
    const one = ticker.firstChild.getBoundingClientRect().width;
    if (!one) return;
    const copies = Math.max(2, Math.ceil(ticker.parentElement.clientWidth / one) + 1);
    for (let i = 1; i < copies; i++) ticker.appendChild(group());
    ticker.style.setProperty("--w", `${one}px`);
    ticker.style.animationDuration = `${Math.max(20, one / 55)}s`;       // about 55 pixels a second
  }

  const tick = () => { const d = new Date(); clock.textContent = `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`; };
  tick();
  const clockTimer = setInterval(tick, 1000);

  // the lists keep their data and draw only as many lines as fit the panel, so the page never scrolls
  const evs = [];
  let attnItems = [];
  function fit(list, make, items) {
    clear(list);
    for (let i = 0; i < items.length; i++) {
      list.appendChild(make(items[i], i));
      if (list.scrollHeight > list.clientHeight + 1) {
        list.lastChild.remove();
        if (attnItems === items && i > 0) { list.lastChild.remove(); list.appendChild(h("li", {}, `+${items.length - i + 1} more`)); if (list.scrollHeight > list.clientHeight + 1) list.lastChild.remove(); }
        break;
      }
    }
  }
  const eventLine = (e, i) => h("li", { class: `${level(e.kind)}${e.fresh && i === 0 ? " new" : ""}` },
    h("a", { href: eventHref(e), title: "Open it" }, h("time", {}, (e.ts || "").slice(11, 19)), `${e.device ? e.device + " · " : ""}${e.detail || e.kind.replace(/_/g, " ")}`));
  const shown = () => (scope === "core" ? evs.filter((e) => e.device_id == null || coreIds.has(e.device_id)) : evs);
  const drawFeed = () => fit(feed, eventLine, shown());
  let attnSig = "";
  const drawAttn = (force = false) => { const sig = JSON.stringify(attnItems); if (sig === attnSig && !force) return; attnSig = sig; if (!attnItems.length) { clear(attn); attn.appendChild(h("li", { class: "ok" }, "All systems nominal")); } else fit(attn, (a) => h("li", { class: a.level === "bad" ? "bad" : a.level === "warn" ? "warn" : "" }, h("a", { href: a.href || "#/dashboard" }, a.text)), attnItems); };
  function addEvent(e, fresh) {
    evs.unshift({ ...e, fresh });
    evs.length = Math.min(evs.length, 80);
    drawFeed();
    if (evs[0]) evs[0].fresh = false;          // only the newest line flashes, once
  }

  // the page fills the window exactly: from where it starts to the bottom edge
  const size = () => { root.style.height = `${Math.max(360, window.innerHeight - root.getBoundingClientRect().top - 30)}px`; drawFeed(); drawAttn(true); };
  window.addEventListener("resize", size);

  async function events(first) {
    try {
      const rows = await get(first ? "/api/events?limit=40" : `/api/events?since_id=${lastId}&limit=100`);
      if (disposed) return;
      for (const e of [...rows].reverse()) { addEvent(e, !first); lastId = Math.max(lastId, e.id); }
    } catch (err) { /* the next round tries again */ }
  }

  async function overview() {
    try {
      const [dash, devices, rel] = await Promise.all([get("/api/dashboard"), get("/api/devices?limit=1000"), get("/api/reliability").catch(() => null)]);
      if (disposed) return;
      lastList = Array.isArray(devices) ? devices : devices.devices || [];
      try { tree = (await get("/api/hierarchy")).nodes || []; } catch (e) { /* the depth view keeps the last tree */ }
      lastDash = dash;
      lastRel = rel;
      paint();
    } catch (err) { /* keep the last picture */ }
  }

  function drawRadar() {
    const shown = scope === "core" ? lastList.filter((d) => d.always_on) : lastList;
    radarSvg.update(shown, { mode: view, all: lastList, tree, rtt });
  }

  // the response times move often: look every few seconds, and let the blips glide when that is the view
  async function responses() {
    try {
      const rows = await get("/api/uptime/latest");
      if (disposed) return;
      rtt = new Map(rows.map((r) => [r.id, r]));
      if (view === "response" && lastList) drawRadar();
    } catch (err) { /* the next round tries again */ }
  }

  // draws what the last fetch brought, for the chosen set of devices
  function paint() {
    try {
      const dash = lastDash, rel = lastRel;
      coreIds = new Set(lastList.filter((d) => d.always_on).map((d) => d.id));
      const list = scope === "core" ? lastList.filter((d) => d.always_on) : lastList;
      const dv = { ...dash.summary.devices, total: list.length, online: list.filter((d) => d.online).length };
      dv.offline = dv.total - dv.online;
      const services = dash.service_checks || [];
      const up = services.filter((s) => s.state === "up").length;
      gDevices.set(dv.total ? 100 * dv.online / dv.total : 0, dv.offline > 3 ? COLOUR.warn : COLOUR.ok, `${dv.online}/${dv.total}`);
      gServices.set(services.length ? 100 * up / services.length : 100, up === services.length ? COLOUR.ok : COLOUR.bad, `${up}/${services.length}`);
      drawFeed();
      gAvail.set(rel ? rel.availability : null, rel && rel.meets_target ? COLOUR.ok : COLOUR.warn);
      attnItems = dash.attention || [];
      drawAttn();
      drawRadar();
      const sp = dash.speed;
      patch(stats, ...[["Flapping", dv.flapping, "#/uptime"], ["Unknown", dv.unknown, "#/devices"], ["New 24h", dv.new_24h, "#/changes"], ["Down", sp && sp.down_mbps ? `${Math.round(sp.down_mbps)} Mb` : "–", "#/speedtest"], ["Latency", sp && sp.latency_ms ? `${Math.round(sp.latency_ms)} ms` : "–", "#/speedtest"]]
        .map(([k, v, href]) => h("a", { href }, h("b", {}, String(v ?? "–")), k)));
      // the ticker keeps scrolling: its text is only replaced when a figure changed, and then the scroll carries on from where it is
      const spans = services.map((s) => h("a", { href: "#/services", title: `Open the checks: ${s.name}` }, `${s.name} `, h("b", { class: s.state === "up" ? "" : "bad" }, s.state === "up" ? `${s.ms != null ? Math.round(s.ms) + " ms" : "OK"}` : "DOWN")));
      const text = spans.map((x) => x.textContent).join("|");
      if (text !== tickerText) { tickerText = text; fillTicker(spans); }
    } catch (err) { /* keep the last picture */ }
  }

  size();
  await Promise.all([events(true), overview(), responses()]);
  if (lastList) drawRadar();
  size();
  const evTimer = setInterval(() => events(false), 4000);
  const ovTimer = setInterval(overview, 15000);
  const rtTimer = setInterval(responses, 5000);
  return () => { disposed = true; window.removeEventListener("resize", size); clearInterval(clockTimer); clearInterval(evTimer); clearInterval(ovTimer); clearInterval(rtTimer); };
}
