import { get } from "../api.js";
import { h, clear, patch } from "../util.js";
import { constellation } from "./hud_constellation.js";
import { replay } from "./hud_replay.js";

// EXPERIMENT: a full-screen command-centre view. It looks "streamed": the event list takes new events the moment the poll sees them (every 4 s), the gauges
// and radar refresh every 15 s, and the ticker runs along the bottom. Nothing is stored; it is read-only and uses the same API as the other pages.
const NS = "http://www.w3.org/2000/svg";
const svg = (tag, attrs = {}) => { const n = document.createElementNS(NS, tag); for (const [k, v] of Object.entries(attrs)) n.setAttribute(k, String(v)); return n; };
const COLOUR = { ok: "#00ffa3", warn: "#ffb020", bad: "#ff3b5c", cyan: "#00e5ff" };
const num = (n) => { if (typeof n === "number") return n; let v = 7; for (const ch of String(n)) v = (Math.imul(v, 31) + ch.charCodeAt(0)) >>> 0; return v; };       // containers have text ids
const cmp = (a, b) => (typeof a === "number" && typeof b === "number" ? a - b : String(a).localeCompare(String(b)));
const hash = (n) => { let x = (num(n) * 2654435761) >>> 0; x ^= x >>> 15; x = Math.imul(x, 2246822519) >>> 0; return (x ^ (x >>> 13)) >>> 0; };
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
// what the panel shows (the menu next to its title): the radar with the four views above, the constellation, or the time machine
const MODES = [["radar", "Radar", "Every device as a blip on the radar"], ["constellation", "Constellation", "Devices as stars joined by the network; every check is a pulse of light"],
  ["replay", "Time machine", "The radar as it was at an earlier moment, from the stored checks (unreachable is worked out from today's network layout; containers have no checks)"]];
const MODE_TITLE = { radar: "Network scope", constellation: "Constellation", replay: "Time machine" };
const R = 230, C = 250;
const SWEEP_MS = 6000;       // one turn of the sweep arm (hud-spin in hud.css)
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
  const roots = (kids.get(null) || []).slice().sort(cmp);
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
      walk((kids.get(id) || []).slice().sort(cmp), from, from + span, depth + 1);
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
    const members = g.members.slice().sort((a, b) => (a.tier === "critical" ? 0 : 1) - (b.tier === "critical" ? 0 : 1) || cmp(a.id, b.id));
    members.forEach((d, i) => { at.set(d.id, polar(from + span * (i + 0.5) / members.length, importance(d, hash(d.id)))); });
    legend.push({ kind: "spoke", ang: from }, { kind: "slice-label", ang: from + span / 2, text: g.name, colour: g.colour });
    from += span;
  }
  return { at, legend };
}

function radar() {
  const s = svg("svg", { viewBox: "8 8 484 484", role: "img", "aria-label": "Radar of all devices; red blips are offline" });
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

  function drawLegend(items, mode, text) {
    const key = `${mode}${text ? "t" : "n"}${JSON.stringify(items)}`;
    if (key === legendKey) return;
    legendKey = key;
    frame.classList.toggle("quiet", mode === "depth" || mode === "group");               // the fixed rings give way to the ones of the view
    clear(legend);
    let lastSpoke = null;
    for (const it of items) {
      if (it.kind === "spoke") lastSpoke = it.ang;
      if (it.kind === "slice-label" && lastSpoke != null) it.span = 2 * (it.ang - lastSpoke);        // the width of the slice, from its first spoke to the middle
      if (it.kind === "ring") legend.appendChild(svg("circle", { class: "lring", cx: C, cy: C, r: it.r }));
      else if (it.kind === "ring-label") { if (text) legend.appendChild(Object.assign(svg("text", { class: "lbl", x: C + 4, y: C - it.r - 3 }), { textContent: it.text })); }
      else if (it.kind === "spoke") legend.appendChild(svg("line", { class: "axis spoke", x1: C, y1: C, x2: C + Math.cos(it.ang) * 240, y2: C + Math.sin(it.ang) * 240 }));
    }
    if (text) drawSliceNames(items.filter((it) => it.kind === "slice-label"));
  }

  // The name of a group is written along the rim, just outside the circle, in the middle of its slice and in its colour: no lines, and a name never gets more room than its
  // own slice, so two names cannot run into each other. The text is turned to follow the circle and never stands on its head.
  function drawSliceNames(labels) {
    const FONT = 13, CHAR = FONT * 0.62;
    for (const it of labels) {
      const a = Math.atan2(Math.sin(it.ang), Math.cos(it.ang));                        // -PI..PI, 0 = right, PI/2 = down
      const bottom = Math.sin(a) > 0.0001;
      const room = (it.span || Math.PI / 4) * 246 * 0.92;                              // the arc of its slice, in drawing units
      const fit = Math.max(3, Math.min(18, Math.floor(room / CHAR)));
      const name = it.text.length > fit ? `${it.text.slice(0, fit - 1)}…` : it.text;
      const r = bottom ? 258 : 247;                                                    // the text grows away from its baseline: outward on top, inward (towards the circle) below
      const t = svg("text", { class: "lbl slice", "text-anchor": "middle", transform: `translate(${(C + Math.cos(a) * r).toFixed(1)} ${(C + Math.sin(a) * r).toFixed(1)}) rotate(${(a * 180 / Math.PI + 90 + (bottom ? 180 : 0)).toFixed(1)})` });
      t.style.fontSize = `${FONT}px`; t.style.fill = it.colour;
      t.textContent = name;
      if (name !== it.text) t.appendChild(Object.assign(svg("title"), { textContent: it.text }));
      legend.appendChild(t);
    }
  }

  // devices: those to show; ctx: { mode, all (every device, so a view keeps its layout when the filter changes), tree (the hierarchy), rtt (Map id -> latest response) }
  s.update = (devices, ctx) => {
    const mode = ctx.mode;
    const text = ctx.text !== false;
    s.setAttribute("viewBox", mode === "group" && text ? "-8 -8 516 516" : "8 8 484 484");       // the group names are written round the circle, so that view needs a little more room
    const { at, legend: items } = mode === "depth" ? layoutDepth(devices, ctx.tree) : mode === "group" ? layoutGroup(devices, ctx.all) : mode === "response" ? layoutResponse(devices, ctx.rtt) : layoutHash(devices);
    drawLegend(items, mode, text);
    const seen = new Set();
    for (const d of devices) {
      seen.add(d.id);
      let pos = at.get(d.id) || polar(hashAngle(d.id), 0.9);
      if (d.virtual && mode !== "depth") {                                  // a container circles its host
        const host = at.get(d.host_id);
        if (host) { const a = hashAngle(d.id); const rr = 9 + (hash(d.id) % 3) * 4; pos = { x: host.x + Math.cos(a) * rr, y: host.y + Math.sin(a) * rr, dim: host.dim }; }
      }
      let dot = dots.get(d.id);
      const born = !dot;
      if (born) {
        dot = svg("circle", { cx: 0, cy: 0, tabindex: 0, role: "link" });
        const open = () => { location.hash = `#/device/${d.virtual ? d.host_id : d.id}`; };       // a container has no page of its own: its host's
        dot.addEventListener("click", open);
        dot.addEventListener("keydown", (e) => { if (e.key === "Enter") open(); });
        dot.style.transition = "none"; dot.appendChild(svg("title")); dots.set(d.id, dot); blips.appendChild(dot);
      }
      const cls = `blip ${d.online ? "on" : "off"}${d.tier === "critical" ? " crit" : ""}${pos.dim ? " dim" : ""}${d.virtual ? " virt" : ""}`;
      if (dot.getAttribute("class") !== cls) {
        dot.setAttribute("class", cls);
        dot.setAttribute("r", d.virtual ? 2.4 : d.tier === "critical" ? 6 : 4);
        dot.setAttribute("fill", d.online ? COLOUR.ok : COLOUR.bad);
        dot.style.filter = `drop-shadow(0 0 5px ${d.online ? COLOUR.ok : COLOUR.bad})`;
        dot.style.setProperty("--blip", d.online ? COLOUR.ok : COLOUR.bad);       // the glow of a check takes the colour of the state
      }
      const move = `translate(${pos.x.toFixed(1)}px, ${pos.y.toFixed(1)}px)`;
      if (dot.style.transform !== move) dot.style.transform = move;
      dot.__at = pos;                                                    // where the blip is going (the sweep is timed on this)
      if (born) requestAnimationFrame(() => requestAnimationFrame(() => { dot.style.transition = ""; }));      // a new blip appears in place; only later moves glide
      const r = ctx.rtt && ctx.rtt.get(d.id);
      dot.setAttribute("aria-label", `Open ${d.custom_name || d.name || d.hostname || d.primary_ip}`);
      dot.firstChild.textContent = `${d.custom_name || d.name || d.hostname || d.primary_ip}${d.virtual ? " (container)" : ""}${d.online ? "" : " (offline)"}${mode === "response" && r && r.rtt_ms != null ? ` · ${r.rtt_ms} ms` : ""}`;
    }
    for (const [id, dot] of dots) if (!seen.has(id)) { dot.remove(); dots.delete(id); }
  };
  // a ring spreads from a blip (the time machine shows every change this way)
  s.ring = (id, up) => {
    const dot = dots.get(id), at = dot && dot.__at;
    if (!at) return;
    const ring = svg("circle", { class: "ripple", cx: at.x, cy: at.y, r: 6, fill: "none", stroke: up ? COLOUR.ok : COLOUR.bad });
    blips.appendChild(ring);
    ring.addEventListener("animationend", () => ring.remove());
    setTimeout(() => ring.remove(), 1500);
  };
  // a check of these devices just ran: each blip glows once when the arm of the sweep passes over it (online and offline alike).
  // The arm turns clockwise once every SWEEP_MS and its bright edge points straight up at phase 0; the glow is an animation with a delay of exactly the time the edge needs to get there.
  s.flash = (ids) => {
    const spin = sweep.getAnimations().find((a) => a.animationName === "hud-spin") || sweep.getAnimations()[0];
    const phase = spin && spin.currentTime != null ? Number(spin.currentTime) % SWEEP_MS : null;
    const now = performance.now();
    const lit = [];
    for (const id of ids) {
      const dot = dots.get(id);
      if (!dot || !dot.__at || (dot.__start && now < dot.__start)) continue;        // unknown, or already waiting for the arm
      const toBlip = (Math.atan2(dot.__at.y - C, dot.__at.x - C) + Math.PI / 2 + 2 * Math.PI) % (2 * Math.PI);       // clockwise from "up"
      const wait = phase == null ? 0 : ((toBlip / (2 * Math.PI)) * SWEEP_MS - phase + SWEEP_MS) % SWEEP_MS;
      dot.classList.remove("ping");
      dot.style.animationDelay = `${Math.round(wait)}ms`;
      dot.__start = now + wait;
      lit.push(dot);
    }
    if (lit.length) void s.getBoundingClientRect();                       // restart the animation of a blip that is still glowing
    for (const dot of lit) dot.classList.add("ping");
  };
  return s;
}

// ---- the traffic graph ----------------------------------------------------------------------------------------------------------------------------
// In and out of all monitored devices combined, and the internet connection (WAN) on lines of its own. Built once; every refresh only changes the paths.
const LINES = [["drx", "Devices in", "#00e5ff", ""], ["dtx", "Devices out", "#ff4fd8", ""], ["wrx", "WAN in", "#ffb020", "5 3"], ["wtx", "WAN out", "#ff7a45", "5 3"]];
const bps = (v) => (v == null ? "–" : v >= 1e9 ? `${(v / 1e9).toFixed(2)} Gbit/s` : v >= 1e6 ? `${(v / 1e6).toFixed(v >= 1e8 ? 0 : 1)} Mbit/s` : v >= 1e3 ? `${Math.round(v / 1e3)} kbit/s` : `${Math.round(v)} bit/s`);
const niceMax = (v) => { if (!(v > 0)) return 1e6; const p = 10 ** Math.floor(Math.log10(v)); const f = v / p; return (f <= 1 ? 1 : f <= 2 ? 2 : f <= 5 ? 5 : 10) * p; };

function trafficChart() {
  const W = 400, H = 120, L = 4, B = 14;
  const s = svg("svg", { viewBox: `0 0 ${W} ${H}`, preserveAspectRatio: "none", role: "img", "aria-label": "Traffic of all devices combined and of the internet connection" });
  for (const f of [0.25, 0.5, 0.75]) s.appendChild(svg("line", { class: "axis", x1: L, x2: W, y1: (H - B) * f, y2: (H - B) * f }));
  const paths = {};
  for (const [key, , colour, dash] of LINES) {
    paths[key] = svg("path", { fill: "none", stroke: colour, "stroke-width": 1.6, "vector-effect": "non-scaling-stroke", "stroke-dasharray": dash, "stroke-linejoin": "round" });
    s.appendChild(paths[key]);
  }
  const top = h("span", { class: "tmax" }), from = h("span", { class: "tfrom" }), to = h("span", { class: "tto" }, "now");      // written in HTML: text inside a stretched drawing would be squashed
  s.labels = [top, from, to];
  s.update = (data) => {
    const series = { drx: data.devices.rx, dtx: data.devices.tx, wrx: data.wan ? data.wan.rx : [], wtx: data.wan ? data.wan.tx : [] };
    const max = niceMax(Math.max(0, ...Object.values(series).flat().map((p) => p[1])));
    const t0 = data.start, t1 = data.end, x = (t) => L + (W - L) * (t - t0) / Math.max(1, t1 - t0), y = (v) => (H - B) - (H - B - 6) * v / max;
    for (const [key] of LINES) {
      const pts = series[key];
      paths[key].setAttribute("d", pts.length ? pts.map((p, i) => `${i ? "L" : "M"}${x(p[0]).toFixed(1)} ${y(p[1]).toFixed(1)}`).join(" ") : "");
    }
    top.textContent = bps(max);
    const fmt = (t) => new Date(t * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", hour12: false });
    from.textContent = fmt(t0);
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
  const viewSwitch = h("div", { class: "hud-scope hud-views", role: "group", "aria-label": "How the radar places the devices" },
    ...VIEWS.map(([key, label]) => (viewBtns[key] = h("button", { type: "button", "aria-pressed": String(key === view), onclick: () => {
      view = key;
      try { localStorage.setItem("netlens.hud.radar", key); } catch (e) { /* only this page remembers it */ }
      markViews();
      if (lastList) drawRadar();
    } }, label))));
  // the layout in use: the time machine has no past response times, so it shows Response as Hash
  const layout = () => (mode === "replay" && view === "response" ? "hash" : view);
  function markViews() {
    for (const [k, b] of Object.entries(viewBtns)) b.setAttribute("aria-pressed", String(k === layout()));
    viewBtns.response.hidden = mode === "replay";
  }
  // the T button: all the text on the radar and the constellation on or off (off gives the radar the whole box)
  let showText = true;
  try { showText = localStorage.getItem("netlens.hud.text") !== "0"; } catch (e) { /* not remembered */ }
  const textBtn = h("button", { type: "button", class: "hud-toggle hud-t", "aria-pressed": String(showText), "aria-label": "Show the text", title: "Text on or off (off: the radar gets the whole box)", onclick: () => {
    showText = !showText;
    textBtn.setAttribute("aria-pressed", String(showText));
    try { localStorage.setItem("netlens.hud.text", showText ? "1" : "0"); } catch (e) { /* only this page remembers it */ }
    stars.setText(showText);
    if (lastList) drawRadar();
  } }, "T");
  // the container switch: containers and apps that plugins report (they are no devices) circle their host
  let showContainers = false;
  try { showContainers = localStorage.getItem("netlens.hud.containers") === "1"; } catch (e) { /* not remembered */ }
  const containerBtn = h("button", { type: "button", class: "hud-toggle", "aria-pressed": String(showContainers), title: "Also show containers and apps that plugins report (Docker, LXC ...) around their host", onclick: async () => {
    showContainers = !showContainers;
    containerBtn.setAttribute("aria-pressed", String(showContainers));
    try { localStorage.setItem("netlens.hud.containers", showContainers ? "1" : "0"); } catch (e) { /* only this page remembers it */ }
    await loadTree();
    if (lastList) drawRadar();
  } }, "Containers");
  const fsIcon = (on) => { const i = svg("svg", { viewBox: "0 0 20 20", width: 14, height: 14, fill: "none", stroke: "currentColor", "stroke-width": 1.8 }); i.appendChild(svg("path", { d: on ? "M8 3v5H3 M12 3v5h5 M8 17v-5H3 M12 17v-5h5" : "M3 8V3h5 M12 3h5v5 M17 12v5h-5 M8 17H3v-5" })); return i; };
  const radarFs = h("button", { type: "button", class: "hud-fs hud-fs-icon", title: "Show only this panel on the whole screen (Esc to leave)", "aria-label": "Full screen for this panel", onclick: () => {
    if (document.fullscreenElement) document.exitFullscreen(); else if (radarPanel.requestFullscreen) radarPanel.requestFullscreen().catch(() => {});
  } }, fsIcon(false));
  // the menu next to the title: what the panel shows (the radar is the default and is not remembered)
  let mode = "radar";
  const modeItems = {};
  const modeMenu = h("div", { class: "hud-menu", role: "menu", hidden: true }, ...MODES.map(([key, label, hint]) => (modeItems[key] = h("button", { type: "button", role: "menuitemradio", "aria-checked": String(key === mode), title: hint, onclick: () => { closeMenu(); setMode(key); } }, label))));
  const modeBtn = h("button", { type: "button", class: "hud-menu-btn", "aria-haspopup": "true", "aria-expanded": "false", "aria-label": "Choose what the panel shows", title: "Radar, constellation or time machine", onclick: (e) => { e.stopPropagation(); modeMenu.hidden ? openMenu() : closeMenu(); } }, "☰");
  const modeWrap = h("div", { class: "hud-menu-wrap" }, modeBtn, modeMenu);
  const outside = (e) => { if (!modeWrap.contains(e.target)) closeMenu(); };
  const escape = (e) => { if (e.key === "Escape") closeMenu(); };
  function openMenu() { modeMenu.hidden = false; modeBtn.setAttribute("aria-expanded", "true"); document.addEventListener("click", outside); document.addEventListener("keydown", escape); }
  function closeMenu() { modeMenu.hidden = true; modeBtn.setAttribute("aria-expanded", "false"); document.removeEventListener("click", outside); document.removeEventListener("keydown", escape); }
  async function setMode(key) {
    const hadGuests = wantGuests();
    mode = key;
    if (wantGuests() !== hadGuests) await loadTree();          // the container nodes are only fetched for the constellation
    for (const [k, b] of Object.entries(modeItems)) b.setAttribute("aria-checked", String(k === mode));
    applyMode();
  }
  const clock = h("span", { class: "hud-clock" });
  const fsButton = h("button", { type: "button", class: "hud-fs", title: "Show the HUD on the whole screen (Esc to leave)", "aria-label": "Full screen", onclick: () => {
    if (document.fullscreenElement) document.exitFullscreen(); else if (root.requestFullscreen) root.requestFullscreen().catch(() => {});
  } }, "Full screen");
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
  let tRange = "1h";
  try { const v = localStorage.getItem("netlens.hud.traffic"); if (["1h", "6h", "24h"].includes(v)) tRange = v; } catch (e) { /* not remembered */ }
  let tMode = "all";
  try { if (localStorage.getItem("netlens.hud.traffic.mode") === "endpoints") tMode = "endpoints"; } catch (e) { /* not remembered */ }
  const tModeBtns = {};
  const tModeSwitch = h("div", { class: "hud-scope", role: "group", "aria-label": "What the traffic graph adds up", title: "All interfaces: every interface of every monitored device, so traffic that crosses a switch or a bridge is counted on each. Endpoints: leaves out switches, routers, access points and virtual interfaces." },
    ...[["all", "All interfaces"], ["endpoints", "Endpoints"]].map(([key, label]) => (tModeBtns[key] = h("button", { type: "button", "aria-pressed": String(key === tMode), onclick: () => {
      tMode = key;
      try { localStorage.setItem("netlens.hud.traffic.mode", key); } catch (e) { /* only this page remembers it */ }
      for (const [k, b] of Object.entries(tModeBtns)) b.setAttribute("aria-pressed", String(k === tMode));
      traffic();
    } }, label))));
  const tChart = trafficChart();
  const tLegend = h("div", { class: "hud-tlegend" });
  const tNote = h("p", { class: "hud-cap" });
  const tBtns = {};
  const tSwitch = h("div", { class: "hud-scope", role: "group", "aria-label": "Period of the traffic graph" },
    ...["1h", "6h", "24h"].map((key) => (tBtns[key] = h("button", { type: "button", "aria-pressed": String(key === tRange), onclick: () => {
      tRange = key;
      try { localStorage.setItem("netlens.hud.traffic", key); } catch (e) { /* only this page remembers it */ }
      for (const [k, b] of Object.entries(tBtns)) b.setAttribute("aria-pressed", String(k === tRange));
      traffic();
    } }, key))));
  const trafficPanel = h("section", { class: "hud-panel hud-traffic" }, h("div", { class: "hud-panel-head" }, h("h3", {}, "Traffic"), tModeSwitch, tSwitch), tLegend, h("div", { class: "hud-tchart" }, tChart, ...tChart.labels), tNote);
  const radarBox = h("div", { class: "hud-radar" });
  const radarSvg = radar();
  radarBox.appendChild(radarSvg);
  const stars = constellation({ onOpen: (n) => { location.hash = `#/device/${n.virtual ? n.host : n.id}`; } });
  radarBox.appendChild(stars.el);
  stars.setText(showText);
  const timeMachine = replay({
    getTree: () => tree, getDevices: () => lastList,
    onChange: (moved) => { if (mode !== "replay" || !lastList) return; drawRadar(); for (const m of moved.slice(0, 30)) radarSvg.ring(m.id, m.up); },
  });
  const gDevices = gauge("Devices online", "#/devices"), gServices = gauge("Services up", "#/services"), gAvail = gauge("Availability 30d", "#/uptime");
  gauges.append(gDevices, gServices, gAvail);
  let tickerText = "";
  const stats = h("div", { class: "hud-stats" });
  const feed = h("ol", {});
  const ticker = h("div", { class: "hud-ticker" });

  const panelTitle = h("h3", {}, MODE_TITLE.radar);
  const radarPanel = h("section", { class: "hud-panel hud-radar-panel", style: "flex:1;display:flex;flex-direction:column" }, h("div", { class: "hud-panel-head" }, textBtn, modeWrap, panelTitle, h("span", { class: "hud-spacer" }), viewSwitch, containerBtn, radarFs), radarBox, timeMachine.el);
  radarPanel.addEventListener("fullscreenchange", () => { const on = document.fullscreenElement === radarPanel; radarFs.replaceChildren(fsIcon(on)); radarFs.title = on ? "Leave full screen (Esc)" : "Show only this panel on the whole screen (Esc to leave)"; radarPanel.classList.toggle("is-full", on); if (mode === "replay") timeMachine.activate(true); });
  if (!document.fullscreenEnabled) radarFs.hidden = true;
  function applyMode() {
    panelTitle.textContent = MODE_TITLE[mode];
    viewSwitch.hidden = mode === "constellation";              // the layouts belong to the radar and the time machine
    markViews();
    containerBtn.hidden = mode !== "constellation";            // containers are drawn in the constellation only
    radarSvg.style.display = mode === "constellation" ? "none" : "";
    stars.show(mode === "constellation");
    timeMachine.activate(mode === "replay");
    if (lastList) drawRadar();
  }

  const root = h("div", { class: "hud" },
    h("div", { class: "hud-top" }, h("span", { class: "hud-title" }, h("i", { class: "hud-live" }), "Netlens // situation"), scopeSwitch, h("span", { class: "hud-top-right" }, clock, fsButton)),
    h("div", { class: "hud-left" }, h("section", { class: "hud-panel" }, h("h3", {}, "Vitals"), gauges), h("section", { class: "hud-panel", style: "flex:1" }, h("h3", {}, "Needs attention"), attn)),
    h("div", { class: "hud-mid" }, radarPanel, h("section", { class: "hud-panel" }, stats)),
    h("div", { class: "hud-right" }, h("section", { class: "hud-panel hud-feed", style: "flex:1" }, h("h3", {}, "Live event stream"), feed), trafficPanel),
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
  root.addEventListener("fullscreenchange", () => { const on = document.fullscreenElement === root; fsButton.textContent = on ? "Exit full screen" : "Full screen"; size(); });
  if (!document.fullscreenEnabled) fsButton.hidden = true;       // some browsers (and iframes) do not allow it

  async function events(first) {
    try {
      const rows = await get(first ? "/api/events?limit=40" : `/api/events?since_id=${lastId}&limit=100`);
      if (disposed) return;
      for (const e of [...rows].reverse()) { addEvent(e, !first); lastId = Math.max(lastId, e.id); }
    } catch (err) { /* the next round tries again */ }
  }

  const wantGuests = () => showContainers && mode === "constellation";
  async function loadTree() {
    try { tree = (await get(wantGuests() ? "/api/hierarchy?guests=true" : "/api/hierarchy")).nodes || []; } catch (e) { /* the views keep the last tree */ }
  }

  // containers as devices without an address: the group and importance of their host, the state of the container
  function withContainers(list) {
    if (!wantGuests()) return list;
    const byId = new Map(list.map((d) => [d.id, d]));
    const extra = [];
    for (const n of tree) {
      if (!n.virtual) continue;
      const host = byId.get(n.parent_id);
      if (!host) continue;                                              // its host is not on the screen (the core scope, for example)
      extra.push({ id: n.id, name: n.name, online: !!n.online, tier: "normal", always_on: false, group_id: host.group_id, group: host.group, group_color: host.group_color, virtual: true, host_id: n.parent_id });
    }
    return list.concat(extra);
  }

  async function overview() {
    try {
      const [dash, devices, rel] = await Promise.all([get("/api/dashboard"), get("/api/devices?limit=1000"), get("/api/reliability").catch(() => null)]);
      if (disposed) return;
      lastList = Array.isArray(devices) ? devices : devices.devices || [];
      await loadTree();
      lastDash = dash;
      lastRel = rel;
      paint();
    } catch (err) { /* keep the last picture */ }
  }

  function drawRadar() {
    const base = scope === "core" ? lastList.filter((d) => d.always_on) : lastList;
    if (mode === "constellation") { stars.update(withContainers(base), tree); return; }
    if (mode === "replay") { radarSvg.update(timeMachine.apply(base), { mode: layout(), all: lastList, tree, rtt, text: showText }); return; }      // containers have no history
    radarSvg.update(base, { mode: view, all: lastList, tree, rtt, text: showText });
  }

  // the response times move often: look every few seconds, and let the blips glide when that is the view
  async function responses() {
    try {
      const rows = await get("/api/uptime/latest");
      if (disposed) return;
      const before = rtt;
      rtt = new Map(rows.map((r) => [r.id, r]));
      if (before.size && mode !== "replay") {
        const checked = rows.filter((r) => { const b = before.get(r.id); return b && b.ts !== r.ts; }).map((r) => r.id);       // a new check since the last look
        radarSvg.flash(checked);
        stars.flash(checked);
      }
      if (mode === "radar" && view === "response" && lastList) drawRadar();
    } catch (err) { /* the next round tries again */ }
  }

  async function traffic() {
    try {
      const data = await get(`/api/traffic?range=${tRange}&mode=${tMode}`);
      if (disposed) return;
      tChart.update(data);
      const now = (o, k) => (o && o.now ? o.now[k] : null);
      const item = (key, label, colour, dash, value) => h("a", { href: "#/health", class: "hud-tl", title: "Open the health monitors" },
        h("i", { style: `background:${dash ? "transparent" : colour};border:1px ${dash ? "dashed" : "solid"} ${colour}` }), `${label} `, h("b", {}, bps(value)));
      patch(tLegend, ...LINES.filter(([key]) => key[0] === "d" || data.wan).map(([key, label, colour, dash]) => item(key, label, colour, dash,
        key === "drx" ? now(data.devices, "rx") : key === "dtx" ? now(data.devices, "tx") : key === "wrx" ? now(data.wan, "rx") : now(data.wan, "tx"))));
      tNote.textContent = !data.devices.count ? "No monitored device reports traffic yet: set up health monitoring on a device."
        : !data.wan ? `${data.devices.count} devices, ${data.devices.interfaces} interfaces. No WAN line: monitor the router (SNMP) and choose its internet interface under Settings → Interface.`
        : `${data.devices.count} devices, ${data.devices.interfaces} interfaces${tMode === "endpoints" ? " (switches, routers and virtual interfaces left out)" : ""} · WAN: ${data.wan.device ? data.wan.device + " · " : ""}${data.wan.label}`;
    } catch (err) { /* the graph keeps its last picture */ }
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
  await Promise.all([events(true), overview(), responses(), traffic()]);
  applyMode();
  size();
  const evTimer = setInterval(() => events(false), 4000);
  const ovTimer = setInterval(overview, 15000);
  const rtTimer = setInterval(responses, 5000);
  const trTimer = setInterval(traffic, 15000);
  return () => { disposed = true; window.removeEventListener("resize", size); clearInterval(clockTimer); clearInterval(evTimer); clearInterval(ovTimer); clearInterval(rtTimer); clearInterval(trTimer); stars.dispose(); timeMachine.dispose(); closeMenu(); };
}
