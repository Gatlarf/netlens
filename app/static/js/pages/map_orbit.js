import { get } from "../api.js";
import { h, clear, shortName } from "../util.js";

// The "Orbit" view of the map: the gateway in the middle, the switches and access points on a ring around it, and every device that hangs on one
// circling it in rows. A lit path shows what a device depends on; pointing at a device reads out its name, address and where it sits. Pan by dragging,
// zoom with the wheel or the buttons. Nothing here is saved: it is drawn fresh from the same data as the other views.
const SVG = "http://www.w3.org/2000/svg";
const GLYPH = { router: "GW", switch: "SW", ap: "AP", server: "SV", nas: "NAS", vm: "VM", container: "CT", camera: "CAM", printer: "PR", phone: "PH", tv: "TV" };
const KIND = { server: "srv", nas: "srv", vm: "guest", container: "guest", app: "guest", router: "net", switch: "net", ap: "net" };
const ROW = 25;                // distance between two devices in a row
const FIRST_RING = 190;        // the smallest radius of the first ring of hubs
const reduceMotion = () => window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;

function svg(tag, attrs = {}, ...children) {
  const el = document.createElementNS(SVG, tag);
  for (const [k, v] of Object.entries(attrs)) if (v !== null && v !== undefined && v !== false) el.setAttribute(k, v === true ? "" : String(v));
  for (const c of children) if (c) el.appendChild(c);
  return el;
}

// parent -> children from the chosen hierarchy (one parent per device), and the main root: the router with the biggest tree
export function buildTree(nodes, edges) {
  const byId = new Map(nodes.map((n) => [n.id, n]));
  const parent = new Map();
  for (const n of nodes) if (n.parent_id !== undefined && n.parent_id !== null && byId.has(n.parent_id) && n.parent_id !== n.id) parent.set(n.id, n.parent_id);
  for (const e of edges) {
    if ((e.kind !== "parent" && e.kind !== "host-of" && e.kind !== "uplink") || !byId.has(e.from) || !byId.has(e.to) || parent.has(e.to) || e.from === e.to) continue;
    parent.set(e.to, e.from);
  }
  for (const id of [...parent.keys()]) {          // a loop in the data would never end: cut it where it closes
    const seen = new Set([id]);
    for (let p = parent.get(id); p !== undefined; p = parent.get(p)) {
      if (seen.has(p)) { parent.delete(id); break; }
      seen.add(p);
    }
  }
  const kids = new Map(nodes.map((n) => [n.id, []]));
  for (const [child, p] of parent) kids.get(p).push(child);
  for (const list of kids.values()) list.sort((a, b) => weightOf(kids, b) - weightOf(kids, a) || String(byId.get(a).label).localeCompare(String(byId.get(b).label)));
  const roots = nodes.filter((n) => !parent.has(n.id)).map((n) => n.id);
  const main = [...roots].sort((a, b) => (byId.get(b).type === "router") - (byId.get(a).type === "router") || weightOf(kids, b) - weightOf(kids, a))[0];
  if (main === undefined) return { kids, parent, root: null, byId };
  for (const r of roots) if (r !== main) { kids.get(main).push(r); parent.set(r, main); }        // other trees hang on the main one so nothing is lost
  return { kids, parent, root: main, byId };
}

const weights = new WeakMap();
function weightOf(kids, id) {
  let memo = weights.get(kids);
  if (!memo) weights.set(kids, memo = new Map());
  if (memo.has(id)) return memo.get(id);
  memo.set(id, 1);                                                                      // guards against a loop while it is being worked out
  const w = 1 + (kids.get(id) || []).reduce((a, c) => a + weightOf(kids, c), 0);
  memo.set(id, w);
  return w;
}

// Radial layout. A hub sits on the ring of its depth; the devices that hang on it (and have nothing below them) circle it in small rows, and the hubs that
// hang on it get their own wedge further out. A cluster takes the room its devices need, so the rings are as far from the middle as that takes.
const FIRST_ROW = 54, ROW_STEP = 22, GAP = 40;
function cluster(count, span) {                // how many rows `count` devices need around a hub, and how far out the last one is
  let placed = 0, row = 0, outer = 0;
  while (placed < count) {
    const rho = FIRST_ROW + row * ROW_STEP;
    const room = Math.max(4, Math.floor((span * rho) / ROW));
    placed += room;
    outer = rho;
    row++;
  }
  return { rows: row, radius: count ? outer + 8 : 20 };
}

export function layout(tree) {
  const { kids, root } = tree;
  const pos = new Map();
  if (root === null) return { pos, rings: [] };
  const info = new Map();                                  // per hub: its devices, its sub-hubs and the size of its cluster
  const prepare = (id, depth) => {
    const children = kids.get(id) || [];
    const hubs = children.filter((c) => (kids.get(c) || []).length);
    const leaves = children.filter((c) => !(kids.get(c) || []).length);
    const span = depth === 0 || hubs.length ? Math.PI * 2 : Math.PI * 1.7;
    const size = cluster(leaves.length, span);
    const entry = { hubs, leaves, span, ...size, depth };
    info.set(id, entry);
    for (const c of hubs) prepare(c, depth + 1);
    entry.width = Math.max(2 * entry.radius + GAP, hubs.reduce((a, c) => a + info.get(c).width, 0));       // the angular room it asks for, as a length
  };
  prepare(root, 0);
  pos.set(root, { x: 0, y: 0, r: 0, depth: 0, hub: true });
  const rings = [0];
  let level = [{ id: root, a0: -Math.PI / 2, a1: Math.PI * 1.5 }];
  let depth = 0;
  while (level.length) {
    const next = [];
    for (const { id, a0, a1 } of level) {
      const e = info.get(id);
      const total = e.hubs.reduce((a, c) => a + info.get(c).width, 0) || 1;
      let cursor = a0;
      for (const c of e.hubs) {
        const share = (info.get(c).width / total) * (a1 - a0);
        next.push({ id: c, a0: cursor, a1: cursor + share });
        cursor += share;
      }
    }
    if (!next.length) break;
    const reach = Math.max(...level.map((n) => info.get(n.id).radius));
    const bigNext = Math.max(...next.map((n) => info.get(n.id).radius));
    const around = next.reduce((a, n) => a + info.get(n.id).width, 0) / (Math.PI * 2);        // the ring must be long enough for everything on it
    const r = Math.max(depth === 0 ? FIRST_RING : rings[depth] + reach + bigNext + 70, reach + bigNext + 70, around * 1.08);
    rings.push(r);
    for (const n of next) {
      const a = (n.a0 + n.a1) / 2;
      pos.set(n.id, { x: r * Math.cos(a), y: r * Math.sin(a), a, r, depth: depth + 1, hub: true });
    }
    level = next;
    depth++;
  }
  for (const [id, e] of info) {                              // the devices circle their hub
    const hub = pos.get(id);
    if (!hub || !e.leaves.length) continue;
    const centre = e.span >= Math.PI * 2 ? 0 : hub.a;        // a hub with nothing beyond it keeps its devices on the far side, away from its own link
    let placed = 0, row = 0;
    while (placed < e.leaves.length) {
      const rho = (id === root ? 62 : FIRST_ROW) + row * ROW_STEP;
      const room = Math.max(4, Math.floor((e.span * rho) / ROW));
      const take = Math.min(room, e.leaves.length - placed);
      for (let i = 0; i < take; i++) {
        const a = e.span >= Math.PI * 2 ? -Math.PI / 2 + ((i + 0.5 + row * 0.5) / take) * Math.PI * 2 : centre - e.span / 2 + ((i + 0.5) / take) * e.span;
        pos.set(e.leaves[placed + i], { x: hub.x + rho * Math.cos(a), y: hub.y + rho * Math.sin(a), a, r: rho, depth: hub.depth + 1, hub: false });
      }
      placed += take;
      row++;
    }
  }
  return { pos, rings: rings.slice(1) };
}

export async function renderOrbit(container, { layouts, current, onLayout }) {
  let destroyed = false;
  const layoutSelect = h("select", { class: "layout-mode", title: "How the devices are arranged" }, ...layouts.map(([v, l]) => h("option", { value: v, selected: v === current }, l)));
  layoutSelect.addEventListener("change", () => onLayout(layoutSelect.value));
  const search = h("input", { type: "search", placeholder: "Search name, IP, vendor" });
  const status = h("select", {}, h("option", { value: "all" }, "All"), h("option", { value: "online" }, "Online"), h("option", { value: "offline" }, "Offline"));
  const names = h("label", { class: "check", title: "Write the name next to every device" }, h("input", { type: "checkbox" }), " Names");
  const zoomIn = h("button", { class: "btn", type: "button", title: "Zoom in" }, "+");
  const zoomOut = h("button", { class: "btn", type: "button", title: "Zoom out" }, "−");
  const fit = h("button", { class: "btn", type: "button", title: "Show everything" }, "Fit");
  const readout = h("div", { class: "orbit-readout", "aria-live": "polite" }, "Point at a device");
  const stage = h("div", { class: "orbit-stage" }, h("p", { class: "hint" }, "Loading..."));
  container.append(h("div", { class: "toolbar" }, search, status, layoutSelect, names, zoomIn, zoomOut, fit), stage, readout);

  let data = { nodes: [], edges: [] };
  let view = { x: 0, y: 0, k: 1 };
  let fitted = false;
  let root = null, world = null, geometry = null, tree = null;

  const apply = () => world && world.setAttribute("transform", `translate(${view.x} ${view.y}) scale(${view.k})`);
  function fitAll() {
    if (!geometry || !root) return;
    const w = stage.clientWidth || 900, hgt = stage.clientHeight || 600;
    let minX = -60, maxX = 60, minY = -60, maxY = 60;
    for (const p of geometry.pos.values()) { minX = Math.min(minX, p.x - 40); maxX = Math.max(maxX, p.x + 40); minY = Math.min(minY, p.y - 40); maxY = Math.max(maxY, p.y + 40); }
    const k = Math.min(1.4, Math.min(w / (maxX - minX), hgt / (maxY - minY)));
    view = { k, x: w / 2 - ((minX + maxX) / 2) * k, y: hgt / 2 - ((minY + maxY) / 2) * k };
    apply();
  }
  function zoomAt(factor, cx, cy) {
    const k = Math.max(0.15, Math.min(4, view.k * factor));
    const f = k / view.k;
    view = { k, x: cx - (cx - view.x) * f, y: cy - (cy - view.y) * f };
    apply();
  }
  const centre = () => [(stage.clientWidth || 900) / 2, (stage.clientHeight || 600) / 2];
  zoomIn.addEventListener("click", () => zoomAt(1.3, ...centre()));
  zoomOut.addEventListener("click", () => zoomAt(1 / 1.3, ...centre()));
  fit.addEventListener("click", fitAll);

  function lineage(id) {                                  // the devices above it, and everything below it
    const set = new Set([id]);
    for (let p = tree.parent.get(id); p !== undefined && !set.has(p); p = tree.parent.get(p)) set.add(p);
    const down = [id];
    while (down.length) for (const c of tree.kids.get(down.pop()) || []) if (!set.has(c)) { set.add(c); down.push(c); }
    return set;
  }

  function matches(n) {
    const q = search.value.trim().toLowerCase();
    return (status.value === "all" || (status.value === "online") === !!n.online) && (!q || `${n.label || ""} ${n.ip || ""} ${n.vendor || ""} ${n.group || ""}`.toLowerCase().includes(q));
  }

  function draw() {
    clear(stage);
    tree = buildTree(data.nodes, data.edges);
    root = tree.root;
    if (root === null) { stage.appendChild(h("p", { class: "hint" }, "No devices yet.")); return; }
    geometry = layout(tree);
    const { pos, rings } = geometry;
    const byId = tree.byId;
    const canvas = svg("svg", { class: "orbit-svg", role: "group", "aria-label": "Network map" });
    world = svg("g", { class: "orbit-world" });
    canvas.appendChild(world);
    const guides = svg("g", { class: "orbit-rings" });
    for (const r of rings) guides.appendChild(svg("circle", { cx: 0, cy: 0, r }));
    world.appendChild(guides);

    const links = svg("g", { class: "orbit-links" });
    const linkOf = new Map();
    const motion = [];
    for (const [child, parentId] of tree.parent) {
      const a = pos.get(parentId), b = pos.get(child);
      if (!a || !b) continue;
      const mx = (a.x + b.x) / 2, my = (a.y + b.y) / 2;
      const bend = 0.12;                                               // a gentle curve, always to the same side, so links do not look like spokes
      const cx = mx - (b.y - a.y) * bend, cy = my + (b.x - a.x) * bend;
      const d = `M${a.x.toFixed(1)},${a.y.toFixed(1)} Q${cx.toFixed(1)},${cy.toFixed(1)} ${b.x.toFixed(1)},${b.y.toFixed(1)}`;
      const n = byId.get(child);
      const path = svg("path", { d, class: `orbit-link${n.online ? "" : " off"}${pos.get(child).hub ? " hub" : ""}`, "data-to": child });
      links.appendChild(path);
      linkOf.set(child, path);
      if (n.online && pos.get(child).hub && !reduceMotion() && motion.length < 24) motion.push(d);
    }
    world.appendChild(links);
    if (motion.length) {                                                // a slow spark runs out along the links to the hubs that are up
      const sparks = svg("g", { class: "orbit-sparks" });
      motion.forEach((d, i) => sparks.appendChild(svg("circle", { r: 2.6 }, svg("animateMotion", { dur: `${5 + (i % 5)}s`, begin: `${(i * 0.7).toFixed(1)}s`, repeatCount: "indefinite", path: d }))));
      world.appendChild(sparks);
    }

    const nodesLayer = svg("g", { class: "orbit-nodes" });
    const elements = new Map();
    const order = [...pos.keys()].sort((a, b) => (pos.get(a).hub - pos.get(b).hub));      // hubs on top of the devices
    for (const id of order) {
      const n = byId.get(id), p = pos.get(id);
      const isRoot = id === root;
      const size = isRoot ? 28 : p.hub ? 20 : 7;
      const tone = n.maintenance ? "held" : n.online ? "on" : "off";
      const href = String(id).startsWith("v") ? null : `#/device/${id}`;
      const link = svg("a", { href, class: `orbit-node ${tone} ${p.hub ? "hub" : "leaf"} k-${KIND[n.type] || "other"}`, "data-id": id, tabindex: "0" });
      link.appendChild(svg("circle", { cx: p.x.toFixed(1), cy: p.y.toFixed(1), r: size }));
      if (p.hub) {
        const code = GLYPH[n.type] || String(n.type || "?").slice(0, 2).toUpperCase();
        link.appendChild(svg("text", { x: p.x.toFixed(1), y: (p.y + 4).toFixed(1), class: "orbit-glyph" }, document.createTextNode(code)));
        const count = tree.kids.get(id).length;
        const label = svg("text", { x: p.x.toFixed(1), y: (p.y + size + 14).toFixed(1), class: "orbit-label" }, document.createTextNode(shortName(n.label) || n.ip || "device"));
        link.appendChild(label);
        if (count) link.appendChild(svg("text", { x: p.x.toFixed(1), y: (p.y + size + 26).toFixed(1), class: "orbit-sub" }, document.createTextNode(`${count} device${count === 1 ? "" : "s"}`)));
      } else {
        link.appendChild(svg("text", { x: (p.x + 11).toFixed(1), y: (p.y + 3.5).toFixed(1), class: "orbit-name" }, document.createTextNode(shortName(n.label) || n.ip || "")));
      }
      link.appendChild(svg("title", {}, document.createTextNode([n.label, n.ip].filter(Boolean).join(" · "))));
      nodesLayer.appendChild(link);
      elements.set(id, link);
    }
    world.appendChild(nodesLayer);
    canvas.classList.toggle("show-names", names.querySelector("input").checked);

    function paint() {
      const filtering = search.value.trim() || status.value !== "all";
      canvas.classList.toggle("filtering", !!filtering);
      for (const [id, el] of elements) el.classList.toggle("match", !!filtering && matches(byId.get(id)));
    }
    function point(id) {
      canvas.classList.toggle("tracing", id !== null);
      for (const el of elements.values()) el.classList.remove("lit");
      for (const path of linkOf.values()) path.classList.remove("lit");
      if (id === null) { readout.textContent = "Point at a device"; return; }
      const set = lineage(id);
      for (const x of set) { elements.get(x)?.classList.add("lit"); linkOf.get(x)?.classList.add("lit"); }
      const n = byId.get(id), up = tree.parent.get(id) !== undefined ? byId.get(tree.parent.get(id)) : null;
      const below = (tree.kids.get(id) || []).length;
      readout.textContent = [shortName(n.label) || n.ip, n.ip, n.vendor, n.online ? "online" : "offline", up ? `on ${shortName(up.label) || up.ip}` : null, below ? `${below} below` : null].filter(Boolean).join(" · ");
    }
    for (const [id, el] of elements) {
      el.addEventListener("mouseenter", () => point(id));
      el.addEventListener("focus", () => point(id));
      el.addEventListener("mouseleave", () => point(null));
      el.addEventListener("blur", () => point(null));
    }

    // pan with a drag on the empty picture, zoom with the wheel
    let drag = null;
    canvas.addEventListener("pointerdown", (e) => {
      if (e.target.closest(".orbit-node")) return;
      drag = { x: e.clientX, y: e.clientY, vx: view.x, vy: view.y };
      canvas.setPointerCapture(e.pointerId);
      canvas.classList.add("panning");
    });
    canvas.addEventListener("pointermove", (e) => { if (drag) { view.x = drag.vx + e.clientX - drag.x; view.y = drag.vy + e.clientY - drag.y; apply(); } });
    const stop = () => { drag = null; canvas.classList.remove("panning"); };
    canvas.addEventListener("pointerup", stop);
    canvas.addEventListener("pointercancel", stop);
    canvas.addEventListener("wheel", (e) => {
      e.preventDefault();
      const box = canvas.getBoundingClientRect();
      zoomAt(e.deltaY < 0 ? 1.12 : 1 / 1.12, e.clientX - box.left, e.clientY - box.top);
    }, { passive: false });
    stage.appendChild(canvas);
    paint();
    draw.paint = paint;
    if (!fitted) { fitted = true; fitAll(); } else apply();
  }

  async function load() {
    try {
      data = await get("/api/map?guests=true");
    } catch (err) {
      if (!destroyed) { clear(stage); stage.appendChild(h("p", { class: "error" }, err.message || "Could not load the map.")); }
      return;
    }
    if (!destroyed) draw();
  }
  search.addEventListener("input", () => draw.paint && draw.paint());
  status.addEventListener("change", () => draw.paint && draw.paint());
  names.querySelector("input").addEventListener("change", (e) => stage.querySelector(".orbit-svg")?.classList.toggle("show-names", e.target.checked));
  window.addEventListener("resize", fitAll);
  await load();
  const timer = setInterval(() => { if (!document.hidden && !search.value) load(); }, 30000);
  return () => { destroyed = true; clearInterval(timer); window.removeEventListener("resize", fitAll); };
}
