import { get } from "../api.js";
import { h, clear, typeBadge, shortName } from "../util.js";

// The "Tiers" view of the map: no tangle of lines. The network is read from top to bottom in bands (gateway, switches and access points,
// servers, virtual machines and containers, everything else); a device is a tile, and pointing at one lights up what it hangs on and what hangs on it.
const TIERS = [
  { id: "gateway", title: "Gateway & internet", types: ["router"] },
  { id: "network", title: "Switches & access points", types: ["switch", "ap"] },
  { id: "servers", title: "Servers & storage", types: ["server", "nas"] },
  { id: "guests", title: "Virtual machines & containers", types: ["vm", "container", "app"] },
  { id: "clients", title: "Computers, phones & things", types: [] },
];
const tierOf = (type) => (TIERS.find((t) => t.types.includes(type)) || TIERS[TIERS.length - 1]).id;

export async function renderTiers(container, { layouts, current, onLayout }) {
  let destroyed = false;
  const layoutSelect = h("select", { class: "layout-mode", title: "How the devices are arranged" }, ...layouts.map(([v, l]) => h("option", { value: v, selected: v === current }, l)));
  layoutSelect.addEventListener("change", () => onLayout(layoutSelect.value));
  const search = h("input", { type: "search", placeholder: "Search name, IP, vendor" });
  const status = h("select", {}, h("option", { value: "all" }, "All"), h("option", { value: "online" }, "Online"), h("option", { value: "offline" }, "Offline"));
  const links = h("label", { class: "check", title: "Draw the links of the device you point at" }, h("input", { type: "checkbox", checked: true }), " Show what it is connected to");
  const body = h("div", { class: "tiers" }, h("p", { class: "hint" }, "Loading..."));
  container.append(h("div", { class: "toolbar" }, search, status, layoutSelect, links), body);

  let data = { nodes: [], edges: [] };
  const folded = new Set();
  try { for (const id of JSON.parse(localStorage.getItem("netlens.map.tiers.folded") || "[]")) folded.add(id); } catch (e) { /* default: all open */ }
  const save = () => { try { localStorage.setItem("netlens.map.tiers.folded", JSON.stringify([...folded])); } catch (e) { /* not kept */ } };

  function relations() {
    const up = new Map(), down = new Map();
    for (const e of data.edges) {
      if (e.kind !== "parent" && e.kind !== "host-of" && e.kind !== "uplink") continue;
      (down.get(e.from) || down.set(e.from, new Set()).get(e.from)).add(e.to);
      (up.get(e.to) || up.set(e.to, new Set()).get(e.to)).add(e.from);
    }
    return { up, down };
  }

  function draw() {
    clear(body);
    const q = search.value.trim().toLowerCase();
    const { up, down } = relations();
    const byId = new Map(data.nodes.map((n) => [n.id, n]));
    const tiles = new Map();
    const visible = data.nodes.filter((n) => (status.value === "all" || (status.value === "online") === !!n.online)
      && (!q || `${n.label || ""} ${n.ip || ""} ${n.vendor || ""} ${n.group || ""}`.toLowerCase().includes(q)));
    const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    svg.setAttribute("class", "tiers-links");
    const wrap = h("div", { class: "tiers-wrap" });
    wrap.appendChild(svg);
    for (const tier of TIERS) {
      const members = visible.filter((n) => tierOf(n.type) === tier.id).sort((a, b) => (a.online - b.online) || String(a.label).localeCompare(String(b.label)));
      if (!members.length && !(tier.id === "gateway")) continue;
      const open = !folded.has(tier.id);
      const online = members.filter((n) => n.online).length;
      const head = h("button", { class: "tier-head", type: "button", "aria-expanded": String(open) }, h("span", { class: "tier-caret" }, open ? "▾" : "▸"), h("strong", {}, tier.title),
        h("span", { class: "hint" }, ` ${online} of ${members.length} online`));
      head.addEventListener("click", () => { if (folded.has(tier.id)) folded.delete(tier.id); else folded.add(tier.id); save(); draw(); });
      const grid = h("div", { class: "tier-grid" });
      if (open) {
        for (const n of members) {
          const tile = h("a", { class: `tier-tile ${n.online ? "" : "off"} ${n.maintenance ? "held" : ""}`, href: String(n.id).startsWith("v") ? "#/map" : `#/device/${n.id}`, "data-id": String(n.id) },
            h("span", { class: `dot ${n.online ? "on" : "off"}` }), h("span", { class: "tier-name" }, shortName(n.label) || n.ip || "device"),
            h("span", { class: "tier-sub" }, [n.ip, n.vendor].filter(Boolean).join(" · ")), typeBadge(n.type));
          tiles.set(n.id, tile);
          grid.appendChild(tile);
        }
        if (!members.length) grid.appendChild(h("span", { class: "hint" }, "Nothing here."));
      }
      wrap.appendChild(h("section", { class: "tier" }, head, grid));
    }
    body.appendChild(wrap);
    if (!visible.length) body.appendChild(h("p", { class: "hint" }, "Nothing matches."));

    function lines(id) {
      while (svg.firstChild) svg.removeChild(svg.firstChild);
      for (const t of tiles.values()) t.classList.remove("lit", "dim");
      if (id === null) return;
      const lit = new Set([id]);
      const box = wrap.getBoundingClientRect();
      svg.setAttribute("width", box.width);
      svg.setAttribute("height", box.height);
      const point = (el, top) => { const r = el.getBoundingClientRect(); return [r.left - box.left + r.width / 2, (top ? r.top : r.bottom) - box.top]; };
      const link = (a, b) => {
        const ta = tiles.get(a), tb = tiles.get(b);
        if (!ta || !tb || !links.querySelector("input").checked) return;
        const [x1, y1] = point(ta, false), [x2, y2] = point(tb, true);
        const mid = (y1 + y2) / 2;
        const path = document.createElementNS("http://www.w3.org/2000/svg", "path");
        path.setAttribute("d", `M${x1},${y1} C${x1},${mid} ${x2},${mid} ${x2},${y2}`);
        path.setAttribute("class", "tier-link");
        svg.appendChild(path);
      };
      for (const parent of up.get(id) || []) { lit.add(parent); link(parent, id); }
      for (const child of down.get(id) || []) { lit.add(child); link(id, child); }
      for (const [nid, tile] of tiles) tile.classList.add(lit.has(nid) ? "lit" : "dim");
    }
    for (const [id, tile] of tiles) {
      tile.addEventListener("mouseenter", () => lines(id));
      tile.addEventListener("focus", () => lines(id));
      tile.addEventListener("mouseleave", () => lines(null));
      tile.addEventListener("blur", () => lines(null));
    }
    void byId;
  }

  async function load() {
    try {
      data = await get("/api/map?guests=true");
    } catch (err) {
      if (!destroyed) { clear(body); body.appendChild(h("p", { class: "error" }, err.message || "Could not load the map.")); }
      return;
    }
    if (!destroyed) draw();
  }
  search.addEventListener("input", draw);
  status.addEventListener("change", draw);
  await load();
  const timer = setInterval(() => { if (!document.hidden && !search.value) load(); }, 30000);
  return () => { destroyed = true; clearInterval(timer); };
}
