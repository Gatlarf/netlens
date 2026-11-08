import { fmtBytes } from "./charts.js";

// Three pictures that are drawn straight from numbers Netlens already holds: a band diagram of traffic, a map of Wi-Fi roaming and a calendar of availability.
const NS = "http://www.w3.org/2000/svg";
export const svg = (tag, attrs = {}, ...kids) => {
  const el = document.createElementNS(NS, tag);
  for (const [k, v] of Object.entries(attrs)) el.setAttribute(k, v);
  for (const kid of kids) if (kid) el.append(kid);
  return el;
};
const tip = (el, text) => { el.appendChild(svg("title")).textContent = text; return el; };
const clip = (text, n) => (text.length > n ? `${text.slice(0, n - 1)}…` : text);

// ----------------------------------------------------------------------------- traffic: devices -> the network edge -> applications
// left and right are [{label, value}]. The two sides come from different counters (the router counts per device and per application separately),
// so the bands meet at the middle bar and never pair a device with an application.
export function trafficBands(left, right, format = fmtBytes) {
  const W = 720, H = Math.max(180, Math.max(left.length, right.length) * 26 + 20), gap = 6;
  const root = svg("svg", { viewBox: `0 0 ${W} ${H}`, class: "flow-bands", role: "img", "aria-label": "Traffic per device and per application" });
  const column = (items, x, side) => {
    const total = items.reduce((a, b) => a + b.value, 0) || 1, free = H - 10 - gap * (items.length - 1);
    let y = 5;
    return items.map((item) => { const height = Math.max(3, (item.value / total) * free); const slot = { item, y, height, share: item.value / total }; y += height + gap; return slot; });
  };
  const mid = { x: W / 2 - 5, w: 10 };
  const sides = [[left, 190, "left"], [right, W - 200, "right"]];
  for (const [items, x, side] of sides) {
    let used = 0;
    for (const [n, slot] of column(items, x, side).entries()) {
      const y0 = 5 + used * (H - 10), y1 = y0 + slot.share * (H - 10);
      used += slot.share;
      const x0 = side === "left" ? x + 10 : mid.x + mid.w, x1 = side === "left" ? mid.x : x, curve = (x1 - x0) / 2;
      const ribbon = svg("path", { class: `flow-ribbon${n % 2 ? " alt" : ""}`, d: `M${x0},${slot.y} C${x0 + curve},${slot.y} ${x1 - curve},${y0} ${x1},${y0} L${x1},${y1} C${x1 - curve},${y1} ${x0 + curve},${slot.y + slot.height} ${x0},${slot.y + slot.height} Z` });
      root.appendChild(tip(ribbon, `${slot.item.label}: ${format(slot.item.value)}`));
      root.appendChild(tip(svg("rect", { class: "flow-bar", x: side === "left" ? x : x, y: slot.y, width: 10, height: slot.height, rx: 2 }), `${slot.item.label}: ${format(slot.item.value)}`));
      if (slot.height >= 10 || items.length <= 12) {
        const label = svg("text", { class: "flow-label", x: side === "left" ? x - 6 : x + 16, y: slot.y + slot.height / 2 + 4, "text-anchor": side === "left" ? "end" : "start" });
        label.textContent = clip(slot.item.label, 26);
        root.appendChild(label);
      }
    }
  }
  root.appendChild(svg("rect", { class: "flow-bar", x: mid.x, y: 5, width: mid.w, height: H - 10, rx: 2 }));
  return root;
}

// ----------------------------------------------------------------------------- Wi-Fi: access points as nodes, moves between them as arcs
export function roamMap(flows) {
  const names = [...new Set(flows.flatMap((f) => [f.from, f.to]))].slice(0, 12);
  const W = 420, H = 340, cx = W / 2, cy = H / 2, R = names.length > 1 ? 105 : 0, max = Math.max(...flows.map((f) => f.count));
  const pos = new Map(names.map((n, i) => { const a = (i / names.length) * Math.PI * 2 - Math.PI / 2; return [n, { x: cx + Math.cos(a) * R, y: cy + Math.sin(a) * R, a }]; }));
  const traffic = new Map(names.map((n) => [n, 0]));
  const root = svg("svg", { viewBox: `0 0 ${W} ${H}`, class: "flow-roam", role: "img", "aria-label": "Clients moving between access points" });
  root.appendChild(svg("defs", {}, svg("marker", { id: "roam-arrow", viewBox: "0 0 8 8", refX: 7, refY: 4, markerWidth: 5, markerHeight: 5, orient: "auto-start-reverse" }, svg("path", { d: "M0,0 L8,4 L0,8 z", class: "flow-arrow" }))));
  for (const f of flows) {
    const a = pos.get(f.from), b = pos.get(f.to);
    if (!a || !b) continue;
    traffic.set(f.from, traffic.get(f.from) + f.count); traffic.set(f.to, traffic.get(f.to) + f.count);
    const dx = b.x - a.x, dy = b.y - a.y, len = Math.hypot(dx, dy) || 1, bend = 0.22 * len;      // the way back bends to the other side, so both directions can be seen
    const mx = (a.x + b.x) / 2 - (dy / len) * bend, my = (a.y + b.y) / 2 + (dx / len) * bend;
    const shorten = (p, q) => { const vx = q.x - p.x, vy = q.y - p.y, l = Math.hypot(vx, vy) || 1; return { x: p.x + (vx / l) * 14, y: p.y + (vy / l) * 14 }; };
    const s = shorten(a, { x: mx, y: my }), e = shorten(b, { x: mx, y: my });
    root.appendChild(tip(svg("path", { class: "flow-arc", d: `M${s.x},${s.y} Q${mx},${my} ${e.x},${e.y}`, "stroke-width": 1.2 + (f.count / max) * 6, "marker-end": "url(#roam-arrow)" }), `${f.from} → ${f.to}: ${f.count}`));
  }
  const top = Math.max(1, ...traffic.values());
  for (const n of names) {
    const p = pos.get(n), r = 7 + Math.sqrt(traffic.get(n) / top) * 9;
    root.appendChild(tip(svg("circle", { class: "flow-node", cx: p.x, cy: p.y, r }), `${n}: ${traffic.get(n)} moves`));
    const out = r + 8, label = svg("text", { class: "flow-label", x: p.x + Math.cos(p.a) * out, y: p.y + Math.sin(p.a) * out + 4, "text-anchor": Math.cos(p.a) > 0.3 ? "start" : Math.cos(p.a) < -0.3 ? "end" : "middle" });
    label.textContent = clip(n, 18);
    root.appendChild(label);
  }
  return root;
}

// ----------------------------------------------------------------------------- availability: one square per day
const level = (pct) => (pct >= 99.9 ? 4 : pct >= 99 ? 3 : pct >= 95 ? 2 : pct >= 80 ? 1 : 0);
export function calendarHeat({ from, to, days, marks }) {
  const byDay = new Map(days.map((d) => [d.d, d]));
  const markDay = new Map();
  for (const m of marks || []) markDay.set(m.d, [...(markDay.get(m.d) || []), m.text]);
  const start = new Date(`${from}T00:00:00Z`), end = new Date(`${to}T00:00:00Z`), pad = start.getUTCDay();       // weeks run down the columns, Sunday first
  const total = Math.round((end - start) / 86400000) + 1, weeks = Math.ceil((total + pad) / 7), cell = 11, step = 14, left = 2, top = 14;
  const root = svg("svg", { viewBox: `0 0 ${left + weeks * step} ${top + 7 * step}`, class: "flow-calendar", role: "img", "aria-label": "Availability per day" });
  let lastMonth = -1;
  for (let i = 0; i < total; i++) {
    const date = new Date(start.getTime() + i * 86400000), key = date.toISOString().slice(0, 10), col = Math.floor((i + pad) / 7), row = (i + pad) % 7, d = byDay.get(key);
    if (row === 0 && date.getUTCMonth() !== lastMonth) {
      lastMonth = date.getUTCMonth();
      const m = svg("text", { class: "flow-label", x: left + col * step, y: 9 });
      m.textContent = date.toLocaleString([], { month: "short", timeZone: "UTC" });
      root.appendChild(m);
    }
    const rect = svg("rect", { class: d ? `cal-day cal-${level(d.pct)}` : "cal-day cal-none", x: left + col * step, y: top + row * step, width: cell, height: cell, rx: 2 });
    const note = markDay.get(key);
    tip(rect, d ? `${key}: ${d.pct}%${d.outages ? ` · ${d.outages} outage${d.outages > 1 ? "s" : ""}` : ""}${note ? ` · ${note.join("; ")}` : ""}` : `${key}: no data`);
    root.appendChild(rect);
    if (note) root.appendChild(tip(svg("circle", { class: "cal-mark", cx: left + col * step + cell - 1, cy: top + row * step + 1, r: 2.6 }), note.join("; ")));
  }
  return root;
}
