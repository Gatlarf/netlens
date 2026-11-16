// Performance graphs: one measurement over time with its lowest/highest band, a read-out under the pointer and
// optional warning / critical lines. Data comes from /api/timeseries (the metrics store); no library.
import { get } from "./api.js";
import { h, fmtTime } from "./util.js";
import { isDark } from "./theme.js";
import { MIN_WINDOW, RANGE_SECONDS, clampWindow, zoomWindow, panWindow, selectionToWindow, nearestPoint, splitAxes, describeWindow, describeSpan, toCsv } from "./graphmath.js";

const NS = "http://www.w3.org/2000/svg";
export const GRAPH_RANGES = [["6h", "6 hours"], ["24h", "24 hours"], ["7d", "7 days"], ["30d", "30 days"], ["90d", "90 days"], ["1y", "1 year"]];
const RANGE_KEY = "netlens.graph.range";

export function savedGraphRange() {
  try {
    const v = localStorage.getItem(RANGE_KEY);
    return GRAPH_RANGES.some(([k]) => k === v) ? v : "24h";
  } catch (e) {
    return "24h";
  }
}

function el(tag, attrs = {}) {
  const node = document.createElementNS(NS, tag);
  for (const [k, v] of Object.entries(attrs)) node.setAttribute(k, String(v));
  return node;
}

// ---------- number formats ----------
function trim(n, digits) {
  return Number(n.toFixed(digits)).toString();
}

export function formatValue(value, unit) {
  if (value === null || value === undefined || Number.isNaN(value)) return "–";
  switch (unit) {
    case "ms": return value >= 1000 ? `${trim(value / 1000, 2)} s` : `${trim(value, value >= 100 ? 0 : 1)} ms`;
    case "%": return `${trim(value, value >= 100 ? 0 : 1)}%`;
    case "state": return value >= 0.995 ? "up" : value <= 0.005 ? "down" : `${trim(value * 100, 1)}% up`;
    case "bps": {
      const units = ["bit/s", "kbit/s", "Mbit/s", "Gbit/s"];
      let v = value, i = 0;
      while (v >= 1000 && i < units.length - 1) { v /= 1000; i += 1; }
      return `${trim(v, v >= 100 ? 0 : 1)} ${units[i]}`;
    }
    case "B": {
      const units = ["B", "KB", "MB", "GB", "TB"];
      let v = value, i = 0;
      while (v >= 1024 && i < units.length - 1) { v /= 1024; i += 1; }
      return `${trim(v, v >= 100 ? 0 : 1)} ${units[i]}`;
    }
    case "s": {
      if (value < 90) return `${Math.round(value)} s`;
      if (value < 5400) return `${Math.round(value / 60)} min`;
      if (value < 172800) return `${trim(value / 3600, 1)} h`;
      return `${Math.round(value / 86400)} d`;
    }
    case "°C": return `${trim(value, 1)} °C`;
    default: return trim(value, Math.abs(value) >= 100 ? 0 : 2) + (unit ? ` ${unit}` : "");
  }
}

function niceMax(v) {
  if (v <= 0) return 1;
  const exp = Math.pow(10, Math.floor(Math.log10(v)));
  for (const m of [1, 1.5, 2, 2.5, 3, 4, 5, 7.5, 10]) if (v <= m * exp) return m * exp;
  return 10 * exp;
}

function timeLabel(t, span) {
  const d = new Date(t * 1000);
  const hm = `${String(d.getHours()).padStart(2, "0")}:${String(d.getMinutes()).padStart(2, "0")}`;
  if (span <= 36 * 3600) return hm;
  if (span <= 120 * 86400) return `${d.getDate()}/${d.getMonth() + 1}`;
  return d.toLocaleDateString(undefined, { month: "short", year: "2-digit" });
}

// ---------- drawing ----------
// data = { points: [[t, avg, min, max]], start, end, step, unit }; options: { unit, warn, crit, height, fixedMax }
const OVERLAY_COLOURS = { light: ["#7c3aed", "#db2777", "#0891b2"], dark: ["#a78bfa", "#f472b6", "#22d3ee"] };
export const overlayColour = (i) => OVERLAY_COLOURS[isDark() ? "dark" : "light"][i % 3];

// overlays = [{name, unit, points}] drawn as plain lines over the main one. A line with the same unit shares the left scale; one with another unit gets the right-hand scale.
// interactive = {onSelect(window), onHover(t), onLeave(), onKey(key), window: {start, end}, now} turns on dragging to zoom, the shared cursor and the keys.
export function drawGraph(data, { unit, warn = null, crit = null, height = 120, fixedMax = null, width = 640, overlays = [], interactive = null } = {}) {
  const unitForAxes = unit || data.unit;
  const axes = splitAxes(unitForAxes, overlays);
  const W = Math.max(240, Math.round(width)), H = height, L = 64, R = axes.right.length ? 58 : 8, T = 8, B = 20;
  const wrap = h("div", { class: "tg" });
  const pts = data.points || [];
  if (!pts.length) {
    wrap.appendChild(h("p", { class: "hint tg-empty" }, "No measurements in this period yet."));
    return wrap;
  }
  const unitName = unit || data.unit;
  const t0 = data.start, t1 = data.end, span = Math.max(1, t1 - t0);
  const isPct = unitName === "%", isState = unitName === "state";
  const sameUnit = axes.left.flatMap((o) => o.points);
  let ymax = fixedMax ?? (isPct ? 100 : isState ? 1 : niceMax(Math.max(...pts.map((p) => p[3]), ...sameUnit.map((p) => p[3]), warn ?? 0, crit ?? 0) * 1.08));
  let ymin = 0;
  if (!isPct && !isState && fixedMax === null) {
    const lo = Math.min(...pts.map((p) => p[2]), ...sameUnit.map((p) => p[2]));
    if (lo < 0) ymin = -niceMax(-lo * 1.08);
  }
  const x = (t) => L + ((t - t0) / span) * (W - L - R);
  const y = (v) => T + (1 - (v - ymin) / (ymax - ymin || 1)) * (H - T - B);
  const root = el("svg", { viewBox: `0 0 ${W} ${H}`, class: "tg-svg", role: "img", width: W, height: H, "aria-label": "Graph" });

  // colours are written on the shapes themselves (not only in the style sheet), so a graph is never drawn black and white
  const OK = "#16a34a", WARN = "#d97706", BAD = "#dc2626", ACCENT = "#2563eb";
  const hasLimits = warn !== null || crit !== null;
  const low = hasLimits && warn !== null && crit !== null && warn > crit;      // battery, supplies: bad when it is LOW
  const beyond = (v, limit) => limit !== null && limit !== undefined && (low ? v <= limit : v >= limit);
  const colourOf = (v) => {
    if (isState) return v >= 0.995 ? OK : BAD;
    if (!hasLimits) return ACCENT;
    return beyond(v, crit) ? BAD : beyond(v, warn) ? WARN : OK;
  };
  const baseColour = isState || hasLimits ? OK : ACCENT;

  // zones: the part of the scale that is a warning or critical level is tinted
  if (hasLimits) {
    const top = y(ymax), bottom = y(ymin);
    const zone = (from, to, colour, opacity) => {
      const a1 = Math.min(y(from), y(to)), a2 = Math.max(y(from), y(to));
      root.appendChild(el("rect", { x: L, y: a1, width: W - L - R, height: Math.max(0, a2 - a1), fill: colour, opacity }));
    };
    if (low) {
      if (warn !== null) zone(Math.min(warn, ymax), crit !== null ? crit : ymin, WARN, 0.16);
      if (crit !== null) zone(Math.min(crit, ymax), ymin, BAD, 0.22);
    } else {
      if (warn !== null && warn < ymax) zone(warn, crit !== null && crit < ymax ? crit : ymax, WARN, 0.16);
      if (crit !== null && crit < ymax) zone(crit, ymax, BAD, 0.22);
    }
    void top; void bottom;
  }

  // grid and value labels
  for (const f of [0, 0.5, 1]) {
    const v = ymin + (ymax - ymin) * f;
    const gy = y(v);
    root.appendChild(el("line", { x1: L, x2: W - R, y1: gy, y2: gy, class: "tg-grid", stroke: "currentColor", "stroke-opacity": 0.18, "stroke-width": 1 }));
    const label = el("text", { x: L - 5, y: gy + 3, class: "tg-axis", "text-anchor": "end", fill: "currentColor", "fill-opacity": 0.65, "font-size": 10 });
    label.textContent = isState ? (f === 1 ? "up" : f === 0 ? "down" : "") : formatValue(v, unitName).replace(/ ?(ms|%)$/, (m) => m.trim());
    root.appendChild(label);
  }
  for (let i = 0; i <= 4; i += 1) {
    const t = t0 + (span * i) / 4;
    const label = el("text", { x: Math.min(W - 14, Math.max(L + 10, x(t))), y: H - 5, class: "tg-axis", "text-anchor": i === 0 ? "start" : i === 4 ? "end" : "middle", fill: "currentColor", "fill-opacity": 0.65, "font-size": 10 });
    label.textContent = timeLabel(t, span);
    root.appendChild(label);
  }
  for (const [value, colour] of [[warn, WARN], [crit, BAD]]) {
    if (value === null || value === undefined || value > ymax || value < ymin) continue;
    root.appendChild(el("line", { x1: L, x2: W - R, y1: y(value), y2: y(value), class: "tg-limit", stroke: colour, "stroke-width": 1, "stroke-dasharray": "5 4" }));
  }

  // runs without a long hole in them, so a gap in the measurements is a gap in the line
  const deltas = pts.slice(1).map((p, i) => p[0] - pts[i][0]).sort((a, b) => a - b);
  const typical = deltas.length ? deltas[Math.floor(deltas.length / 2)] : 0;
  const gap = Math.max(data.step, typical) * 3.5;
  const runs = [];
  let run = [];
  for (const p of pts) {
    if (run.length && p[0] - run[run.length - 1][0] > gap) { runs.push(run); run = []; }
    run.push(p);
  }
  if (run.length) runs.push(run);
  const base = y(Math.max(ymin, 0));
  for (const r of runs) {
    if (r.length === 1) {
      root.appendChild(el("circle", { cx: x(r[0][0]), cy: y(r[0][1]), r: 2.5, fill: colourOf(r[0][1]) }));
      continue;
    }
    if (isState) {
      // availability: a filled strip that is green while it is up and red where it was down
      for (let i = 1; i < r.length; i += 1) {
        const v = Math.min(r[i - 1][1], r[i][1]);
        root.appendChild(el("polygon", { points: `${x(r[i - 1][0]).toFixed(1)},${base} ${x(r[i - 1][0]).toFixed(1)},${y(r[i - 1][1]).toFixed(1)} ${x(r[i][0]).toFixed(1)},${y(r[i][1]).toFixed(1)} ${x(r[i][0]).toFixed(1)},${base}`,
          fill: colourOf(v), opacity: 0.22 }));
      }
    } else {
      const upper = r.map((p) => `${x(p[0]).toFixed(1)},${y(p[3]).toFixed(1)}`);
      const lower = r.slice().reverse().map((p) => `${x(p[0]).toFixed(1)},${y(p[2]).toFixed(1)}`);
      root.appendChild(el("polygon", { points: [...upper, ...lower].join(" "), class: "tg-band", fill: baseColour, opacity: 0.2 }));
      if (hasLimits) {   // the peaks that went past a limit stand out in the band itself
        for (let i = 1; i < r.length; i += 1) {
          const peak = low ? Math.min(r[i - 1][2], r[i][2]) : Math.max(r[i - 1][3], r[i][3]);
          const c = colourOf(peak);
          if (c === OK) continue;
          root.appendChild(el("polygon", { points: `${x(r[i - 1][0]).toFixed(1)},${y(r[i - 1][1]).toFixed(1)} ${x(r[i - 1][0]).toFixed(1)},${y(low ? r[i - 1][2] : r[i - 1][3]).toFixed(1)} ${x(r[i][0]).toFixed(1)},${y(low ? r[i][2] : r[i][3]).toFixed(1)} ${x(r[i][0]).toFixed(1)},${y(r[i][1]).toFixed(1)}`,
            fill: c, opacity: 0.35 }));
        }
      }
    }
    // the line itself, in the colour of the level it is at (one piece per stretch of the same colour)
    let piece = [r[0]], pieceColour = null;
    const flush = (pts2, colour) => {
      if (pts2.length < 2) return;
      root.appendChild(el("path", { d: pts2.map((p, i) => `${i ? "L" : "M"}${x(p[0]).toFixed(1)},${y(p[1]).toFixed(1)}`).join(""), class: "tg-line",
        fill: "none", stroke: colour, "stroke-width": 1.8, "stroke-linejoin": "round", "stroke-linecap": "round" }));
    };
    for (let i = 1; i < r.length; i += 1) {
      const c = colourOf(low ? Math.min(r[i - 1][1], r[i][1]) : Math.max(r[i - 1][1], r[i][1]));
      if (pieceColour === null) pieceColour = c;
      if (c !== pieceColour) {
        flush(piece, pieceColour);
        piece = [r[i - 1]];
        pieceColour = c;
      }
      piece.push(r[i]);
    }
    flush(piece, pieceColour || baseColour);
  }

  // the lines laid over this one (another device, another measurement): same unit on the left scale, another unit on the right
  const overlayPoints = (o) => o.points.filter((p) => p[0] >= t0 && p[0] <= t1);
  if (overlays.length) {
    let rightMax = 1;
    if (axes.right.length) {
      rightMax = niceMax(Math.max(...axes.right.flatMap((o) => o.points.map((p) => p[3])), 0) * 1.08);
      for (const f of [0, 0.5, 1]) {
        const label = el("text", { x: W - R + 5, y: T + (1 - f) * (H - T - B) + 3, class: "tg-axis tg-axis-right", "text-anchor": "start", fill: overlayColour(overlays.indexOf(axes.right[0])), "font-size": 10 });
        label.textContent = formatValue(rightMax * f, axes.rightUnit).replace(/ ?(ms|%)$/, (m) => m.trim());
        root.appendChild(label);
      }
    }
    overlays.forEach((o, i) => {
      const onRight = axes.right.includes(o);
      if (!onRight && !axes.left.includes(o)) return;                      // a third unit has no scale to be drawn on
      const yo = onRight ? (v) => T + (1 - v / rightMax) * (H - T - B) : y;
      const runsO = [];
      let cur = [];
      const ds = o.points.slice(1).map((p, k) => p[0] - o.points[k][0]).sort((a, b) => a - b);
      const stepO = Math.max(data.step, ds.length ? ds[Math.floor(ds.length / 2)] : 0, 1) * 3.5;       // by the spacing of this line, not of the main one
      for (const p of overlayPoints(o)) {
        if (cur.length && p[0] - cur[cur.length - 1][0] > stepO) { runsO.push(cur); cur = []; }
        cur.push(p);
      }
      if (cur.length) runsO.push(cur);
      for (const r of runsO) {
        if (r.length === 1) { root.appendChild(el("circle", { cx: x(r[0][0]), cy: yo(r[0][1]), r: 2.5, fill: overlayColour(i) })); continue; }
        root.appendChild(el("path", { d: r.map((p, k) => `${k ? "L" : "M"}${x(p[0]).toFixed(1)},${yo(p[1]).toFixed(1)}`).join(""), class: "tg-overlay", fill: "none", stroke: overlayColour(i), "stroke-width": 1.6,
          "stroke-linejoin": "round", "stroke-linecap": "round", "stroke-dasharray": onRight ? "6 3" : "" }));
      }
    });
  }

  const cursor = el("line", { x1: 0, x2: 0, y1: T, y2: H - B, class: "tg-cursor", stroke: "currentColor", "stroke-opacity": 0.5, "stroke-width": 1, visibility: "hidden" });
  const marker = el("circle", { r: 4, class: "tg-marker", fill: ACCENT, stroke: "#fff", "stroke-width": 1.5, visibility: "hidden" });
  const selection = el("rect", { class: "tg-sel", y: T, height: H - T - B, fill: ACCENT, "fill-opacity": 0.18, stroke: ACCENT, "stroke-opacity": 0.7, "stroke-width": 1, visibility: "hidden" });
  const selectionText = el("text", { class: "tg-sel-text", y: T + 12, "font-size": 10, fill: "currentColor", "text-anchor": "middle", visibility: "hidden" });
  root.append(selection, selectionText, cursor, marker);
  const tipBox = h("div", { class: "tg-tip", hidden: true });
  wrap.append(root, tipBox);
  const plot = { left: L, width: W - L - R };
  const toSvgX = (clientX) => { const rect = root.getBoundingClientRect(); return ((clientX - rect.left) / rect.width) * W; };
  const timeAt = (px) => t0 + ((Math.min(plot.left + plot.width, Math.max(plot.left, px)) - plot.left) / plot.width) * span;
  const reach = Math.max(data.step, typical, 1) * 2;

  const nearest = (clientX) => {
    const px = toSvgX(clientX);
    if (px < L - 4 || px > W - R + 4) return null;
    let best = null, dist = Infinity;
    for (const p of pts) {
      const d = Math.abs(x(p[0]) - px);
      if (d < dist) { dist = d; best = p; }
    }
    return dist < 40 ? best : null;
  };
  const place = (p) => {
    cursor.setAttribute("x1", x(p[0])); cursor.setAttribute("x2", x(p[0])); cursor.setAttribute("visibility", "visible");
    marker.setAttribute("cx", x(p[0])); marker.setAttribute("cy", y(p[1])); marker.setAttribute("visibility", "visible");
    marker.setAttribute("fill", colourOf(p[1]));
  };
  let selecting = null;
  const move = (e) => {
    if (selecting) {
      const x1 = Math.min(plot.left + plot.width, Math.max(plot.left, toSvgX(e.clientX)));
      const a = Math.min(selecting.x0, x1), b = Math.max(selecting.x0, x1);
      if (b - a > 3) {
        selection.setAttribute("x", a); selection.setAttribute("width", b - a); selection.setAttribute("visibility", "visible");
        selectionText.textContent = describeSpan(((b - a) / plot.width) * span);
        selectionText.setAttribute("x", (a + b) / 2); selectionText.setAttribute("visibility", b - a > 46 ? "visible" : "hidden");
        tipBox.hidden = true;
      }
      return;
    }
    const p = nearest(e.clientX);
    if (!p) { leave(); return; }
    place(p);
    const many = data.step > 1 && Math.abs(p[3] - p[2]) > 1e-9;
    const others = overlays.map((o, i) => ({ o, i, q: nearestPoint(o.points, p[0], reach) })).filter((r) => r.q && (axes.left.includes(r.o) || axes.right.includes(r.o)));
    tipBox.replaceChildren(
      h("div", { class: "tg-tip-time" }, fmtTime(new Date(p[0] * 1000).toISOString())),
      h("div", {}, formatValue(p[1], unitName)),
      many ? h("div", { class: "tg-tip-note" }, `${formatValue(p[2], unitName)} – ${formatValue(p[3], unitName)}`) : null,
      ...others.map((r) => h("div", { class: "tg-tip-other" }, h("span", { class: "tg-dot", style: `background:${overlayColour(r.i)}` }), `${r.o.name}: ${formatValue(r.q[1], r.o.unit)}`)));
    tipBox.hidden = false;
    const rect = wrap.getBoundingClientRect();
    const left = ((x(p[0]) / W) * rect.width);
    tipBox.style.left = `${Math.max(4, Math.min(rect.width - tipBox.offsetWidth - 4, left - tipBox.offsetWidth / 2))}px`;
    if (interactive && interactive.onHover) interactive.onHover(p[0]);
  };
  const hide = () => {
    cursor.setAttribute("visibility", "hidden");
    marker.setAttribute("visibility", "hidden");
    tipBox.hidden = true;
  };
  const leave = () => {
    if (selecting) return;                                          // a drag that leaves the picture goes on until the button is released
    hide();
    if (interactive && interactive.onLeave) interactive.onLeave();
  };
  const endSelection = (e, apply) => {
    if (!selecting) return;
    const from = selecting.x0;
    selecting = null;
    selection.setAttribute("visibility", "hidden"); selectionText.setAttribute("visibility", "hidden");
    try { root.releasePointerCapture(e.pointerId); } catch (err) { /* already released */ }
    if (!apply || !interactive || !interactive.onSelect) return;
    const win = selectionToWindow(from, toSvgX(e.clientX), plot, { start: t0, end: t1 }, interactive.now || Math.floor(Date.now() / 1000));
    if (win) interactive.onSelect(win);
  };
  root.addEventListener("pointermove", move);
  root.addEventListener("pointerdown", (e) => {
    if (interactive && interactive.onSelect && (e.pointerType !== "mouse" || e.button === 0) && toSvgX(e.clientX) >= L - 2 && toSvgX(e.clientX) <= W - R + 2) {
      selecting = { x0: Math.min(plot.left + plot.width, Math.max(plot.left, toSvgX(e.clientX))) };
      try { root.setPointerCapture(e.pointerId); } catch (err) { /* the drag still works inside the picture */ }
    }
    move(e);
  });
  root.addEventListener("pointerup", (e) => endSelection(e, true));
  root.addEventListener("pointercancel", (e) => endSelection(e, false));
  root.addEventListener("pointerleave", leave);
  if (interactive) {
    root.setAttribute("tabindex", "0");
    root.setAttribute("aria-label", "Graph. Drag across it to zoom in. Plus and minus change the period, the arrow keys move it, Escape goes back.");
    root.classList.add("tg-interactive");
    root.addEventListener("keydown", (e) => {
      const key = { "+": "in", "=": "in", "-": "out", "_": "out", ArrowLeft: "earlier", ArrowRight: "later", Escape: "reset" }[e.key];
      if (!key || !interactive.onKey) return;
      e.preventDefault();
      interactive.onKey(key);
    });
  }
  // the shared cursor: another graph of the same group is being pointed at
  wrap.cursorAt = (t) => {
    const p = nearestPoint(pts, t, reach);
    if (!p) { hide(); return null; }
    place(p);
    return p;
  };
  wrap.hideCursor = hide;
  return wrap;
}

function levelColour(value, unit, warn, crit) {
  if (unit === "state") return value >= 0.995 ? "#16a34a" : "#dc2626";
  if (warn === null && crit === null) return "";
  const low = warn !== null && crit !== null && warn > crit;
  const beyond = (limit) => limit !== null && limit !== undefined && (low ? value <= limit : value >= limit);
  return beyond(crit) ? "#dc2626" : beyond(warn) ? "#d97706" : "#16a34a";
}

function summary(points, unit) {
  if (!points.length) return null;
  const avg = points.reduce((a, p) => a + p[1], 0) / points.length;
  return {
    last: points[points.length - 1][1],
    avg,
    lo: Math.min(...points.map((p) => p[2])),
    hi: Math.max(...points.map((p) => p[3])),
    unit,
  };
}

// ---------- a group of graphs that share one period, one zoom and one cursor ----------
// The graphs of a card are one group: the range buttons, dragging across any graph, the zoom bar and the keys act on all of them at once,
// and pointing at one graph puts a cursor at the same time in the others.
const GroupMemory = new Map();
export class GraphGroup {
  constructor(range = savedGraphRange()) {
    this.range = range;
    this.window = null;                 // {start, end} while zoomed in, else null (the named range is shown)
    this.trail = [];                    // the views before the current zoom, for "Back"
    this.graphs = new Set();
    this.bars = new Set();
    this.tabs = new Set();
  }

  // The page redraws its cards now and then; the group of a card is kept under a name so that a zoom, and the period, survive that.
  static shared(name) {
    if (!GroupMemory.has(name)) GroupMemory.set(name, new GraphGroup());
    return GroupMemory.get(name);
  }

  now() { return Math.floor(Date.now() / 1000); }
  get zoomed() { return this.window !== null; }

  // what is shown now, as a window
  shown() {
    if (this.window) return this.window;
    const end = this.now();
    return { start: end - (RANGE_SECONDS[this.range] || 86400), end };
  }

  // the query for the time series API
  query() { return this.window ? `start=${this.window.start}&end=${this.window.end}` : `range=${this.range}`; }

  add(graph) { this.graphs.add(graph); }

  changed() {
    for (const g of [...this.graphs]) { if (g.isConnected) g.reload(); else this.graphs.delete(g); }
    for (const b of [...this.bars]) { if (b.isConnected) b.refresh(); else this.bars.delete(b); }
    for (const t of [...this.tabs]) { if (t.isConnected) t.refresh(); else this.tabs.delete(t); }
  }

  setRange(key) {
    this.range = key;
    this.window = null;
    this.trail = [];
    this.changed();
  }

  zoomTo(win) {
    this.trail.push(this.window ? { window: this.window } : { range: this.range });
    this.window = clampWindow(win, this.now());
    this.changed();
  }

  zoomBy(factor) {
    const next = zoomWindow(this.shown(), factor, this.now());
    if (!this.window && factor > 1) return;                       // already showing a whole range: zooming out is the range buttons' job
    if (this.window && next.end - next.start >= (RANGE_SECONDS[this.range] || 86400) * 1.5 && factor > 1) { this.reset(); return; }
    this.zoomTo(next);
  }

  pan(fraction) {
    if (!this.window) return;
    this.window = panWindow(this.window, fraction, this.now());
    this.changed();
  }

  back() {
    const before = this.trail.pop();
    if (!before) return;
    this.window = before.window || null;
    if (before.range) this.range = before.range;
    this.changed();
  }

  reset() {
    this.window = null;
    this.trail = [];
    this.changed();
  }

  key(name) {
    ({ in: () => this.zoomBy(0.5), out: () => this.zoomBy(2), earlier: () => this.pan(-0.5), later: () => this.pan(0.5), reset: () => this.reset() })[name]?.();
  }

  // the pointer is over one graph: the others show the same moment
  hover(t, source) {
    for (const g of this.graphs) if (g !== source && g.isConnected) g.showAt(t);
  }
  leave(source) {
    for (const g of this.graphs) if (g !== source && g.isConnected) g.showAt(null);
  }

  // the line that appears above the graphs while a zoom is on: what is shown, and the way back
  bar() {
    const text = h("span", { class: "tg-zoom-text" });
    const button = (label, title, act) => h("button", { type: "button", class: "btn", title, onclick: act }, label);
    const bar = h("div", { class: "tg-zoombar", role: "group", "aria-label": "Zoom", hidden: true }, text,
      button("◀ Earlier", "Move half a period back", () => this.pan(-0.5)), button("Later ▶", "Move half a period forward", () => this.pan(0.5)),
      button("Zoom out", "Show twice as long", () => this.zoomBy(2)), button("Back", "The view before this zoom", () => this.back()), button("Show full period", "Stop zooming", () => this.reset()));
    bar.refresh = () => {
      bar.hidden = !this.window;
      if (this.window) text.textContent = `${describeWindow(this.window)} (${describeSpan(this.window.end - this.window.start)})`;
    };
    this.bars.add(bar);
    bar.refresh();
    return bar;
  }
}

// the lines laid over a graph are remembered while the page is open, so a redraw of the card keeps them
const OVERLAYS = new Map();
const overlayKey = (g) => `${g.entity}:${g.id}:${g.metric}:${g.label}`;

// One graph with a title, the newest value and a lowest / average / highest line. `group` makes it share its period, zoom and cursor with the others;
// without one it has a group of its own (and `range` is its period).
export function metricGraph({ entity, id, metric, label = "", title, unit = "", warn = null, crit = null, range, height = 110, fixedMax = null, showLimits = false, group = null, tools = true }) {
  const mine = group || new GraphGroup(range);
  const key = overlayKey({ entity, id, metric, label });
  const box = h("section", { class: "tg-box", "data-metric": metric, "data-label": label });          // the health chips at the top of a device page find their graph by these
  const end = h("div", { class: "tg-head-end" });
  const head = h("div", { class: "tg-head" }, h("strong", {}, title), end);
  const now = h("span", { class: "tg-now" });
  const chips = h("div", { class: "tg-chips", hidden: true });
  end.appendChild(now);
  const foot = h("div", { class: "tg-foot hint" });
  const body = h("div", {}, h("p", { class: "hint" }, "Loading…"));
  box.append(head, chips, body, foot);
  let token = 0, last = null, lastWidth = 0, latest = "", latestColour = "";
  let overlayData = [];

  function paint() {
    if (!last) return;
    const width = body.clientWidth || 640;
    lastWidth = width;
    const view = drawGraph(last, {
      unit: unit || last.unit, warn: showLimits ? warn : null, crit: showLimits ? crit : null, height, fixedMax, width, overlays: overlayData,
      interactive: {
        now: mine.now(), onSelect: (win) => mine.zoomTo(win), onKey: (k) => mine.key(k),
        onHover: (t) => { showAt(t); mine.hover(t, box); }, onLeave: () => { showAt(null); mine.leave(box); },
      },
    });
    const hadFocus = body.contains(document.activeElement);       // a key that zoomed the graph must not lose the keyboard
    body.replaceChildren(view);
    box.view = view;
    if (hadFocus) view.querySelector("svg")?.focus({ preventScroll: true });
  }
  if (typeof ResizeObserver !== "undefined") {
    new ResizeObserver(() => { if (last && Math.abs((body.clientWidth || 0) - lastWidth) > 8) paint(); }).observe(body);
  }

  // the number in the corner follows the cursor (of this graph or of another one in the group) and goes back to the newest value
  function showAt(t) {
    if (t === null || t === undefined || !last) {
      now.textContent = latest;
      now.style.color = latestColour;
      now.classList.remove("at-cursor");
      if (box.view && box.view.hideCursor && t === null) box.view.hideCursor();
      return;
    }
    const p = box.view && box.view.cursorAt ? box.view.cursorAt(t) : null;
    if (!p) { now.textContent = ""; now.classList.add("at-cursor"); return; }
    const u = unit || last.unit;
    now.textContent = formatValue(p[1], u);
    now.style.color = levelColour(p[1], u, warn, crit);
    now.classList.add("at-cursor");
  }
  box.showAt = showAt;

  function drawChips() {
    const list = OVERLAYS.get(key) || [];
    chips.hidden = !list.length;
    chips.replaceChildren(...list.map((o, i) => h("span", { class: "tg-chip" }, h("span", { class: "tg-dot", style: `background:${overlayColour(i)}` }), o.name,
      h("button", { type: "button", class: "tg-chip-x", title: "Remove this line", "aria-label": `Remove ${o.name}`, onclick: () => {
        OVERLAYS.set(key, list.filter((x) => x !== o));
        box.reload();
      } }, "×"))));
  }

  async function load() {
    const mineToken = ++token;
    const list = OVERLAYS.get(key) || [];
    drawChips();
    try {
      const asked = mine.query();
      const [data, ...extra] = await Promise.all([
        get(`/api/timeseries/${entity}/${id}/${encodeURIComponent(metric)}?label=${encodeURIComponent(label)}&${asked}&points=240`),
        ...list.map((o) => get(`/api/timeseries/${o.entity}/${o.id}/${encodeURIComponent(o.metric)}?label=${encodeURIComponent(o.label || "")}&${asked}&points=240`).catch(() => null)),
      ]);
      if (mineToken !== token) return;
      const u = unit || data.unit;
      last = data;
      overlayData = list.map((o, i) => (extra[i] ? { name: o.name, unit: o.unit || extra[i].unit, points: extra[i].points } : null)).filter(Boolean);
      paint();
      const s = summary(data.points, u);
      latest = s ? formatValue(s.last, u) : "";
      latestColour = s ? levelColour(s.last, u, warn, crit) : "";
      showAt(null);
      foot.textContent = !s ? "" : u === "state" ? `Available ${trim(s.avg * 100, 2)}% of the time`
        : `Lowest ${formatValue(s.lo, u)} \u00b7 average ${formatValue(s.avg, u)} \u00b7 highest ${formatValue(s.hi, u)}`;
    } catch (err) {
      if (mineToken === token) body.replaceChildren(h("p", { class: "error" }, err.message || "Could not load the graph"));
    }
  }

  // the small menu in the corner of the graph
  if (tools) {
    const item = (text, act) => h("button", { type: "button", class: "tg-menu-item", onclick: (e) => { e.currentTarget.closest("details").open = false; act(); } }, text);
    const menu = h("details", { class: "tg-menu" }, h("summary", { class: "tg-menu-btn", title: "Compare, correlate, download", "aria-label": `Options for ${title}` }, "⋯"),
      h("div", { class: "tg-menu-list" },
        item("Compare with…", async () => {
          const { chooseOverlay } = await import("./graphtools.js");
          const list = OVERLAYS.get(key) || [];
          const picked = await chooseOverlay({ entity, id, metric, label, title, unit: unit || (last && last.unit) || "", overlays: list });
          if (!picked) return;
          OVERLAYS.set(key, [...list, picked]);
          box.reload();
        }),
        item("Correlate with…", async () => {
          const { openCorrelate } = await import("./graphtools.js");
          openCorrelate({ x: { entity, id, metric, label, title }, query: mine.query(), windowText: mine.window ? describeWindow(mine.window) : (GRAPH_RANGES.find(([k]) => k === mine.range) || [, mine.range])[1] });
        }),
        item("Download as CSV", () => {
          if (!last) return;
          const u = unit || last.unit;
          const text = toCsv([{ name: title, unit: u, points: last.points }, ...overlayData.map((o) => ({ name: o.name, unit: o.unit, points: o.points }))]);
          const url = URL.createObjectURL(new Blob([text], { type: "text/csv" }));
          const a = h("a", { href: url, download: `${metric}${label ? "-" + label : ""}.csv` });
          document.body.appendChild(a); a.click(); a.remove();
          setTimeout(() => URL.revokeObjectURL(url), 2000);
        })));
    end.appendChild(menu);
  }

  mine.add(box);
  box.reload = (newRange) => { if (typeof newRange === "string" && !group) mine.setRange(newRange); else load(); };
  box.setLimits = (on) => { showLimits = on; paint(); };       // the dashed lines and tinted zones are off until asked for
  load();
  return box;
}

// The period buttons. They act on the group: choosing one ends a zoom.
export function graphRangeTabs(current, onChange, group = null) {
  const wrap = h("div", { class: "range-tabs", role: "group", "aria-label": "Period" });
  const buttons = new Map();
  for (const [key, text] of GRAPH_RANGES) {
    const b = h("button", { type: "button", "aria-pressed": String(key === current) }, text);
    b.addEventListener("click", () => {
      try { localStorage.setItem(RANGE_KEY, key); } catch (e) { /* only this page remembers it */ }
      for (const other of wrap.children) other.setAttribute("aria-pressed", String(other === b));
      if (group) group.setRange(key);
      onChange(key);
    });
    buttons.set(key, b);
    wrap.appendChild(b);
  }
  if (group) {
    wrap.refresh = () => { for (const [key, b] of buttons) b.setAttribute("aria-pressed", String(!group.zoomed && key === group.range)); };
    group.tabs.add(wrap);
    wrap.refresh();                                  // a zoom that is on (kept across a redraw) leaves no period pressed
  }
  return wrap;
}
