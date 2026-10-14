// Performance graphs: one measurement over time with its lowest/highest band, a read-out under the pointer and
// optional warning / critical lines. Data comes from /api/timeseries (the metrics store); no library.
import { get } from "./api.js";
import { h, fmtTime } from "./util.js";

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
export function drawGraph(data, { unit, warn = null, crit = null, height = 120, fixedMax = null, width = 640 } = {}) {
  const W = Math.max(240, Math.round(width)), H = height, L = 64, R = 8, T = 8, B = 20;
  const wrap = h("div", { class: "tg" });
  const pts = data.points || [];
  if (!pts.length) {
    wrap.appendChild(h("p", { class: "hint tg-empty" }, "No measurements in this period yet."));
    return wrap;
  }
  const unitName = unit || data.unit;
  const t0 = data.start, t1 = data.end, span = Math.max(1, t1 - t0);
  const isPct = unitName === "%", isState = unitName === "state";
  let ymax = fixedMax ?? (isPct ? 100 : isState ? 1 : niceMax(Math.max(...pts.map((p) => p[3]), warn ?? 0, crit ?? 0) * 1.08));
  let ymin = 0;
  if (!isPct && !isState && fixedMax === null) {
    const lo = Math.min(...pts.map((p) => p[2]));
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

  const cursor = el("line", { x1: 0, x2: 0, y1: T, y2: H - B, class: "tg-cursor", stroke: "currentColor", "stroke-opacity": 0.5, "stroke-width": 1, visibility: "hidden" });
  const marker = el("circle", { r: 4, class: "tg-marker", fill: ACCENT, stroke: "#fff", "stroke-width": 1.5, visibility: "hidden" });
  root.append(cursor, marker);
  const tipBox = h("div", { class: "tg-tip", hidden: true });
  wrap.append(root, tipBox);

  const nearest = (clientX) => {
    const rect = root.getBoundingClientRect();
    const px = ((clientX - rect.left) / rect.width) * W;
    let best = null, dist = Infinity;
    for (const p of pts) {
      const d = Math.abs(x(p[0]) - px);
      if (d < dist) { dist = d; best = p; }
    }
    return dist < 40 ? best : null;
  };
  const move = (e) => {
    const p = nearest(e.clientX);
    if (!p) { leave(); return; }
    cursor.setAttribute("x1", x(p[0])); cursor.setAttribute("x2", x(p[0])); cursor.setAttribute("visibility", "visible");
    marker.setAttribute("cx", x(p[0])); marker.setAttribute("cy", y(p[1])); marker.setAttribute("visibility", "visible");
    marker.setAttribute("fill", colourOf(p[1]));
    const many = data.step > 1 && Math.abs(p[3] - p[2]) > 1e-9;
    tipBox.replaceChildren(
      h("div", { class: "tg-tip-time" }, fmtTime(new Date(p[0] * 1000).toISOString())),
      h("div", {}, formatValue(p[1], unitName)),
      many ? h("div", { class: "tg-tip-note" }, `${formatValue(p[2], unitName)} – ${formatValue(p[3], unitName)}`) : null);
    tipBox.hidden = false;
    const rect = wrap.getBoundingClientRect();
    const left = ((x(p[0]) / W) * rect.width);
    tipBox.style.left = `${Math.max(4, Math.min(rect.width - tipBox.offsetWidth - 4, left - tipBox.offsetWidth / 2))}px`;
  };
  const leave = () => {
    cursor.setAttribute("visibility", "hidden");
    marker.setAttribute("visibility", "hidden");
    tipBox.hidden = true;
  };
  root.addEventListener("pointermove", move);
  root.addEventListener("pointerdown", move);
  root.addEventListener("pointerleave", leave);
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

// One graph with a title, the newest value and a lowest / average / highest line. `range` is a string key.
export function metricGraph({ entity, id, metric, label = "", title, unit = "", warn = null, crit = null, range, height = 110, fixedMax = null }) {
  const box = h("section", { class: "tg-box" });
  const head = h("div", { class: "tg-head" }, h("strong", {}, title));
  const now = h("span", { class: "tg-now" });
  head.appendChild(now);
  const foot = h("div", { class: "tg-foot hint" });
  const body = h("div", {}, h("p", { class: "hint" }, "Loading…"));
  box.append(head, body, foot);
  let token = 0, last = null, lastWidth = 0;

  function paint() {
    if (!last) return;
    const width = body.clientWidth || 640;
    lastWidth = width;
    body.replaceChildren(drawGraph(last, { unit: unit || last.unit, warn, crit, height, fixedMax, width }));
  }
  if (typeof ResizeObserver !== "undefined") {
    new ResizeObserver(() => { if (last && Math.abs((body.clientWidth || 0) - lastWidth) > 8) paint(); }).observe(body);
  }

  async function load(newRange) {
    const mine = ++token;
    try {
      const data = await get(`/api/timeseries/${entity}/${id}/${encodeURIComponent(metric)}?label=${encodeURIComponent(label)}&range=${newRange}&points=240`);
      if (mine !== token) return;
      const u = unit || data.unit;
      last = data;
      paint();
      const s = summary(data.points, u);
      now.textContent = s ? formatValue(s.last, u) : "";
      now.style.color = s ? levelColour(s.last, u, warn, crit) : "";
      foot.textContent = !s ? "" : u === "state" ? `Available ${trim(s.avg * 100, 2)}% of the time`
        : `Lowest ${formatValue(s.lo, u)} \u00b7 average ${formatValue(s.avg, u)} \u00b7 highest ${formatValue(s.hi, u)}`;
    } catch (err) {
      if (mine === token) body.replaceChildren(h("p", { class: "error" }, err.message || "Could not load the graph"));
    }
  }
  load(range);
  box.reload = load;
  return box;
}

export function graphRangeTabs(current, onChange) {
  const wrap = h("div", { class: "range-tabs", role: "group", "aria-label": "Period" });
  for (const [key, text] of GRAPH_RANGES) {
    const b = h("button", { type: "button", "aria-pressed": String(key === current) }, text);
    b.addEventListener("click", () => {
      try { localStorage.setItem(RANGE_KEY, key); } catch (e) { /* only this page remembers it */ }
      for (const other of wrap.children) other.setAttribute("aria-pressed", String(other === b));
      onChange(key);
    });
    wrap.appendChild(b);
  }
  return wrap;
}
