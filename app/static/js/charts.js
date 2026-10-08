// Small SVG/DOM charts for the Statistics page (no library). Everything is built with createElement/createElementNS,
// colours come from CSS variables (text, borders) or a fixed series palette that keeps contrast in both themes.
import { h } from "./util.js";
import { isDark } from "./theme.js";

const NS = "http://www.w3.org/2000/svg";
const SERIES_LIGHT = ["#2563eb", "#059669", "#d97706", "#7c3aed", "#db2777", "#0891b2", "#dc2626", "#64748b", "#a16207", "#0d9488"];
const SERIES_DARK = ["#60a5fa", "#34d399", "#fbbf24", "#a78bfa", "#f472b6", "#22d3ee", "#f87171", "#cbd5e1", "#facc15", "#2dd4bf"];

export function seriesColors() {
  return isDark() ? SERIES_DARK : SERIES_LIGHT;
}

function svg(tag, attrs = {}, ...children) {
  const el = document.createElementNS(NS, tag);
  for (const [k, v] of Object.entries(attrs)) el.setAttribute(k, String(v));
  for (const c of children) if (c) el.appendChild(c);
  return el;
}

export function fmtNumber(n) {
  return n === null || n === undefined ? "–" : Number(n).toLocaleString();
}

export function fmtPct(n) {
  return n === null || n === undefined ? "–" : `${Number(n).toFixed(n % 1 === 0 ? 0 : 1)}%`;
}

export function fmtDuration(seconds) {
  if (seconds === null || seconds === undefined) return "–";
  const s = Math.round(seconds);
  if (s < 90) return `${s} s`;
  if (s < 5400) return `${Math.round(s / 60)} min`;
  if (s < 172800) return `${(s / 3600).toFixed(1).replace(/\.0$/, "")} h`;
  return `${Math.round(s / 86400)} d`;
}

export function fmtBytes(n) {
  if (n === null || n === undefined) return "–";
  if (n < 1024) return `${n} B`;
  if (n < 1048576) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1048576).toFixed(1)} MB`;
}

// Horizontal bars: items = [{label, count, href?}]
export function barList(items, { unit = "" } = {}) {
  const box = h("div", { class: "bars" });
  if (!items.length) return emptyNote();
  const max = Math.max(...items.map((i) => i.count), 1);
  const colors = seriesColors();
  items.forEach((item, idx) => {
    const label = item.href ? h("a", { href: item.href }, item.label) : h("span", {}, item.label);
    const fill = h("span", { class: "bar-fill" });
    fill.style.width = `${Math.max(2, (item.count / max) * 100)}%`;
    fill.style.background = colors[idx % colors.length];
    box.appendChild(h("div", { class: "bar-row", title: `${item.label}: ${item.count}${unit}` },
      h("span", { class: "bar-label" }, label), h("span", { class: "bar-track" }, fill), h("span", { class: "bar-value" }, `${fmtNumber(item.count)}${unit}`)));
  });
  return box;
}

export function emptyNote(text = "No data yet.") {
  return h("p", { class: "hint empty-note" }, text);
}

// Donut with a legend: items = [{label, count}]
export function donut(items, { size = 140 } = {}) {
  const total = items.reduce((s, i) => s + i.count, 0);
  if (!total) return emptyNote();
  const colors = seriesColors();
  const r = size / 2 - 10;
  const cx = size / 2;
  const root = svg("svg", { viewBox: `0 0 ${size} ${size}`, width: size, height: size, role: "img", "aria-label": "Share per category" });
  let angle = -Math.PI / 2;
  items.forEach((item, idx) => {
    const frac = item.count / total;
    const color = colors[idx % colors.length];
    if (frac >= 0.9999) {
      root.appendChild(svg("circle", { cx, cy: cx, r, fill: "none", stroke: color, "stroke-width": 18 }, svg("title", {})));
      return;
    }
    const end = angle + frac * 2 * Math.PI;
    const large = frac > 0.5 ? 1 : 0;
    const d = `M ${cx + r * Math.cos(angle)} ${cx + r * Math.sin(angle)} A ${r} ${r} 0 ${large} 1 ${cx + r * Math.cos(end)} ${cx + r * Math.sin(end)}`;
    const path = svg("path", { d, fill: "none", stroke: color, "stroke-width": 18 });
    const title = svg("title", {});
    title.textContent = `${item.label}: ${item.count} (${Math.round(frac * 100)}%)`;
    path.appendChild(title);
    root.appendChild(path);
    angle = end;
  });
  const center = svg("text", { x: cx, y: cx + 5, "text-anchor": "middle", class: "donut-total" });
  center.textContent = String(total);
  root.appendChild(center);
  const legend = h("ul", { class: "legend-list" });
  items.forEach((item, idx) => {
    const dot = h("span", { class: "dot" });
    dot.style.background = colors[idx % colors.length];
    legend.appendChild(h("li", {}, dot, `${item.label} `, h("strong", {}, String(item.count))));
  });
  return h("div", { class: "donut" }, root, legend);
}

// Line chart: points = [{x: label, a: number, b: number}], lines = [{key, label}]
export function lineChart(points, lines, { height = 150, yFormat = fmtNumber } = {}) {
  if (points.length < 2) return emptyNote(points.length ? "Not enough history yet (need two points)." : "No data yet.");
  const width = 600;
  const pad = { l: 40, r: 10, t: 10, b: 22 };
  const colors = seriesColors();
  const values = points.flatMap((p) => lines.map((l) => p[l.key]).filter((v) => v !== null && v !== undefined));
  let min = Math.min(...values, 0);
  let max = Math.max(...values, 1);
  if (max === min) max = min + 1;
  const x = (i) => pad.l + (i / (points.length - 1)) * (width - pad.l - pad.r);
  const y = (v) => pad.t + (1 - (v - min) / (max - min)) * (height - pad.t - pad.b);
  const root = svg("svg", { viewBox: `0 0 ${width} ${height}`, class: "line-chart", role: "img" });
  for (const frac of [0, 0.5, 1]) {
    const v = min + (max - min) * frac;
    root.appendChild(svg("line", { x1: pad.l, x2: width - pad.r, y1: y(v), y2: y(v), class: "grid" }));
    const t = svg("text", { x: pad.l - 4, y: y(v) + 4, "text-anchor": "end", class: "axis" });
    t.textContent = yFormat(Math.round(v * 10) / 10);
    root.appendChild(t);
  }
  [0, Math.floor((points.length - 1) / 2), points.length - 1].forEach((i) => {
    const t = svg("text", { x: x(i), y: height - 5, "text-anchor": i === 0 ? "start" : i === points.length - 1 ? "end" : "middle", class: "axis" });
    t.textContent = points[i].x;
    root.appendChild(t);
  });
  lines.forEach((line, li) => {
    const pts = points.map((p, i) => (p[line.key] === null || p[line.key] === undefined ? null : `${x(i)},${y(p[line.key])}`)).filter(Boolean);
    root.appendChild(svg("polyline", { points: pts.join(" "), fill: "none", stroke: colors[li % colors.length], "stroke-width": 2, "stroke-linejoin": "round" }));
    points.forEach((p, i) => {
      if (p[line.key] === null || p[line.key] === undefined) return;
      const dot = svg("circle", { cx: x(i), cy: y(p[line.key]), r: points.length > 60 ? 1.5 : 3, fill: colors[li % colors.length] });
      const title = svg("title", {});
      title.textContent = `${p.x} · ${line.label}: ${yFormat(p[line.key])}`;
      dot.appendChild(title);
      root.appendChild(dot);
    });
  });
  const legend = h("ul", { class: "legend-list inline" });
  lines.forEach((line, li) => {
    const dot = h("span", { class: "dot" });
    dot.style.background = colors[li % colors.length];
    legend.appendChild(h("li", {}, dot, line.label));
  });
  return h("div", { class: "chart" }, root, lines.length > 1 ? legend : null);
}

// Columns: points = [{x, v}]
export function columnChart(points, { height = 110 } = {}) {
  if (!points.length) return emptyNote();
  const max = Math.max(...points.map((p) => p.v), 1);
  const box = h("div", { class: "columns", style: `height:${height}px` });
  const color = seriesColors()[0];
  for (const p of points) {
    const col = h("span", { class: "col", title: `${p.x}: ${p.v}` });
    col.style.height = `${Math.max(2, (p.v / max) * 100)}%`;
    col.style.background = color;
    box.appendChild(col);
  }
  return h("div", { class: "chart" }, box, h("div", { class: "col-axis" }, h("span", {}, points[0].x), h("span", {}, points[points.length - 1].x)));
}

export function tile(value, label, { tone = "" } = {}) {
  return h("div", { class: `tile ${tone}` }, h("div", { class: "tile-value" }, String(value)), h("div", { class: "tile-label" }, label));
}
