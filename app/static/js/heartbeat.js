import { fmtTime } from "./util.js";

// ---------- the infobox that follows the pointer over a bar or a point of a graph ----------

let tipEl = null;

function tip() {
  if (!tipEl) {
    tipEl = document.createElement("div");
    tipEl.className = "hb-tip";
    tipEl.setAttribute("role", "tooltip");
    tipEl.hidden = true;
    document.body.appendChild(tipEl);
    window.addEventListener("scroll", hideTip, { passive: true, capture: true });
  }
  return tipEl;
}

export function hideTip() {
  if (tipEl) tipEl.hidden = true;
}

// what the infobox says about one measurement (or one slice of time that holds several): the time, up or down, and the response time
export function describe(item) {
  const lines = [];
  const many = typeof item.n === "number" && item.n > 1;
  lines.push(["hb-tip-time", many && item.end ? `${fmtTime(item.ts)} \u2013 ${fmtTime(item.end).slice(-5)}` : fmtTime(item.ts)]);
  const state = item.up ? "Up" : "Down";
  lines.push([item.up ? "hb-tip-up" : "hb-tip-down", many && !item.up ? `${state} \u00b7 ${item.down} of ${item.n} checks failed` : state]);
  if (typeof item.rtt_ms === "number") {
    lines.push(["", many ? `Response: ${item.rtt_ms} ms on average${typeof item.rtt_max === "number" ? `, up to ${item.rtt_max} ms` : ""}` : `Response: ${item.rtt_ms} ms`]);
  } else if (item.up === false) {
    lines.push(["hb-tip-note", "No response"]);
  }
  if (many && item.up) lines.push(["hb-tip-note", `${item.n} checks`]);
  return lines;
}

function showTip(item, x, y) {
  const el = tip();
  el.replaceChildren(...describe(item).map(([cls, text]) => Object.assign(document.createElement("div"), { className: cls, textContent: text })));
  el.hidden = false;
  const w = el.offsetWidth, hgt = el.offsetHeight;
  el.style.left = `${Math.max(6, Math.min(window.innerWidth - w - 6, x - w / 2))}px`;
  el.style.top = `${y - hgt - 14 < 6 ? y + 18 : y - hgt - 14}px`;
}

// hover (or touch) over `host`: `pick(event)` says which item the pointer is on, or null
function watch(host, pick, onMove) {
  const move = (e) => {
    const hit = pick(e);
    if (!hit) { hideTip(); if (onMove) onMove(null); return; }
    showTip(hit.item, hit.x ?? e.clientX, hit.y ?? e.clientY);
    if (onMove) onMove(hit);
  };
  host.addEventListener("pointermove", move);
  host.addEventListener("pointerdown", move);
  host.addEventListener("pointerleave", () => { hideTip(); if (onMove) onMove(null); });
}

// ---------- the Uptime-Kuma style bar: one block per measurement (or per slice of time) ----------

export function heartbeatBar(items, total = 60) {
  const bar = document.createElement("div");
  bar.className = "hb-bar";

  const list = items.slice(-total);
  const pad = total - list.length;

  for (let i = 0; i < pad; i++) {
    const span = document.createElement("span");
    span.className = "hb hb-empty";
    bar.appendChild(span);
  }

  const shown = [];
  for (const item of list) {
    const span = document.createElement("span");
    const up = typeof item === "number" ? item === 1 : item.up;
    span.className = "hb " + (up ? "hb-up" : "hb-down");
    if (typeof item === "object" && item.ts) shown.push([span, { ...item, up }]);
    bar.appendChild(span);
  }
  if (shown.length) {
    watch(bar, (e) => {
      const span = e.target.closest && e.target.closest(".hb");
      const hit = span && shown.find(([el]) => el === span);
      if (!hit) return null;
      const r = span.getBoundingClientRect();
      return { item: hit[1], x: r.left + r.width / 2, y: r.top };
    });
  }

  return bar;
}

// ---------- the response-time line: items as for heartbeatBar, drawn over the same `total` slots ----------
// options: height (px), axis (show the highest value and the average as small labels)

export function responseLine(items, total = 60, { height = 44, axis = false } = {}) {
  const list = items.slice(-total);
  const values = list.map((i) => (typeof i === "object" && typeof i.rtt_ms === "number" ? i.rtt_ms : null));
  const wrap = document.createElement("div");
  wrap.className = "rl";
  wrap.style.height = `${height}px`;
  if (values.filter((v) => v !== null).length < 2) {
    wrap.classList.add("rl-empty");
    wrap.textContent = "No response times yet";
    return wrap;
  }
  const W = 1000, H = 100, pad = 6;
  const max = Math.max(...values.filter((v) => v !== null)) * 1.1 || 1;
  const slot = W / total, offset = total - list.length;
  const xOf = (i) => (offset + i + 0.5) * slot;
  const yOf = (v) => H - pad - (v / max) * (H - 2 * pad);
  const NS = "http://www.w3.org/2000/svg";
  const svg = document.createElementNS(NS, "svg");
  svg.setAttribute("viewBox", `0 0 ${W} ${H}`);
  svg.setAttribute("preserveAspectRatio", "none");
  svg.setAttribute("class", "rl-svg");
  let segment = [], paths = [], areas = [];
  const flush = () => {
    if (segment.length > 1) {
      paths.push("M" + segment.map(([x, y]) => `${x.toFixed(1)},${y.toFixed(1)}`).join(" L"));
      areas.push(`M${segment[0][0].toFixed(1)},${H} L` + segment.map(([x, y]) => `${x.toFixed(1)},${y.toFixed(1)}`).join(" L") + ` L${segment[segment.length - 1][0].toFixed(1)},${H} Z`);
    }
    segment = [];
  };
  values.forEach((v, i) => { if (v === null) flush(); else segment.push([xOf(i), yOf(v)]); });
  flush();
  const make = (name, attrs) => { const el = document.createElementNS(NS, name); for (const [k, v] of Object.entries(attrs)) el.setAttribute(k, v); return el; };
  svg.appendChild(make("path", { d: areas.join(" "), class: "rl-area" }));
  svg.appendChild(make("path", { d: paths.join(" "), class: "rl-path", fill: "none", "vector-effect": "non-scaling-stroke" }));
  list.forEach((item, i) => {      // a failed check is a red tick at the bottom
    if (typeof item === "object" && item.up === false) svg.appendChild(make("rect", { x: (xOf(i) - slot * 0.35).toFixed(1), y: H - 10, width: (slot * 0.7).toFixed(1), height: 10, class: "rl-down" }));
  });
  wrap.appendChild(svg);
  const dot = document.createElement("span");
  dot.className = "rl-dot";
  dot.hidden = true;
  wrap.appendChild(dot);
  if (axis) {
    const nums = values.filter((v) => v !== null);
    const avg = Math.round((nums.reduce((a, b) => a + b, 0) / nums.length) * 10) / 10;
    const label = document.createElement("span");
    label.className = "rl-axis";
    label.textContent = `highest ${Math.round(Math.max(...nums) * 10) / 10} ms \u00b7 average ${avg} ms`;
    wrap.appendChild(label);
  }
  watch(wrap, (e) => {
    const r = wrap.getBoundingClientRect();
    if (!r.width) return null;
    const i = Math.round(((e.clientX - r.left) / r.width) * total - 0.5) - offset;
    const k = Math.max(0, Math.min(list.length - 1, i));
    const item = list[k];
    if (typeof item !== "object" || !item.ts) return null;
    const x = r.left + (xOf(k) / W) * r.width;
    const v = values[k];
    return { item: { ...item, up: item.up !== false }, x, y: v === null ? r.bottom - 4 : r.top + (yOf(v) / H) * r.height, index: k, value: v, left: (xOf(k) / W) * 100, top: v === null ? null : (yOf(v) / H) * 100 };
  }, (hit) => {
    dot.hidden = !hit || hit.value === null;
    if (hit && hit.value !== null) { dot.style.left = `${hit.left}%`; dot.style.top = `${hit.top}%`; }
  });
  return wrap;
}

export function uptimeText(percent) {
  if (percent === null || percent === undefined) return "\u2013";
  const rounded = Math.round(percent * 100) / 100;
  return rounded + "%";
}

export function uptimeClass(percent) {
  if (percent === null || percent === undefined) return "up-na";
  if (percent >= 99) return "up-good";
  if (percent >= 95) return "up-ok";
  return "up-bad";
}

export function humanDuration(seconds) {
  if (seconds === null || seconds === undefined) return "\u2013";
  if (seconds === 0) return "0s";

  const d = Math.floor(seconds / 86400);
  const h = Math.floor((seconds % 86400) / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const s = seconds % 60;

  const parts = [];
  if (d > 0) parts.push(d + "d");
  if (h > 0) parts.push(h + "h");
  if (m > 0) parts.push(m + "m");
  if (s > 0) parts.push(s + "s");

  return parts.slice(0, 2).join(" ");
}

export function sparkline(values, width = 240, height = 36) {
  const numeric = values.filter((v) => typeof v === "number");
  if (numeric.length < 2) {
    const span = document.createElement("span");
    span.className = "hint";
    span.textContent = "Not enough data yet";
    return span;
  }

  const min = Math.min(...numeric);
  const max = Math.max(...numeric);
  const range = max - min;
  const pad = 2;

  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("class", "sparkline");
  svg.setAttribute("viewBox", `0 0 ${width} ${height}`);
  svg.setAttribute("preserveAspectRatio", "none");

  const polyline = document.createElementNS("http://www.w3.org/2000/svg", "polyline");
  polyline.setAttribute("class", "sparkline-line");
  polyline.setAttribute("fill", "none");
  polyline.setAttribute("stroke", "currentColor");
  polyline.setAttribute("stroke-width", "1.5");

  const points = [];
  for (let i = 0; i < values.length; i++) {
    const v = values[i];
    if (typeof v !== "number") continue;

    const x = (i / (values.length - 1)) * width;
    let y;
    if (range === 0) {
      y = height / 2;
    } else {
      y = pad + ((v - min) / range) * (height - 2 * pad);
    }
    points.push(`${x},${y}`);
  }

  polyline.setAttribute("points", points.join(" "));
  svg.appendChild(polyline);

  return svg;
}

// ---------- 24 hours / 7 days / 30 days ----------

export const RANGES = [["24h", "24 hours"], ["7d", "7 days"], ["30d", "30 days"]];
const RANGE_KEY = "netlens.uptime.range";

// the period last chosen on any uptime view (kept in this browser only)
export function savedRange() {
  try {
    const v = localStorage.getItem(RANGE_KEY);
    return RANGES.some(([k]) => k === v) ? v : "24h";
  } catch (e) {
    return "24h";
  }
}

export function rangeTabs(current, onChange) {
  const wrap = document.createElement("div");
  wrap.className = "range-tabs";
  wrap.setAttribute("role", "group");
  wrap.setAttribute("aria-label", "Period");
  for (const [key, label] of RANGES) {
    const b = document.createElement("button");
    b.type = "button";
    b.textContent = label;
    b.dataset.range = key;
    b.setAttribute("aria-pressed", String(key === current));
    b.addEventListener("click", () => {
      try { localStorage.setItem(RANGE_KEY, key); } catch (e) { /* only this page remembers it */ }
      for (const other of wrap.children) other.setAttribute("aria-pressed", String(other === b));
      onChange(key);
    });
    wrap.appendChild(b);
  }
  return wrap;
}
