import { fmtTime } from "./util.js";

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

  for (const item of list) {
    const span = document.createElement("span");
    const up = typeof item === "number" ? item === 1 : item.up;
    span.className = "hb " + (up ? "hb-up" : "hb-down");

    if (typeof item === "object") {
      let title = fmtTime(item.ts) + ": " + (up ? "up" : "down");
      if (typeof item.rtt_ms === "number") {
        title += " (" + item.rtt_ms + " ms)";
      }
      span.title = title;
    }

    bar.appendChild(span);
  }

  return bar;
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