// The arithmetic behind graph zooming and comparing. No DOM in here, so it can be tested on its own (tests/test_js_logic.py).
// A "window" is {start, end} in epoch seconds.

export const MIN_WINDOW = 600;                 // the smallest period a person can zoom in to: ten minutes
export const MAX_WINDOW = 366 * 86400;
export const RANGE_SECONDS = { "1h": 3600, "6h": 21600, "24h": 86400, "7d": 604800, "30d": 2592000, "90d": 7776000, "1y": 31536000 };

// Keep a window inside what can be asked for: not shorter than MIN_WINDOW, not longer than a year, not in the future.
export function clampWindow(win, now) {
  let { start, end } = win;
  let span = Math.min(MAX_WINDOW, Math.max(MIN_WINDOW, end - start));
  if (end > now) end = now;
  start = end - span;
  if (end - start < MIN_WINDOW) { end = start + MIN_WINDOW; if (end > now) { end = now; start = end - MIN_WINDOW; } }
  return { start: Math.round(start), end: Math.round(end) };
}

// Zoom around the middle: factor 2 doubles the period, 0.5 halves it.
export function zoomWindow(win, factor, now) {
  const mid = (win.start + win.end) / 2;
  const half = ((win.end - win.start) * factor) / 2;
  return clampWindow({ start: mid - half, end: mid + half }, now);
}

// Move by a fraction of the period (-0.5 = half a period earlier). Never into the future.
export function panWindow(win, fraction, now) {
  const span = win.end - win.start;
  let start = win.start + span * fraction, end = win.end + span * fraction;
  if (end > now) { end = now; start = end - span; }
  return clampWindow({ start, end }, now);
}

// A drag from x0 to x1 (pixels in the drawing) over a plot that starts at `left` and is `width` wide, showing `win`.
// Returns the new window, or null when the drag was too small to mean anything (a click, a jitter).
export function selectionToWindow(x0, x1, plot, win, now, minPixels = 8) {
  const a = Math.min(x0, x1), b = Math.max(x0, x1);
  if (b - a < minPixels) return null;
  const at = (x) => win.start + ((Math.min(plot.left + plot.width, Math.max(plot.left, x)) - plot.left) / plot.width) * (win.end - win.start);
  return clampWindow({ start: at(a), end: at(b) }, now);
}

// The point of a series nearest to time t, but only if it is within `reach` seconds; points are [t, avg, min, max], oldest first.
export function nearestPoint(points, t, reach = Infinity) {
  if (!points.length) return null;
  let lo = 0, hi = points.length - 1;
  while (lo < hi) {
    const mid = (lo + hi) >> 1;
    if (points[mid][0] < t) lo = mid + 1; else hi = mid;
  }
  let best = points[lo];
  if (lo > 0 && Math.abs(points[lo - 1][0] - t) <= Math.abs(best[0] - t)) best = points[lo - 1];
  return Math.abs(best[0] - t) <= reach ? best : null;
}

// How a correlation coefficient reads in words.
export function describeCorrelation(r) {
  if (r === null || r === undefined) return "Not enough varying readings to say.";
  const strength = Math.abs(r);
  const how = strength >= 0.8 ? "very strong" : strength >= 0.6 ? "strong" : strength >= 0.4 ? "moderate" : strength >= 0.2 ? "weak" : null;
  if (how === null) return "No clear relationship.";
  return r > 0 ? `A ${how} relationship: when one rises, the other tends to rise.` : `A ${how} relationship: when one rises, the other tends to fall.`;
}

// A tidy scale for a scatter plot axis: [min, max, ticks] covering the values.
export function niceScale(lo, hi, wantedTicks = 5) {
  if (!(hi > lo)) { const pad = Math.abs(lo) * 0.1 || 1; lo -= pad; hi += pad; }
  const rough = (hi - lo) / wantedTicks;
  const exp = Math.pow(10, Math.floor(Math.log10(rough)));
  const step = [1, 2, 2.5, 5, 10].map((m) => m * exp).find((s) => s >= rough) || 10 * exp;
  const min = Math.floor(lo / step) * step, max = Math.ceil(hi / step) * step;
  const ticks = [];
  for (let v = min; v <= max + step / 2; v += step) ticks.push(Math.round(v * 1e9) / 1e9);
  return [min, max, ticks];
}

// Which line of the same unit shares the left scale, and which different unit gets the right one. `main` and each overlay have a unit;
// at most one other unit is allowed (there is only one right-hand scale). Returns the overlays split into {left, right, rightUnit}.
export function splitAxes(mainUnit, overlays) {
  const left = [], right = [];
  let rightUnit = null;
  for (const o of overlays) {
    if (o.unit === mainUnit) left.push(o);
    else if (rightUnit === null || rightUnit === o.unit) { rightUnit = o.unit; right.push(o); }
  }
  return { left, right, rightUnit };
}

// Can this unit still be added as another overlay on a graph that shows `mainUnit` and `overlays`?
export function canOverlay(mainUnit, overlays, unit, limit = 3) {
  if (overlays.length >= limit) return false;
  const { rightUnit } = splitAxes(mainUnit, overlays);
  return unit === mainUnit || rightUnit === null || rightUnit === unit;
}

// The text for a window: "12 Nov 10:00 – 12:30" (same day) or "12 Nov 22:00 – 13 Nov 02:00".
export function describeWindow(win, locale = undefined) {
  const a = new Date(win.start * 1000), b = new Date(win.end * 1000);
  const day = (d) => d.toLocaleDateString(locale, { day: "numeric", month: "short" });
  const hm = (d) => d.toLocaleTimeString(locale, { hour: "2-digit", minute: "2-digit", hour12: false });
  const same = a.toDateString() === b.toDateString();
  return same ? `${day(a)} ${hm(a)} – ${hm(b)}` : `${day(a)} ${hm(a)} – ${day(b)} ${hm(b)}`;
}

export function describeSpan(seconds) {
  if (seconds < 5400) return `${Math.round(seconds / 60)} min`;
  if (seconds < 172800) return `${(seconds / 3600).toFixed(1).replace(/\.0$/, "")} h`;
  return `${Math.round(seconds / 86400)} d`;
}

// CSV text for a graph: one row per point. `series` = [{name, unit, points}] with points [t, avg, min, max]; rows are joined on the time of the first series.
export function toCsv(series) {
  const first = series[0];
  const esc = (v) => (/[",\n]/.test(String(v)) ? `"${String(v).replace(/"/g, '""')}"` : String(v));
  const head = ["time (UTC)", ...series.flatMap((s) => (s === first ? [`${s.name} average (${s.unit})`, `${s.name} lowest`, `${s.name} highest`] : [`${s.name} (${s.unit})`]))];
  const rows = first.points.map((p) => {
    const cells = [new Date(p[0] * 1000).toISOString().replace(".000Z", "Z"), p[1], p[2], p[3]];
    for (const s of series.slice(1)) {
      const q = nearestPoint(s.points, p[0], 1);
      cells.push(q ? q[1] : "");
    }
    return cells.map(esc).join(",");
  });
  return [head.map(esc).join(","), ...rows].join("\n") + "\n";
}
