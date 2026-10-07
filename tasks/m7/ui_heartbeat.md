
TASK: write app/static/js/heartbeat.js (full file, under 90 lines). Shared helpers for uptime displays. Exports:

export function heartbeatBar(items, total = 60)
  - `items` is an array ordered OLDEST FIRST where each entry is either a number (1 = up, 0 = down) or an object {ts: iso string, up: boolean, rtt_ms?: number|null}. Returns a div with class "hb-bar" containing exactly `total` span children: the last `items.length` (at most `total`; if there are more items keep only the newest `total`) spans represent the checks, right-aligned so the newest is at the far right; the spans before them are empty placeholders. Classes: "hb hb-up" for up, "hb hb-down" for down, "hb hb-empty" for placeholders. For object entries set title to `${fmtTime(ts)}: up` / `down` (+ ` (${rtt_ms} ms)` when rtt_ms is a number); for numbers no title.

export function uptimeText(percent)
  - null/undefined -> "–" (en dash); otherwise the number rounded to at most 2 decimals followed by "%", e.g. 100 -> "100%", 99.5 -> "99.5%", 87.456 -> "87.46%".

export function uptimeClass(percent)
  - returns "up-na" for null/undefined, "up-good" for >= 99, "up-ok" for >= 95, otherwise "up-bad".

export function humanDuration(seconds)
  - null/undefined -> "–". Otherwise a compact string using the two largest non-zero units among d, h, m, s: 45 -> "45s", 125 -> "2m 5s", 7500 -> "2h 5m", 90000 -> "1d 1h"; 0 -> "0s".

export function sparkline(values, width = 240, height = 36)
  - `values` is an array of numbers (response times, null entries are gaps and are skipped). Returns an SVG element (use document.createElementNS("http://www.w3.org/2000/svg", ...), class "sparkline", viewBox `0 0 ${width} ${height}`, preserveAspectRatio "none") containing one <polyline> (class "sparkline-line", fill "none", stroke "currentColor", stroke-width "1.5") scaled to fit with 2px padding; x spreads over the width by index; y maps min..max (when all values are equal draw a flat line in the middle). Fewer than 2 numeric values -> return an empty <span class="hint"> element with text "Not enough data yet".
  Import only { fmtTime } from "./util.js".
