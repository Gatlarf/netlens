
TASK: write app/static/js/pages/uptime.js (full file, under 150 lines). It is a page module like the existing pages: `export async function render(container, params)`; it must RETURN a cleanup function (the router calls it when the user leaves the page).

Imports: import { get } from "../api.js"; import { h, clear, toast, statusDot } from "../util.js"; import { heartbeatBar, uptimeText, uptimeClass } from "../heartbeat.js";
(heartbeatBar(items, total) returns a div.hb-bar for an oldest-first array of 0/1 numbers; uptimeText(percent) -> "99.5%" or "–"; uptimeClass(percent) -> CSS class string.)

API: GET /api/uptime?bars=60 -> array of {id: int, name: str, ip: str|null, online: bool, up_24h: number|null, up_7d: number|null, bars: [0|1,...] (oldest first, may be empty), last_ts: iso|null}, already sorted by name.

Page: <h1>Uptime</h1> plus a <p class="hint"> "Every scan records whether each device answered. Green = up, red = down. The bars show the most recent scans, newest on the right." Then a card with a table (class "data", columns: status (statusDot(online)), Device (link h("a", {href: `#/device/${id}`}, name) and below it a small mono ip), Last 60 scans (heartbeatBar(bars, 60)), 24 h (uptimeText(up_24h) in a span with class uptimeClass(up_24h)), 7 days (same)). When the list is empty show a row/paragraph "No devices yet. Run a scan first."
Add a small filter input above the table (placeholder "Filter by name or IP") that hides non-matching rows client-side (case-insensitive) without refetching; keep its text across refreshes.
Lifecycle: load once, then refresh every 30000 ms. Build the new table body OFF-SCREEN and replace the old one in a single step (never clear and fill in place, and never run two loads at once: keep an `inFlight` boolean). Use a `disposed` flag set by the returned cleanup function (which also calls clearInterval) so no DOM work happens after leaving the page. Report a failed load with toast("Failed to load uptime", "error") only ONCE until a load succeeds again.
