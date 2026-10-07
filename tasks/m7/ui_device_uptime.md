
TASK: write app/static/js/cards/device_uptime.js (full file, under 90 lines). Export `export async function buildDeviceUptimeCard(deviceId)` returning a `div.card` (shows "Loading..." first, then content; on error a <p class="error"> with the message).

Imports: import { get } from "../api.js"; import { h, fmtTime } from "../util.js"; import { heartbeatBar, uptimeText, uptimeClass, humanDuration, sparkline } from "../heartbeat.js";
(heartbeatBar(items, total): items oldest first, each {ts, up: bool, rtt_ms}; uptimeText(p); uptimeClass(p); humanDuration(seconds); sparkline(valuesArray) returns an SVG/span element.)

API: GET /api/devices/{deviceId}/uptime?limit=90 -> {up_24h: number|null, up_7d: number|null, up_30d: number|null, checks: [{ts: iso, up: bool, rtt_ms: number|null}] (oldest first), avg_rtt_ms: number|null, since: iso|null, status_for_seconds: int|null}.

Card: <h2>Uptime</h2>. If checks is empty show <p class="hint"> "No scans recorded yet." and stop. Otherwise: the heartbeat bar (heartbeatBar(checks, 90)); then kv rows (class "kv", label span "kv-label"): "Last 24 hours" (uptimeText(up_24h), span with class uptimeClass), "Last 7 days", "Last 30 days", "Average response" (`${avg_rtt_ms} ms` or "–"), "Current status" (a span: "Up for X" or "Down for X" using the newest check's `up` and humanDuration(status_for_seconds)), "Monitored since" (fmtTime(since)); then, when at least 2 checks have a numeric rtt_ms, a small caption <p class="hint"> "Response time (ms)" followed by sparkline(checks.map(c => c.rtt_ms)).
