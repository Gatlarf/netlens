// The columns of the Services table (checks and plugins), and the views that come with Netlens. The server keeps the same list of keys (app/tableviews.py; a test keeps them the same).
import { h, timeAgo, shortName } from "../util.js";
import { uptimeText, uptimeClass } from "../heartbeat.js";

const KIND = { http: "Web page", https: "Web page", tcp: "Port", dns: "DNS", tls: "Certificate", process: "Process", ping: "Ping" };
const lower = (v) => (v == null || v === "" ? null : String(v).toLowerCase());
const ms = (v) => (v === null || v === undefined ? "–" : v >= 1000 ? `${(v / 1000).toFixed(1)} s` : `${Math.round(v)} ms`);

export const dot = (c) => {
  const cls = !c.enabled ? "paused" : c.state === "up" ? "up" : c.state === "down" ? "down" : "unknown";
  return h("span", { class: `svc-dot svc-${cls}`, title: !c.enabled ? "Paused" : c.state === "up" ? "Up" : c.state === "down" ? "Down" : "Waiting" }, "");
};

export const CATALOG = [
  { key: "status", label: "", title: "Status", group: "Basics", sort: (c) => (!c.enabled ? 0 : c.state === "down" ? 1 : c.state === "up" ? 3 : 2), cell: dot, text: (c) => (!c.enabled ? "paused" : c.state || "waiting"), min: 40 },
  {
    key: "name", label: "Name", group: "Basics", sort: (c) => lower(c.name), min: 160, text: (c) => c.name || "",
    cell: (c) => h("span", { title: c.target || null }, c.name, c.state === "down" && c.last_detail ? h("div", { class: "hint" }, c.last_detail) : null),
  },
  {
    key: "device", label: "Device", group: "Basics", sort: (c) => lower(c.device_name), min: 120, text: (c) => c.device_name || "",
    cell: (c) => (c.device_id ? h("a", { href: `#/device/${c.device_id}`, title: c.device_name || null, onclick: (e) => e.stopPropagation() }, shortName(c.device_name) || `device ${c.device_id}`) : ""),
  },
  { key: "kind", label: "Kind", group: "Basics", sort: (c) => lower(c.kind), min: 90, text: (c) => (c.plugin ? "Plugin" : KIND[c.kind] || c.kind || ""), cell: (c) => (c.plugin ? `Plugin (${c.kind || ""})` : KIND[c.kind] || c.kind || "") },
  { key: "target", label: "Target", group: "Basics", sort: (c) => lower(c.target), min: 160, text: (c) => c.target || "", cell: (c) => (c.target ? h("span", { class: "mono" }, c.target) : "") },
  { key: "history", label: "History", group: "Health", min: 150, text: () => "", cell: (c) => c.bars || "" },
  { key: "uptime_24h", label: "24 h", title: "Availability, 24 hours", group: "Health", numeric: true, sort: (c) => c.uptime_24h, min: 70, text: (c) => (c.uptime_24h == null ? "" : `${c.uptime_24h}%`), cell: (c) => h("span", { class: uptimeClass(c.uptime_24h) }, uptimeText(c.uptime_24h)) },
  { key: "last_ms", label: "Resp.", title: "Last answer time", group: "Health", numeric: true, sort: (c) => c.last_ms, min: 80, text: (c) => (c.last_ms == null ? "" : String(Math.round(c.last_ms))), cell: (c) => ms(c.last_ms) },
  { key: "last_ts", label: "Checked", title: "Last checked", group: "Health", sort: (c) => c.last_ts, min: 100, text: (c) => c.last_ts || "", cell: (c) => (c.last_ts ? timeAgo(c.last_ts) : "never") },
  { key: "interval_s", label: "Every", title: "Interval", group: "Basics", numeric: true, sort: (c) => c.interval_s, min: 70, text: (c) => (c.interval_s == null ? "" : String(c.interval_s)), cell: (c) => (c.interval_s ? (c.interval_s % 60 === 0 ? `${c.interval_s / 60} min` : `${c.interval_s} s`) : "") },
  { key: "tier", label: "Importance", group: "Basics", sort: (c) => ({ critical: 0, normal: 1, low: 2 }[c.tier] ?? 1), min: 100, text: (c) => c.tier || "", cell: (c) => ({ critical: "Critical", normal: "Normal", low: "Low" }[c.tier] || "") },
  { key: "since", label: "Since", title: "In this state since", group: "Health", sort: (c) => c.since, min: 100, text: (c) => c.since || "", cell: (c) => (c.since ? timeAgo(c.since) : "") },
];

export const BUILTIN_VIEWS = [
  { id: "standard", name: "Standard", columns: ["status", "name", "device", "history", "uptime_24h", "last_ms", "last_ts"] },
  { id: "compact", name: "Compact", columns: ["status", "name", "uptime_24h", "last_ms"] },
  { id: "details", name: "Details", columns: ["status", "name", "device", "kind", "target", "interval_s", "tier", "uptime_24h", "last_ms", "last_ts"] },
];
