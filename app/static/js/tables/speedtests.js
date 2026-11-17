// The columns of the speed test results, and the views that come with Netlens. The server keeps the same list of keys (app/tableviews.py; a test keeps them the same).
import { h, timeAgo, fmtTime } from "../util.js";

const mbps = (v) => (v === null || v === undefined ? "–" : v >= 1000 ? `${(v / 1000).toFixed(2)} Gbps` : `${v >= 100 ? Math.round(v) : v.toFixed(1)} Mbps`);
const ms = (v) => (v === null || v === undefined ? "–" : `${v.toFixed(v < 10 ? 1 : 0)} ms`);
export function kindLabel(r) {
  const d = r.detail || {};
  if (r.kind === "internet") return "Internet";
  if (r.kind === "iperf-in") return "iperf3 from a host";
  if (r.kind === "iperf-out") return "iperf3 to a host";
  return d.label ? `Browser: ${d.label}` : "Browser";
}
const lower = (v) => (v == null || v === "" ? null : String(v).toLowerCase());

export const CATALOG = [
  { key: "when", label: "When", group: "Basics", sort: (r) => r.ts, min: 120, text: (r) => r.ts || "", cell: (r) => h("span", { title: fmtTime(r.ts) }, timeAgo(r.ts)) },
  { key: "test", label: "Test", group: "Basics", sort: (r) => lower(kindLabel(r)), min: 130, text: kindLabel, cell: kindLabel },
  { key: "target", label: "Target", group: "Basics", sort: (r) => lower(r.target), min: 130, text: (r) => r.target || "", cell: (r) => r.target || "" },
  { key: "download", label: "Download", group: "Basics", numeric: true, sort: (r) => (r.ok ? r.down_mbps : null), min: 100, text: (r) => (r.ok && r.down_mbps != null ? String(r.down_mbps) : ""), cell: (r) => (r.ok ? mbps(r.down_mbps) : "") },
  { key: "upload", label: "Upload", group: "Basics", numeric: true, sort: (r) => (r.ok ? r.up_mbps : null), min: 100, text: (r) => (r.ok && r.up_mbps != null ? String(r.up_mbps) : ""), cell: (r) => (r.ok ? mbps(r.up_mbps) : "") },
  { key: "ping", label: "Ping", group: "Basics", numeric: true, sort: (r) => (r.ok ? r.latency_ms : null), min: 80, text: (r) => (r.ok && r.latency_ms != null ? String(r.latency_ms) : (r.error || "")), cell: (r) => (r.ok ? ms(r.latency_ms) : h("span", { class: "error" }, r.error || "failed")) },
  { key: "result", label: "Result", group: "Basics", sort: (r) => (r.ok ? 0 : 1), min: 90, text: (r) => (r.ok ? "ok" : r.error || "failed"), cell: (r) => (r.ok ? "ok" : h("span", { class: "error" }, r.error || "failed")) },
];

export const BUILTIN_VIEWS = [
  { id: "standard", name: "Standard", columns: ["when", "test", "target", "download", "upload", "ping"], sort: { key: "when", dir: "desc" } },
  { id: "speeds", name: "Speeds only", columns: ["when", "download", "upload", "ping"], sort: { key: "when", dir: "desc" } },
];
