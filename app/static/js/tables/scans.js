// The columns of the scan history, and the views that come with Netlens. The server keeps the same list of keys (app/tableviews.py; a test keeps them the same).
import { h, fmtTime } from "../util.js";

export function statusClass(status) {
  if (status === "done") return "ok";
  if (status === "failed") return "bad";
  if (status === "running" || status === "cancelled") return "warn";
  return "";
}

export function duration(started, finished) {
  if (!started || !finished) return "—";
  const start = new Date(started);
  const end = new Date(finished);
  if (Number.isNaN(start.getTime()) || Number.isNaN(end.getTime())) return "—";
  const ms = end.getTime() - start.getTime();
  if (ms < 0) return "—";
  const totalSec = Math.floor(ms / 1000);
  const minutes = Math.floor(totalSec / 60);
  const seconds = totalSec % 60;
  if (minutes > 0) {
    return `${minutes}m ${String(seconds).padStart(2, "0")}s`;
  }
  return `${seconds}s`;
}


const ms = (scan) => (scan.started && scan.finished ? new Date(scan.finished) - new Date(scan.started) : null);

export const CATALOG = [
  { key: "started", label: "Started", group: "Basics", sort: (s) => s.started, min: 150, text: (s) => s.started || "", cell: (s) => fmtTime(s.started) },
  { key: "kind", label: "Kind", group: "Basics", sort: (s) => (s.kind || "").toLowerCase(), min: 120, text: (s) => (s.target ? `${s.kind} ${s.target}` : s.kind || ""), cell: (s) => (s.target ? `${s.kind} ${s.target}` : s.kind) },
  { key: "status", label: "Status", group: "Basics", sort: (s) => s.status, min: 90, text: (s) => s.status || "", cell: (s) => h("span", { class: statusClass(s.status) }, s.status) },
  { key: "hosts_found", label: "Hosts found", group: "Basics", numeric: true, sort: (s) => s.hosts_found ?? 0, min: 100, text: (s) => String(s.hosts_found ?? 0), cell: (s) => String(s.hosts_found ?? 0) },
  { key: "duration", label: "Duration", group: "Basics", numeric: true, sort: (s) => ms(s), min: 90, text: (s) => duration(s.started, s.finished), cell: (s) => duration(s.started, s.finished) },
  { key: "finished", label: "Finished", group: "Basics", sort: (s) => s.finished, min: 150, text: (s) => s.finished || "", cell: (s) => (s.finished ? fmtTime(s.finished) : "") },
  { key: "error", label: "Error", group: "Basics", sort: (s) => (s.error || "").toLowerCase() || null, min: 200, text: (s) => s.error || "", cell: (s) => h("span", { class: "muted col-text", title: s.error || null }, s.error || "") },
];

export const BUILTIN_VIEWS = [
  { id: "standard", name: "Standard", columns: ["started", "kind", "status", "hosts_found", "duration", "error"], sort: { key: "started", dir: "desc" } },
  { id: "compact", name: "Compact", columns: ["started", "status", "hosts_found"], sort: { key: "started", dir: "desc" } },
];
