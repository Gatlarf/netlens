// The columns of the audit log, and the views that come with Netlens. The server keeps the same list of keys (app/tableviews.py; a test keeps them the same).
import { fmtTime } from "../util.js";

const lower = (v) => (v == null || v === "" ? null : String(v).toLowerCase());

export const CATALOG = [
  { key: "when", label: "When", group: "Basics", sort: (e) => e.ts, min: 150, text: (e) => e.ts || "", cell: (e) => fmtTime(e.ts) },
  { key: "who", label: "Who", group: "Basics", sort: (e) => lower(e.user), min: 100, text: (e) => e.user || "", cell: (e) => e.user || "—" },
  { key: "what", label: "What", group: "Basics", sort: (e) => lower(e.action), min: 260, text: (e) => e.action || "", cell: (e) => e.action },
  { key: "from", label: "From", group: "Network", sort: (e) => lower(e.ip), min: 110, text: (e) => e.ip || "", cell: (e) => e.ip || "" },
  { key: "result", label: "Result", title: "Result (status code)", group: "Basics", numeric: true, sort: (e) => e.status, min: 80, text: (e) => (e.status == null ? "" : String(e.status)), cell: (e) => (e.status == null ? "" : String(e.status)) },
];

export const BUILTIN_VIEWS = [
  { id: "standard", name: "Standard", columns: ["when", "who", "what", "from"] },
  { id: "failures", name: "With result", columns: ["when", "who", "what", "result", "from"] },
];
