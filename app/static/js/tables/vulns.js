// The columns of the vulnerability findings, and the views that come with Netlens. The server keeps the same list of keys (app/tableviews.py; a test keeps them the same).
import { h, timeAgo } from "../util.js";
import { sevBadge, findingDetail, cveLink, SEV_LABEL } from "../cards/vulns.js";

const RANK = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const lower = (v) => (v == null || v === "" ? null : String(v).toLowerCase());

export const CATALOG = [
  {
    key: "severity", label: "Severity", group: "Basics", sort: (f) => RANK[f.severity] ?? 5, min: 100, text: (f) => SEV_LABEL[f.severity] || f.severity,
    cell: (f) => h("span", {}, sevBadge(f.severity), f.exploited ? h("span", { class: "vuln-exploited", title: "Known to be exploited in the wild" }, "exploited") : null),
  },
  { key: "title", label: "Finding", group: "Basics", sort: (f) => lower(f.title), min: 260, text: (f) => f.title || "", cell: (f) => findingDetail(f) },
  { key: "device", label: "Device", group: "Basics", sort: (f) => lower(f.device), min: 130, text: (f) => f.device || "", cell: (f) => (f.device_id ? h("a", { href: `#/device/${f.device_id}` }, f.device) : f.device || "") },
  { key: "port", label: "Port", group: "Network", sort: (f) => (f.port ? Number(f.port) : null), min: 80, text: (f) => (f.port ? `${f.port}/${f.proto}` : ""), cell: (f) => h("span", { class: "mono" }, f.port ? `${f.port}/${f.proto}` : "") },
  { key: "score", label: "Score", title: "Score (CVSS)", group: "Basics", numeric: true, sort: (f) => (f.score == null ? null : Number(f.score)), min: 70, text: (f) => (f.score == null ? "" : String(f.score)), cell: (f) => (f.score == null ? "" : String(f.score)) },
  { key: "cve", label: "CVE", group: "Basics", sort: (f) => (f.cve && f.cve.length ? f.cve[0] : null), min: 130, text: (f) => (f.cve || []).join(" "), cell: (f) => h("span", {}, ...(f.cve || []).slice(0, 3).flatMap((c, i) => (i ? [", ", cveLink(c)] : [cveLink(c)])), (f.cve || []).length > 3 ? ` +${f.cve.length - 3}` : "") },
  { key: "exploited", label: "Exploited", title: "Known to be exploited", group: "Basics", sort: (f) => (f.exploited ? 0 : 1), min: 90, text: (f) => (f.exploited ? "yes" : ""), cell: (f) => (f.exploited ? h("span", { class: "vuln-exploited" }, "exploited") : "") },
  { key: "last_seen", label: "Last seen", group: "Basics", sort: (f) => f.last_seen, min: 110, text: (f) => f.last_seen || "", cell: (f) => (f.last_seen ? timeAgo(f.last_seen) : "") },
];

export const BUILTIN_VIEWS = [
  { id: "standard", name: "Standard", columns: ["severity", "title", "device", "port"], sort: { key: "severity", dir: "asc" } },
  { id: "worklist", name: "Work list", columns: ["severity", "title", "device", "score", "exploited", "last_seen"], sort: { key: "exploited", dir: "asc" } },
  { id: "cve", name: "By CVE", columns: ["severity", "title", "cve", "device", "port", "score"], sort: { key: "score", dir: "desc" } },
];
