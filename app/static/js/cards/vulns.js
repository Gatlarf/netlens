// Vulnerability findings, shared by the Vulnerabilities page and the device page.
import { get } from "../api.js";
import { h } from "../util.js";

export const SEV_LABEL = { critical: "Critical", high: "High", medium: "Medium", low: "Low", info: "Info" };

export const sevBadge = (sev) => h("span", { class: `vuln-sev vuln-${sev}` }, SEV_LABEL[sev] || sev);

const cveLink = (id) => h("a", { href: `https://nvd.nist.gov/vuln/detail/${id}`, target: "_blank", rel: "noopener noreferrer" }, id);

// One row per finding. The solution and the details sit behind the title, so a long list stays readable.
export function findingsTable(findings, { showDevice = true } = {}) {
  const head = ["Severity", "Finding", showDevice ? "Device" : null, "Port"].filter(Boolean);
  return h("table", { class: "data vuln-table" }, h("thead", {}, h("tr", {}, head.map((t) => h("th", {}, t)))),
    h("tbody", {}, findings.map((f) => h("tr", {},
      h("td", {}, sevBadge(f.severity), f.exploited ? h("span", { class: "vuln-exploited", title: "Known to be exploited in the wild" }, "exploited") : null),
      h("td", {}, h("details", { class: "vuln-detail" }, h("summary", {}, f.title, f.score !== null && f.score !== undefined ? h("span", { class: "hint" }, ` · ${f.score}`) : null),
        h("div", { class: "vuln-body" },
          f.cve.length ? h("p", {}, "CVE: ", f.cve.flatMap((c, i) => (i ? [", ", cveLink(c)] : [cveLink(c)]))) : null,
          f.solution ? h("p", {}, h("strong", {}, "What to do: "), f.solution) : h("p", { class: "hint" }, "The scanner gave no advice for this one."),
          f.url ? h("p", {}, h("a", { href: f.url, target: "_blank", rel: "noopener noreferrer" }, "More from the scanner")) : null,
          f.last_seen ? h("p", { class: "hint" }, `Last seen ${f.last_seen.replace("T", " ").replace("Z", " UTC")}`) : null))),
      showDevice ? h("td", {}, f.device_id ? h("a", { href: `#/device/${f.device_id}` }, f.device) : f.device || "") : null,
      h("td", { class: "mono" }, f.port ? `${f.port}/${f.proto}` : "")))));
}

// The card on a device page: only when the licence allows it and the scanner found something on this device.
export async function buildDeviceVulnCard(device) {
  const r = await get(`/api/vulns?device_id=${device.id}`);
  if (!r.allowed || !r.findings.length) return null;
  const worst = r.findings[0].severity;
  const counts = {};
  for (const f of r.findings) counts[f.severity] = (counts[f.severity] || 0) + 1;
  return h("div", { class: "card" }, h("h2", {}, "Vulnerabilities"),
    h("p", {}, ["critical", "high", "medium", "low", "info"].filter((s) => counts[s]).map((s) => h("span", { class: "vuln-count" }, sevBadge(s), ` ${counts[s]}`)),
      worst === "critical" || worst === "high" ? h("span", { class: "hint" }, "  Fix the serious ones first.") : null),
    findingsTable(r.findings, { showDevice: false }), h("p", { class: "hint" }, h("a", { href: "#/vulnerabilities" }, "All vulnerabilities")));
}
