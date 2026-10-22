// Vulnerabilities: what the vulnerability scanners (Greenbone, Tenable, Rapid7 ...) found on your devices, worst first.
import { get } from "../api.js";
import { h, clear, timeAgo } from "../util.js";
import { pageHead, tile, tileRow, emptyState } from "../ui.js";
import { findingsTable, sevBadge, SEV_LABEL } from "../cards/vulns.js";
import { buildCveCheckCard } from "../cards/cve_check.js";

const SHOW = 25;

export async function render(container) {
  clear(container);
  container.append(pageHead("Vulnerabilities", "What your vulnerability scanner found on the devices of this network, the most serious first."));
  const body = h("div", {}, h("p", { class: "hint" }, "Loading…"));
  container.append(body);
  let sev = "", q = "", all = false;
  let data;
  const cveCard = buildCveCheckCard(() => load());

  const draw = () => {
    clear(body);
    if (!data.allowed) {
      body.append(emptyState("Vulnerabilities need a licence or the free trial", "Netlens shows the findings of Greenbone, Tenable Nessus or Rapid7 InsightVM next to your devices, warns about new critical ones and puts them in the reports.",
        h("a", { class: "btn primary", href: "#/settings/licence" }, "Open the licence page")));
      return;
    }
    const s = data.summary;
    body.append(cveCard);
    if (!s.configured) {
      body.append(emptyState("No vulnerability scanner is connected yet", "Switch on the version check above for a first look, or install a scanner plugin (Greenbone/OpenVAS, Tenable or Rapid7) from the Plugin store and turn it on. Netlens then lists what it finds next to each device and warns about new critical vulnerabilities.",
        h("a", { class: "btn primary", href: "#/settings/plugin-browse" }, "Open the Plugin store")));
      return;
    }
    const c = s.counts;
    body.append(tileRow(tile("Critical", String(c.critical), s.exploited ? `${s.exploited} known to be exploited` : "fix these first", c.critical ? "bad" : "ok"),
      tile("High", String(c.high), "", c.high ? "warn" : "ok"), tile("Medium", String(c.medium), c.low + c.info ? `and ${c.low + c.info} low or info` : "", ""),
      tile("Devices at risk", String(s.devices), "with a critical or high finding", s.devices ? "warn" : "ok")));
    const lines = data.servers.map((x) => h("span", { class: "hint" }, `${x.name}${x.version ? ` ${x.version}` : ""}: ${x.online ? (x.last_scan ? `last scan ${timeAgo(x.last_scan)}` : "connected") : "not reachable"}`));
    if (lines.length) body.append(h("p", { class: "vuln-servers" }, ...lines.flatMap((l, i) => (i ? [" · ", l] : [l]))));
    if (data.top.length) {
      body.append(h("div", { class: "card" }, h("h2", {}, "Devices with the most findings"),
        h("table", { class: "data" }, h("thead", {}, h("tr", {}, ["Device", "Critical", "High", "Medium", "Low"].map((t) => h("th", {}, t)))),
          h("tbody", {}, data.top.map((d) => h("tr", {}, h("td", {}, d.device_id ? h("a", { href: `#/device/${d.device_id}` }, d.device) : d.device),
            h("td", {}, d.critical ? sevBadge("critical") : "", d.critical ? ` ${d.critical}` : ""), h("td", {}, String(d.high || "")), h("td", {}, String(d.medium || "")), h("td", {}, String(d.low || ""))))))));
    }
    const list = data.findings;
    const bar = h("div", { class: "toolbar" },
      h("select", { onchange: (e) => { sev = e.target.value; load(); } }, h("option", { value: "" }, "All severities"), Object.entries(SEV_LABEL).map(([k, v]) => h("option", { value: k, selected: k === sev }, v))),
      h("input", { type: "search", placeholder: "Search title, device or CVE", value: q, oninput: (e) => { q = e.target.value; clearTimeout(render.t); render.t = setTimeout(load, 250); } }));
    const shown = all ? list : list.slice(0, SHOW);
    body.append(h("div", { class: "card" }, h("h2", {}, `Findings (${list.length})`), bar,
      list.length ? findingsTable(shown) : h("p", { class: "hint" }, "Nothing matches."),
      list.length > SHOW ? h("button", { class: "btn", type: "button", onclick: () => { all = !all; draw(); } }, all ? "Show fewer" : `Show all ${list.length}`) : null));
  };

  async function load() {
    const params = new URLSearchParams();
    if (sev) params.set("severity", sev);
    if (q.trim()) params.set("q", q.trim());
    try {
      data = await get(`/api/vulns?${params.toString()}`);
      const keep = document.activeElement && document.activeElement.type === "search";
      draw();
      if (keep) { const input = body.querySelector("input[type=search]"); if (input) { input.focus(); input.setSelectionRange(q.length, q.length); } }
    } catch (err) {
      body.replaceChildren(h("p", { class: "error" }, err.message || "Could not load the vulnerabilities"));
    }
  }
  await load();
}
