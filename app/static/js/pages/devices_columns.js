// The columns of the Devices table, and the views that come with Netlens. The server keeps the same list of keys (app/tableviews.py; a test keeps them the same).
import { h, fmtTime, timeAgo, typeBadge, statusDot, shortName, vendorText, vendorTitle } from "../util.js";

const ipToNum = (ip) => {
  const parts = String(ip || "").split(".");
  if (parts.length !== 4) return null;
  let n = 0;
  for (const p of parts) { const v = parseInt(p, 10); if (Number.isNaN(v)) return null; n = n * 256 + v; }
  return n;
};
const lower = (v) => (v == null || v === "" ? null : String(v).toLowerCase());
const stop = (e) => e.stopPropagation();
const TIER = { critical: "Critical", normal: "Normal", low: "Low" };
const quality = (rssi) => (rssi >= -60 ? "d-ok" : rssi >= -72 ? "d-warn" : "d-bad");
const link = (id, text) => (id == null ? text : h("a", { href: `#/device/${id}`, onclick: stop }, text));

export const CATALOG = [
  { key: "status", label: "", title: "Status", group: "Basics", sort: (d) => (d.online ? 1 : 0), cell: (d) => statusDot(d.online), text: (d) => (d.online ? "online" : "offline"), min: 40 },
  {
    key: "name", label: "Name", group: "Basics", sort: (d) => lower(d.name), min: 160, text: (d) => d.name || "",
    cell: (d, ctx) => {
      const box = h("span", {}, h("span", { class: "device-name", title: d.name || null }, shortName(d.name) || "—"));
      if (!d.trusted) box.appendChild(h("span", { class: "tag unknown-tag", title: "Not marked as a known device yet" }, "unknown"));
      if (!ctx.has("tags") && Array.isArray(d.tags) && d.tags.length) box.appendChild(h("div", { class: "tags" }, ...d.tags.map((t) => h("span", { class: "tag" }, t))));
      return box;
    },
  },
  {
    key: "primary_ip", label: "IP", group: "Basics", sort: (d) => ipToNum(d.primary_ip), min: 110, text: (d) => d.primary_ip || "",
    cell: (d) => {
      const box = h("span", {}, d.primary_ip || "—");
      if (Array.isArray(d.ipv6) && d.ipv6.length) box.appendChild(h("div", { class: "ipv6-list mono hint", title: d.ipv6.join("\n") }, d.ipv6[0] + (d.ipv6.length > 1 ? " …" : "")));
      return box;
    },
  },
  { key: "type", label: "Type", group: "Basics", sort: (d) => lower(d.type), cell: (d) => typeBadge(d.type), text: (d) => d.type || "", min: 90 },
  {
    key: "group", label: "Group", group: "Basics", sort: (d) => lower(d.group), min: 110, text: (d) => d.group || "",
    cell: (d) => {
      if (!d.group) return "";
      const dot = h("span", { class: "legend-dot" });
      dot.style.background = d.group_color;
      return [dot, d.group];
    },
  },
  { key: "mac", label: "MAC", group: "Network", sort: (d) => lower(d.mac), min: 130, text: (d) => d.mac || "", cell: (d) => h("span", { class: "mono", title: d.mac_kind === "randomized" ? "A private (randomized) address" : null }, d.mac || "—") },
  { key: "vendor", label: "Vendor", group: "Network", sort: (d) => lower(vendorText(d)), min: 120, text: (d) => vendorText(d) || "", cell: (d) => h("span", { title: vendorTitle(d) }, vendorText(d)) },
  { key: "network", label: "Network", group: "Network", sort: (d) => lower(d.network && d.network.label), min: 110, text: (d) => (d.network ? d.network.label : ""), cell: (d) => (d.network ? d.network.label : "") },
  { key: "ipv6", label: "IPv6", group: "Network", sort: (d) => lower((d.ipv6 || [])[0]), min: 150, text: (d) => (d.ipv6 || []).join(" "), cell: (d) => h("span", { class: "mono", title: (d.ipv6 || []).join("\n") }, (d.ipv6 || [])[0] || "") },
  { key: "tags", label: "Tags", group: "Basics", sort: (d) => lower((d.tags || []).join(" ")), min: 110, text: (d) => (d.tags || []).join(" "), cell: (d) => h("div", { class: "tags" }, ...(d.tags || []).map((t) => h("span", { class: "tag" }, t))) },
  { key: "os_name", label: "OS", group: "System", sort: (d) => lower(d.os_name), min: 110, text: (d) => d.os_name || "", cell: (d) => d.os_name || "—" },
  {
    key: "open_ports", label: "Open ports", group: "System", sort: (d) => Number(d.open_ports) || 0, numeric: true, min: 90, text: (d) => String(d.open_ports ?? 0),
    cell: (d) => {
      const box = h("span", {}, String(d.open_ports ?? 0));
      if (d.ports_drift > 0) box.appendChild(h("span", { class: "tag unknown-tag", title: "Open ports differ from the baseline" }, `${d.ports_drift} changed`));
      return box;
    },
  },
  { key: "tier", label: "Importance", group: "System", sort: (d) => ({ critical: 3, normal: 2, low: 1 })[d.tier] || 2, min: 100, text: (d) => TIER[d.tier] || "Normal", cell: (d) => TIER[d.tier] || "Normal" },
  { key: "always_on", label: "Always on", group: "System", sort: (d) => (d.always_on ? 1 : 0), min: 90, text: (d) => (d.always_on ? "yes" : "no"), cell: (d) => (d.always_on ? "Yes" : "—") },
  { key: "first_seen", label: "First seen", group: "System", sort: (d) => d.first_seen || null, min: 110, text: (d) => d.first_seen || "", cell: (d) => h("span", { title: fmtTime(d.first_seen) }, timeAgo(d.first_seen)) },
  { key: "last_seen", label: "Last seen", group: "System", sort: (d) => d.last_seen || null, min: 110, text: (d) => d.last_seen || "", cell: (d) => h("span", { title: fmtTime(d.last_seen) }, timeAgo(d.last_seen)) },
  { key: "trusted", label: "Known", group: "System", sort: (d) => (d.trusted ? 1 : 0), min: 80, text: (d) => (d.trusted ? "known" : "unknown"), cell: (d) => (d.trusted ? "Known" : "Unknown") },
  { key: "dns_name", label: "DNS name", group: "Network", sort: (d) => lower(d.dns_name), min: 140, text: (d) => d.dns_name || "", cell: (d) => d.dns_name || "" },
  {
    key: "parent", label: "Connected to", group: "Network", extra: "link", sort: (d) => lower(d.link && d.link.parent), min: 140, text: (d) => (d.link && d.link.parent) || "",
    cell: (d) => (d.link && d.link.parent ? link(d.link.parent_id, shortName(d.link.parent)) : ""),
  },
  { key: "port", label: "Port", group: "Network", extra: "link", sort: (d) => lower(d.link && d.link.port), min: 80, text: (d) => (d.link && d.link.port) || "", cell: (d) => (d.link && d.link.port) || "" },
  { key: "medium", label: "Connection", group: "Network", extra: "link", sort: (d) => lower(d.link && d.link.medium), min: 90, text: (d) => (d.link && d.link.medium) || "", cell: (d) => ({ wired: "Cable", wifi: "Wi-Fi" })[d.link && d.link.medium] || "" },
  { key: "wifi_band", label: "Wi-Fi band", group: "Wi-Fi", extra: "wifi", sort: (d) => lower(d.wifi && d.wifi.band), min: 90, text: (d) => (d.wifi && d.wifi.band) || "", cell: (d) => (d.wifi && d.wifi.band) || "" },
  {
    key: "wifi_signal", label: "Wi-Fi signal", group: "Wi-Fi", extra: "wifi", sort: (d) => (d.wifi && d.wifi.rssi != null ? d.wifi.rssi : null), numeric: true, min: 100,
    text: (d) => (d.wifi && d.wifi.rssi != null ? `${d.wifi.rssi} dBm` : ""), cell: (d) => (d.wifi && d.wifi.rssi != null ? h("span", { class: quality(d.wifi.rssi) }, `${d.wifi.rssi} dBm`) : ""),
  },
  { key: "wifi_node", label: "Access point", group: "Wi-Fi", extra: "wifi", sort: (d) => lower(d.wifi && d.wifi.node), min: 130, text: (d) => (d.wifi && d.wifi.node) || "", cell: (d) => (d.wifi && d.wifi.node) || "" },
  {
    key: "uptime_7d", label: "Up, 7 days", group: "Health", extra: "uptime", sort: (d) => (d.uptime_7d == null ? null : d.uptime_7d), numeric: true, min: 90, text: (d) => (d.uptime_7d == null ? "" : `${d.uptime_7d}%`),
    cell: (d) => (d.uptime_7d == null ? "" : h("span", { class: d.uptime_7d >= 99 ? "d-ok" : d.uptime_7d >= 95 ? "d-warn" : "d-bad" }, `${d.uptime_7d}%`)),
  },
  { key: "rtt_24h", label: "Answer time", group: "Health", extra: "uptime", sort: (d) => (d.rtt_24h == null ? null : d.rtt_24h), numeric: true, min: 100, text: (d) => (d.rtt_24h == null ? "" : `${d.rtt_24h} ms`), cell: (d) => (d.rtt_24h == null ? "" : `${d.rtt_24h} ms`) },
  { key: "maintenance", label: "Maintenance", group: "System", sort: (d) => lower(typeof d.maintenance === "string" ? d.maintenance : d.maintenance && d.maintenance.name), min: 110, text: (d) => (typeof d.maintenance === "string" ? d.maintenance : (d.maintenance && d.maintenance.name) || ""), cell: (d) => (typeof d.maintenance === "string" ? d.maintenance : (d.maintenance && d.maintenance.name) || "") },
  { key: "notes", label: "Notes", group: "System", sort: (d) => lower(d.notes), min: 180, text: (d) => d.notes || "", cell: (d) => h("span", { class: "tv-note", title: d.notes || null }, d.notes || "") },
];

export const BUILTIN_VIEWS = [
  { id: "standard", name: "Standard", columns: ["status", "name", "primary_ip", "mac", "vendor", "type", "group", "os_name", "open_ports", "last_seen"], sort: { key: "primary_ip", dir: "asc" } },
  { id: "network", name: "Network", columns: ["status", "name", "primary_ip", "mac", "vendor", "type", "network", "parent", "port", "medium", "last_seen"], sort: { key: "parent", dir: "asc" } },
  { id: "wifi", name: "Wi-Fi", columns: ["status", "name", "primary_ip", "type", "wifi_node", "wifi_band", "wifi_signal", "last_seen"], sort: { key: "wifi_signal", dir: "asc" }, filters: {} },
  { id: "inventory", name: "Inventory", columns: ["status", "name", "type", "vendor", "os_name", "primary_ip", "mac", "group", "tier", "always_on", "tags", "first_seen", "notes"], sort: { key: "name", dir: "asc" } },
  { id: "health", name: "Health", columns: ["status", "name", "type", "uptime_7d", "rtt_24h", "open_ports", "tier", "always_on", "last_seen"], sort: { key: "uptime_7d", dir: "asc" } },
];
