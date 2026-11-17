// The columns of the smart-home devices, and the views that come with Netlens. The server keeps the same list of keys (app/tableviews.py; a test keeps them the same).
import { h, timeAgo, webUrl } from "../util.js";

const lower = (v) => (v == null || v === "" ? null : String(v).toLowerCase());
function battery(d) {
  if (d.battery === null || d.battery === undefined) return d.battery_low ? h("span", { class: "warn-text" }, "low") : h("span", { class: "hint" }, "");
  return h("span", { class: d.battery_low ? "warn-text" : "" }, `${d.battery}%`);
}

export const CATALOG = [
  { key: "name", label: "Device", group: "Basics", sort: (d) => lower(d.name), min: 160, text: (d) => d.name || "", cell: (d) => (webUrl(d.url) ? h("a", { href: webUrl(d.url), target: "_blank", rel: "noopener" }, d.name) : d.name) },
  { key: "model", label: "Model", group: "Basics", sort: (d) => lower([d.manufacturer, d.model].filter(Boolean).join(" ")), min: 140, text: (d) => [d.manufacturer, d.model].filter(Boolean).join(" "), cell: (d) => [d.manufacturer, d.model].filter(Boolean).join(" ") },
  { key: "manufacturer", label: "Manufacturer", group: "Basics", sort: (d) => lower(d.manufacturer), min: 120, text: (d) => d.manufacturer || "", cell: (d) => d.manufacturer || "" },
  { key: "area", label: "Area", group: "Basics", sort: (d) => lower(d.area), min: 100, text: (d) => d.area || "", cell: (d) => d.area || "" },
  { key: "protocol", label: "Protocol", group: "Network", sort: (d) => lower(d.protocol), min: 90, text: (d) => d.protocol || "", cell: (d) => d.protocol || "" },
  {
    key: "state", label: "State", group: "Health", sort: (d) => (d.available ? 1 : 0), min: 150, text: (d) => (d.available ? "available" : "unavailable") + (d.update ? ", update waiting" : ""),
    cell: (d) => h("span", { title: d.unavailable_since || "" }, d.available ? h("span", { class: "run-ok" }, "available") : h("span", { class: "error" }, `unavailable${d.unavailable_since ? ` · ${timeAgo(d.unavailable_since)}` : ""}`), d.update ? h("span", { class: "warn-text" }, " · update") : ""),
  },
  { key: "battery", label: "Battery", group: "Health", numeric: true, sort: (d) => (d.battery == null ? null : d.battery), min: 80, text: (d) => (d.battery == null ? (d.battery_low ? "low" : "") : `${d.battery}%`), cell: battery },
  { key: "via", label: "Paired through", group: "Network", sort: (d) => lower(d.via), min: 120, text: (d) => d.via || "", cell: (d) => d.via || "" },
  { key: "network", label: "On the network", group: "Network", sort: (d) => lower(d.device), min: 130, text: (d) => d.device || "", cell: (d) => (d.device_id ? h("a", { href: `#/device/${d.device_id}` }, d.device || "device") : "") },
];

export const BUILTIN_VIEWS = [
  { id: "standard", name: "Standard", columns: ["name", "model", "area", "protocol", "state", "battery", "via", "network"] },
  { id: "health", name: "Health", columns: ["name", "area", "state", "battery", "network"], sort: { key: "state", dir: "asc" } },
  { id: "inventory", name: "Inventory", columns: ["name", "manufacturer", "model", "area", "protocol", "via"] },
];
