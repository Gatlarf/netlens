import { get } from "../api.js";
import { h } from "../util.js";
import { formatValue } from "../timegraph.js";

// The headline readings of a device in one row under the tabs, so its health is visible on every section.
// Each value takes the colour of its level (the limits are the ones set under Monitoring -> Health).
const CHIPS = [
  { metric: "cpu_pct", title: "Processor", unit: "%", pick: "max" },
  { metric: "mem_pct", title: "Memory", unit: "%", pick: "max" },
  { metric: "disk_pct", title: "Disk", unit: "%", pick: "max" },
  { metric: "temp_c", title: "Temperature", unit: "°C", pick: "max" },
  { metric: "supply_pct", title: "Supply", unit: "%", pick: "min", lowIsBad: true },
  { metric: "battery_pct", title: "UPS battery", unit: "%", pick: "min", lowIsBad: true },
  { metric: "net_rx_bps", title: "In", unit: "bps", pick: "sum" },
  { metric: "net_tx_bps", title: "Out", unit: "bps", pick: "sum" },
  { metric: "storage_status", title: "Storage", unit: "storage", pick: "max", always: true },
];
const STORAGE_TEXT = ["healthy", "degraded", "failed"];
const FRESH = 3600;      // a reading older than this is not shown as "now"

function level(value, rule, lowIsBad) {
  if (!rule || !rule.enabled || value == null) return "ok";
  if (lowIsBad) return rule.crit != null && value <= rule.crit ? "crit" : rule.warn != null && value <= rule.warn ? "warn" : "ok";
  return rule.crit != null && value >= rule.crit ? "crit" : rule.warn != null && value >= rule.warn ? "warn" : "ok";
}

export async function buildHealthGlance(device, onOpen) {
  let data;
  try {
    data = await get(`/api/timeseries/device/${device.id}`);
  } catch (err) {
    return null;
  }
  let rules = {};
  try {
    rules = (await get(`/api/devices/${device.id}/limits`)).rules || {};
  } catch (err) {
    rules = {};
  }
  const now = Date.now() / 1000;
  const chips = [];
  for (const c of CHIPS) {
    const rows = data.series.filter((s) => s.metric === c.metric && s.last != null && s.last_ts != null && now - s.last_ts <= FRESH);
    if (!rows.length) continue;
    const values = rows.map((s) => s.last);
    const value = c.pick === "sum" ? values.reduce((a, b) => a + b, 0) : c.pick === "min" ? Math.min(...values) : Math.max(...values);
    const label = (rows.length > 1 || c.unit === "storage") && c.pick !== "sum" ? (rows.find((s) => s.last === value) || {}).label : "";
    const lvl = c.unit === "storage" ? (value >= 2 ? "crit" : value >= 1 ? "warn" : "ok") : level(value, rules[c.metric], c.lowIsBad);
    const shown = c.unit === "storage" ? `${STORAGE_TEXT[Math.min(2, Math.round(value))]}${value >= 1 && label ? ` (${label})` : ""}` : formatValue(value, c.unit);
    chips.push(h("button", { type: "button", class: `glance-chip glance-${lvl}`, title: `${c.title}${label ? ` (${label})` : ""}: open the health graphs`, onclick: onOpen },
      h("span", { class: "glance-title" }, c.title), h("span", { class: "glance-value" }, shown)));
  }
  if (!chips.length) return null;
  return h("div", { class: "glance-row" }, ...chips);
}
