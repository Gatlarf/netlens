import { get } from "../api.js";
import { h } from "../util.js";
import { metricGraph, graphRangeTabs, savedGraphRange } from "../timegraph.js";

// How a measurement is shown: title, unit, fixed scale and limits. Anything not listed gets a plain graph.
const KNOWN = {
  rtt_ms: { title: "Response time", unit: "ms", order: 0 },
  response_ms: { title: "Response time", unit: "ms", order: 0 },
  up: { title: "Availability", unit: "state", order: 1 },
  cpu_pct: { title: "Processor", unit: "%", fixedMax: 100, warn: 85, crit: 95, order: 2 },
  load1: { title: "Load (1 minute)", unit: "", order: 3 },
  mem_pct: { title: "Memory in use", unit: "%", fixedMax: 100, warn: 85, crit: 95, order: 4 },
  swap_pct: { title: "Swap in use", unit: "%", fixedMax: 100, order: 5 },
  disk_pct: { title: "Disk used", unit: "%", fixedMax: 100, warn: 85, crit: 95, order: 6 },
  disk_free_b: { title: "Disk free", unit: "B", order: 6.5 },
  supply_pct: { title: "Supply left", unit: "%", fixedMax: 100, order: 11 },
  battery_pct: { title: "UPS battery", unit: "%", fixedMax: 100, order: 12 },
  battery_minutes: { title: "UPS runtime", unit: "min", order: 12.5 },
  on_battery: { title: "UPS on battery", unit: "state", order: 13 },
  net_rx_bps: { title: "Received", unit: "bps", order: 7 },
  net_tx_bps: { title: "Sent", unit: "bps", order: 8 },
  temp_c: { title: "Temperature", unit: "°C", order: 9 },
  uptime_s: { title: "Time since start", unit: "s", order: 10 },
  cert_days: { title: "Certificate days left", unit: "days", order: 14 },
};

export function describeSeries(s) {
  const known = KNOWN[s.metric] || { title: s.metric.replace(/_/g, " "), unit: s.unit || "", order: 50 };
  return { ...known, title: s.label ? `${known.title} · ${s.label}` : known.title };
}

// The measurements of one entity (device or service check) with a shared period switch. `only` limits which
// metrics are shown; `minimum` is how many series there must be before the card appears at all.
export async function buildPerformanceCard(entity, id, { title = "Performance", only = null, skip = [], minimum = 1, hint = null, unlessOnly = [] } = {}) {
  let data;
  try {
    data = await get(`/api/timeseries/${entity}/${id}`);
  } catch (err) {
    return null;
  }
  const series = data.series.filter((s) => !skip.includes(s.metric) && (!only || only.includes(s.metric)))
    .sort((a, b) => describeSeries(a).order - describeSeries(b).order || a.label.localeCompare(b.label));
  if (series.length < minimum) return null;
  if (unlessOnly.length && series.every((s) => unlessOnly.includes(s.metric))) return null;     // nothing beyond what the Uptime card shows
  let limits = {};
  try {
    limits = (await get("/api/monitoring/limits")).rules || {};
  } catch (err) {
    limits = {};
  }
  let range = savedGraphRange();
  const graphs = h("div", { class: "tg-grid-list" });
  const make = () => series.map((s) => {
    const d = describeSeries(s);
    const rule = limits[s.metric];            // the limits the user set decide where the dashed lines are
    const warn = rule ? (rule.enabled ? rule.warn : null) : d.warn ?? null;
    const crit = rule ? (rule.enabled ? rule.crit : null) : d.crit ?? null;
    return metricGraph({ entity, id, metric: s.metric, label: s.label, title: d.title, unit: d.unit, warn, crit, fixedMax: d.fixedMax ?? null, range });
  });
  graphs.append(...make());
  const card = h("div", { class: "card tg-card" },
    h("div", { class: "upc-head" }, h("h2", {}, title), graphRangeTabs(range, (key) => { range = key; for (const g of graphs.children) g.reload(key); })),
    hint ? h("p", { class: "hint" }, hint) : null,
    graphs);
  return card;
}
