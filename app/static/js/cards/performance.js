import { get } from "../api.js";
import { h } from "../util.js";
import { metricGraph, graphRangeTabs, savedGraphRange, GraphGroup, GRAPH_RANGES } from "../timegraph.js";
import { describeSeries } from "../seriesinfo.js";

export { describeSeries };

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
    limits = (await get(entity === "device" ? `/api/devices/${id}/limits` : "/api/monitoring/limits")).rules || {};   // a device may have limits of its own
  } catch (err) {
    limits = {};
  }
  const group = GraphGroup.shared(`perf:${entity}:${id}`);          // the graphs of this card share their period, zoom and cursor (kept when the page redraws)
  const graphs = h("div", { class: "tg-grid-list" });
  let showLimits = false;
  try { showLimits = localStorage.getItem("nl.graph.limits") === "1"; } catch (e) { /* off */ }
  const make = () => series.map((s) => {
    const d = describeSeries(s);
    const rule = limits[s.metric];            // the limits the user set decide where the dashed lines are
    const warn = rule ? (rule.enabled ? rule.warn : null) : d.warn ?? null;
    const crit = rule ? (rule.enabled ? rule.crit : null) : d.crit ?? null;
    return metricGraph({ entity, id, metric: s.metric, label: s.label, title: d.title, unit: d.unit, warn, crit, fixedMax: d.fixedMax ?? null, range: group.range, showLimits, group });
  });
  graphs.append(...make());
  const anyLimits = series.some((s) => { const r = limits[s.metric]; const d = describeSeries(s); return r ? r.enabled : d.warn != null || d.crit != null; });
  const limitBox = h("input", { type: "checkbox" });
  limitBox.checked = showLimits;
  limitBox.addEventListener("change", () => {
    showLimits = limitBox.checked;
    try { localStorage.setItem("nl.graph.limits", showLimits ? "1" : "0"); } catch (e) { /* only this page remembers it */ }
    for (const g of graphs.children) g.setLimits(showLimits);
  });
  // "Correlate…" starts from the first graph; the same is in the menu of every graph
  const correlate = series.length >= 2 ? h("button", { type: "button", class: "btn", title: "Do two measurements move together?", onclick: async () => {
    const first = series[0];
    const { openCorrelate } = await import("../graphtools.js");
    const d = describeSeries(first);
    openCorrelate({ x: { entity, id, metric: first.metric, label: first.label, title: d.title }, query: group.query(),
      windowText: group.window ? "the zoomed period" : (GRAPH_RANGES.find(([k]) => k === group.range) || [, group.range])[1] });
  } }, "Correlate…") : null;
  const card = h("div", { class: "card tg-card" },
    h("div", { class: "upc-head" }, h("h2", {}, title), anyLimits ? h("label", { class: "check" }, limitBox, " Show limits") : null, correlate, graphRangeTabs(group.range, () => {}, group)),
    group.bar(),
    hint ? h("p", { class: "hint" }, hint) : null,
    graphs);
  return card;
}
