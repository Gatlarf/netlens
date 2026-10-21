import { get } from "../api.js";
import { h } from "../util.js";
import { formatValue, metricGraph, graphRangeTabs, savedGraphRange } from "../timegraph.js";

// The ports of a switch (or the interfaces of any device with many): link, traffic, how full the link is and errors.
// Fewer than MIN interfaces are left to the ordinary performance graphs.
export const PORT_METRICS = ["net_rx_bps", "net_tx_bps", "net_rx_pps", "net_tx_pps", "if_util_pct", "if_err_ps", "if_up"];
const MIN = 3;
const FRESH = 3600;

const natural = (a, b) => a.localeCompare(b, undefined, { numeric: true, sensitivity: "base" });

export async function buildDevicePortsCard(device) {
  let data;
  try {
    data = await get(`/api/timeseries/device/${device.id}`);
  } catch (err) {
    return null;
  }
  const now = Date.now() / 1000;
  const ports = new Map();
  for (const s of data.series) {
    if (!PORT_METRICS.includes(s.metric) || !s.label) continue;
    const p = ports.get(s.label) || { label: s.label };
    p[s.metric] = s.last_ts != null && now - s.last_ts <= FRESH ? s.last : null;
    p[`${s.metric}_seen`] = true;
    ports.set(s.label, p);
  }
  if (ports.size < MIN) return null;
  let limits = {};
  try {
    limits = (await get(`/api/devices/${device.id}/limits`)).rules || {};
  } catch (err) {
    limits = {};
  }
  const rows = [...ports.values()].sort((a, b) => natural(a.label, b.label));
  const body = h("tbody", {});
  let range = savedGraphRange();
  const open = new Set();
  const details = new Map();

  const level = (metric, v) => {
    const r = limits[metric];
    if (v == null || !r || !r.enabled) return "";
    return r.crit != null && v >= r.crit ? "bad" : r.warn != null && v >= r.warn ? "warn" : "";
  };

  function graphsFor(p) {
    const cell = h("td", { colspan: "6" });
    const wrap = h("div", { class: "tg-grid-list" });
    const add = (metric, title, unit, extra = {}) => { if (p[`${metric}_seen`]) wrap.appendChild(metricGraph({ entity: "device", id: device.id, metric, label: p.label, title: `${title} · ${p.label}`, unit, range, ...extra })); };
    add("net_rx_bps", "Received", "bps");
    add("net_tx_bps", "Sent", "bps");
    add("net_rx_pps", "Received packets", "pps");          // switches that only count packets (TP-Link Easy Smart)
    add("net_tx_pps", "Sent packets", "pps");
    add("if_util_pct", "Port busy", "%", { fixedMax: 100, warn: limits.if_util_pct?.warn ?? null, crit: limits.if_util_pct?.crit ?? null });
    add("if_err_ps", "Errors", "/s");
    add("if_up", "Link", "state");
    cell.appendChild(wrap);
    return h("tr", { class: "port-detail" }, cell);
  }

  const traffic = (p, way) => {
    if (p[`net_${way}_bps`] != null) return formatValue(p[`net_${way}_bps`], "bps");
    return p[`net_${way}_pps`] != null ? `${formatValue(p[`net_${way}_pps`], "pps")}` : "–";
  };

  function draw() {
    body.replaceChildren();
    for (const p of rows) {
      const up = p.if_up;
      const link = up == null ? h("span", { class: "hint" }, "–") : h("span", { class: up >= 0.5 ? "port-up" : "port-down" }, up >= 0.5 ? "up" : "down");
      const util = p.if_util_pct;
      const tr = h("tr", { class: `port-row ${open.has(p.label) ? "open" : ""}`, tabindex: "0", title: "Show the graphs of this port" },
        h("td", {}, p.label), h("td", {}, link),
        h("td", { class: "num" }, traffic(p, "rx")),
        h("td", { class: "num" }, traffic(p, "tx")),
        h("td", { class: `num d-${level("if_util_pct", util) || "ok"}` }, util == null ? "–" : formatValue(util, "%")),
        h("td", { class: `num d-${level("if_err_ps", p.if_err_ps) || "ok"}` }, !p.if_err_ps_seen ? "" : p.if_err_ps == null ? "–" : `${Math.round(p.if_err_ps * 10) / 10}/s`));
      const toggle = () => {
        if (open.has(p.label)) { open.delete(p.label); details.delete(p.label); } else { open.add(p.label); }
        draw();
      };
      tr.addEventListener("click", toggle);
      tr.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); toggle(); } });
      body.appendChild(tr);
      if (open.has(p.label)) {
        const detail = graphsFor(p);
        details.set(p.label, detail);
        body.appendChild(detail);
      }
    }
  }
  draw();

  const down = rows.filter((p) => p.if_up != null && p.if_up < 0.5).length;
  const upCount = rows.filter((p) => p.if_up != null && p.if_up >= 0.5).length;
  return h("div", { class: "card ports-card" },
    h("div", { class: "upc-head" }, h("h2", {}, "Ports"), graphRangeTabs(range, (key) => { range = key; draw(); })),
    h("p", { class: "hint" }, `${upCount} up, ${down} without a link. Click a port for its graphs.`),
    h("div", { class: "rep-scroll" }, h("table", { class: "rep-table ports-table" },
      h("thead", {}, h("tr", {}, ...["Port", "Link", "In", "Out", "Busy", "Errors"].map((t) => h("th", {}, t)))), body)));
}
