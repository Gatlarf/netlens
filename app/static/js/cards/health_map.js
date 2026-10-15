import { h, shortName, timeAgo } from "../util.js";
import { formatValue } from "../timegraph.js";

// The Health card of the dashboard: a headline, a heat-map with one tile per monitored device, and what is past a limit.
// A tile is coloured by the worst level of that device; its three bars show processor, memory and the fullest disk,
// each coloured by its own level, so a glance tells which device is in trouble and with what.
const BARS = [["cpu", "Processor", "cpu_pct"], ["mem", "Memory", "mem_pct"], ["disk", "Disk", "disk_pct"]];
const RANK = { ok: 0, warning: 1, critical: 2 };

function levelOf(value, rule) {
  if (value == null || !rule || rule.enabled === false) return "ok";
  const hit = (limit) => limit != null && (rule.low ? value <= limit : value >= limit);
  return hit(rule.crit) ? "critical" : hit(rule.warn) ? "warning" : "ok";
}

function tileState(m) {
  if (!m.enabled) return "off";
  if (m.last_ok === false) return "unreachable";
  if (m.last_ok === null && m.last_ts == null) return "waiting";
  return m.level === "critical" ? "critical" : m.level === "warning" ? "warning" : "ok";
}

const STATE_TEXT = { ok: "healthy", warning: "warning", critical: "critical", unreachable: "cannot be read", waiting: "waiting for the first reading", off: "monitoring paused" };

function tile(m, rules) {
  const state = tileState(m);
  const bars = BARS.map(([key, title, metric]) => {
    const v = m.latest[key];
    const lvl = state === "unreachable" || state === "waiting" || state === "off" ? "none" : levelOf(v, rules[metric]);
    const bar = h("span", { class: `hm-bar hm-${v == null ? "none" : lvl}`, title: `${title}: ${v == null ? "no reading" : formatValue(v, "%")}` },
      h("span", { class: "hm-fill", style: `height:${v == null ? 0 : Math.max(4, Math.min(100, v))}%` }));
    return bar;
  });
  const detail = BARS.map(([key, title]) => (m.latest[key] == null ? null : `${title} ${formatValue(m.latest[key], "%")}`)).filter(Boolean);
  if (m.latest.temp != null) detail.push(`Temperature ${Math.round(m.latest.temp)} °C`);
  const title = [`${m.name}: ${STATE_TEXT[state]}`, ...detail, m.last_error && state === "unreachable" ? m.last_error : null].filter(Boolean).join("\n");
  return h("a", { class: `hm-tile hm-state-${state}`, href: `#/device/${m.device_id}`, title,
    onclick: () => { try { sessionStorage.setItem("netlens.devicetab", "health"); } catch (e) { /* the page then opens on Overview */ } } },
    h("span", { class: "hm-name" }, shortName(m.name)), h("span", { class: "hm-bars" }, ...bars));
}

export function buildHealthCard({ monitors, problems, rules }) {
  const tiles = [...monitors].sort((a, b) => (RANK[tileState(b)] ?? 0) - (RANK[tileState(a)] ?? 0) || a.name.localeCompare(b.name));
  const states = tiles.map(tileState);
  const critical = states.filter((s) => s === "critical").length, warning = states.filter((s) => s === "warning").length;
  const silent = states.filter((s) => s === "unreachable").length;
  let headline = `All ${monitors.length} monitored ${monitors.length === 1 ? "device is" : "devices are"} healthy`;
  let cls = "ok";
  if (critical || warning) {
    const parts = [critical ? `${critical} critical` : null, warning ? `${warning} warning` : null].filter(Boolean).join(", ");
    headline = `${critical + warning} of ${monitors.length} need attention: ${parts}`;
    cls = critical ? "bad" : "warn";
  } else if (silent) {
    headline = `${silent} of ${monitors.length} cannot be read`;
    cls = "warn";
  }
  const body = h("div", { class: "hm" }, h("p", { class: `hm-headline d-${cls}` }, headline), h("div", { class: "hm-grid" }, ...tiles.map((m) => tile(m, rules))));
  if (problems.length) {
    const list = [...problems].sort((a, b) => (RANK[b.level] ?? 0) - (RANK[a.level] ?? 0)).slice(0, 5);
    body.appendChild(h("ul", { class: "d-attention hm-problems" }, list.map((p) => h("li", { class: p.level === "critical" ? "d-bad" : "d-warn" },
      h("a", { href: `#/device/${p.device_id}`, onclick: () => { try { sessionStorage.setItem("netlens.devicetab", "health"); } catch (e) { /* ignore */ } } },
        `${shortName(p.device)} · ${p.title}${p.label ? ` (${p.label})` : ""} ${formatValue(p.value, p.unit)}`),
      h("span", { class: "d-note" }, ` ${p.level} since ${timeAgo(p.since)}`)))));
  } else {
    const busiest = [];
    for (const [key, title] of BARS) {
      const top = monitors.filter((m) => m.latest[key] != null).sort((a, b) => b.latest[key] - a.latest[key])[0];
      if (top) busiest.push(`${title} ${formatValue(top.latest[key], "%")} (${shortName(top.name)})`);
    }
    if (busiest.length) body.appendChild(h("p", { class: "hint hm-busiest" }, `Busiest: ${busiest.join(" · ")}`));
  }
  body.appendChild(h("p", { class: "hint hm-legend" }, "Bars: processor, memory, fullest disk. Colours follow the limits under Monitoring → Health."));
  return body;
}

export const healthTone = (monitors, problems) => {
  if (problems.some((p) => p.level === "critical") || monitors.some((m) => m.level === "critical")) return "bad";
  if (problems.length || monitors.some((m) => m.level === "warning" || m.last_ok === false)) return "warn";
  return "ok";
};
