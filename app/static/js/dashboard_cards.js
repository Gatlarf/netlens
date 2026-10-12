// What the dashboard cards are made of: small building blocks, the cards a user makes (values, devices, groups, services, notes)
// and the cards a plugin offers. The page (pages/dashboard.js) puts them in the grid.
import { h, timeAgo, shortName } from "./util.js";
import { fmtBytes } from "./charts.js";

export const plural = (n, one, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;

export function sparkline(values, { height = 28 } = {}) {
  const v = values.filter((x) => x !== null && x !== undefined);
  if (v.length < 2) return null;
  const min = Math.min(...v), max = Math.max(...v), span = max - min || 1, w = 100;
  const pts = v.map((x, i) => `${((i / (v.length - 1)) * w).toFixed(1)},${(height - 3 - ((x - min) / span) * (height - 6)).toFixed(1)}`).join(" ");
  const ns = "http://www.w3.org/2000/svg";
  const svg = document.createElementNS(ns, "svg");
  svg.setAttribute("viewBox", `0 0 ${w} ${height}`);
  svg.setAttribute("preserveAspectRatio", "none");
  svg.setAttribute("class", "spark");
  svg.setAttribute("aria-hidden", "true");
  const line = document.createElementNS(ns, "polyline");
  line.setAttribute("points", pts);
  line.setAttribute("fill", "none");
  line.setAttribute("stroke", "currentColor");
  line.setAttribute("stroke-width", "2");
  line.setAttribute("vector-effect", "non-scaling-stroke");
  svg.appendChild(line);
  return svg;
}

// a big number with a caption and, optionally, a small line chart and extra lines
export const big = (value, sub, { spark = null, extra = null } = {}) => h("div", { class: "d-body" }, h("div", { class: "d-value" }, value), h("div", { class: "d-sub" }, sub), spark, extra);

// label / value lines: rows = [[label, value, tone?]]
export const rows = (list) => h("dl", { class: "d-rows" }, list.map(([k, v, tone]) => h("div", { class: tone ? `d-${tone}` : "" }, h("dt", {}, k), h("dd", {}, v))));

export const linkList = (items) => h("ul", { class: "d-list" }, items.map((i) => h("li", { class: i.tone ? `d-${i.tone}` : "" }, i.href ? h("a", { href: i.href }, i.text) : h("span", {}, i.text), i.note ? h("span", { class: "d-note" }, i.note) : null)));

export const toneUp = (pct) => (pct === null || pct === undefined ? "" : pct >= 99 ? "ok" : pct >= 95 ? "warn" : "bad");

// ---------- values ----------

export const FORMATS = [["number", "Number"], ["percent", "Percent"], ["mbps", "Speed (Mbit/s)"], ["ms", "Milliseconds"], ["duration", "Seconds as a time (3 h)"], ["bytes", "Bytes (MB, GB)"], ["text", "Text"]];

function seconds(n) {
  const s = Math.abs(n);
  return s < 90 ? `${Math.round(s)} s` : s < 5400 ? `${Math.round(s / 60)} min` : s < 129600 ? `${(s / 3600).toFixed(s < 36000 ? 1 : 0)} h` : `${Math.round(s / 86400)} d`;
}

export function formatValue(value, format = "number", decimals = 0, unit = "") {
  if (value === null || value === undefined || value === "") return "–";
  if (format === "text" || (typeof value !== "number" && typeof value !== "boolean")) return `${typeof value === "boolean" ? (value ? "yes" : "no") : value}${unit ? ` ${unit}` : ""}`;
  const n = Number(value);
  const fixed = (x) => x.toFixed(decimals);
  switch (format) {
    case "percent": return `${fixed(n)}%`;
    case "mbps": return n >= 1000 ? `${(n / 1000).toFixed(2)} Gbps` : `${fixed(n)} Mbps`;
    case "ms": return `${fixed(n)} ms`;
    case "duration": return seconds(n);
    case "bytes": return fmtBytes(n);
    default: return `${fixed(n)}${unit ? ` ${unit}` : ""}`;
  }
}

// ok / warn / bad from the two limits; "below": it is a problem when the value falls under the limit (uptime, speed), "above": when it rises over it (errors, latency)
export function limitTone(value, { warn, bad, direction }) {
  const v = typeof value === "boolean" ? (value ? 1 : 0) : value;
  if (typeof v !== "number" || (warn === null || warn === undefined) && (bad === null || bad === undefined)) return "";
  const past = (limit) => limit !== null && limit !== undefined && (direction === "above" ? v > limit : v < limit);
  return past(bad) ? "bad" : past(warn) ? "warn" : "ok";
}

export function dig(data, path) {
  let node = data;
  for (const key of path.split(".")) {
    if (node === null || typeof node !== "object") return undefined;
    node = node[key];
  }
  return node;
}

// every single value of the dashboard data a card could show: [{path, label, value}]
const SKIP = new Set(["device_list", "devices_uptime", "service_checks", "plugin_cards", "events", "attention", "worst", "trend", "new_devices", "certificates", "plugins", "services_down"]);
const FRIENDLY = {
  "summary.devices.online": "Devices online", "summary.devices.offline": "Devices offline", "summary.devices.total": "Devices known", "summary.devices.flapping": "Unstable devices",
  "summary.devices.unknown": "Devices not marked known", "summary.devices.new_24h": "New devices today", "summary.devices.new_7d": "New devices this week",
  "summary.uptime.24h": "Network uptime, 24 hours", "summary.uptime.7d": "Network uptime, 7 days", "summary.services.up": "Services up", "summary.services.down": "Services down",
  "summary.containers.running": "Containers running", "summary.containers.unhealthy": "Unhealthy containers", "summary.containers.restarting": "Restarting containers",
  "summary.guests.running": "Guests running", "summary.guests.total": "Guests in total", "summary.sites.total": "Proxy sites", "summary.sites.next_expiry_days": "Days until the next certificate ends",
  "summary.wifi.clients": "Wi-Fi clients", "summary.wifi.avg_rssi": "Average Wi-Fi signal (dBm)", "summary.wifi.weak": "Wi-Fi clients with a weak signal",
  "summary.dns.registered": "DNS names registered", "summary.dns.pending": "DNS names waiting", "summary.dns.conflicts": "DNS conflicts", "summary.ports.open": "Open ports",
  "summary.events.24h": "Events in 24 hours", "summary.problems": "Open problems", "login_failed_24h": "Failed sign-in bursts, 24 hours", "maintenance": "Devices in maintenance",
  "speed.down_mbps": "Internet download speed", "speed.up_mbps": "Internet upload speed", "speed.latency_ms": "Internet ping", "speed.jitter_ms": "Internet jitter",
};
const humanize = (path) => path.replace(/^summary\./, "").split(".").map((p, i) => (i ? p : p[0].toUpperCase() + p.slice(1)).replace(/_/g, " ")).join(" › ");

export function flatten(data) {
  const out = [];
  const walk = (node, path, depth) => {
    for (const [key, value] of Object.entries(node || {})) {
      if (SKIP.has(key) && depth <= 1) continue;
      const here = path ? `${path}.${key}` : key;
      if (value !== null && typeof value === "object" && !Array.isArray(value)) { if (depth < 4) walk(value, here, depth + 1); }
      else if (!Array.isArray(value) && value !== null && (typeof value === "number" || typeof value === "boolean" || (typeof value === "string" && value.length <= 40))) {
        out.push({ path: here, label: FRIENDLY[here] || humanize(here), value });
      }
    }
  };
  walk(data, "", 0);
  return out.sort((a, b) => a.label.localeCompare(b.label));
}

// a sensible format for a value, guessed from its name
export function guessFormat(path) {
  if (/_mbps$/.test(path)) return "mbps";
  if (/_ms$/.test(path)) return "ms";
  if (/uptime|_pct$|percent/.test(path)) return "percent";
  if (/_s$|age_s$/.test(path)) return "duration";
  if (/bytes/.test(path)) return "bytes";
  return "number";
}

// ---------- the cards a user makes ----------

export const TYPES = [["value", "A value from your data", "Any single number or status Netlens knows, with colours for when it is good or bad."],
  ["device", "A device", "Whether one device is up, since when, its address and uptime."],
  ["group", "A group of devices", "How many devices of a group are online, and which are not."],
  ["service", "A service check", "The state and response time of one of your service checks."],
  ["notes", "Notes and links", "Some text and shortcuts, for example to Grafana, Portainer or your router."]];

const dot = (up) => h("span", { class: `dot ${up ? "on" : "off"}` });

function valueCard(def, data) {
  const value = dig(data, def.source);
  const tone = limitTone(value, def);
  const text = formatValue(value, def.format, def.decimals, def.unit);
  if (def.display === "gauge") {
    const lo = def.min ?? 0, hi = def.max ?? 100;
    const pct = typeof value === "number" ? Math.max(0, Math.min(100, ((value - lo) / ((hi - lo) || 1)) * 100)) : 0;
    const bar = h("div", { class: "d-gauge", role: "img", "aria-label": `${text}, from ${lo} to ${hi}` }, h("span", { class: `d-gauge-fill ${tone ? `d-${tone}` : ""}`, style: `width:${pct}%` }));
    return h("div", { class: "d-body" }, h("div", { class: "d-value" }, text), bar, h("div", { class: "d-sub d-range" }, h("span", {}, String(lo)), h("span", {}, String(hi))));
  }
  if (def.display === "status") {
    const good = tone ? tone === "ok" : typeof value === "boolean" ? value : value !== 0 && value !== null && value !== undefined;
    return h("div", { class: "d-body" }, h("div", { class: `d-value d-status ${good ? "d-ok" : tone === "warn" ? "d-warn" : "d-bad"}` }, h("span", { class: "d-status-dot", "aria-hidden": "true" }), good ? "OK" : tone === "warn" ? "Warning" : "Problem"), h("div", { class: "d-sub" }, text));
  }
  return h("div", { class: "d-body" }, h("div", { class: "d-value" }, text));
}

function deviceCard(def, data) {
  const d = data.summary.device_list.find((x) => x.id === def.device_id);
  if (!d) return h("p", { class: "hint" }, "This device is no longer known to Netlens.");
  const up = data.devices_uptime?.[d.id] || [];
  return h("div", { class: "d-body" },
    h("div", { class: "d-value d-device" }, dot(d.online), h("span", {}, shortName(d.name))),
    h("div", { class: "d-sub" }, d.online ? "online" : `offline · last seen ${timeAgo(d.last_seen)}`),
    rows([["Address", d.ip || "–"], ["Uptime 24 h", up[0] === null || up[0] === undefined ? "–" : `${up[0]}%`], ["Uptime 7 d", up[1] === null || up[1] === undefined ? "–" : `${up[1]}%`]]));
}

function groupCard(def, data) {
  const list = data.summary.device_list.filter((d) => (d.group || "(no group)") === def.group);
  if (!list.length) return h("p", { class: "hint" }, "No device is in this group.");
  const off = list.filter((d) => !d.online);
  return big(`${list.length - off.length} / ${list.length}`, off.length ? `offline: ${off.slice(0, 3).map((d) => shortName(d.name)).join(", ")}${off.length > 3 ? "…" : ""}` : "all online");
}

function serviceCard(def, data) {
  const c = (data.service_checks || []).find((x) => x.id === def.check_id);
  if (!c) return h("p", { class: "hint" }, "This service check no longer exists.");
  const word = !c.enabled ? "Paused" : c.state === "up" ? "Up" : c.state === "down" ? "Down" : "Waiting";
  return big(word, `${c.kind}${c.ms !== null && c.ms !== undefined ? ` · ${Math.round(c.ms)} ms` : ""}${c.uptime_24h !== null && c.uptime_24h !== undefined ? ` · ${c.uptime_24h}% in 24 h` : ""}`);
}

function notesCard(def) {
  return h("div", { class: "d-body d-notes" },
    def.text ? h("div", { class: "d-note-text" }, def.text.split("\n").map((line) => h("p", {}, line))) : null,
    def.links.length ? h("div", { class: "d-links" }, def.links.filter((l) => /^(https?:\/\/|#\/)/.test(l.url)).map((l) => {
      const external = /^https?:/.test(l.url);
      return h("a", { class: "btn", href: l.url, target: external ? "_blank" : null, rel: external ? "noopener noreferrer" : null }, l.label);
    })) : null);
}

// the card object the page puts in its grid (same shape as the built-in ones)
export function customCard(def, data) {
  const named = def.type === "device" ? data?.summary.device_list.find((x) => x.id === def.device_id)?.name
    : def.type === "group" ? def.group ? `Group: ${def.group}` : null
    : def.type === "service" ? data?.service_checks?.find((x) => x.id === def.check_id)?.name : null;
  const base = { id: def.id, title: def.title || (named ? shortName(named) : TYPES.find((t) => t[0] === def.type)[1]), custom: def, size: "s", def: false, about: "A card of your own." };
  switch (def.type) {
    case "value": return { ...base, href: /^#\//.test(def.href || "") ? def.href : null, tone: (d) => limitTone(dig(d, def.source), def), build: (d) => valueCard(def, d) };
    case "device": return { ...base, href: `#/device/${def.device_id}`, tone: (d) => { const x = d.summary.device_list.find((y) => y.id === def.device_id); return x ? (x.online ? "ok" : "bad") : ""; }, build: (d) => deviceCard(def, d) };
    case "group": return { ...base, href: "#/devices", tone: (d) => { const l = d.summary.device_list.filter((x) => (x.group || "(no group)") === def.group); return l.length ? (l.every((x) => x.online) ? "ok" : "warn") : ""; }, build: (d) => groupCard(def, d) };
    case "service": return { ...base, href: "#/services", tone: (d) => { const c = (d.service_checks || []).find((x) => x.id === def.check_id); return c && c.enabled ? (c.state === "up" ? "ok" : c.state === "down" ? "bad" : "") : ""; }, build: (d) => serviceCard(def, d) };
    default: return { ...base, size: (def.text || "").length > 240 ? "w" : "s", tone: () => "", build: () => notesCard(def) };
  }
}

// ---------- the cards a plugin offers ----------

export function pluginCard(pc) {
  const worst = pc.rows.some((r) => r.tone === "bad") ? "bad" : pc.rows.some((r) => r.tone === "warn") ? "warn" : "";
  return {
    id: `p.${pc.plugin}.${pc.id}`, title: pc.title, href: pc.href, size: "s", def: false, plugin: pc.plugin, about: pc.about,
    tone: () => worst,
    build: () => rows(pc.rows.map((r) => [r.label, r.format === "ago" ? (r.value ? timeAgo(r.value) : "never") : r.format === "number" ? String(r.value) : (r.value ?? "–"), r.tone])),
  };
}
