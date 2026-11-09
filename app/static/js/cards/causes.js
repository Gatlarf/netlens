import { get } from "../api.js";
import { h, clear, fmtTime } from "../util.js";
import { calendarHeat } from "../flows.js";

// Two sections at the bottom of the Uptime card of a device (administrators): what changed shortly before an outage, and what depends on the device.
// Both load when opened and keep the device page from refreshing itself while open, like the Stability section.
let open = 0;
export function isInsightOpen() {
  return open > 0;
}

function section(id, title, hint, load) {
  const details = h("details", { class: "stability-details", id });
  details.appendChild(h("summary", { title: hint }, h("strong", {}, title)));
  const body = h("div", { class: "stability-body" });
  details.appendChild(body);
  let was = false, loaded = false;
  details.addEventListener("toggle", () => {
    if (details.open !== was) open += details.open ? 1 : -1;
    was = details.open;
    if (details.open && !loaded) { loaded = true; load(body); }
  });
  return details;
}

function problem(body, err) {
  clear(body);
  body.appendChild(h("p", { class: "hint" }, err && err.status === 402 ? "This needs Insights: a licence or the free trial (Settings → Licence)." : (err && err.message) || "Could not load this."));
}

const RELATION = { "this device": "this device", "above it": "the device it is plugged into", "further up": "further up the network", "the whole network": "the whole network", "a setting": "a setting in Netlens" };

// ----------------------------------------------------------------------------- what changed before it broke
export function showCauses(body, out, reload) {
  clear(body);
  if (reload && out.outages.length) {
    const pick = h("select", { "data-nosave": "1", name: "outage", "aria-label": "Which outage" });
    for (const ts of out.outages) pick.appendChild(h("option", { value: ts, selected: ts === out.at }, `went offline ${fmtTime(ts)}`));
    pick.addEventListener("change", () => reload(pick.value));
    body.appendChild(h("div", { class: "btn-row" }, pick));
  }
  if (!out.suspects.length) {
    body.appendChild(h("p", { class: "hint" }, `Nothing that counts as a change was recorded around ${out.device} in that time. That is information too: the cause is probably outside what Netlens watches.`));
    return;
  }
  const list = h("ul", { class: "findings", title: out.note });
  const top = out.suspects[0].score;
  for (const s of out.suspects) {
    const strong = s.score >= top * 0.6;
    list.appendChild(h("li", { class: `finding ${strong ? "warn" : "info"}` },
      h("strong", {}, s.text), h("span", { class: "finding-level" }, s.when),
      h("p", {}, [RELATION[s.relation] || s.relation, s.device && s.relation !== "this device" ? `(${s.device})` : "", s.who ? `· by ${s.who}` : "", s.times > 1 ? `· ${s.times} times` : ""].filter(Boolean).join(" "))));
  }
  body.appendChild(list);
}

export function buildCausesSection(device) {
  const load = async (body, at) => {
    try {
      showCauses(body, await get(`/api/insights/devices/${device.id}/causes${at ? `?at=${encodeURIComponent(at)}` : ""}`), (ts) => load(body, ts));
    } catch (err) {
      problem(body, err);
    }
  };
  return section("causes-card", "What changed before it broke?", "Ports, updates, containers and settings that changed shortly before an outage.", (body) => load(body));
}

// ----------------------------------------------------------------------------- what depends on it
const NS = "http://www.w3.org/2000/svg";
const svg = (tag, attrs = {}) => { const el = document.createElementNS(NS, tag); for (const [k, v] of Object.entries(attrs)) el.setAttribute(k, v); return el; };

// The device in the middle, every level below it as a ring; a dot per device (green online, red offline, a ring around those marked always-on)
function rings(out) {
  const step = 34, size = Math.min(280, 2 * (24 + out.levels.length * step + 14)), c = size / 2;
  const fit = Math.min(step, (c - 38) / Math.max(1, out.levels.length));
  const root = svg("svg", { viewBox: `0 0 ${size} ${size}`, class: "impact-rings", role: "img", "aria-label": `${out.device} and the ${out.total} devices that depend on it, one ring per level` });
  out.levels.forEach((level, depth) => {
    const radius = 24 + (depth + 1) * fit;
    root.appendChild(svg("circle", { cx: c, cy: c, r: radius, class: "impact-ring" }));
    const shown = level.slice(0, 48);
    shown.forEach((d, i) => {
      const angle = (i / shown.length) * Math.PI * 2 - Math.PI / 2 + depth * 0.35;
      const dot = svg("circle", { cx: c + Math.cos(angle) * radius, cy: c + Math.sin(angle) * radius, r: d.always_on ? 5.5 : 4, class: `impact-dot ${d.online ? "up" : "down"}${d.always_on ? " core" : ""}` });
      dot.appendChild(svg("title")).textContent = `${d.name}${d.online ? "" : " (offline now)"}${d.always_on ? " · always-on" : ""}`;
      root.appendChild(dot);
    });
  });
  root.appendChild(svg("circle", { cx: c, cy: c, r: 14, class: "impact-centre" }));
  return root;
}

function showImpact(body, out) {
  clear(body);
  body.appendChild(h("p", { class: `impact-summary risk-${out.risk}` }, out.summary));
  if (out.total) {
    const grid = h("div", { class: "impact-grid" });
    grid.appendChild(rings(out));
    const text = h("div", { class: "impact-levels" });
    out.levels.forEach((level, depth) => {
      text.appendChild(h("h4", {}, depth === 0 ? "Directly connected" : `${depth + 1} steps away`));
      const ul = h("ul", { class: "impact-list" });
      for (const d of level.slice(0, 30)) ul.appendChild(h("li", {}, h("i", { class: `impact-dot ${d.online ? "up" : "down"}` }), h("a", { href: `#/device/${d.id}` }, d.name), h("span", { class: "hint" }, `${d.type}${d.always_on ? " · always-on" : ""}${d.online ? "" : " · offline now"}`)));
      if (level.length > 30) ul.appendChild(h("li", { class: "hint" }, `…and ${level.length - 30} more`));
      text.appendChild(ul);
    });
    grid.appendChild(text);
    body.appendChild(grid);
  }
  if (out.guests.length) body.appendChild(h("p", {}, h("strong", {}, "Containers and apps on it: "), out.guests.slice(0, 20).map((g) => g.name).join(", ") + (out.guests.length > 20 ? `, … (${out.guests.length})` : "")));
  if (out.services.length) body.appendChild(h("p", {}, h("strong", {}, "Service checks that would fail: "), out.services.slice(0, 20).map((s) => s.name).join(", ") + (out.services.length > 20 ? `, … (${out.services.length})` : "")));
  body.title = out.note;
}

export function buildImpactSection(device) {
  return section("impact-card", "If this goes down…", "What depends on this device: use it before you reboot or unplug it.", async (body) => {
    try {
      showImpact(body, await get(`/api/insights/devices/${device.id}/impact`));
    } catch (err) {
      problem(body, err);
    }
  });
}

// ----------------------------------------------------------------------------- the year of a device, one square per day (everybody)
export function buildCalendarSection(device) {
  return section("calendar-card", "A year of availability", "One square per day: green is a full day, red a bad one; a dot marks a firmware or system change.", async (body) => {
    try {
      const out = await get(`/api/devices/${device.id}/calendar?days=365`);
      body.appendChild(out.days.length ? calendarHeat(out) : h("p", { class: "hint" }, "No history yet."));
    } catch (err) {
      problem(body, err);
    }
  });
}
