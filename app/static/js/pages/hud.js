import { get } from "../api.js";
import { h, clear, patch } from "../util.js";

// EXPERIMENT: a full-screen command-centre view. It looks "streamed": the event list takes new events the moment the poll sees them (every 4 s), the gauges
// and radar refresh every 15 s, and the ticker runs along the bottom. Nothing is stored; it is read-only and uses the same API as the other pages.
const NS = "http://www.w3.org/2000/svg";
const svg = (tag, attrs = {}) => { const n = document.createElementNS(NS, tag); for (const [k, v] of Object.entries(attrs)) n.setAttribute(k, String(v)); return n; };
const COLOUR = { ok: "#00ffa3", warn: "#ffb020", bad: "#ff3b5c", cyan: "#00e5ff" };
const hash = (n) => { let x = (Number(n) * 2654435761) >>> 0; x ^= x >>> 15; x = Math.imul(x, 2246822519) >>> 0; return (x ^ (x >>> 13)) >>> 0; };
const pad = (n) => String(n).padStart(2, "0");
const BAD = new Set(["device_offline", "service_down", "metric_critical", "probe_offline", "remote_service_down", "capacity_critical", "dhcp_rogue", "gateway_changed"]);
const WARN = new Set(["metric_warning", "device_new", "container_restarting", "capacity_warning"]);
const GOOD = new Set(["device_online", "service_up", "metric_ok", "probe_online"]);
const level = (kind) => (BAD.has(kind) ? "bad" : WARN.has(kind) ? "warn" : GOOD.has(kind) ? "ok" : "");

// A gauge is built once and then only its numbers change, so the ring slides to the new value instead of being redrawn.
function gauge(label) {
  const r = 38, c = 2 * Math.PI * r;
  const box = h("div", { class: "hud-gauge" });
  const s = svg("svg", { viewBox: "0 0 100 100" });
  const arc = svg("circle", { class: "arc", cx: 50, cy: 50, r, "stroke-width": 7, "stroke-dasharray": c, "stroke-dashoffset": c, transform: "rotate(-90 50 50)" });
  const num = svg("text", { class: "num", x: 50, y: 51 });
  s.append(svg("circle", { class: "track", cx: 50, cy: 50, r, "stroke-width": 7 }), arc, num);
  box.append(s, h("div", { class: "cap" }, label));
  box.set = (pct, colour, text) => {
    const p = Math.max(0, Math.min(100, pct ?? 0));
    s.style.color = colour;
    arc.setAttribute("stroke", colour);
    arc.setAttribute("stroke-dashoffset", String(c * (1 - p / 100)));
    num.textContent = text ?? (pct == null ? "–" : `${Math.round(p)}%`);
  };
  return box;
}

// The radar frame and the sweep are built once; later refreshes only add, move or recolour blips, so the sweep never restarts.
function radar() {
  const s = svg("svg", { viewBox: "0 0 500 500", role: "img", "aria-label": "Radar of all devices; red blips are offline" });
  const defs = svg("defs");
  const grad = svg("linearGradient", { id: "hudsweep", x1: 0, y1: 0, x2: 1, y2: 0 });
  grad.append(svg("stop", { offset: "0", "stop-color": COLOUR.cyan, "stop-opacity": 0 }), svg("stop", { offset: "1", "stop-color": COLOUR.cyan, "stop-opacity": 0.55 }));
  defs.appendChild(grad);
  s.appendChild(defs);
  for (const r of [60, 120, 180, 235]) s.appendChild(svg("circle", { class: "ring", cx: 250, cy: 250, r }));
  for (const a of [0, 45, 90, 135]) s.appendChild(svg("line", { class: "axis", x1: 250 - 240 * Math.cos(a * Math.PI / 180), y1: 250 - 240 * Math.sin(a * Math.PI / 180), x2: 250 + 240 * Math.cos(a * Math.PI / 180), y2: 250 + 240 * Math.sin(a * Math.PI / 180) }));
  const sweep = svg("g", { class: "sweep" });
  sweep.appendChild(svg("path", { d: "M250 250 L250 12 A238 238 0 0 1 418 82 Z", fill: "url(#hudsweep)", transform: "rotate(-45 250 250)" }));
  s.appendChild(sweep);
  const blips = svg("g");
  s.appendChild(blips);
  s.appendChild(svg("circle", { cx: 250, cy: 250, r: 4, fill: COLOUR.cyan }));
  const dots = new Map();
  s.update = (devices) => {
    const seen = new Set();
    for (const d of devices) {
      seen.add(d.id);
      const hh = hash(d.id), ang = (hh % 3600) / 10 * Math.PI / 180;
      const ring = d.tier === "critical" ? 0.18 + (hh >>> 12) % 30 / 100 : d.always_on ? 0.3 + (hh >>> 12) % 35 / 100 : 0.5 + (hh >>> 12) % 45 / 100;      // critical near the centre
      const x = (250 + Math.cos(ang) * 230 * ring).toFixed(1), y = (250 + Math.sin(ang) * 230 * ring).toFixed(1);
      let dot = dots.get(d.id);
      if (!dot) { dot = svg("circle", { cx: x, cy: y }); dot.appendChild(svg("title")); dots.set(d.id, dot); blips.appendChild(dot); }
      const cls = `blip ${d.online ? "on" : "off"}${d.tier === "critical" ? " crit" : ""}`;
      if (dot.getAttribute("class") !== cls) {
        dot.setAttribute("class", cls);
        dot.setAttribute("r", d.tier === "critical" ? 6 : 4);
        dot.setAttribute("fill", d.online ? COLOUR.ok : COLOUR.bad);
        dot.style.filter = `drop-shadow(0 0 5px ${d.online ? COLOUR.ok : COLOUR.bad})`;
      }
      if (dot.getAttribute("cx") !== x) dot.setAttribute("cx", x);
      if (dot.getAttribute("cy") !== y) dot.setAttribute("cy", y);
      dot.firstChild.textContent = `${d.custom_name || d.hostname || d.primary_ip}${d.online ? "" : " (offline)"}`;
    }
    for (const [id, dot] of dots) if (!seen.has(id)) { dot.remove(); dots.delete(id); }
  };
  return s;
}

export async function render(container) {
  let disposed = false, lastId = 0;
  let scope = "all", coreIds = new Set();            // "core": only the always-on devices
  try { scope = localStorage.getItem("netlens.hud.scope") === "core" ? "core" : "all"; } catch (e) { /* not remembered */ }
  let lastList = null, lastDash = null, lastRel = null;
  const clock = h("span", { class: "hud-clock" });
  const scopeBtns = {};
  const scopeSwitch = h("div", { class: "hud-scope", role: "group", "aria-label": "Which devices" },
    ...[["all", "All devices"], ["core", "Always-on"]].map(([key, label]) => (scopeBtns[key] = h("button", { type: "button", "aria-pressed": String(key === scope), onclick: () => {
      scope = key;
      try { localStorage.setItem("netlens.hud.scope", key); } catch (e) { /* only this page remembers it */ }
      for (const [k, b] of Object.entries(scopeBtns)) b.setAttribute("aria-pressed", String(k === scope));
      if (lastDash) paint();
    } }, label))));
  const gauges = h("div", { class: "hud-gauges" });
  const attn = h("ol", { class: "hud-attn" });
  const radarBox = h("div", { class: "hud-radar" });
  const radarSvg = radar();
  radarBox.appendChild(radarSvg);
  const gDevices = gauge("Devices online"), gServices = gauge("Services up"), gAvail = gauge("Availability 30d");
  gauges.append(gDevices, gServices, gAvail);
  let tickerText = "";
  const stats = h("div", { class: "hud-stats" });
  const feed = h("ol", {});
  const ticker = h("div", { class: "hud-ticker" });

  const root = h("div", { class: "hud" },
    h("div", { class: "hud-top" }, h("span", { class: "hud-title" }, h("i", { class: "hud-live" }), "Netlens // situation"), scopeSwitch, clock),
    h("div", { class: "hud-left" }, h("section", { class: "hud-panel" }, h("h3", {}, "Vitals"), gauges), h("section", { class: "hud-panel", style: "flex:1" }, h("h3", {}, "Needs attention"), attn)),
    h("div", { class: "hud-mid" }, h("section", { class: "hud-panel hud-radar-panel", style: "flex:1;display:flex;flex-direction:column" }, h("h3", {}, "Network scope"), radarBox), h("section", { class: "hud-panel" }, stats)),
    h("div", { class: "hud-right" }, h("section", { class: "hud-panel hud-feed", style: "flex:1" }, h("h3", {}, "Live event stream"), feed)),
    h("div", { class: "hud-bottom" }, ticker));
  clear(container);
  container.appendChild(root);

  const tick = () => { const d = new Date(); clock.textContent = `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`; };
  tick();
  const clockTimer = setInterval(tick, 1000);

  // the lists keep their data and draw only as many lines as fit the panel, so the page never scrolls
  const evs = [];
  let attnItems = [];
  function fit(list, make, items) {
    clear(list);
    for (let i = 0; i < items.length; i++) {
      list.appendChild(make(items[i], i));
      if (list.scrollHeight > list.clientHeight + 1) {
        list.lastChild.remove();
        if (attnItems === items && i > 0) { list.lastChild.remove(); list.appendChild(h("li", {}, `+${items.length - i + 1} more`)); if (list.scrollHeight > list.clientHeight + 1) list.lastChild.remove(); }
        break;
      }
    }
  }
  const eventLine = (e, i) => h("li", { class: `${level(e.kind)}${e.fresh && i === 0 ? " new" : ""}` }, h("time", {}, (e.ts || "").slice(11, 19)), `${e.device ? e.device + " · " : ""}${e.detail || e.kind.replace(/_/g, " ")}`);
  const shown = () => (scope === "core" ? evs.filter((e) => e.device_id == null || coreIds.has(e.device_id)) : evs);
  const drawFeed = () => fit(feed, eventLine, shown());
  let attnSig = "";
  const drawAttn = (force = false) => { const sig = JSON.stringify(attnItems); if (sig === attnSig && !force) return; attnSig = sig; if (!attnItems.length) { clear(attn); attn.appendChild(h("li", { class: "ok" }, "All systems nominal")); } else fit(attn, (a) => h("li", { class: a.level === "bad" ? "bad" : a.level === "warn" ? "warn" : "" }, h("a", { href: a.href || "#/dashboard" }, a.text)), attnItems); };
  function addEvent(e, fresh) {
    evs.unshift({ ...e, fresh });
    evs.length = Math.min(evs.length, 80);
    drawFeed();
    if (evs[0]) evs[0].fresh = false;          // only the newest line flashes, once
  }

  // the page fills the window exactly: from where it starts to the bottom edge
  const size = () => { root.style.height = `${Math.max(360, window.innerHeight - root.getBoundingClientRect().top - 30)}px`; drawFeed(); drawAttn(true); };
  window.addEventListener("resize", size);

  async function events(first) {
    try {
      const rows = await get(first ? "/api/events?limit=40" : `/api/events?since_id=${lastId}&limit=100`);
      if (disposed) return;
      for (const e of [...rows].reverse()) { addEvent(e, !first); lastId = Math.max(lastId, e.id); }
    } catch (err) { /* the next round tries again */ }
  }

  async function overview() {
    try {
      const [dash, devices, rel] = await Promise.all([get("/api/dashboard"), get("/api/devices?limit=1000"), get("/api/reliability").catch(() => null)]);
      if (disposed) return;
      lastList = Array.isArray(devices) ? devices : devices.devices || [];
      lastDash = dash;
      lastRel = rel;
      paint();
    } catch (err) { /* keep the last picture */ }
  }

  // draws what the last fetch brought, for the chosen set of devices
  function paint() {
    try {
      const dash = lastDash, rel = lastRel;
      coreIds = new Set(lastList.filter((d) => d.always_on).map((d) => d.id));
      const list = scope === "core" ? lastList.filter((d) => d.always_on) : lastList;
      const dv = { ...dash.summary.devices, total: list.length, online: list.filter((d) => d.online).length };
      dv.offline = dv.total - dv.online;
      const services = dash.service_checks || [];
      const up = services.filter((s) => s.state === "up").length;
      gDevices.set(dv.total ? 100 * dv.online / dv.total : 0, dv.offline > 3 ? COLOUR.warn : COLOUR.ok, `${dv.online}/${dv.total}`);
      gServices.set(services.length ? 100 * up / services.length : 100, up === services.length ? COLOUR.ok : COLOUR.bad, `${up}/${services.length}`);
      drawFeed();
      gAvail.set(rel ? rel.availability : null, rel && rel.meets_target ? COLOUR.ok : COLOUR.warn);
      attnItems = dash.attention || [];
      drawAttn();
      radarSvg.update(list);
      const sp = dash.speed;
      patch(stats, ...[["Flapping", dv.flapping], ["Unknown", dv.unknown], ["New 24h", dv.new_24h], ["Down", sp && sp.down_mbps ? `${Math.round(sp.down_mbps)} Mb` : "–"], ["Latency", sp && sp.latency_ms ? `${Math.round(sp.latency_ms)} ms` : "–"]]
        .map(([k, v]) => h("div", {}, h("b", {}, String(v ?? "–")), k)));
      // the ticker keeps scrolling: its text is only replaced when a figure changed, and then the scroll carries on from where it is
      const spans = services.map((s) => h("span", {}, `${s.name} `, h("b", { class: s.state === "up" ? "" : "bad" }, s.state === "up" ? `${s.ms != null ? Math.round(s.ms) + " ms" : "OK"}` : "DOWN")));
      const text = spans.map((x) => x.textContent).join("|");
      if (text !== tickerText) { tickerText = text; ticker.replaceChildren(...spans); }
    } catch (err) { /* keep the last picture */ }
  }

  size();
  await Promise.all([events(true), overview()]);
  size();
  const evTimer = setInterval(() => events(false), 4000);
  const ovTimer = setInterval(overview, 15000);
  return () => { disposed = true; window.removeEventListener("resize", size); clearInterval(clockTimer); clearInterval(evTimer); clearInterval(ovTimer); };
}
