import { get } from "../api.js";
import { h, clear } from "../util.js";

// The time machine of the HUD: the radar, but every device shows the state it had at the chosen moment. The state comes from the stored checks
// (GET /api/uptime/replay returns only the changes), so nothing new is collected. Containers have no checks, so they are not part of the replay.
// Caveat shown to the user: "unreachable" is worked out from today's hierarchy, Netlens does not store how the network was wired in the past.
const RANGES = [["6h", 6, 60], ["24h", 24, 360], ["7d", 168, 1800]];            // label, hours, default speed (times real time)
const SPEEDS = [[60, "1 min/s"], [360, "6 min/s"], [1800, "30 min/s"], [7200, "2 h/s"]];

export function replay({ onChange, getTree, getDevices }) {
  const el = h("div", { class: "hud-replay", hidden: true });
  const playBtn = h("button", { type: "button", class: "hud-rbtn" }, "▶ Play");
  const rangeSel = h("select", { "aria-label": "How far back to replay" }, ...RANGES.map(([k]) => h("option", { value: k }, `Last ${k}`)));
  const speedSel = h("select", { "aria-label": "Replay speed" }, ...SPEEDS.map(([v, l]) => h("option", { value: String(v) }, l)));
  const nowBtn = h("button", { type: "button", class: "hud-rbtn" }, "Back to now");
  const clock = h("span", { class: "hud-rclock" });
  const strip = h("canvas", { class: "hud-rstrip", height: 36, title: "Amber ticks: something changed (a port, an update, a container)", "aria-hidden": "true" });
  const slider = h("input", { type: "range", min: 0, max: 1, step: 1, value: 1, "aria-label": "Moment to show" });
  const list = h("div", { class: "hud-revents" });
  const note = h("div", { class: "hud-rnote" });
  el.append(h("div", { class: "hud-rbar" }, playBtn, rangeSel, speedSel, nowBtn, clock), strip, slider, list, note);

  let data = null;                 // { from, to, series: Map(id -> [[ms, up]]), changes: [{id, t, up}], counts: [..] }
  let t = 0, playing = false, raf = 0, last = 0, active = false, loading = 0;

  const state = (id, at = t) => {
    const s = data && data.series.get(id);
    if (!s) return undefined;
    let lo = 0, hi = s.length - 1, ans = -1;
    while (lo <= hi) { const mid = (lo + hi) >> 1; if (s[mid][0] <= at) { ans = mid; lo = mid + 1; } else hi = mid - 1; }
    return ans < 0 ? s[0][1] : s[ans][1];
  };

  async function load() {
    const key = rangeSel.value, hours = RANGES.find((r) => r[0] === key)[1], ticket = ++loading;
    note.textContent = "Loading the history…";
    let body;
    try { body = await get(`/api/uptime/replay?hours=${hours}`); } catch (err) { note.textContent = "The history could not be loaded."; return; }
    if (ticket !== loading) return;
    const series = new Map(), changes = [];
    const from = Date.parse(body.from), to = Math.max(Date.parse(body.to), from + 60000);
    for (const c of body.changes) {
      const ms = Date.parse(c.ts);
      if (!series.has(c.id)) series.set(c.id, []);
      series.get(c.id).push([ms, c.up ? 1 : 0]);
      if (!c.initial) changes.push({ id: c.id, t: ms, up: c.up });
    }
    changes.sort((a, b) => a.t - b.t);
    // how many devices were online over the window (the strip under the radar)
    const bins = 240, counts = new Array(bins).fill(0), total = new Array(bins).fill(0);
    for (const [, s] of series) {
      let k = 0, cur = s[0][1];
      for (let b = 0; b < bins; b++) {
        const at = from + (to - from) * (b + 0.5) / bins;
        while (k + 1 < s.length && s[k + 1][0] <= at) { k++; cur = s[k][1]; }
        counts[b] += cur; total[b]++;
      }
    }
    const markers = (body.markers || []).map((m) => ({ id: m.id, t: Date.parse(m.ts), text: m.text })).filter((m) => m.t >= from && m.t <= to).sort((a, b) => a.t - b.t);
    data = { from, to, series, changes, counts, total, markers };
    slider.max = String(Math.round((to - from) / 60000));
    set(to, false);
    note.textContent = changes.length ? "" : "No device changed state in this period.";
    if (!series.size) note.textContent = "There are no checks in this period yet.";
  }

  function nameOf(id) { const d = (getDevices() || []).find((x) => x.id === id); return d ? (d.custom_name || d.hostname || d.primary_ip || `#${id}`) : `#${id}`; }
  function behind(id, at) {          // a device that is down while something above it is down (by today's hierarchy)
    const parent = new Map((getTree() || []).map((n) => [n.id, n.parent_id]));
    for (let p = parent.get(id), i = 0; p != null && i < 40; p = parent.get(p), i++) if (state(p, at) === 0) return p;
    return null;
  }
  function suspect(id, at) {          // a change on the device, or on something above it, in the three hours before it went down
    const parent = new Map((getTree() || []).map((n) => [n.id, n.parent_id]));
    const mine = new Set([id]);
    for (let p = parent.get(id), i = 0; p != null && i < 40; p = parent.get(p), i++) mine.add(p);
    let best = null;
    for (const m of data.markers) if (m.t <= at && at - m.t <= 3 * 3600000 && mine.has(m.id)) best = m;
    return best;
  }
  function drawList() {
    clear(list);
    const shown = data ? data.changes.filter((c) => c.t <= t).slice(-3).reverse() : [];
    if (!shown.length) { list.appendChild(h("div", { class: "hud-rev" }, "No changes yet in this period.")); return; }
    for (const c of shown) {
      const cause = !c.up ? behind(c.id, c.t) : null, after = !c.up && cause == null ? suspect(c.id, c.t) : null;
      list.appendChild(h("a", { class: `hud-rev ${c.up ? "ok" : "bad"}`, href: `#/device/${c.id}` },
        h("span", { class: "t" }, fmt(c.t)), ` ${nameOf(c.id)} ${c.up ? "answered again" : cause != null ? `unreachable (behind ${nameOf(cause)})` : "stopped answering"}`,
        after ? h("span", { class: "hud-rmark", title: "Something changed shortly before; open the device and ask 'What changed before it broke?'" }, ` · after: ${after.text}`) : ""));
    }
  }
  const fmt = (ms) => new Date(ms).toLocaleString([], { weekday: "short", hour: "2-digit", minute: "2-digit" });

  function drawStrip() {
    const r = strip.getBoundingClientRect(), dpr = Math.min(2, window.devicePixelRatio || 1);
    if (!r.width) return;
    strip.width = Math.round(r.width * dpr); strip.height = Math.round(36 * dpr);
    const c = strip.getContext("2d"); c.setTransform(dpr, 0, 0, dpr, 0, 0);
    const w = r.width, hh = 36; c.clearRect(0, 0, w, hh);
    if (!data) return;
    const bins = data.counts.length, max = Math.max(1, ...data.total), min = Math.min(...data.counts.map((v, i) => (data.total[i] ? v / data.total[i] : 1)));
    c.beginPath();
    for (let b = 0; b < bins; b++) {
      const frac = data.total[b] ? data.counts[b] / data.total[b] : 1;
      const y = 6 + (1 - (frac - Math.min(min, 0.9)) / (1 - Math.min(min, 0.9) || 1)) * (hh - 22);
      b ? c.lineTo(b / (bins - 1) * w, y) : c.moveTo(0, y);
    }
    c.strokeStyle = "#00e5ff"; c.lineWidth = 1.4; c.stroke();
    c.lineTo(w, hh); c.lineTo(0, hh); c.closePath();
    const g = c.createLinearGradient(0, 0, 0, hh); g.addColorStop(0, "rgba(0,229,255,.28)"); g.addColorStop(1, "rgba(0,229,255,0)"); c.fillStyle = g; c.fill();
    c.fillStyle = "rgba(255,59,92,.75)";
    for (const ch of data.changes) if (!ch.up) c.fillRect((ch.t - data.from) / (data.to - data.from) * w, hh - 5, 2, 5);
    c.fillStyle = "rgba(255,176,32,.9)";
    for (const m of data.markers) c.fillRect((m.t - data.from) / (data.to - data.from) * w - 1, 0, 2, 7);
    const x = (t - data.from) / (data.to - data.from) * w; c.strokeStyle = "#fff"; c.lineWidth = 1; c.beginPath(); c.moveTo(x, 0); c.lineTo(x, hh); c.stroke();
    void max;
  }

  // move to a moment; the radar is told which devices changed on the way (a ring spreads from each)
  function set(ms, fromUser) {
    if (!data) return;
    const prev = t;
    t = Math.max(data.from, Math.min(data.to, ms));
    slider.value = String(Math.round((t - data.from) / 60000));
    clock.textContent = `${fmt(t)}${t >= data.to - 60000 ? " · now" : ""}`;
    const lo = Math.min(prev, t), hi = Math.max(prev, t);
    const moved = prev && Math.abs(t - prev) < (data.to - data.from) / 3 ? data.changes.filter((c) => c.t > lo && c.t <= hi) : [];
    drawList(); drawStrip();
    onChange(moved.map((c) => ({ id: c.id, up: t >= prev ? c.up : !c.up })));
    if (fromUser) stop();
  }
  function stop() { playing = false; playBtn.textContent = "▶ Play"; }

  function frame(now) {
    raf = 0;
    if (!active) return;
    const dt = Math.min(80, now - (last || now)); last = now;
    if (playing && data) { if (t >= data.to) stop(); else set(t + dt * Number(speedSel.value)); }
    raf = requestAnimationFrame(frame);
  }

  playBtn.addEventListener("click", () => { if (!data) return; if (t >= data.to - 1000) set(data.from, false); playing = !playing; playBtn.textContent = playing ? "❚❚ Pause" : "▶ Play"; last = 0; });
  nowBtn.addEventListener("click", () => { stop(); load(); });
  rangeSel.addEventListener("change", () => { stop(); speedSel.value = String(RANGES.find((r) => r[0] === rangeSel.value)[2]); load(); });
  rangeSel.value = RANGES[1][0];
  speedSel.value = String(RANGES[1][2]);
  slider.addEventListener("input", () => data && set(data.from + Number(slider.value) * 60000, true));
  strip.addEventListener("click", (e) => { if (!data) return; const r = strip.getBoundingClientRect(); set(data.from + (e.clientX - r.left) / r.width * (data.to - data.from), true); });
  const observer = typeof ResizeObserver === "function" ? new ResizeObserver(() => drawStrip()) : null;
  if (observer) observer.observe(strip);

  return {
    el,
    // the devices of the radar as they were at the chosen moment (devices without checks in the period are left out)
    apply: (devices) => devices.filter((d) => !d.virtual && state(d.id) !== undefined).map((d) => ({ ...d, online: state(d.id) === 1 })),
    activate(on) {
      active = on; el.hidden = !on;
      if (on) { last = 0; if (!data) load(); else drawStrip(); if (!raf) raf = requestAnimationFrame(frame); } else { stop(); if (raf) { cancelAnimationFrame(raf); raf = 0; } }
    },
    dispose() { active = false; stop(); if (raf) cancelAnimationFrame(raf); if (observer) observer.disconnect(); },
  };
}
