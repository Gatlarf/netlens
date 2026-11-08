import { h, clear } from "../util.js";
import { svg } from "../flows.js";

// An incident replayed on the network tree: press play and the devices turn red and green in the order they went and came back.
export function cascade(box, data) {
  clear(box);
  if (!data.steps.length) return;
  const kids = new Map(), byId = new Map(data.nodes.map((n) => [n.id, n]));
  for (const n of data.nodes) if (n.parent_id != null) kids.set(n.parent_id, [...(kids.get(n.parent_id) || []), n.id]);
  const x = new Map(), depth = new Map();
  let leaf = 0, deepest = 0;
  const place = (id, d) => {
    depth.set(id, d); deepest = Math.max(deepest, d);
    const children = kids.get(id) || [];
    if (!children.length) { x.set(id, leaf++); return; }
    children.forEach((c) => place(c, d + 1));
    x.set(id, children.reduce((a, c) => a + x.get(c), 0) / children.length);
  };
  data.nodes.filter((n) => n.parent_id == null).forEach((n) => place(n.id, 0));
  const dx = Math.max(64, Math.min(110, 720 / Math.max(1, leaf))), dy = 62, W = Math.max(240, leaf * dx), H = 40 + deepest * dy + 28;
  const root = svg("svg", { viewBox: `0 0 ${W} ${H}`, width: Math.round(W * 1.3), class: "cascade-tree", role: "img", "aria-label": `${data.title}, replayed` });
  const at = (id) => ({ x: (x.get(id) + 0.5) * dx, y: 22 + depth.get(id) * dy });
  for (const n of data.nodes) if (n.parent_id != null) { const a = at(n.parent_id), b = at(n.id); root.appendChild(svg("line", { class: "cascade-edge", x1: a.x, y1: a.y, x2: b.x, y2: b.y })); }
  const dots = new Map();
  for (const n of data.nodes) {
    const p = at(n.id), dot = svg("circle", { class: "cascade-dot", cx: p.x, cy: p.y, r: 9 });
    dot.appendChild(svg("title")).textContent = n.name;
    root.append(dot);
    const label = svg("text", { class: "flow-label", x: p.x, y: p.y + 24, "text-anchor": "middle" });
    label.textContent = n.name.length > 16 ? `${n.name.slice(0, 15)}…` : n.name;
    root.append(label);
    dots.set(n.id, dot);
  }
  const play = h("button", { type: "button", class: "btn" }, "▶ Play");
  const slider = h("input", { type: "range", min: 0, max: 1000, value: 0, "aria-label": "Moment of the incident" });
  const clock = h("span", { class: "cascade-clock" });
  const span = Math.max(data.steps[data.steps.length - 1].t, data.duration);
  let t = 0, playing = false, last = 0, raf = 0;
  const fmt = (s) => (s < 90 ? `+${Math.round(s)} s` : s < 5400 ? `+${Math.round(s / 60)} min` : `+${(s / 3600).toFixed(1)} h`);
  const draw = (fresh) => {
    const state = new Map(), when = new Map();
    for (const s of data.steps) if (s.t <= t) { state.set(s.id, s.state); when.set(s.id, s.t); }
    for (const [id, dot] of dots) {
      const s = state.get(id), pulse = fresh && s && t - when.get(id) < span * 0.04;
      dot.setAttribute("class", `cascade-dot${s ? ` ${s}` : ""}${pulse ? " fresh" : ""}`);
    }
    clock.textContent = fmt(t);
    slider.value = String(Math.round((t / span) * 1000));
  };
  const frame = (now) => {
    raf = 0;
    if (!playing) return;
    t += Math.min(80, now - (last || now)) * (span / 9000); last = now;
    if (t >= span) { t = span; playing = false; play.textContent = "▶ Play"; }
    draw(true);
    if (playing) raf = requestAnimationFrame(frame);
  };
  play.addEventListener("click", () => {
    if (playing) { playing = false; play.textContent = "▶ Play"; return; }
    if (t >= span) t = 0;
    playing = true; last = 0; play.textContent = "❚❚ Pause"; raf = requestAnimationFrame(frame);
  });
  slider.addEventListener("input", () => { playing = false; play.textContent = "▶ Play"; t = (Number(slider.value) / 1000) * span; draw(false); });
  draw(false);
  box.append(h("div", { class: "cascade-bar" }, play, slider, clock), root);
}
