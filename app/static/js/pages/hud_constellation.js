import { h } from "../util.js";

// The constellation view of the HUD: every device is a star, the links are the network hierarchy, and a check of a device sends a pulse of light from the top of
// the network down the links to it. A device that is down answers with a red flash; everything behind a broken device turns grey (the pulse cannot get there).
// The layout is a small force simulation that is calculated while you look and settles by itself; stars keep their place when the data refreshes.
const REDUCED = typeof matchMedia === "function" && matchMedia("(prefers-reduced-motion: reduce)").matches;
const OK = "#00ffa3", BAD = "#ff3b5c", GREY = "#4a6272", CYAN = "#00e5ff";
const MAX_PULSES = 70;                // more at once is noise, not information
const HOP_MS = 230;                   // time a pulse needs for one link

export function constellation({ onOpen }) {
  const el = h("div", { class: "hud-const", hidden: true });
  const canvas = h("canvas", { class: "hud-const-canvas", tabindex: 0, role: "img", "aria-label": "Constellation of all devices: stars are devices, lines are the network links, a pulse of light is a check" });
  const tip = h("div", { class: "hud-const-tip", hidden: true });
  const note = h("div", { class: "hud-const-note" });
  el.append(canvas, tip, note);

  const nodes = new Map();            // id -> star
  const pulses = [], queue = [];
  let w = 300, h2 = 300, dpr = 1, raf = 0, visible = false, alpha = 1, hover = null, last = 0, signature = "";
  const ctx = canvas.getContext("2d");

  function resize() {
    const r = el.getBoundingClientRect();
    if (!r.width || !r.height) return;
    dpr = Math.min(2, window.devicePixelRatio || 1);
    w = r.width; h2 = r.height;
    canvas.width = Math.round(w * dpr); canvas.height = Math.round(h2 * dpr);
    canvas.style.width = `${w}px`; canvas.style.height = `${h2}px`;
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    alpha = Math.max(alpha, 0.5);
    request();
  }
  const observer = typeof ResizeObserver === "function" ? new ResizeObserver(resize) : null;
  if (observer) observer.observe(el);

  // ---- data ----
  // devices: what to show (real devices and, with the switch on, containers); tree: the hierarchy (parent_id of every device and container)
  function update(devices, tree) {
    const present = new Map(devices.map((d) => [d.id, d]));
    const parentOf = new Map((tree || []).map((n) => [n.id, n.parent_id]));
    const effective = (id) => { for (let p = parentOf.get(id); p != null; p = parentOf.get(p)) if (present.has(p)) return p; return null; };   // the nearest parent that is on the screen
    let changed = false;
    for (const id of [...nodes.keys()]) if (!present.has(id)) { nodes.delete(id); changed = true; }
    for (const d of devices) {
      let n = nodes.get(d.id);
      if (!n) {
        const parent = nodes.get(effective(d.id));
        const a = Math.random() * 6.283;
        n = { id: d.id, x: (parent ? parent.x : w / 2) + Math.cos(a) * 30, y: (parent ? parent.y : h2 / 2) + Math.sin(a) * 30, vx: 0, vy: 0, flash: 0, flashCol: OK, kids: 0 };
        nodes.set(d.id, n);
        changed = true;
      }
      const parentId = effective(d.id);
      if (n.parentId !== parentId) changed = true;
      n.parentId = parentId;
      n.name = d.custom_name || d.name || d.hostname || d.primary_ip || String(d.id);
      n.online = !!d.online; n.virtual = !!d.virtual; n.host = d.host_id;
      n.colour = d.group_color || CYAN;
      n.important = d.tier === "critical" || !!d.always_on;
    }
    for (const n of nodes.values()) n.kids = 0;
    for (const n of nodes.values()) { const p = nodes.get(n.parentId); if (p) p.kids++; }
    const sig = [...nodes.keys()].join(",");
    if (changed || sig !== signature) { signature = sig; alpha = 1; if (nodes.size <= 120) settle(160); }
    for (const n of nodes.values()) n.radius = n.virtual ? 2.2 : 3.2 + (n.important ? 1.8 : 0) + Math.min(3, n.kids * 0.45);
    note.textContent = nodes.size ? "" : "No devices to show.";
    request();
  }

  const unreachable = (n) => { for (let p = nodes.get(n.parentId), i = 0; p && i < 40; p = nodes.get(p.parentId), i++) if (!p.online) return p; return null; };

  // ---- the layout: links are springs, stars push each other away, a little gravity keeps them on the screen ----
  function settle(steps) { for (let i = 0; i < steps; i++) step(); }
  function step() {
    const list = [...nodes.values()], n = list.length;
    if (!n) return;
    const len = Math.max(26, Math.min(80, Math.sqrt(w * h2 / n) * 0.42));
    const push = len * len * 1.6;
    for (const a of list) { a.vx *= 0.8; a.vy *= 0.8; a.vx += (w / 2 - a.x) * 0.0018 * alpha; a.vy += (h2 / 2 - a.y) * 0.0018 * alpha; }
    for (let i = 0; i < n; i++) for (let j = i + 1; j < n; j++) {
      const a = list[i], b = list[j];
      let dx = a.x - b.x, dy = a.y - b.y;
      const d2 = Math.max(40, dx * dx + dy * dy);
      if (d2 > push * 30) continue;                      // far apart: no effect worth the time
      const f = push / d2 * alpha, d = Math.sqrt(d2);
      dx /= d; dy /= d; a.vx += dx * f; a.vy += dy * f; b.vx -= dx * f; b.vy -= dy * f;
    }
    for (const a of list) {
      const p = nodes.get(a.parentId); if (!p) continue;
      const dx = p.x - a.x, dy = p.y - a.y, dist = Math.hypot(dx, dy) || 1;
      const want = a.virtual ? len * 0.45 : len * (0.7 + Math.min(1, a.kids * 0.12));
      const f = (dist - want) * 0.04 * alpha;
      a.vx += dx / dist * f; a.vy += dy / dist * f; p.vx -= dx / dist * f * 0.6; p.vy -= dy / dist * f * 0.6;
    }
    for (const a of list) { a.x = Math.max(24, Math.min(w - 24, a.x + a.vx)); a.y = Math.max(34, Math.min(h2 - 28, a.y + a.vy)); }
    alpha = Math.max(0.0, alpha * 0.985 - 0.0004);
  }

  // ---- checks: a pulse from the top of the network down to the device ----
  function flash(ids) {
    if (!visible || REDUCED) return;               // no pulses for people who asked for less motion
    let rank = 0;
    for (const id of ids) {
      const n = nodes.get(id);
      if (!n) continue;
      const path = [];
      for (let p = n, i = 0; p && i < 40; p = nodes.get(p.parentId), i++) path.unshift(p);
      queue.push({ path, at: performance.now() + Math.min(4000, rank++ * 35 + Math.random() * 200) });     // a scan of many devices becomes a wave, not a flash
    }
    request();
  }
  function arrive(n, ok) { n.flash = 1; n.flashCol = ok ? OK : BAD; }

  // ---- drawing ----
  function draw(now) {
    const dt = Math.min(60, now - (last || now)); last = now;
    if (alpha > 0.002 && nodes.size) step();
    for (let i = queue.length - 1; i >= 0; i--) if (queue[i].at <= now) { const q = queue.splice(i, 1)[0]; if (pulses.length < MAX_PULSES) pulses.push({ path: q.path, seg: 0, t: 0 }); }
    ctx.clearRect(0, 0, w, h2);
    const bg = ctx.createRadialGradient(w / 2, h2 / 2, 20, w / 2, h2 / 2, Math.max(w, h2) * 0.7);
    bg.addColorStop(0, "rgba(6, 41, 60, 0.55)"); bg.addColorStop(1, "rgba(1, 10, 18, 0)");
    ctx.fillStyle = bg; ctx.fillRect(0, 0, w, h2);
    if (!REDUCED) for (const n of nodes.values()) { n.x += Math.sin(now / 2400 + n.x) * 0.04; n.y += Math.cos(now / 2900 + n.y) * 0.04; }   // a slow breathing

    for (const n of nodes.values()) {
      const p = nodes.get(n.parentId); if (!p) continue;
      const dead = !n.online || !p.online || unreachable(n);
      ctx.strokeStyle = dead ? "rgba(255, 59, 92, 0.32)" : n.virtual ? "rgba(0, 229, 255, 0.14)" : "rgba(0, 229, 255, 0.28)";
      ctx.lineWidth = n.virtual ? 0.7 : 1 + Math.min(2, n.kids * 0.2); ctx.setLineDash(dead ? [4, 5] : []);
      ctx.beginPath(); ctx.moveTo(n.x, n.y); ctx.lineTo(p.x, p.y); ctx.stroke();
    }
    ctx.setLineDash([]);

    for (let i = pulses.length - 1; i >= 0; i--) {
      const u = pulses[i], a = u.path[u.seg], b = u.path[u.seg + 1];
      if (!b) { pulses.splice(i, 1); continue; }
      u.t += dt / HOP_MS;
      const f = Math.min(1, u.t), x = a.x + (b.x - a.x) * f, y = a.y + (b.y - a.y) * f;
      const g = ctx.createRadialGradient(x, y, 0, x, y, 13);
      g.addColorStop(0, "rgba(170, 255, 255, 0.95)"); g.addColorStop(1, "rgba(0, 229, 255, 0)");
      ctx.fillStyle = g; ctx.beginPath(); ctx.arc(x, y, 13, 0, 6.3); ctx.fill();
      if (u.t >= 1) {
        if (!b.online) { arrive(b, false); pulses.splice(i, 1); continue; }          // a device that is down stops the pulse and answers with red
        u.seg++; u.t = 0;
        if (u.seg >= u.path.length - 1) { arrive(b, true); pulses.splice(i, 1); }
      }
    }

    for (const n of nodes.values()) {
      const blocked = n.online && unreachable(n);
      const col = !n.online ? BAD : blocked ? GREY : n.colour;
      n.flash = Math.max(0, n.flash - dt / 700);
      const r = n.radius, halo = r * 4.5 + n.flash * 20;
      const g = ctx.createRadialGradient(n.x, n.y, 0, n.x, n.y, halo);
      g.addColorStop(0, !n.online ? `rgba(255, 59, 92, ${0.35 + n.flash * 0.5})` : blocked ? "rgba(90, 120, 140, 0.3)" : `rgba(0, 229, 255, ${0.25 + n.flash * 0.5})`); g.addColorStop(1, "rgba(0, 0, 0, 0)");
      ctx.fillStyle = g; ctx.beginPath(); ctx.arc(n.x, n.y, halo, 0, 6.3); ctx.fill();
      ctx.fillStyle = col; ctx.shadowColor = col; ctx.shadowBlur = 7 + n.flash * 14;
      ctx.beginPath(); ctx.arc(n.x, n.y, r + n.flash * 1.4, 0, 6.3); ctx.fill(); ctx.shadowBlur = 0;
      if (n.flash > 0) { ctx.strokeStyle = n.flashCol; ctx.globalAlpha = n.flash; ctx.lineWidth = 1.4; ctx.beginPath(); ctx.arc(n.x, n.y, r + (1 - n.flash) * 20, 0, 6.3); ctx.stroke(); ctx.globalAlpha = 1; }
    }
    drawLabels();
  }

  // names: the busiest stars first, a name that would overlap one already written is left out, and none runs off the edge
  function drawLabels() {
    ctx.font = "11px ui-monospace, Menlo, Consolas, monospace"; ctx.textAlign = "left";
    const want = [...nodes.values()].filter((n) => n === hover || (!n.virtual && (n.important || n.kids >= 3)));
    want.sort((a, b) => (b === hover) - (a === hover) || b.kids - a.kids || (b.important === true) - (a.important === true));
    const placed = [];
    for (const n of want) {
      const text = n.name.length > 18 ? `${n.name.slice(0, 17)}…` : n.name;
      const tw = ctx.measureText(text).width, x = Math.max(4, Math.min(w - tw - 4, n.x - tw / 2)), y = n.y - n.radius - 7;
      const box = { x0: x - 2, x1: x + tw + 2, y0: y - 10, y1: y + 3 };
      if (n !== hover && placed.some((b) => box.x0 < b.x1 && box.x1 > b.x0 && box.y0 < b.y1 && box.y1 > b.y0)) continue;
      placed.push(box);
      ctx.fillStyle = n === hover ? "#ffffff" : "rgba(170, 220, 242, 0.85)"; ctx.fillText(text, x, y);
    }
  }

  function frame(now) {
    raf = 0;
    if (!visible) return;
    draw(now);
    if (!REDUCED) request();                      // the breathing never stops; with reduced motion the picture is only redrawn when something changes
  }
  function request() { if (visible && !raf) raf = requestAnimationFrame(frame); }

  // ---- hover and click ----
  const find = (e) => {
    const r = canvas.getBoundingClientRect(), x = e.clientX - r.left, y = e.clientY - r.top;
    let best = null, bd = 16;
    for (const n of nodes.values()) { const d = Math.hypot(n.x - x, n.y - y); if (d < bd) { bd = d; best = n; } }
    return { n: best, x, y };
  };
  canvas.addEventListener("mousemove", (e) => {
    const { n, x, y } = find(e);
    hover = n; canvas.style.cursor = n ? "pointer" : "";
    if (n) { const p = unreachable(n); tip.hidden = false; tip.style.left = `${x + 14}px`; tip.style.top = `${y + 10}px`; tip.textContent = `${n.name}${n.virtual ? " (container)" : ""} · ${!n.online ? "offline" : p ? `unreachable, behind ${p.name}` : "online"}`; }
    else tip.hidden = true;
  });
  canvas.addEventListener("mouseleave", () => { hover = null; tip.hidden = true; });
  canvas.addEventListener("click", (e) => { const { n } = find(e); if (n) onOpen(n); });

  return {
    el,
    update,
    flash,
    show(on) { visible = on; el.hidden = !on; if (on) { resize(); last = 0; request(); } else if (raf) { cancelAnimationFrame(raf); raf = 0; } },
    dispose() { visible = false; if (raf) cancelAnimationFrame(raf); if (observer) observer.disconnect(); },
  };
}
