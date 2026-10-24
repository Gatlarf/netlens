import { get } from "./api.js";
import { applyDefaultLook, isHud } from "./theme.js";

// The look-and-feel options the administrator set (Settings → Interface), applied to every page, and the HUD scanline that flashes red when a device
// goes offline and green when one comes back. The options arrive with the session (so the sign-in page has them too) and again when they are saved.
const DEFAULTS = { default_look: "system", pulse_seconds: 2, pulse_scope: "hud", pulse_for: "all", hud_sweep: true, hud_lines: true };
let cfg = { ...DEFAULTS };
let lastId = null;
let timer = null;
let flasher = null;
let off = null;

export const interfaceSettings = () => ({ ...cfg });

export function applyInterface(settings) {
  cfg = { ...DEFAULTS, ...(settings || {}) };
  const root = document.documentElement;
  root.toggleAttribute("data-no-sweep", !cfg.hud_sweep);
  root.toggleAttribute("data-no-lines", !cfg.hud_lines);
  try { localStorage.setItem("netlens.default-look", cfg.default_look); } catch (e) { /* the next visit asks again */ }
  applyDefaultLook(cfg.default_look);
  if (!timer) timer = setInterval(poll, 4000);
}

// the scanline pulse: kind "bad" (red) or "good" (green)
export function flash(kind, seconds = cfg.pulse_seconds) {
  if (!isHud() || !(seconds > 0) || window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;
  if (!flasher) { flasher = document.createElement("div"); flasher.id = "hud-pulse"; flasher.setAttribute("aria-hidden", "true"); document.body.appendChild(flasher); }
  flasher.className = "";
  void flasher.offsetWidth;                                   // restart the animation when a second event follows the first
  flasher.dataset.kind = kind;
  flasher.style.setProperty("--pulse-s", `${seconds}s`);
  flasher.className = "go";
  clearTimeout(off);
  off = setTimeout(() => { flasher.className = ""; }, seconds * 1000 + 300);
}

const wanted = (e) => {
  if (e.maintenance) return false;                            // held back by a maintenance window: nothing to flash about
  if (cfg.pulse_for === "always_on") return !!e.always_on || e.tier === "critical";
  if (cfg.pulse_for === "critical") return e.tier === "critical";
  return true;
};

async function poll() {
  if (document.hidden || !isHud()) return;
  try {
    if (lastId === null) { const first = await get("/api/events?limit=1"); lastId = first.length ? first[0].id : 0; return; }
    const events = await get(`/api/events?since_id=${lastId}&limit=100`);
    if (!events.length) return;
    lastId = Math.max(lastId, ...events.map((e) => e.id));
    if (!(cfg.pulse_seconds > 0) || (cfg.pulse_scope === "hud" && !location.hash.startsWith("#/hud"))) return;
    const mine = events.filter((e) => (e.kind === "device_offline" || e.kind === "device_online") && wanted(e));
    if (mine.some((e) => e.kind === "device_offline")) flash("bad");
    else if (mine.length) flash("good");
  } catch (err) { /* the next round tries again */ }
}

document.addEventListener("netlens:interface", (e) => applyInterface(e.detail));
