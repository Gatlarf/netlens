// The menu level: Basic shows the everyday pages, Standard adds the regular ones, Advanced shows everything.
// It only changes what the menus list. It is not access control: the server decides what a user may open, and every address keeps working.
// (Mock-up: kept per browser. The real thing would be a setting of the user.)
export const LEVELS = ["basic", "standard", "advanced"];
const KEY = "netlens.menu_level";

export function getLevel() {
  try {
    const v = localStorage.getItem(KEY);
    return LEVELS.includes(v) ? v : "advanced";     // nothing is hidden until someone asks for it
  } catch (e) {
    return "advanced";
  }
}

export function setLevel(level) {
  if (!LEVELS.includes(level)) return;
  try { localStorage.setItem(KEY, level); } catch (e) { /* the level then lasts for this visit only */ }
  document.dispatchEvent(new CustomEvent("netlens:level-changed", { detail: level }));
}

export function levelShows(min) {
  return LEVELS.indexOf(getLevel()) >= LEVELS.indexOf(min || "basic");
}

export function lowestLevel(levels) {
  return levels.reduce((a, b) => (LEVELS.indexOf(b || "basic") < LEVELS.indexOf(a) ? (b || "basic") : a), "advanced");
}
