// Light / dark switch. The choice is remembered in this browser; without one the system setting applies.
const KEY = "netlens.theme";
const ICON = { dark: "☀", light: "☾" }; // shows the mode a click switches to: sun / moon

export function currentTheme() {
  const attr = document.documentElement.getAttribute("data-theme");
  if (attr === "dark" || attr === "light") return attr;
  return window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
}

export function isDark() {
  return currentTheme() === "dark";
}

// the value of a CSS variable of the current theme, e.g. cssVar("--text")
export function cssVar(name, fallback = "") {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim() || fallback;
}

function updateButton() {
  const btn = document.getElementById("theme-toggle");
  if (!btn) return;
  const dark = isDark();
  btn.textContent = dark ? ICON.dark : ICON.light;
  const label = dark ? "Switch to light mode" : "Switch to dark mode";
  btn.setAttribute("aria-label", label);
  btn.title = label;
}

function announce() {
  updateButton();
  document.dispatchEvent(new CustomEvent("netlens:theme", { detail: { theme: currentTheme() } }));
}

export function setTheme(theme) {
  document.documentElement.setAttribute("data-theme", theme);
  try {
    localStorage.setItem(KEY, theme);
  } catch (e) {
    // storage unavailable: the choice lasts until the page is closed
  }
  announce();
}

export function initThemeToggle() {
  const btn = document.getElementById("theme-toggle");
  if (!btn) return;
  updateButton();
  btn.addEventListener("click", () => setTheme(isDark() ? "light" : "dark"));
  // while the user has not chosen, follow the system when it changes
  if (window.matchMedia) {
    window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", () => {
      if (!document.documentElement.hasAttribute("data-theme")) announce();
    });
  }
}
