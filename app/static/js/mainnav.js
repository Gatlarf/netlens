// The page menu: only the headings on the left, the pages of the current heading as tabs above the page (the same design as Settings).
// Optional pages (backups, storage, ...) are listed only when a plugin of their kind is switched on; pages that need an administrator are not listed for anybody else.
import { h, clear, isAdmin } from "./util.js";
import { fold, unfold, peek, canFold } from "./sidefold.js";
import { slideAwayOnScroll } from "./tabbar.js";

// route = the page's name in app.js; also = other routes that belong to the same tab (a device page is part of Devices)
export const NAV = [
  { key: "dashboard", title: "Dashboard", items: [{ route: "dashboard", href: "#/dashboard", label: "Dashboard" }] },
  { key: "network", title: "Network", items: [
    { route: "map", href: "#/map", label: "Map" },
    { route: "hud", href: "#/hud", label: "HUD" },
    { route: "devices", href: "#/devices", label: "Devices", also: ["device"] },
    { route: "dns", href: "#/dns", label: "DNS", feature: "dns", admin: true },
    { route: "remote_sites", href: "#/remote-sites", label: "Remote sites", feature: "remote_sites" },
    { route: "remote", href: "#/remote", label: "Remote access", admin: true },
  ] },
  { key: "monitoring", title: "Monitoring", items: [
    { route: "uptime", href: "#/uptime", label: "Uptime" },
    { route: "health", href: "#/health", label: "Health" },
    { route: "services", href: "#/services", label: "Services" },
    { route: "backups", href: "#/backups", label: "Backups", feature: "backups", admin: true },
    { route: "storage", href: "#/storage", label: "Storage", feature: "storage", admin: true },
    { route: "smarthome", href: "#/smarthome", label: "Smart home", feature: "smarthome", admin: true },
  ] },
  { key: "analysis", title: "Analysis", items: [
    { route: "stats", href: "#/stats", label: "Statistics" },
    { route: "network_health", href: "#/network-health", label: "Network health", admin: true },
    { route: "vulnerabilities", href: "#/vulnerabilities", label: "Vulnerabilities", feature: "vulnerabilities", admin: true },
    { route: "reports", href: "#/reports", label: "Reports" },
    { route: "insights", href: "#/insights", label: "Insights", admin: true },
    { route: "changes", href: "#/changes", label: "What changed" },
    { route: "speedtest", href: "#/speedtest", label: "Speed tests" },
    { route: "scans", href: "#/scans", label: "Scans & events" },
  ] },
  { key: "automation", title: "Automation", admin: true, items: [{ route: "remediation", href: "#/remediation", label: "Remediation", admin: true }] },
  { key: "settings", title: "Settings", admin: true, items: [{ route: "settings", href: "#/settings", label: "Settings", admin: true }] },
];

const ALSO = { hierarchy: "network", wizard: "settings" };          // pages that belong to a heading without a tab of their own
const HUD_DELAY = 8000;                                             // the HUD stays open for hours: its menu goes away after this long

let features = {};
let current = "";
let sideBox = null;
let tabsBox = null;
let stopScroll = null;

const remembered = (key) => { try { return sessionStorage.getItem(`netlens.nav.tab.${key}`) || ""; } catch (e) { return ""; } };
const remember = (key, route) => { try { sessionStorage.setItem(`netlens.nav.tab.${key}`, route); } catch (e) { /* private window */ } };

// What this person sees: no page that needs an administrator for anybody else, no optional page without its plugin
function visibleItems(group) {
  if (group.admin && !isAdmin()) return [];
  return group.items.filter((i) => (!i.admin || isAdmin()) && (!i.feature || features[i.feature] !== false));
}

function groupOf(route) {
  return NAV.find((g) => g.items.some((i) => i.route === route || (i.also || []).includes(route))) || NAV.find((g) => g.key === ALSO[route]) || null;
}

const scoped = () => Boolean(sideBox && sideBox.dataset.scoped);          // a customer's own view has a short menu of its own (app.js)

function drawSide() {
  if (!sideBox || scoped()) return;
  clear(sideBox);
  const here = groupOf(current);
  let hiddenFeatures = 0;
  for (const g of NAV) for (const i of g.items) if (i.feature && features[i.feature] === false) hiddenFeatures += 1;
  for (const g of NAV) {
    const shown = visibleItems(g);
    if (!shown.length) continue;
    const target = shown.find((i) => i.route === remembered(g.key)) || shown[0];
    const single = shown.length === 1;
    const link = h("a", { class: `nav-link${g === here ? " active" : ""}`, href: target.href, "data-group": g.key, ...(single ? { "data-route": target.route } : {}) }, g.title);
    if (g === here) link.setAttribute("aria-current", "page");
    sideBox.appendChild(link);
  }
  if (isAdmin() && hiddenFeatures) {
    sideBox.appendChild(h("a", { id: "nav-more", class: "nav-link nav-more", href: "#/settings/plugin-browse", title: "Backups, storage, vulnerabilities and more come from plugins" }, "+ More features"));
  }
}

function drawTabs() {
  if (!tabsBox) return;
  clear(tabsBox);
  if (scoped()) { tabsBox.hidden = true; return; }
  const g = groupOf(current);
  const shown = g ? visibleItems(g) : [];
  tabsBox.hidden = shown.length < 2 || current === "settings";          // Settings has its own tabs
  for (const i of shown) {
    const on = i.route === current || (i.also || []).includes(current);
    const link = h("a", { href: i.href, role: "tab", "data-route": i.route }, i.label);
    if (on) { link.classList.add("active"); link.setAttribute("aria-current", "page"); link.setAttribute("aria-selected", "true"); }
    tabsBox.appendChild(link);
  }
}

// ---- the HUD: a page that stays open. Its menu goes away after a while; the left edge of the screen or the menu button brings it back for a moment.
let hudTimer = 0;
let hudStop = null;
function hudMenu(show) {
  if (tabsBox) { tabsBox.classList.toggle("tabs-away", !show); tabsBox.classList.toggle("tabs-folded", !show); }          // folded: it takes no room either
  fold();                      // takes hold of the menu (a menu hidden by choice stays that way when the HUD is left)
  peek(show);
}
function startHud() {
  stopHud();
  const arm = () => { clearTimeout(hudTimer); hudTimer = setTimeout(() => hudMenu(false), HUD_DELAY); };
  const edge = h("div", { id: "side-peek", class: "side-peek", "aria-hidden": "true" });
  document.body.appendChild(edge);
  const onEdge = () => { hudMenu(true); arm(); };
  edge.addEventListener("mouseenter", onEdge);
  const burger = document.getElementById("nav-toggle");
  const onBurger = (e) => {            // on the HUD the button shows the menu for a moment instead of changing your saved choice
    if (!canFold()) return;
    e.stopImmediatePropagation();
    e.preventDefault();
    const hiddenNow = document.body.classList.contains("side-hidden");
    hudMenu(hiddenNow);
    if (hiddenNow) arm();
  };
  const keep = () => { if (!document.body.classList.contains("side-hidden")) arm(); };
  const nav = document.getElementById("nav");
  if (burger) burger.addEventListener("click", onBurger, true);
  if (nav) { nav.addEventListener("mousemove", keep); nav.addEventListener("focusin", keep); }
  if (tabsBox) { tabsBox.addEventListener("mousemove", keep); tabsBox.addEventListener("focusin", keep); }
  arm();
  hudStop = () => {
    clearTimeout(hudTimer);
    edge.remove();
    if (burger) burger.removeEventListener("click", onBurger, true);
    if (nav) { nav.removeEventListener("mousemove", keep); nav.removeEventListener("focusin", keep); }
    if (tabsBox) { tabsBox.removeEventListener("mousemove", keep); tabsBox.removeEventListener("focusin", keep); tabsBox.classList.remove("tabs-away", "tabs-folded"); }
    unfold();
  };
}
function stopHud() { if (hudStop) { hudStop(); hudStop = null; } }

// ---- the page changed
export function showRoute(route) {
  const was = current;
  current = route === "device" ? "device" : route;
  const g = groupOf(current);
  if (g) {
    const item = g.items.find((i) => i.route === current || (i.also || []).includes(current));
    if (item) remember(g.key, item.route);
  }
  drawSide();
  drawTabs();
  if (current === "hud" && was !== "hud") startHud();
  else if (current !== "hud" && was === "hud") stopHud();
}

export function setFeatures(next) {
  features = next || {};
  drawSide();
  drawTabs();
}

// The session is known (who may see what): build the menu
export function initMainNav() {
  sideBox = document.getElementById("side-links");
  tabsBox = document.getElementById("page-tabs");
  if (!sideBox) return;
  if (tabsBox && !stopScroll) stopScroll = slideAwayOnScroll(tabsBox);
  drawSide();
  drawTabs();
}
