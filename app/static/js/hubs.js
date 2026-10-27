// Pages that were separate menu items and are now tabs of one page. A tab keeps its own address ("#/hierarchy"), so old links,
// bookmarks and the click-throughs from problems still work: the address opens the page it belongs to, on the right tab.
import { isAdmin } from "./util.js";
import { levelShows, lowestLevel } from "./levels.js";

export const HUBS = [
  { id: "devices", tabs: [
    { route: "devices", hash: "#/devices", label: "List", level: "basic" },
    { route: "hierarchy", hash: "#/hierarchy", label: "Hierarchy", level: "standard" },
    { route: "dns", hash: "#/dns", label: "DNS", level: "standard", feature: "dns" },
    { route: "remote", hash: "#/remote", label: "Remote access", level: "advanced", admin: true },
  ] },
  { id: "uptime", tabs: [
    { route: "uptime", hash: "#/uptime", label: "Uptime", level: "basic" },
    { route: "services", hash: "#/services", label: "Services", level: "standard" },
  ] },
  { id: "health", tabs: [
    { route: "health", hash: "#/health", label: "Health", level: "basic" },
    { route: "network_health", hash: "#/network-health", label: "Network checks", level: "standard" },
  ] },
  { id: "storage", tabs: [
    { route: "storage", hash: "#/storage", label: "Storage", level: "standard", feature: "storage" },
    { route: "backups", hash: "#/backups", label: "Backups", level: "standard", feature: "backups" },
    { route: "smarthome", hash: "#/smarthome", label: "Smart home", level: "standard", feature: "smarthome" },
  ] },
  { id: "stats", tabs: [
    { route: "stats", hash: "#/stats", label: "Traffic", level: "basic" },
    { route: "speedtest", hash: "#/speedtest", label: "Speed tests", level: "basic" },
    { route: "reports", hash: "#/reports", label: "Reports", level: "standard" },
  ] },
  { id: "changes", tabs: [
    { route: "changes", hash: "#/changes", label: "What changed", level: "standard" },
    { route: "scans", hash: "#/scans", label: "Scans & events", level: "advanced" },
  ] },
  { id: "insights", tabs: [
    { route: "insights", hash: "#/insights", label: "Insights", level: "standard", admin: true },
    { route: "remediation", hash: "#/remediation", label: "Remediation", level: "advanced", admin: true },
  ] },
];

export const featureFlags = {};      // filled from /api/features; a missing key counts as on

export const hubById = (id) => HUBS.find((h) => h.id === id);
export const hubOf = (route) => HUBS.find((h) => h.tabs.some((t) => t.route === route));

// the tabs this user can use at all (installed, allowed), whatever the level
export function usableTabs(hub) {
  return hub.tabs.filter((t) => (!t.feature || featureFlags[t.feature] !== false) && (!t.admin || isAdmin()));
}

// the tabs the menu level shows
export function shownTabs(hub) {
  return usableTabs(hub).filter((t) => levelShows(t.level));
}

export const hubLevel = (hub) => lowestLevel(usableTabs(hub).map((t) => t.level));

// the tab bar above a page; the tab being looked at is always listed, even when the level would hide it
export function tabBar(hub, activeRoute) {
  const bar = document.createElement("div");
  bar.className = "tabs hub-tabs";
  bar.setAttribute("role", "tablist");
  const tabs = usableTabs(hub).filter((t) => levelShows(t.level) || t.route === activeRoute);
  if (tabs.length < 2) return null;
  for (const t of tabs) {
    const a = document.createElement("a");
    a.className = "tab" + (t.route === activeRoute ? " active" : "");
    a.href = t.hash;
    a.textContent = t.label;
    a.setAttribute("role", "tab");
    if (t.route === activeRoute) a.setAttribute("aria-selected", "true");
    bar.appendChild(a);
  }
  return bar;
}
