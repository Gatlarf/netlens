// Which Netlens this browser tab is looking at: this one, or a remote site shown through it (app/relay.py). Per tab, so another tab stays where it is.
const KEY = "netlens.site";

export function currentSite() {
  try {
    const v = JSON.parse(sessionStorage.getItem(KEY) || "null");
    return v && Number.isInteger(v.id) ? v : null;
  } catch (e) {
    return null;
  }
}

export function enterSite(site) {
  try { sessionStorage.setItem(KEY, JSON.stringify({ id: site.id, name: site.name })); } catch (e) { /* the tab cannot remember it */ }
  location.hash = "#/dashboard";
  location.reload();
}

export function leaveSite() {
  try { sessionStorage.removeItem(KEY); } catch (e) { /* nothing stored */ }
  location.hash = "#/dashboard";
  location.reload();
}

// What always comes from this Netlens: who is signed in, the list of sites, the licence, this version.
const LOCAL = /^\/api\/(session|login|logout|me|licence|probes|probes-search|probe|site-view|update|changelog|health|plugin-index)(\/|\?|$)/;

// The address a request really goes to: inside a remote site the pages ask the site's own API through the central one.
export function routed(path) {
  const site = currentSite();
  if (!site || typeof path !== "string" || !path.startsWith("/api/") || LOCAL.test(path)) return path;
  return `/api/site-view/${site.id}${path}`;
}
