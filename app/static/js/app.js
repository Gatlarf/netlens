import { initSearch } from "./search.js";
import { initActions } from "./actions.js";
import { autoResizable } from "./colresize.js";
import { describeScan, describeTiming } from "./progress.js";
import { initThemeToggle } from "./theme.js";
import { initUpdateBadge } from "./update.js";
import { initTopbar } from "./topbar.js";
import { maybeShowWhatsNew } from "./changelog.js";
import { renderSetup } from "./setup.js";
import { applyInterface } from "./interface.js";
import { get, post, ApiError } from "./api.js";
import { initSiteBar } from "./sitebar.js";
import { getLevel, setLevel, levelShows } from "./levels.js";
import { featureFlags, hubById, hubOf, usableTabs, hubLevel, tabBar } from "./hubs.js";
import { clear, toast, el, setDomainSuffix, setSessionUser, sessionInfo } from "./util.js";

const ROUTES = {
  "": "dashboard",
  "#/": "dashboard",
  "#/dashboard": "dashboard",
  "#/overview": "dashboard",
  "#/map": "map",
  "#/hud": "hud",
  "#/devices": "devices",
  "#/hierarchy": "hierarchy",
  "#/dns": "dns",
  "#/ipv6": "network_health",
  "#/network-health": "network_health",
  "#/vulnerabilities": "vulnerabilities",
  "#/speedtest": "speedtest",
  "#/uptime": "uptime",
  "#/stats": "stats",
  "#/services": "services",
  "#/backups": "backups",
  "#/storage": "storage",
  "#/smarthome": "smarthome",
  "#/remediation": "remediation",
  "#/insights": "insights",
  "#/health": "health",
  "#/remote-sites": "remote_sites",
  "#/reports": "reports",
  "#/scans": "scans",
  "#/changes": "changes",
  "#/settings": "settings",
  "#/wizard": "wizard",
  "#/remote": "remote",
};

let currentCleanup = null;
let currentRoute = null;
let pollTimer = null;
let wasRunning = false;
let renderGen = 0;

function parseRoute() {
  const hash = location.hash;
  if (!hash || hash === "#/") return { name: "dashboard", params: {} };
  if (hash.startsWith("#/device/")) {
    const id = Number(hash.slice(9));
    if (Number.isInteger(id) && id > 0) {
      return { name: "device", params: { id } };
    }
    return { name: "devices", params: {} };
  }
  const settingsSection = /^#\/settings\/([a-z0-9_-]+)$/.exec(hash);
  if (settingsSection) return { name: "settings", params: { section: settingsSection[1] } };
  const name = ROUTES[hash.split("?")[0]];
  return name ? { name, params: {} } : { name: "devices", params: {} };
}

function updateNav(name) {
  document.querySelectorAll(".nav-link").forEach((link) => {
    const hub = hubOf(name);
    link.classList.toggle("active", link.dataset.route === (name === "device" ? "devices" : hub ? hub.id : name));
  });
}

let displayLoaded = false;

async function loadDisplaySettings() {
  if (displayLoaded) return;
  try {
    setDomainSuffix((await get("/api/map-settings")).domain_suffix);
    displayLoaded = true;
  } catch (e) {
    // names are then shown in full
  }
}

let setupMode = false;

async function renderPage() {
  const view = el("#view");
  if (!view || setupMode) return;
  await loadDisplaySettings();

  const gen = ++renderGen;

  if (currentCleanup) {
    try {
      currentCleanup();
    } catch (e) {
      // ignore cleanup errors
    }
    currentCleanup = null;
  }

  const route = parseRoute();
  currentRoute = route;
  updateNav(route.name);

  const fresh = document.createElement("div");
  fresh.className = "page";

  clear(view);
  // a spinner until the page has its data (the script of the page may still have to load, and the page asks the server for its numbers)
  const waiting = document.createElement("div");
  waiting.className = "page-loading";
  waiting.setAttribute("role", "status");
  waiting.textContent = "Loading…";
  view.appendChild(waiting);
  view.appendChild(fresh);

  try {
    const mod = await import(`./pages/${route.name}.js`);
    // a page that is a tab of a bigger page gets the tab bar above it (not in a customer view, which has its own short menu)
    const hub = document.body.dataset.scoped ? null : hubOf(route.name);
    const bar = hub ? tabBar(hub, route.name) : null;
    let target = fresh;
    if (bar) {
      target = document.createElement("div");
      target.className = "hub-body";
      fresh.append(bar, target);
    }
    const cleanup = await mod.render(target, route.params);
    waiting.remove();

    if (gen !== renderGen) {
      if (typeof cleanup === "function") cleanup();
      return;
    }

    if (typeof cleanup === "function") {
      currentCleanup = cleanup;
    }
  } catch (err) {
    waiting.remove();
    if (gen !== renderGen) return;

    const card = document.createElement("div");
    card.className = "card";
    const msg = document.createElement("p");
    msg.textContent = err.message || "Error rendering page";
    card.appendChild(msg);
    clear(fresh);
    fresh.appendChild(card);
  }

  if (gen === renderGen) {
    fresh.focus();
  }
}

let cancelling = false; // a cancel request is in flight or the scan is shutting down
let scanSnapshot = null; // last /api/scans/current response and when it arrived
let tickTimer = null;

function renderScanTime() {
  const timeEl = el("#scan-time");
  if (!timeEl) return;
  const text = scanSnapshot ? describeTiming(scanSnapshot.res, (Date.now() - scanSnapshot.at) / 1000) : "";
  timeEl.textContent = text;
  timeEl.hidden = !text;
}

function setScanSnapshot(res) {
  scanSnapshot = res && res.running ? { res, at: Date.now() } : null;
  renderScanTime();
  if (scanSnapshot && !tickTimer) {
    tickTimer = setInterval(renderScanTime, 1000); // smooth seconds between the 2 s polls
  } else if (!scanSnapshot && tickTimer) {
    clearInterval(tickTimer);
    tickTimer = null;
  }
}

function updateCancelButton(res) {
  const btn = el("#scan-cancel");
  if (!btn) return;
  const running = !!(res && res.running);
  btn.hidden = !running;
  if (!running) {
    cancelling = false;
    btn.disabled = false;
    btn.textContent = "Cancel scan";
    btn.removeAttribute("title");
    return;
  }
  btn.disabled = cancelling || res.cancellable === false;
  btn.title = res.cancellable === false && !cancelling ? "The results are being saved; it is too late to cancel" : "";
}

async function handleCancel() {
  const btn = el("#scan-cancel");
  if (!btn || cancelling) return;
  cancelling = true;
  btn.disabled = true;
  btn.textContent = "Cancelling…";
  try {
    await post("/api/scans/cancel");
    toast("Scan cancelled", "info");
  } catch (err) {
    cancelling = false;
    btn.textContent = "Cancel scan";
    toast(err.message || "Could not cancel the scan", "error");
  }
}

function startPoll() {
  if (pollTimer) return;
  wasRunning = false;
  pollTimer = setInterval(async () => {
    try {
      const res = await get("/api/scans/current");
      const running = res.running;
      const statusEl = el("#scan-status");
      const barEl = el("#scan-progress");
      const stripEl = el("#scan-info");
      if (stripEl) stripEl.hidden = !running;
      const info = describeScan(res);
      setScanSnapshot(res);
      updateCancelButton(res);
      if (statusEl) {
        statusEl.textContent = running ? info.text || "Scanning…" : "";
      }
      if (barEl) {
        barEl.hidden = !running;
        if (running && info.percent !== null) {
          barEl.value = info.percent;
        } else {
          barEl.removeAttribute("value"); // indeterminate while there is no percentage
        }
      }
      const quickBtn = el("#scan-quick");
      const deepBtn = el("#scan-deep");
      if (quickBtn) quickBtn.disabled = running;
      if (deepBtn) deepBtn.disabled = running;

      if (wasRunning && !running) {
        document.dispatchEvent(new CustomEvent("netlens:scan-finished"));
      }
      wasRunning = running;
    } catch (e) {
      // ignore polling errors
    }
  }, 2000);
}

function stopPoll() {
  if (pollTimer) {
    clearInterval(pollTimer);
    pollTimer = null;
  }
  wasRunning = false;
  const statusEl = el("#scan-status");
  if (statusEl) statusEl.textContent = "";
  const barEl = el("#scan-progress");
  if (barEl) barEl.hidden = true;
  const stripEl = el("#scan-info");
  if (stripEl) stripEl.hidden = true;
  setScanSnapshot(null);
  updateCancelButton(null);
  const quickBtn = el("#scan-quick");
  const deepBtn = el("#scan-deep");
  if (quickBtn) quickBtn.disabled = false;
  if (deepBtn) deepBtn.disabled = false;
}

function openLoginDialog() {
  const dialog = el("#login-dialog");
  if (dialog && !dialog.open) {
    dialog.showModal();
  }
  const first = el(loginByUser ? "#login-user" : "#login-token");
  if (first) {
    first.focus();
  }
}

function closeLoginDialog() {
  const dialog = el("#login-dialog");
  if (dialog && dialog.open) {
    dialog.close();
  }
}

function showLoginError(message) {
  const errorEl = el("#login-error");
  if (errorEl) {
    errorEl.textContent = message;
    errorEl.hidden = false;
  }
}

function clearLoginError() {
  const errorEl = el("#login-error");
  if (errorEl) {
    errorEl.textContent = "";
    errorEl.hidden = true;
  }
}

let loginByUser = true;                 // a user name and password is the normal way in; the access token stays as the second choice

function setLoginMode(byUser) {
  loginByUser = byUser;
  el("#login-token-fields").hidden = byUser;
  el("#login-user-fields").hidden = !byUser;
  el("#login-switch").textContent = byUser ? "Sign in with the access token instead" : "Sign in with a user name instead";
  const focus = el(byUser ? "#login-user" : "#login-token");
  if (focus) focus.focus();
}

let whatsNewChecked = false;

// Demo mode: a banner on every page, and the demo account filled in on the sign-in page
function showDemo(demo) {
  const banner = el("#demo-banner");
  if (!demo || !banner) return;
  const again = demo.reset === "off" ? "" : ` The data starts over ${demo.reset === "hourly" ? "every hour" : "every day"}.`;
  banner.textContent = `Demo: everything here is made up, and changes are switched off.${again} `;
  const link = document.createElement("a");
  link.href = "https://github.com/Gatlarf/netlens";
  link.target = "_blank";
  link.rel = "noopener noreferrer";
  link.textContent = "Get Netlens";
  banner.append(link);
  banner.hidden = false;
  const hint = el("#login-demo");
  if (hint) {
    hint.textContent = `Demo account: user name ${demo.username}, password ${demo.password}`;
    hint.hidden = false;
  }
  if (el("#login-user") && !el("#login-user").value) el("#login-user").value = demo.username;
  if (el("#login-password") && !el("#login-password").value) el("#login-password").value = demo.password;
}

async function applySession() {
  const session = await get("/api/session");
  if (session.interface) applyInterface(session.interface);
  setSessionUser(session.authenticated ? session.user : null);
  // the coffee button in the top bar is for free and open-source use; a licensed install keeps it in the account menu only
  get("/api/licence").then((lic) => document.body.classList.toggle("licensed", lic.state === "active" || lic.state === "grace")).catch(() => {});
  if (session.authenticated && session.user && session.user.scoped) { scopedUser = session.user; restrictToOwnDevices(); }
  const out = el("#logout");
  if (out && session.user) out.title = `Signed in as ${session.user.username} (${session.user.role})`;
  const name = session.user ? session.user.username : "Account";
  if (el("#user-name")) el("#user-name").textContent = name;
  if (el("#user-who")) {
    el("#user-who").textContent = "";
    if (session.user) {
      const who = document.createElement("div");
      who.append("Signed in as ", Object.assign(document.createElement("b"), { textContent: session.user.username }));
      const role = document.createElement("small");
      role.textContent = session.user.role === "admin" ? "administrator" : session.user.role;
      el("#user-who").append(who, role);
    } else {
      el("#user-who").textContent = "Not signed in";
    }
  }
  showDemo(session.demo);
  initSiteBar(session).catch(() => {});
  if (session.authenticated && !whatsNewChecked && !session.demo) {
    whatsNewChecked = true;
    maybeShowWhatsNew();
  }
  return session;
}

// A customer view (a viewer limited to some groups): the menu offers only the pages it may open, and other addresses lead back to the devices.
let scopedUser = {};
function restrictToOwnDevices() {
  document.body.dataset.scoped = "1";
  const pages = [...(scopedUser.devices ? [["#/devices", "Devices", "devices"], ["#/uptime", "Uptime", "uptime"]] : []), ...(scopedUser.sites ? [["#/remote-sites", "Remote sites", "remote_sites"]] : [])];
  const SCOPED_ROUTES = pages.map((p) => p[0]);
  const nav = el("#side-links");
  if (nav && !nav.dataset.scoped) {
    nav.dataset.scoped = "1";
    nav.textContent = "";
    for (const [href, label, route] of pages) {
      const a = document.createElement("a");
      Object.assign(a, { className: "nav-link", href, textContent: label });
      a.dataset.route = route;
      nav.appendChild(a);
    }
  }
  const here = location.hash.split("?")[0];
  if (!SCOPED_ROUTES.some((r) => here === r || here.startsWith(`${r}/`)) && !(scopedUser.devices && here.startsWith("#/device/"))) location.replace(SCOPED_ROUTES[0] || "#/devices");
}

// Open on the page the user chose (only when no page was asked for: a link to a page, a reload and the back button are left alone)
function goToStartPage(session) {
  const hash = location.hash;
  if ((!hash || hash === "#") && session && session.start_page && ROUTES[session.start_page]) {
    location.replace(session.start_page);
  }
}

async function handleLogin(e) {
  e.preventDefault();
  const body = loginByUser
    ? { username: el("#login-user").value.trim(), password: el("#login-password").value }
    : { token: (el("#login-token").value || "").trim() };

  try {
    await post("/api/login", body);
    closeLoginDialog();
    clearLoginError();
    el("#login-password").value = "";
    const session = await applySession();
    goToStartPage(session);
    displayLoaded = false;
    startPoll();
    renderPage();
  } catch (err) {
    const detail = err instanceof ApiError ? err.detail : err.message;
    showLoginError(detail);
  }
}

async function handleLogout() {
  try {
    await post("/api/logout");
    stopPoll();
    openLoginDialog();
  } catch (err) {
    toast(err.message || "Logout failed", "error");
  }
}

async function handleScan(kind) {
  try {
    const res = await post("/api/scans", { kind });
    toast("Scan started", "info");
  } catch (err) {
    if (err instanceof ApiError && err.status === 409) {
      toast("A scan is already running", "info");
    } else {
      toast(err.message || "Scan failed", "error");
    }
  }
}

// No user exists yet (and no NETLENS_TOKEN): the first-run wizard instead of the pages.
function startSetup() {
  setupMode = true;
  document.body.classList.add("setup-mode");
  renderSetup(el("#view"), async () => {
    setupMode = false;
    document.body.classList.remove("setup-mode");
    await applySession();
    displayLoaded = false;
    location.hash = "#/wizard"; // a fresh install goes straight into the getting-started guide
    startPoll();
    renderPage();
  });
}

// Without NETLENS_TOKEN only a user name and password sign in: show just that form.
function hideTokenLogin() {
  setLoginMode(true);
  const switchBtn = el("#login-switch");
  if (switchBtn) switchBtn.hidden = true;
}

// The stylesheets are linked below the spinner (so it paints first); keep it up until they are in, or the page would flash unstyled.
function stylesheetsReady() {
  const pending = [...document.querySelectorAll('link[rel="stylesheet"]')].filter((l) => !l.sheet);
  return Promise.all(pending.map((l) => new Promise((done) => {
    l.addEventListener("load", done, { once: true });
    l.addEventListener("error", done, { once: true });
  })));
}

function hideBoot() {
  const boot = document.getElementById("boot");      // the spinner of index.html, shown until the scripts are here and the session is known
  if (boot) boot.remove();
}

// The menu only lists what is installed, allowed and within the chosen menu level. An admin sees a "+" on Settings when plugins could add more.
function refreshNav() {
  let missing = 0;
  for (const link of document.querySelectorAll("#side-links .nav-link")) {
    const hub = link.dataset.hub ? hubById(link.dataset.hub) : null;
    if (hub) {
      const usable = usableTabs(hub);
      missing += hub.tabs.filter((t) => t.feature && featureFlags[t.feature] === false).length;
      const shown = usable.filter((t) => levelShows(t.level));
      link.hidden = shown.length === 0;
      if (shown.length) link.href = shown[0].hash;            // the first tab that is on: the Infrastructure page may open on Backups
      continue;
    }
    const off = link.dataset.feature ? featureFlags[link.dataset.feature] === false : false;
    if (off) missing += 1;
    link.hidden = off || !levelShows(link.dataset.level);
  }
  for (const group of document.querySelectorAll("#side-links .side-group")) {
    const links = group.querySelectorAll(".nav-link");
    group.hidden = links.length > 0 && [...links].every((l) => l.hidden);
  }
  const more = el("#nav-more");
  if (more) more.hidden = !missing;
}

async function applyFeatures() {
  try { Object.assign(featureFlags, await get("/api/features")); } catch { return; }
  refreshNav();
}

// the menu level switch in the user menu
function initLevelSwitch() {
  const show = () => document.querySelectorAll("#menu-level .lvl-btn").forEach((b) => b.setAttribute("aria-pressed", String(b.dataset.level === getLevel())));
  for (const b of document.querySelectorAll("#menu-level .lvl-btn")) b.addEventListener("click", () => setLevel(b.dataset.level));
  document.addEventListener("netlens:level-changed", () => { show(); refreshNav(); renderPage(); });
  show();
}

async function init() {
  initActions();
  initLevelSwitch();
  const session = await applySession();
  await stylesheetsReady();
  hideBoot();

  if (!session.authenticated && session.setup_required) {
    startSetup();
  } else if (!session.authenticated) {
    if (session.token_login === false) hideTokenLogin();
    const sso = el("#login-sso");
    if (sso && session.oidc && session.oidc.enabled) { sso.hidden = false; sso.textContent = session.oidc.label || "Single sign-on"; }
    openLoginDialog();
  } else {
    goToStartPage(session);
    applyFeatures();
    setInterval(() => { if (!document.hidden) applyFeatures(); }, 60000);
    startPoll();
    renderPage();
  }

  const switchBtn = el("#login-switch");
  if (switchBtn) switchBtn.addEventListener("click", () => setLoginMode(!loginByUser));

  const loginForm = el("#login-form");
  if (loginForm) {
    loginForm.addEventListener("submit", handleLogin);
  }

  const loginDialog = el("#login-dialog");
  if (loginDialog) {
    loginDialog.addEventListener("cancel", (e) => {
      e.preventDefault();
    });
  }

  const logoutBtn = el("#logout");
  if (logoutBtn) {
    logoutBtn.addEventListener("click", handleLogout);
  }

  const scanCancel = el("#scan-cancel");
  if (scanCancel) scanCancel.addEventListener("click", handleCancel);
  const scanQuick = el("#scan-quick");
  const scanDeep = el("#scan-deep");
  if (scanQuick) {
    scanQuick.addEventListener("click", () => handleScan("quick"));
  }
  if (scanDeep) {
    scanDeep.addEventListener("click", () => handleScan("deep"));
  }

  document.addEventListener("netlens:unauth", () => {
    if (setupMode) return; // a background request before the first account exists must not cover the wizard
    stopPoll();
    openLoginDialog();
  });

  window.addEventListener("hashchange", () => { if (document.body.dataset.scoped) restrictToOwnDevices(); renderPage(); });
}

init().finally(hideBoot);       // never leave the spinner on the screen, also when something went wrong
// Show the running version next to the logo.
fetch("/api/health").then((r) => r.json()).then((d) => {
  const el = document.getElementById("app-version");
  if (el && d.version) el.textContent = "v" + d.version;
}).catch(() => {});

initThemeToggle();
initUpdateBadge();
initTopbar();
initSearch();
autoResizable();

// Installable app (needs HTTPS or localhost); the worker only caches the public interface files, see sw.js
if ("serviceWorker" in navigator && window.isSecureContext) {
  navigator.serviceWorker.register("sw.js").catch(() => {});
}
