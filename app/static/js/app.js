import { initSearch } from "./search.js";
import { initAsk } from "./ask.js";
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
import * as webauthn from "./webauthn.js";
import { initSiteBar } from "./sitebar.js";
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
    link.classList.toggle("active", link.dataset.route === (name === "device" ? "devices" : name));
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
    const cleanup = await mod.render(fresh, route.params);
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
  if (dialog && dialog.open) return;                  // already showing: the background refresh asks again, and must not pull the cursor back to the user name while the password is typed
  if (dialog) dialog.showModal();
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

// A second factor that the administrator requires and the user has not set up yet: a banner (and, after the grace period, only the Account page opens)
function showMfa(user) {
  const banner = el("#mfa-banner");
  if (!banner) return;
  const mfa = user && user.mfa;
  if (!mfa || !mfa.required || mfa.enrolled) { banner.hidden = true; return; }
  banner.textContent = mfa.restricted ? "Your administrator requires a second factor. Set one up now to continue. " : `Your administrator requires a second factor: set one up before ${mfa.deadline ? mfa.deadline.slice(0, 10) : "the end of the grace period"}. `;
  const link = document.createElement("a");
  link.href = "#/settings/session";
  link.textContent = "Set it up";
  banner.append(link);
  banner.hidden = false;
  if (mfa.restricted && !location.hash.startsWith("#/settings/session")) location.replace("#/settings/session");
}

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
  showMfa(session.authenticated ? session.user : null);
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

let loginKeyOptions = null;
let loginChallenge = null;              // set between the password and the code of a second factor: no session exists yet

let loginStash = [];                    // what the first step showed, to put it back when the second step ends

// the security key step: the browser asks for the key; a failed try needs a new challenge from the server (the first one is used up)
async function useSecurityKey(first) {
  let options = first;
  const button = el("#login-key");
  button.disabled = true;
  try {
    if (!options) options = await post("/api/login/webauthn/options", { challenge: loginChallenge });
    const credential = await webauthn.get(options);
    await post("/api/login/webauthn", { challenge: loginChallenge, credential });
    await finishLogin();
  } catch (err) {
    const detail = err instanceof ApiError ? err.detail : err.message;
    showLoginError(detail);
    if (/expired|ended/.test(detail || "")) resetLoginSteps();
  }
  button.disabled = false;
}

function showTotpStep(result) {
  loginStash = [];
  const keys = Boolean(result && result.webauthn) && webauthn.supported();
  el("#login-key-fields").hidden = !keys;
  el("#login-totp-text").textContent = result && result.methods && !result.methods.totp
    ? "Use your security key. If you lost it, enter one of your recovery codes below."
    : "Enter the 6-digit code from your authenticator app, or one of your recovery codes.";
  loginKeyOptions = keys ? result.webauthn : null;
  for (const id of ["#login-user-fields", "#login-token-fields", "#login-sso", "#login-switch", "#login-demo"]) {
    const node = el(id);
    if (node) {
      loginStash.push([node, node.hidden]);
      node.hidden = true;
    }
  }
  el("#login-totp-fields").hidden = false;
  el("#login-code").value = "";
  if (keys) useSecurityKey(loginKeyOptions); else el("#login-code").focus();
}

function resetLoginSteps() {
  loginChallenge = null;
  el("#login-totp-fields").hidden = true;
  el("#login-key-fields").hidden = true;
  el("#login-code").value = "";
  for (const [node, was] of loginStash) node.hidden = was;
  loginStash = [];
  clearLoginError();
  el("#login-password").focus();
}

async function finishLogin() {
  closeLoginDialog();
  clearLoginError();
  el("#login-password").value = "";
  el("#login-code").value = "";
  loginChallenge = null;
  const session = await applySession();
  goToStartPage(session);
  displayLoaded = false;
  startPoll();
  renderPage();
}

async function handleLogin(e) {
  e.preventDefault();
  if (loginChallenge) {                                                  // the second step: the code
    try {
      await post("/api/login/totp", { challenge: loginChallenge, code: el("#login-code").value.trim() });
      await finishLogin();
    } catch (err) {
      const detail = err instanceof ApiError ? err.detail : err.message;
      showLoginError(detail);
      if (/expired|ended/.test(detail || "")) resetLoginSteps();
      else el("#login-code").select();
    }
    return;
  }
  const body = loginByUser
    ? { username: el("#login-user").value.trim(), password: el("#login-password").value }
    : { token: (el("#login-token").value || "").trim() };

  try {
    const result = await post("/api/login", body);
    if (result && result.totp_required) {
      loginChallenge = result.challenge;
      el("#login-password").value = "";                                  // the password is not needed again
      clearLoginError();
      showTotpStep(result);
      return;
    }
    await finishLogin();
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
  el("#login-key").addEventListener("click", () => useSecurityKey(null));
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

// The menu only lists the optional pages (backups, storage, ...) that have a plugin switched on or already hold data; an admin gets a link to add more.
async function applyFeatures() {
  let features;
  try { features = await get("/api/features"); } catch { return; }
  let hidden = 0;
  for (const link of document.querySelectorAll("#side-links [data-feature]")) {
    const on = features[link.dataset.feature] !== false;
    link.hidden = !on;
    if (!on) hidden += 1;
  }
  for (const group of document.querySelectorAll("#side-links .side-group")) {
    const links = group.querySelectorAll(".nav-link");
    group.hidden = links.length > 0 && [...links].every((l) => l.hidden);
  }
  const more = el("#nav-more");
  if (more) more.hidden = !hidden;
}

async function init() {
  initActions();
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

  document.addEventListener("netlens:session-changed", () => { applySession().then(() => renderPage()).catch(() => {}); });
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
initAsk();
autoResizable();

// Installable app (needs HTTPS or localhost); the worker only caches the public interface files, see sw.js
if ("serviceWorker" in navigator && window.isSecureContext) {
  navigator.serviceWorker.register("sw.js").catch(() => {});
}
