import { describeScan, describeTiming } from "./progress.js";
import { initThemeToggle } from "./theme.js";
import { initUpdateBadge } from "./update.js";
import { initTopbar } from "./topbar.js";
import { maybeShowWhatsNew } from "./changelog.js";
import { renderSetup } from "./setup.js";
import { get, post, ApiError } from "./api.js";
import { clear, toast, el, setDomainSuffix, setSessionUser, sessionInfo } from "./util.js";

const ROUTES = {
  "": "map",
  "#/": "map",
  "#/map": "map",
  "#/devices": "devices",
  "#/hierarchy": "hierarchy",
  "#/uptime": "uptime",
  "#/stats": "stats",
  "#/services": "services",
  "#/scans": "scans",
  "#/settings": "settings",
};

let currentCleanup = null;
let currentRoute = null;
let pollTimer = null;
let wasRunning = false;
let renderGen = 0;

function parseRoute() {
  const hash = location.hash;
  if (!hash || hash === "#/") return { name: "map", params: {} };
  if (hash.startsWith("#/device/")) {
    const id = Number(hash.slice(9));
    if (Number.isInteger(id) && id > 0) {
      return { name: "device", params: { id } };
    }
    return { name: "devices", params: {} };
  }
  const settingsSection = /^#\/settings\/([a-z0-9_-]+)$/.exec(hash);
  if (settingsSection) return { name: "settings", params: { section: settingsSection[1] } };
  const name = ROUTES[hash];
  return name ? { name, params: {} } : { name: "devices", params: {} };
}

function updateNav(name) {
  document.querySelectorAll(".nav-link").forEach((link) => {
    link.classList.toggle("active", link.dataset.route === name);
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
  view.appendChild(fresh);

  try {
    const mod = await import(`./pages/${route.name}.js`);
    const cleanup = await mod.render(fresh, route.params);

    if (gen !== renderGen) {
      if (typeof cleanup === "function") cleanup();
      return;
    }

    if (typeof cleanup === "function") {
      currentCleanup = cleanup;
    }
  } catch (err) {
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
  const tokenInput = el("#login-token");
  if (tokenInput) {
    tokenInput.focus();
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

let loginByUser = false;

function setLoginMode(byUser) {
  loginByUser = byUser;
  el("#login-token-fields").hidden = byUser;
  el("#login-user-fields").hidden = !byUser;
  el("#login-switch").textContent = byUser ? "Sign in with the access token instead" : "Sign in with a user name instead";
  const focus = el(byUser ? "#login-user" : "#login-token");
  if (focus) focus.focus();
}

let whatsNewChecked = false;

async function applySession() {
  const session = await get("/api/session");
  setSessionUser(session.authenticated ? session.user : null);
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
  if (session.authenticated && !whatsNewChecked) {
    whatsNewChecked = true;
    maybeShowWhatsNew();
  }
  return session;
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
    await applySession();
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
    location.hash = "#/map";
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

async function init() {
  const session = await applySession();

  if (!session.authenticated && session.setup_required) {
    startSetup();
  } else if (!session.authenticated) {
    if (session.token_login === false) hideTokenLogin();
    openLoginDialog();
  } else {
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

  window.addEventListener("hashchange", renderPage);
}

init();
// Show the running version next to the logo.
fetch("/api/health").then((r) => r.json()).then((d) => {
  const el = document.getElementById("app-version");
  if (el && d.version) el.textContent = "v" + d.version;
}).catch(() => {});

initThemeToggle();
initUpdateBadge();
initTopbar();

// Installable app (needs HTTPS or localhost); the worker only caches the public interface files, see sw.js
if ("serviceWorker" in navigator && window.isSecureContext) {
  navigator.serviceWorker.register("sw.js").catch(() => {});
}
