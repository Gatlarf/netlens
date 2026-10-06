Fix the defects below and output the COMPLETE corrected file. Keep everything else identical.

DEFECTS:
renderPage() can run twice concurrently (initial load and after login, or fast hash changes); because page render() functions are async, the slower call appends its DOM after the faster one and pages show duplicated content, and stale pages register timers/listeners that are never cleaned up. Fix: keep a module-level counter renderGen. In renderPage: const gen = ++renderGen; call and clear the previous cleanup; create a fresh container element for this render (document.createElement('div') with class 'page'); await mod.render(fresh, route.params); AFTER the await, if gen !== renderGen the render is stale: call the returned cleanup (if it is a function) immediately and return without touching the DOM; otherwise clear #view, append the fresh element to #view, store the cleanup. Note the page's render() builds its DOM in the container passed to it before returning, so attach the fresh element to #view BEFORE awaiting render (so size/layout measuring works), but when a newer render has started replace/remove it: i.e. at the start of each renderPage clear #view and append the new fresh element immediately; stale renders keep writing only into their own detached element. Error handling stays the same but writes into the fresh element.

CURRENT FILE:
import { get, post, ApiError } from "./api.js";
import { clear, toast, el } from "./util.js";

const ROUTES = {
  "": "map",
  "#/": "map",
  "#/map": "map",
  "#/devices": "devices",
  "#/scans": "scans",
  "#/settings": "settings",
};

let currentCleanup = null;
let currentRoute = null;
let pollTimer = null;
let wasRunning = false;

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
  const name = ROUTES[hash];
  return name ? { name, params: {} } : { name: "devices", params: {} };
}

function updateNav(name) {
  document.querySelectorAll(".nav-link").forEach((link) => {
    link.classList.toggle("active", link.dataset.route === name);
  });
}

async function renderPage() {
  const container = el("#view");
  if (!container) return;

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

  try {
    const mod = await import(`./pages/${route.name}.js`);
    const cleanup = await mod.render(container, route.params);
    if (typeof cleanup === "function") {
      currentCleanup = cleanup;
    }
  } catch (err) {
    const card = document.createElement("div");
    card.className = "card";
    const msg = document.createElement("p");
    msg.textContent = err.message || "Error rendering page";
    card.appendChild(msg);
    clear(container);
    container.appendChild(card);
  }

  container.focus();
}

function startPoll() {
  if (pollTimer) return;
  wasRunning = false;
  pollTimer = setInterval(async () => {
    try {
      const res = await get("/api/scans/current");
      const running = res.running;
      const statusEl = el("#scan-status");
      if (statusEl) {
        statusEl.textContent = running ? "Scanning…" : "";
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
  }, 3000);
}

function stopPoll() {
  if (pollTimer) {
    clearInterval(pollTimer);
    pollTimer = null;
  }
  wasRunning = false;
  const statusEl = el("#scan-status");
  if (statusEl) statusEl.textContent = "";
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

async function handleLogin(e) {
  e.preventDefault();
  const tokenInput = el("#login-token");
  const token = tokenInput ? tokenInput.value.trim() : "";

  try {
    await post("/api/login", { token });
    closeLoginDialog();
    clearLoginError();
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

async function init() {
  const session = await get("/api/session");

  if (!session.authenticated) {
    openLoginDialog();
  } else {
    startPoll();
    renderPage();
  }

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

  const scanQuick = el("#scan-quick");
  const scanDeep = el("#scan-deep");
  if (scanQuick) {
    scanQuick.addEventListener("click", () => handleScan("quick"));
  }
  if (scanDeep) {
    scanDeep.addEventListener("click", () => handleScan("deep"));
  }

  document.addEventListener("netlens:unauth", () => {
    stopPoll();
    openLoginDialog();
  });

  window.addEventListener("hashchange", renderPage);
}

init();