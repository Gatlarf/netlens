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
  const name = ROUTES[hash];
  return name ? { name, params: {} } : { name: "devices", params: {} };
}

function updateNav(name) {
  document.querySelectorAll(".nav-link").forEach((link) => {
    link.classList.toggle("active", link.dataset.route === name);
  });
}

async function renderPage() {
  const view = el("#view");
  if (!view) return;

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
// Show the running version next to the logo.
fetch("/api/health").then((r) => r.json()).then((d) => {
  const el = document.getElementById("app-version");
  if (el && d.version) el.textContent = "v" + d.version;
}).catch(() => {});
