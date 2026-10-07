import { get, put, post, ApiError } from "../api.js";
import { h, clear, toast, timeAgo } from "../util.js";

function buildBody(form) {
  const body = {};
  const enabled = form.querySelector('[name="enabled"]');
  const url = form.querySelector('[name="url"]');
  const verify_tls = form.querySelector('[name="verify_tls"]');
  const username = form.querySelector('[name="username"]');
  const token_id = form.querySelector('[name="token_id"]');
  const token_secret = form.querySelector('[name="token_secret"]');
  const password = form.querySelector('[name="password"]');

  if (enabled) body.enabled = enabled.checked;
  if (url) body.url = url.value;
  if (verify_tls) body.verify_tls = verify_tls.checked;
  if (username) body.username = username.value;
  if (token_id) body.token_id = token_id.value;
  if (token_secret && token_secret.value) body.token_secret = token_secret.value;
  if (password && password.value) body.password = password.value;

  return body;
}

function fillProxmoxCard(card, cfg) {
  clear(card);
  card.appendChild(h("h2", {}, "Proxmox connector"));
  card.appendChild(h("p", { class: "hint" },
    "Reads your Proxmox VMs and containers so the map and device pages show which devices run on which Proxmox host. Read-only."));

  const form = h("form", { class: "edit-form" });

  // Enable checkbox
  const enabledField = h("div", { class: "field" });
  enabledField.appendChild(h("label", {}, "Enable the connector"));
  const enabledInput = h("input", {
    type: "checkbox",
    name: "enabled",
    checked: cfg.enabled,
  });
  enabledField.appendChild(enabledInput);
  form.appendChild(enabledField);

  // URL
  const urlField = h("div", { class: "field" });
  urlField.appendChild(h("label", {}, "Proxmox URL"));
  const urlInput = h("input", {
    type: "text",
    name: "url",
    placeholder: "https://192.168.0.10:8006",
    value: cfg.url || "",
  });
  urlField.appendChild(urlInput);
  form.appendChild(urlField);

  // Verify TLS
  const verifyField = h("div", { class: "field" });
  verifyField.appendChild(h("label", {}, "Verify TLS certificate"));
  const verifyInput = h("input", {
    type: "checkbox",
    name: "verify_tls",
    checked: cfg.verify_tls,
  });
  verifyField.appendChild(verifyInput);
  verifyField.appendChild(h("p", { class: "hint" },
    "Turn off for the self-signed certificate Proxmox uses by default."));
  form.appendChild(verifyField);

  // API token section
  form.appendChild(h("h3", {}, "API token (recommended; give it the read-only PVEAuditor role)"));

  const tokenIdField = h("div", { class: "field" });
  tokenIdField.appendChild(h("label", {}, "Token ID"));
  const tokenIdInput = h("input", {
    type: "text",
    name: "token_id",
    placeholder: "user@pam!netlens",
    value: cfg.token_id || "",
  });
  tokenIdField.appendChild(tokenIdInput);
  form.appendChild(tokenIdField);

  const tokenSecretField = h("div", { class: "field" });
  tokenSecretField.appendChild(h("label", {}, "Token secret"));
  const tokenSecretInput = h("input", {
    type: "password",
    name: "token_secret",
    placeholder: cfg.token_secret_set ? "unchanged" : "",
  });
  tokenSecretField.appendChild(tokenSecretInput);
  form.appendChild(tokenSecretField);

  form.appendChild(h("p", { class: "hint" }, "or"));

  // User and password section
  form.appendChild(h("h3", {}, "User and password"));

  const usernameField = h("div", { class: "field" });
  usernameField.appendChild(h("label", {}, "Username"));
  const usernameInput = h("input", {
    type: "text",
    name: "username",
    placeholder: "root@pam",
    value: cfg.username || "",
  });
  usernameField.appendChild(usernameInput);
  form.appendChild(usernameField);

  const passwordField = h("div", { class: "field" });
  passwordField.appendChild(h("label", {}, "Password"));
  const passwordInput = h("input", {
    type: "password",
    name: "password",
    placeholder: cfg.password_set ? "unchanged" : "",
  });
  passwordField.appendChild(passwordInput);
  form.appendChild(passwordField);

  form.appendChild(h("p", { class: "hint" },
    "The token is used when both token fields are filled."));

  // Buttons
  const testBtn = h("button", { type: "button", class: "btn" }, "Test connection");
  const saveBtn = h("button", { type: "submit", class: "btn" }, "Save");
  const syncBtn = h("button", { type: "button", class: "btn" }, "Sync now");
  syncBtn.disabled = !cfg.configured;

  form.appendChild(testBtn);
  form.appendChild(saveBtn);
  form.appendChild(syncBtn);

  // Result paragraph for test
  const resultEl = h("p", { class: "hint" }, "");
  form.appendChild(resultEl);

  // Status line
  const statusEl = h("p", { class: "hint" }, "");
  if (cfg.status) {
    if (cfg.status.ok) {
      statusEl.textContent = `Last sync ${timeAgo(cfg.status.ts)}: ${cfg.status.guests} guests, ${cfg.status.guests_matched} matched, ${cfg.status.links} map links`;
    } else {
      statusEl.textContent = `Last sync failed (${timeAgo(cfg.status.ts)}): ${cfg.status.error}`;
      statusEl.className = "error";
    }
  }
  card.appendChild(statusEl);

  // Test handler
  testBtn.addEventListener("click", async () => {
    testBtn.disabled = true;
    resultEl.textContent = "";
    try {
      const body = buildBody(form);
      const res = await post("/api/proxmox/test", body);
      resultEl.textContent = `Connected: Proxmox VE ${res.version}, ${res.nodes} node(s), ${res.guests} guest(s)`;
      resultEl.className = "hint";
      toast("Connection test successful", "success");
    } catch (err) {
      resultEl.textContent = err.message || "Test failed";
      resultEl.className = "error";
      toast(err.message || "Test failed", "error");
    }
    testBtn.disabled = false;
  });

  // Save handler
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    saveBtn.disabled = true;
    try {
      const body = buildBody(form);
      const updated = await put("/api/proxmox", body);
      toast("Proxmox settings saved", "success");
      fillProxmoxCard(card, updated);
    } catch (err) {
      const errorEl = h("p", { class: "error" }, err.message || "Failed to save");
      form.appendChild(errorEl);
      toast(err.message || "Failed to save", "error");
      saveBtn.disabled = false;
    }
  });

  // Sync handler
  syncBtn.addEventListener("click", async () => {
    syncBtn.disabled = true;
    try {
      const res = await post("/api/proxmox/sync", {});
      toast(`Synced ${res.guests} guests (${res.guests_matched} matched to devices)`, "success");
      fillProxmoxCard(card, await get("/api/proxmox"));
    } catch (err) {
      toast(err.message || "Sync failed", "error");
      syncBtn.disabled = false;
    }
  });

  card.appendChild(form);
}

export async function buildProxmoxCard() {
  const card = h("div", { class: "card" });
  card.appendChild(h("h2", {}, "Proxmox connector"));
  card.appendChild(h("p", { class: "hint" }, "Loading..."));

  try {
    const cfg = await get("/api/proxmox");
    fillProxmoxCard(card, cfg);
  } catch (err) {
    clear(card);
    card.appendChild(h("h2", {}, "Proxmox connector"));
    card.appendChild(h("p", { class: "error" }, err.message || "Failed to load"));
  }

  return card;
}