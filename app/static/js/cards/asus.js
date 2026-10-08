import { get, put, post } from "../api.js";
import { h, clear, toast, timeAgo } from "../util.js";

function field(label, input, hint) {
  const wrap = h("div", { class: "field" });
  wrap.appendChild(h("label", {}, label));
  wrap.appendChild(input);
  if (hint) wrap.appendChild(h("p", { class: "hint" }, hint));
  return wrap;
}

function buildBody(form) {
  const q = (name) => form.querySelector(`[name="${name}"]`);
  const body = {
    enabled: q("enabled").checked,
    url: q("url").value,
    verify_tls: q("verify_tls").checked,
    username: q("username").value,
  };
  if (q("password").value) body.password = q("password").value;
  return body;
}

function fillAsusCard(card, cfg) {
  clear(card);
  card.appendChild(h("h2", {}, "ASUS router / AiMesh connector"));
  card.appendChild(h("p", { class: "hint" },
    "Reads which device is connected to which AiMesh node and shows it in the network hierarchy and on the map. Read-only. " +
    "It logs in once after each scan, reads two pages and logs out again, so no sessions are left open on the router."));

  const form = h("form", { class: "edit-form" });
  form.appendChild(field("Enable the connector", h("input", { type: "checkbox", name: "enabled", checked: cfg.enabled })));
  form.appendChild(field("Router address", h("input", {
    type: "text", name: "url", placeholder: "https://192.168.0.1:8443", value: cfg.url || "",
  }), "The router's web interface. HTTPS defaults to port 8443."));
  form.appendChild(field("Verify TLS certificate", h("input", { type: "checkbox", name: "verify_tls", checked: cfg.verify_tls }),
    "Leave off: ASUS routers use a self-signed certificate."));
  form.appendChild(field("Username", h("input", { type: "text", name: "username", value: cfg.username || "", autocomplete: "off" })));
  form.appendChild(field("Password", h("input", {
    type: "password", name: "password", placeholder: cfg.password_set ? "unchanged" : "", autocomplete: "new-password",
  })));

  const testBtn = h("button", { type: "button", class: "btn" }, "Test connection");
  const saveBtn = h("button", { type: "submit", class: "btn" }, "Save");
  const syncBtn = h("button", { type: "button", class: "btn" }, "Sync now");
  syncBtn.disabled = !cfg.configured;
  form.appendChild(testBtn);
  form.appendChild(saveBtn);
  form.appendChild(syncBtn);

  const resultEl = h("p", { class: "hint" }, "");
  form.appendChild(resultEl);

  const statusEl = h("p", { class: "hint" }, "");
  if (cfg.status) {
    if (cfg.status.ok) {
      statusEl.textContent = `Last sync ${timeAgo(cfg.status.ts)}: ${cfg.status.nodes} mesh nodes, ${cfg.status.clients} online clients, ${cfg.status.links} links`;
    } else {
      statusEl.textContent = `Last sync failed (${timeAgo(cfg.status.ts)}): ${cfg.status.error}` +
        (cfg.status.auth_failed ? ". Automatic syncing is paused until you save or sync again." : "");
      statusEl.className = "error";
    }
  }
  card.appendChild(statusEl);

  testBtn.addEventListener("click", async () => {
    testBtn.disabled = true;
    resultEl.textContent = "";
    try {
      const res = await post("/api/asus/test", buildBody(form));
      resultEl.textContent = `Connected: ${res.nodes} mesh node(s), ${res.clients} online client(s)`;
      resultEl.className = "hint";
      toast("Connection test successful", "success");
    } catch (err) {
      resultEl.textContent = err.message || "Test failed";
      resultEl.className = "error";
      toast(err.message || "Test failed", "error");
    }
    testBtn.disabled = false;
  });

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    saveBtn.disabled = true;
    try {
      const updated = await put("/api/asus", buildBody(form));
      toast("Router settings saved", "success");
      fillAsusCard(card, updated);
    } catch (err) {
      toast(err.message || "Failed to save", "error");
      saveBtn.disabled = false;
    }
  });

  syncBtn.addEventListener("click", async () => {
    syncBtn.disabled = true;
    try {
      const res = await post("/api/asus/sync", {});
      toast(`Synced ${res.clients} clients (${res.links} links)`, "success");
    } catch (err) {
      toast(err.message || "Sync failed", "error");
    }
    fillAsusCard(card, await get("/api/asus"));
  });

  card.appendChild(form);
}

export async function buildAsusCard() {
  const card = h("div", { class: "card" });
  card.appendChild(h("h2", {}, "ASUS router / AiMesh connector"));
  card.appendChild(h("p", { class: "hint" }, "Loading..."));
  try {
    fillAsusCard(card, await get("/api/asus"));
  } catch (err) {
    clear(card);
    card.appendChild(h("h2", {}, "ASUS router / AiMesh connector"));
    card.appendChild(h("p", { class: "error" }, err.message || "Failed to load"));
  }
  return card;
}
