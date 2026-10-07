FRONTEND CONVENTIONS for Netlens (vanilla ES modules in the browser, no frameworks, no build step, no external libraries):
- Files live in app/static/js/cards/ (or app/static/js/pages/). Import with relative paths:
    import { get, post, put, patch, del, ApiError } from "../api.js";
    import { h, clear, toast, fmtTime, timeAgo, statusDot } from "../util.js";
  api functions take (path, body) and return parsed JSON (null for empty responses). On HTTP errors they throw ApiError; `err.message` is the server's "detail" text (a readable sentence) and `err.status` the HTTP status. Network failure gives message "network error".
- h(tag, attrs, ...children) builds DOM elements. attrs: class, type, name, value, placeholder, min, max, step, for, title, href, and boolean attributes (checked, disabled, selected, readonly are set when true and omitted when false/null/undefined); event handlers as onclick, onchange, onsubmit etc. (function values). Children may be strings, DOM nodes, nested arrays, null/false (ignored). Set input values with the `value` attribute or the .value property; set a checkbox state with `checked: true` or .checked.
- clear(el) removes all children. toast(message, kind) shows a toast, kind is "info", "success" or "error". fmtTime(iso) -> local date/time text. timeAgo(iso) -> e.g. "5m ago". statusDot(online: boolean) -> a small colored dot element.
- NEVER use innerHTML or insertAdjacentHTML; build everything with h() and textContent so server data cannot inject markup.
- Already styled CSS classes: "card" (a box; give it an <h2> title), "kv" (a row) containing <span class="kv-label"> and a value element, "edit-form" (a <form>), "field" (wrapper for a <label> plus an input/select/textarea; inputs are full width), "btn" (button), "hint" (small muted paragraph), "error" (red text; hidden while empty), "mono" (monospace), "badge".
- Each card module exports ONE async function that RETURNS a ready-to-insert `div.card`; it first shows "Loading..." inside the card, then fetches and renders. If the GET fails, show the error message in a <p class="error"> inside the card. After a successful save the card re-renders itself (clear the card and fill it again with fresh data from the server) and shows a toast. Buttons are disabled while a request is running. Validation errors from the server (HTTP 422/502) are shown in a <p class="error"> inside the form and as an error toast; do not throw.
- Example of the existing style (the "Scan ranges" card of the Settings page); follow this structure and naming style:

const SOURCE_TEXT = {
  ui: "set on this page",
  env: "from the NETLENS_RANGES environment variable",
  auto: "auto-detected from this host's network interfaces",
};

function fillRangesCard(card, cfg) {
  clear(card);
  card.appendChild(h("h2", {}, "Scan ranges"));

  const current = cfg.ranges && cfg.ranges.length > 0
    ? cfg.ranges.join(", ")
    : (cfg.detected_ranges && cfg.detected_ranges.length > 0
      ? cfg.detected_ranges.join(", ")
      : "none found");
  card.appendChild(kvRow("Scanning", current));
  card.appendChild(kvRow("Source", SOURCE_TEXT[cfg.ranges_source] || ""));
  if (cfg.ranges_source !== "auto" && cfg.detected_ranges && cfg.detected_ranges.length > 0) {
    card.appendChild(kvRow("Detected on this host", cfg.detected_ranges.join(", ")));
  }

  const form = h("form", { class: "edit-form" });
  const field = h("div", { class: "field" });
  field.appendChild(h("label", {}, "Ranges to scan"));
  const input = h("input", {
    type: "text",
    name: "ranges",
    placeholder: "e.g. 192.168.1.0/24, 10.0.0.0/22",
    value: cfg.ranges_source === "ui" ? cfg.ranges.join(", ") : "",
  });
  field.appendChild(input);
  field.appendChild(h("p", { class: "hint" },
    "Separate several ranges with commas. Private IPv4 only (10.x, 172.16-31.x, 192.168.x), " +
    "each /20 or smaller. Applies from the next scan. It also limits which devices the web " +
    "terminal may connect to. Leave empty and save, or use Reset, to go back to the default."));
  form.appendChild(field);

  const errorEl = h("p", { class: "error" }, "");
  form.appendChild(errorEl);

  const saveBtn = h("button", { type: "submit", class: "btn" }, "Save");
  const resetBtn = h("button", { type: "button", class: "btn" }, "Reset to default");
  form.appendChild(saveBtn);
  form.appendChild(resetBtn);

  async function submit(ranges, doneMessage) {
    errorEl.textContent = "";
    saveBtn.disabled = true;
    resetBtn.disabled = true;
    try {
      const updated = await put("/api/config/ranges", { ranges });
      toast(doneMessage, "success");
      fillRangesCard(card, updated);
    } catch (err) {
      errorEl.textContent = err.message || "Failed to save";
      saveBtn.disabled = false;
      resetBtn.disabled = false;
    }
  }

  form.addEventListener("submit", (e) => {
    e.preventDefault();
    const ranges = input.value.split(/[\s,;]+/).filter(Boolean);
    submit(ranges, ranges.length > 0 ? "Scan ranges saved" : "Scan ranges reset");
  });
  resetBtn.addEventListener("click", () => submit([], "Scan ranges reset"));

  card.appendChild(form);
}

TASK: write app/static/js/cards/proxmox.js (full file, under 200 lines). Export `export async function buildProxmoxCard()`.

API:
GET /api/proxmox -> {enabled: bool, url: str, verify_tls: bool, username: str, token_id: str, password_set: bool, token_secret_set: bool, auth_method: "token"|"password"|"none", configured: bool, status: null | {ts: iso, ok: bool, error?: str, nodes?: int, guests?: int, guests_matched?: int, links?: int}}.
PUT /api/proxmox with any of {enabled, url, verify_tls, username, password, token_id, token_secret}; only the fields sent change; leave secrets (password, token_secret) OUT of the body when their input is empty (the server keeps the saved ones). Saving with enabled=true triggers an immediate sync. Returns the same shape as GET. Errors 422 with a readable detail.
POST /api/proxmox/test with the same body shape built from the CURRENT FORM VALUES (nothing is saved) -> {ok: true, version: str, nodes: int, guests: int} or error 422/502 with a readable detail.
POST /api/proxmox/sync (no body) -> {nodes, hosts_matched, guests, guests_matched, links} or error 502/422 with detail.

Card: <h2>Proxmox connector</h2> with an introductory <p class="hint"> "Reads your Proxmox VMs and containers so the map and device pages show which devices run on which Proxmox host. Read-only."
Form fields: checkbox "Enable the connector" (enabled); text input "Proxmox URL" (placeholder "https://192.168.0.10:8006"); checkbox "Verify TLS certificate" with hint "Turn off for the self-signed certificate Proxmox uses by default."; a sub-heading <h3>API token (recommended; give it the read-only PVEAuditor role)</h3> with inputs "Token ID" (placeholder "user@pam!netlens") and "Token secret" (password input, placeholder "unchanged" when token_secret_set); a line <p class="hint">or</p>; sub-heading <h3>User and password</h3> with inputs "Username" (placeholder "root@pam") and "Password" (password input, placeholder "unchanged" when password_set). A hint that the token is used when both token fields are filled.
Buttons: "Test connection", "Save", "Sync now". Test builds the body from the form values (include url, verify_tls, username, token_id, and password/token_secret only when non-empty), shows the result inline in a result paragraph (green text via class "hint" on success: `Connected: Proxmox VE ${version}, ${nodes} node(s), ${guests} guest(s)`; class "error" on failure) and as a toast. Save does PUT then re-renders the card and toasts "Proxmox settings saved". "Sync now" is disabled unless the saved config has configured=true; on success toast `Synced ${guests} guests (${guests_matched} matched to devices)`.
Status line (<p class="hint"> or class "error" when failed) from status: ok -> `Last sync ${timeAgo(ts)}: ${guests} guests, ${guests_matched} matched, ${links} map links`; not ok -> `Last sync failed (${timeAgo(ts)}): ${error}`.
