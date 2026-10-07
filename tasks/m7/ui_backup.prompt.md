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

TASK: write app/static/js/cards/backup.js (full file, under 110 lines). Export `export function buildBackupCard()` (synchronous, returns a div.card).

API:
GET /api/backup downloads the database snapshot (a file download, the session cookie authenticates a normal browser navigation/link).
POST /api/restore: the RAW file bytes as the request body (do NOT use the api.js helpers because they JSON-encode; use fetch("/api/restore", {method: "POST", credentials: "same-origin", headers: {"Content-Type": "application/octet-stream"}, body: file})). Success: JSON {ok: true, backup_schema_version: int, devices: int}. Errors: JSON {detail: "readable text"} with status 409 (a scan is running), 413, 422 (invalid file) or 401.

Card: <h2>Backup and restore</h2>.
- Paragraph <p class="hint">: "The backup contains all devices, history and settings, including saved e-mail and Proxmox credentials. Store it somewhere safe."
- A link styled as button: h("a", {class: "btn", href: "/api/backup", download: ""}, "Download backup").
- A form for restore: file input (accept ".db,.sqlite,.sqlite3,application/octet-stream"), button "Restore from file" (disabled until a file is chosen). On click: window.confirm("Restore this backup? It REPLACES all current data (devices, history, settings). A safety copy of the current database is kept on the server.") ; if confirmed, send the file as described; while running disable the button and show "Restoring..." text; on success toast `Restored ${devices} devices. Reloading...` and after 1200 ms call location.reload(); on failure show the detail in a <p class="error"> inside the card and an error toast; if the response is not JSON show `Restore failed (HTTP ${status})`.
- Keep the chosen file input in the card; clear it after a failed attempt is NOT required.
