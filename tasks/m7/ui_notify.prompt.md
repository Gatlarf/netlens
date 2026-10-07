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

TASK: write app/static/js/cards/notifications.js (full file, under 190 lines). Export `export async function buildNotificationsCard()`.

API:
GET /api/notifications -> {enabled: bool, smtp_host: str, smtp_port: int, security: "none"|"starttls"|"ssl", username: str, from_addr: str, to_addrs: [str], notify_new: bool, notify_offline: bool, password_set: bool, configured: bool, status: null | {ts: iso, ok: bool, error?: str, sent?: int, subject?: str, pending?: int}}.
PUT /api/notifications with any of {enabled, smtp_host, smtp_port (int), security, username, password, from_addr, to_addrs (comma separated string accepted), notify_new, notify_offline}; only the fields sent change. Omit `password` from the body when the password input is empty (the server then keeps the saved one). Returns the same shape as GET. Errors 422 with a readable detail.
POST /api/notifications/test (no body) -> {ok: true, to: [str]} or error 422/502 with a readable detail. It uses the SAVED settings.

Card: <h2>E-mail notifications</h2> and a form with:
- checkbox "Send e-mail notifications" (enabled)
- inputs: SMTP server (smtp_host), Port (number, smtp_port), select Security with options "STARTTLS (port 587)" = starttls, "SSL/TLS (port 465)" = ssl, "None (port 25)" = none; Username; Password (type password, autocomplete "new-password", placeholder "unchanged" when password_set, else empty); From address; To address(es) (text, comma separated, value to_addrs.join(", ")).
- checkbox "Notify when a new device appears" (notify_new); checkbox "Notify when a device goes offline" (notify_offline) with a hint "You can switch this off for individual devices on their device page."
- Buttons: "Save" (submit) and "Send test email". The test button first saves the current form (PUT) and then calls POST /api/notifications/test; on success toast "Test email sent to a@b.c" (join to) , on failure show the error inline. Disable both buttons while busy.
- A status line at the bottom (<p class="hint">, red via class "error" when failed) built from `status`: ok -> `Last notification mail: ${timeAgo(ts)} (${sent} event(s))`; not ok -> `Last problem (${timeAgo(ts)}): ${error}`; null -> nothing.
- When security changes in the select and the port input still holds the previous default (587/465/25), set the port to the new default.
