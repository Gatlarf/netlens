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

TASK: write app/static/js/cards/general.js (full file, under 120 lines). Export `export async function buildGeneralCard()`.

API: GET /api/config returns (among others) {quick_interval: seconds, deep_interval: seconds, quick_interval_source: "ui"|"env", deep_interval_source: "ui"|"env", env_quick_interval: seconds, env_deep_interval: seconds, terminal_enabled: bool, terminal_source: "ui"|"env", env_terminal_enabled: bool}.
PUT /api/config/general accepts any of {quick_interval: int seconds (60..2592000), deep_interval: int seconds, terminal_enabled: bool}; a field set to null resets that setting to its environment default. It returns the same shape as GET /api/config.

Card: <h2>Scan schedule and terminal</h2> with a form:
- number input "Quick scan every (minutes)" showing quick_interval/60 (min 1, step 1) with a hint "From the environment (NETLENS_QUICK_INTERVAL)" when quick_interval_source is "env" or "Changed here; environment default: N min" when "ui".
- number input "Deep scan every (hours)" showing deep_interval/3600 (min 0.05, step any/0.5), same style hint with env_deep_interval.
- checkbox "Enable the web terminal (SSH/Telnet from the device page)" checked = terminal_enabled, hint about source ("From the environment (NETLENS_TERMINAL)" or "Changed here").
- Buttons: Save (submit) and "Reset to defaults".
- Save sends {quick_interval: Math.round(minutes*60), deep_interval: Math.round(hours*3600), terminal_enabled: checkbox}; show an inline error for non-numeric/empty input before sending ("Enter a number of minutes"). Reset sends {quick_interval: null, deep_interval: null, terminal_enabled: null}. Toasts: "Settings saved" / "Settings reset".
- After saving, mention in a hint: "Takes effect from the next scheduler cycle; no restart needed."
