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

TASK: write app/static/js/cards/scan_options.js (full file, under 260 lines). Export `export async function buildScanOptionsCard()`.

EXACT imports to use (nothing else is available): 
  import { get, put, del } from "../api.js";
  import { h, clear, toast, timeAgo } from "../util.js";
  import { humanDuration } from "../heartbeat.js";      // humanDuration(seconds) -> "2m 5s", "45s", "7m 26s"
  Do not use any helper that is not imported or defined in the file.
Input rules: every <input type="number"> needs min and step attributes: whole numbers use step "1"; use h("input", {type: "number", min: "1", max: "10000", step: "1", ...}). Use `oninput` (not onchange) for handlers that must react while typing. Labels are <label> elements placed before their input inside a div.field.

API:
GET /api/scan-options -> {options: {timing: int, quick_mode: "ports"|"discovery", quick_top_ports: int, quick_ports: str, deep_top_ports: int, deep_ports: str, deep_version: "full"|"light"|"off", deep_os: bool, deep_traceroute: bool, skip_dns: bool, host_timeout: int}, defaults: {same keys}, is_default: bool, presets: {default: {all keys}, fast: {all keys}, fastest: {all keys}}, preview: {quick: str, deep: str}}.
PUT /api/scan-options with a JSON object of any of the option keys (send ALL keys from the form every time); returns the same shape as GET. Errors: HTTP 422 with a readable detail (e.g. "quick_ports: '22;ls' is not a valid port or range").
DELETE /api/scan-options (use del("/api/scan-options")) resets to defaults and returns the same shape as GET.
GET /api/scans?limit=60 -> array (newest first) of {id, kind: "quick"|"deep", status: "done"|"failed"|"running", started: iso, finished: iso|null, hosts_found: int, error: str|null}.

Card (a div with class "card" AND id "nmap-settings"; first show "Loading..."; after a save/reset rebuild the whole card from fresh GET data):
- <h2>Scan performance (nmap)</h2>
- <p class="hint">: "Deep scans (service versions, OS detection and traceroute over 1000 ports) are the slow part. Check fewer ports, lighten the detection, or pick a preset."
- A "last scans" line (<p class="hint">): from GET /api/scans pick the newest status "done" scan of kind quick and of kind deep and show `Last quick scan: ${humanDuration(seconds)} (${hosts_found} hosts) · Last deep scan: ${humanDuration(seconds)} (${hosts_found} hosts)` where seconds = (Date.parse(finished) - Date.parse(started)) / 1000 rounded; show "none yet" for a kind without a finished scan. If this request fails just omit the line.
- Preset buttons (class "btn", type "button"): "Default", "Fast", "Fastest". Clicking one fills ALL form fields with the preset's values (it does NOT save; show toast("Preset loaded. Press Save to apply.", "info")). Under the buttons a <p class="hint"> per preset: Fast: "Aggressive timing, deep scans check the top 200 ports with light version detection." Fastest: "Also no OS or version detection, no reverse DNS, quick scans check the top 50 ports, and slow hosts are abandoned after 2 minutes. You lose OS names, service versions and DNS names." Default: "The original behavior." Mark the preset whose values equal the CURRENT SAVED options (compare all keys) by appending " (active)" to its button label.
- Form (class "edit-form") with sections (<h3>):
  1. "Speed": select "Timing" with options value 2 "Polite (T2, slowest)", 3 "Normal (T3, default)", 4 "Aggressive (T4, recommended for a local network)", 5 "Insane (T5, can miss hosts)". Convert the value with Number().
  2. "Quick scan (runs every few minutes)": select "Method" with options "ports" = "Check the most common ports" and "discovery" = "Only find which hosts are up (fastest, no port info)"; number "Number of top ports" (min 1, max 10000, step 1); text "Or these specific ports" (placeholder "22,80,443,8000-8100") with hint "Overrides the number above."
  3. "Deep scan (runs daily)": number "Number of top ports" (1..10000); text "Or these specific ports" (hint "Overrides the number. Ports that are not on the list disappear from a device after the next deep scan."); select "Service version detection" with options "full" = "Full (most accurate)", "light" = "Light (faster)", "off" = "Off (fastest)" and a hint "Without it, product and version columns are cleared at the next deep scan."; checkbox "OS detection" (hint "Off keeps the last known OS but stops updating it."); checkbox "Traceroute" (hint "Needed for the route links on the map.").
  4. "Both": checkbox "Skip reverse DNS lookups" (hint "Faster, but hostnames that come from DNS are no longer updated. Names from mDNS/SSDP stay."); number "Give up on a host after (seconds, 0 = never)" (min 0, max 86400, step 1; hint "0 or at least 10.").
- Below the form: <h3>Resulting nmap commands</h3> and a <pre class="mono"> with `${preview.quick}\n${preview.deep}` (from the saved options; it updates after saving).
- Buttons: "Save" (type submit) and "Reset to defaults" (type button; calls del). Disable buttons while a request runs. On save success toast("Scan settings saved. They apply from the next scan.", "success") and rebuild; on a 422/other error show err.message in a <p class="error"> inside the form and an error toast, do not rebuild.
- Collect values from the form into an object with EXACTLY the keys: timing, quick_mode, quick_top_ports, quick_ports, deep_top_ports, deep_ports, deep_version, deep_os, deep_traceroute, skip_dns, host_timeout (numbers via Number(), checkboxes via .checked, text trimmed).
