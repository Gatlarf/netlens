
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
