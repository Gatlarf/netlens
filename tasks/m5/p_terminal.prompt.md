FRONTEND CONVENTIONS: plain ES modules, no framework, no build step, no CDN, no inline event-handler attributes, never use innerHTML with data (build DOM with the h() helper or textContent). Files live under app/static/ and are served from / (so index.html loads css/app.css and js/app.js as an ES module).

REAL API RESPONSES (authenticated, JSON; cookie auth, credentials same-origin):
GET /api/devices (first item): {
 "id": 1,
 "primary_ip": "192.168.1.1",
 "mac": "c0:56:27:aa:bb:01",
 "hostname": "router.lan",
 "custom_name": null,
 "vendor": "Belkin International",
 "device_type": "router",
 "type_override": null,
 "notes": null,
 "tags": [],
 "online": 1,
 "first_seen": "2026-10-06T21:24:38Z",
 "last_seen": "2026-10-06T21:24:38Z",
 "name": "router.lan",
 "type": "router",
 "open_ports": 4
}
GET /api/devices/1: {
 "id": 1,
 "primary_ip": "192.168.1.1",
 "mac": "c0:56:27:aa:bb:01",
 "hostname": "router.lan",
 "custom_name": null,
 "vendor": "Belkin International",
 "device_type": "router",
 "type_override": null,
 "notes": null,
 "tags": [],
 "online": 1,
 "first_seen": "2026-10-06T21:24:38Z",
 "last_seen": "2026-10-06T21:24:38Z",
 "name": "router.lan",
 "type": "router",
 "open_ports": 4,
 "ips": [
  {
   "ip": "192.168.1.1",
   "last_seen": "2026-10-06T21:24:38Z"
  }
 ],
 "names": [
  {
   "name": "router.lan",
   "source": "ptr"
  }
 ],
 "ports": [
  {
   "port": 22,
   "proto": "tcp",
   "service": "ssh"
  },
  {
   "port": 53,
   "proto": "tcp",
   "service": "domain"
  },
  {
   "port": 80,
   "proto": "tcp",
   "service": "http"
  },
  {
   "port": 443,
   "proto": "tcp",
   "service": "https"
  }
 ],
 "events": [
  {
   "id": 1,
   "ts": "2026-10-06T21:24:38Z",
   "kind": "device_new",
   "detail": "192.168.1.1 Belkin International"
  }
 ]
}
GET /api/scans: [{"id": 1, "kind": "deep", "status": "done", "started": "2026-10-06T21:24:38Z", "finished": "2026-10-06T21:24:38Z", "hosts_found": 4, "error": null}]
GET /api/scans/current: {"running": false, "scan": null}
GET /api/events (first 2): [{"id": 4, "ts": "2026-10-06T21:24:38Z", "device_id": 4, "kind": "device_new", "detail": "192.168.1.50"}, {"id": 3, "ts": "2026-10-06T21:24:38Z", "device_id": 3, "kind": "device_new", "detail": "192.168.1.30"}]
POST /api/scans body {kind:'quick'|'deep'} -> 202 {id}; 409 {detail:'scan already running'}
PATCH /api/devices/{id} body {custom_name?, notes?, tags?: [str], type_override?} -> device detail; 422 on invalid type_override
Other endpoints: GET /api/config -> {version, ranges:[str], quick_interval, deep_interval, terminal_enabled, snmp_enabled, bind}; POST /api/login {token} -> {ok:true} | 401 {detail}; POST /api/logout; GET /api/session -> {authenticated: bool} (never 401). GET /api/devices?online=true|false&q=text. Device types: router, switch, ap, server, pc, phone, printer, iot, camera, nas, vm, unknown. Event kinds: device_new, device_online, device_offline, ip_changed, port_opened, os_changed. Device JSON also has os_name, os_confidence, pos_x, pos_y.

## EXISTING app/static/js/util.js
1:export function h(tag, attrs = {}, ...children) {
42:export function clear(el) {
48:export function fmtTime(iso) {
60:export function timeAgo(iso, now = Date.now()) {
75:export function debounce(fn, ms) {
83:export function toast(message, kind = "info") {
99:export function el(selector, root = document) {
103:export const TYPE_LABELS = {
118:export function typeBadge(type) {
122:export function statusDot(online) {

## EXISTING app/static/js/api.js
1:export class ApiError extends Error {
9:export async function api(path, { method = "GET", body } = {}) {
56:export const get = (p) => api(p);
57:export const post = (p, body = {}) => api(p, { method: "POST", body });
58:export const patch = (p, body) => api(p, { method: "PATCH", body });
59:export const del = (p) => api(p, { method: "DELETE" });

TASK:
Create app/static/js/terminal.js (ES module) exporting: async function mountTerminal(slot, device) and function isTerminalActive(slot). Imports: { get, del, ApiError } from "./api.js"; { h, clear, toast } from "./util.js".
`slot` is an empty <div id="terminal-slot">; `device` is the device detail JSON (id, primary_ip, name, ports: [{proto, port, state, service,...}], ...). Libraries are vendored (classic scripts, UMD globals): vendor/xterm.js defines global `Terminal`; vendor/addon-fit.js defines global `FitAddon` with class FitAddon.FitAddon; vendor/xterm.css is the stylesheet. Write loadXterm(): injects <link rel="stylesheet" href="vendor/xterm.css"> and the two <script> tags once (sequentially, xterm.js first), returns a Promise that resolves when both are loaded (cached for later calls, reject with a clear error message when loading fails).
mountTerminal: 1) const cfg = await get("/api/config") (catch errors -> return); if !cfg.terminal_enabled return null. 2) Determine protocols: ssh when a port with state starting "open", proto "tcp" and (port == 22 or service == "ssh") exists (use that port, prefer 22); telnet likewise for port 23 or service "telnet". If neither exists return null. 3) Build into slot a .card with h2 "Console" and a row of buttons (class btn): "SSH (<port>)" and/or "Telnet (<port>)"; clicking one shows a connection area below. For SSH the area is a form with: Username (text, autocomplete off, required), Password (type password, autocomplete off), a collapsible "Use a private key" section with a textarea (private key PEM) plus a file input that fills the textarea via FileReader, Passphrase (password), and a Connect button; a note "Credentials are sent to the Netlens server only to open this session; they are not stored." For Telnet the area only has a Connect button (the login happens inside the terminal). 4) On connect: await loadXterm(); clear the connection area; create a div.terminal-wrap and a status line p.muted; create `const term = new Terminal({cursorBlink: true, fontFamily: "ui-monospace, Menlo, Consolas, monospace", fontSize: 14, theme: {background: "#0b1020"}})`, `const fit = new FitAddon.FitAddon(); term.loadAddon(fit); term.open(wrapEl); fit.fit();`. Open the WebSocket: new WebSocket((location.protocol === "https:" ? "wss://" : "ws://") + location.host + "/api/terminal/" + device.id + "/ws?proto=" + proto + "&port=" + port); ws.binaryType = "arraybuffer". On open send JSON.stringify({type: "auth", username, password: password || null, private_key: key || null, passphrase: passphrase || null, cols: term.cols, rows: term.rows}) and IMMEDIATELY blank the password/key/passphrase input values and local variables (keep nothing in memory beyond sending). Incoming: ArrayBuffer -> term.write(new Uint8Array(data)); string -> JSON control messages: {"type":"status","state":"connected","fingerprint","new_key"} -> status line "Connected" plus, for ssh, " · host key " + fingerprint + (new_key ? " (trusted on first use)" : " (verified)") and focus the terminal; {"type":"error","message"} -> term.writeln in red ("\x1b[31m" + message + "\x1b[0m") and status line text; {"type":"hostkey_mismatch","expected","actual"} -> replace the terminal with a div.card.warning that says "WARNING: the SSH host key of this device has CHANGED." showing expected and actual fingerprints in .mono and the text "This can mean the device was reinstalled, or that someone is intercepting the connection." and a button "Forget stored key and try again" that calls del("/api/devices/" + device.id + "/hostkey") then re-shows the connection form; {"type":"closed","reason"} -> status line "Session closed: " + reason. On ws close show "Disconnected" and a "Reconnect" button that re-shows the form. Keyboard: term.onData(d => ws.send(new TextEncoder().encode(d))) only when ws.readyState === 1. Resize: on window "resize" and via a ResizeObserver on the wrap call fit.fit() and send JSON {"type":"resize","cols": term.cols, "rows": term.rows} when open (debounce 100 ms). A "Disconnect" button (btn danger) closes the websocket and disposes the terminal. 5) Return an object { dispose() } that closes the websocket, disposes the terminal, disconnects the ResizeObserver and removes the window listener. isTerminalActive(slot) returns true when a websocket for that slot is open or connecting (track it in a WeakMap keyed by slot or a data attribute). Never use innerHTML, never log credentials, never put credentials in the URL.
