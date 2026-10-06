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
Create app/static/js/pages/device.js exporting async function render(container, params) where params.id is the device id. Imports: { get, patch, ApiError } from "../api.js"; { h, clear, fmtTime, timeAgo, typeBadge, statusDot, toast, TYPE_LABELS } from "../util.js".
Load GET /api/devices/<id> (404 -> show a card "Device not found" with a link back to #/devices). Layout:
- Heading row: statusDot, device name (h1), typeBadge, "← Devices" link to #/devices.
- .grid-2: left .card "Details" with .kv rows: IP, MAC (mono), Vendor, Hostname, OS (os_name plus " (<os_confidence>%)" when os_confidence is not null), Type (type, and "(override)" when type_override is set), First seen, Last seen (fmtTime and timeAgo), Status. Under it a card "Open ports": table.data with Port/Proto, Service, Product, Version for the "ports" list (state shown when not plain "open"); for ports 80, 443, 8080, 8443, 8006, 5000, 5001, 9000 add an "Open" link <a target="_blank" rel="noopener noreferrer" href="http(s)://<ip>:<port>"> (https for 443, 8443, 8006, 5001, else http). Right: .card "Edit" with a form: Custom name input, Type override <select> (empty option "(automatic)" plus TYPE_LABELS entries), Tags input (comma separated), Notes textarea, Save button: PATCH /api/devices/<id> with {custom_name, type_override, tags: [...], notes}; empty strings clear values; on success toast "Saved" and re-render; on ApiError toast its message. Then card "Names & addresses": names with source badge, IP history with last seen. Then card "Recent events": the events list with timeAgo.
- Below the cards add an empty <div id="terminal-slot" class="terminal-slot"></div> (a later milestone fills it).
Auto refresh every 20 seconds without losing unsaved form edits (skip refresh while any form field has focus or the form is dirty); cleanup clears the interval. Never use innerHTML.
