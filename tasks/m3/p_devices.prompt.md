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
Create app/static/js/pages/devices.js exporting async function render(container, params). Imports: { get } from "../api.js"; { h, clear, fmtTime, timeAgo, debounce, typeBadge, statusDot, TYPE_LABELS } from "../util.js".
Build a toolbar (search <input type="search" placeholder="Search name, IP, MAC, vendor…"> debounced 250 ms, <select> status filter All/Online/Offline, <select> type filter All + each TYPE_LABELS entry, a result count, and links "Export CSV" (href /api/export/devices.csv) and "Export JSON" (href /api/export/devices.json) with the download attribute) and a table.data inside .table-wrap. Columns (sortable by clicking th.sortable, toggling asc/desc and adding the class sorted-asc/sorted-desc): Status (statusDot), Name, IP (numeric-aware IPv4 sort), MAC (mono), Vendor, Type (typeBadge), OS (os_name or "—"), Open ports (number), Last seen (timeAgo, title = fmtTime). Default sort: IP ascending. Clicking a row navigates to location.hash = "#/device/" + id (rows are keyboard-focusable, Enter works). Data: GET /api/devices with query params q and online when set (online=true/false); the type filter is applied client side. Tags are shown as small .tag chips under the name. Show an .empty message when there are no devices ("No devices yet. Run a scan."). Refresh every 15 seconds and on the "netlens:scan-finished" document event, keeping search/sort/filter state; return a cleanup function that clears the interval and removes the event listener. Never use innerHTML.
