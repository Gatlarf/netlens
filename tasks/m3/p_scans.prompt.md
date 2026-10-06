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
Create app/static/js/pages/scans.js exporting async function render(container, params). Imports: { get } from "../api.js"; { h, clear, fmtTime, timeAgo } from "../util.js".
Two cards side by side (.grid-2). Left card "Scans": table.data of GET /api/scans?limit=50 with columns Started (fmtTime), Kind, Status (class-coloured text: done=ok, failed=bad, running=warn), Hosts found, Duration (finished minus started as "1m 05s", "—" if running), Error (muted, truncated, full text in title). Right card "Events": a filter row (<select> of kinds: All, device_new, device_online, device_offline, ip_changed, port_opened, os_changed with friendly labels such as "New device", "Device online", "Device offline", "IP changed", "Port opened", "OS changed") and a ul.event-list of GET /api/events?limit=200[&kind=...] items showing time (timeAgo with title fmtTime), a coloured label for the kind, the detail text, and when device_id is not null a link to "#/device/<device_id>". Empty states with .empty. Refresh every 10 seconds and on "netlens:scan-finished"; the cleanup function clears the interval and listener. Never use innerHTML.
