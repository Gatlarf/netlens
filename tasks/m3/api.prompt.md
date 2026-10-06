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

TASK:
Create app/static/js/api.js (ES module).
- export class ApiError extends Error { constructor(status, detail) } with .status and .detail; message = detail string.
- export async function api(path, { method = "GET", body } = {}): fetch(path, { method, credentials: "same-origin", headers: body !== undefined ? {"Content-Type": "application/json"} : {}, body: body !== undefined ? JSON.stringify(body) : undefined }). Parse JSON when the response has content (204/empty body -> null). If !res.ok: detail = parsed.detail if it is a string, else JSON.stringify(parsed.detail) or res.statusText; when status === 401 also dispatch document.dispatchEvent(new CustomEvent("netlens:unauth")); throw new ApiError(status, detail). Network errors become ApiError(0, "network error").
- export const get = (p) => api(p); export const post = (p, body = {}) => api(p, {method: "POST", body}); export const patch = (p, body) => api(p, {method: "PATCH", body}); export const del = (p) => api(p, {method: "DELETE"}).
