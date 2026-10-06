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
Create app/static/js/util.js (ES module) exporting:
- h(tag, attrs = {}, ...children): create an element. attrs: "class" sets className; "dataset" object sets data-*; keys starting with "on" and a function value (e.g. onclick) are added with addEventListener(key.slice(2).toLowerCase(), fn); boolean true sets the attribute to "", false/null/undefined skips it; everything else setAttribute(key, String(value)). Children: strings/numbers become text nodes, null/false/undefined are skipped, arrays are flattened, Nodes are appended.
- clear(el): remove all children.
- fmtTime(iso): for an ISO-8601 UTC string like "2026-10-06T21:24:38Z" return a local "YYYY-MM-DD HH:MM" string; "" for null/invalid.
- timeAgo(iso, now = Date.now()): "just now" (<45s), "5 min ago", "3 h ago", "2 d ago"; "never" for null/invalid.
- debounce(fn, ms).
- toast(message, kind = "info"): append a div.toast.<kind> to #toasts (create the container div with id "toasts" in document.body if it does not exist), remove after 4 seconds.
- el(selector, root = document): querySelector shorthand.
- TYPE_LABELS: object mapping device type to display label {router:"Router", switch:"Switch", ap:"Access point", server:"Server", pc:"Computer", phone:"Phone/tablet", printer:"Printer", iot:"IoT", camera:"Camera", nas:"NAS", vm:"Virtual machine", unknown:"Unknown"}.
- typeBadge(type): returns h("span", {class: "badge type-" + type}, TYPE_LABELS[type] || type).
- statusDot(online): returns h("span", {class: "dot " + (online ? "on" : "off"), title: online ? "online" : "offline"}).
