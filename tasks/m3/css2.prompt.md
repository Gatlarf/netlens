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
Create app/static/css/pages.css, a supplementary stylesheet loaded after app.css. It must style these extra classes used by the page scripts (CSS variables available from app.css: --bg, --surface, --text, --muted, --border, --accent, --accent-text, --ok, --warn, --bad). Structure notes:
- .heading-row: flex row, align-items center, gap 12px, wraps; contains a status dot, h1.device-name, a type badge and a back link (push the back link to the right with margin-left:auto); .device-name: margin 0.
- .col-left / .col-right: flex columns with 16px gap (they are the two children of .grid-2 on the device page); .card-title: margin 0 0 12px, font-size 1.05rem; .card-body: plain block; .card gets margin-bottom 0 inside these columns.
- Key/value rows: each row is a div.kv-row?? NO: rows are elements with class "kv" (already in app.css as a row container) holding span.kv-key / span.kv-label (muted, fixed width 130px, flex none) and span.kv-value (flex 1, word-break). Make any element that has a .kv-key or .kv-label child use display:flex with gap 12px and 4px vertical padding; .kv-value mono-friendly with overflow-wrap:anywhere.
- .edit-form: grid, gap 12px; .field: grid with the label above its input/select/textarea (label muted small); inputs/selects/textarea width 100%; textarea min-height 90px; the submit button in .edit-form aligns to the start.
- .names-list, .ip-list, .events-list, .event-list: list-style none, padding 0, margin 0; each li: padding 6px 0, border-bottom 1px solid var(--border), flex with gap 10px, wrap, align-items baseline; last li has no border. .name-value normal weight, .source-badge small pill (muted background, 0.75rem, uppercase), .ip-seen muted small margin-left auto, .event-time muted small min-width 90px, .event-kind small bold pill, .event-detail flex 1, .event-link accent colour, .event-item same as li.
- .filter-row: flex row with gap 8px, margin-bottom 12px, align-items center; .kind-filter: min-width 160px; .export-link: accent colour, underline on hover only, margin-right 12px.
- .terminal-slot: margin-top 16px (empty when it has no children); .count: muted, font-size .9rem.
Keep it under 140 lines. Use only the variables listed.
