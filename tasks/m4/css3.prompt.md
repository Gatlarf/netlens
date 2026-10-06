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
Create app/static/css/map.css (CSS variables from app.css: --bg, --surface, --text, --muted, --border, --accent, --accent-text, --ok, --warn, --bad). Style: .legend (inline-flex, gap 14px, align-items center, margin-left auto, font-size .85rem, color var(--muted)); .legend-item (inline-flex, gap 6px, align-items center); .legend-swatch (inline-block width 26px, height 0, border-top 2px solid; modifiers by sibling text are not possible, so give each swatch an inline-free look using these extra classes the script adds: .legend-swatch.gateway {border-top: 2px solid #888}, .legend-swatch.route {border-top: 2px dashed #2563eb}, .legend-swatch.host-of {border-top: 2px dotted #7c3aed}, .legend-swatch.manual {border-top: 4px solid var(--accent)}); .map-wrap { position: relative; display: block; background: var(--surface); border: 1px solid var(--border); border-radius: 8px; overflow: hidden; height: calc(100vh - 150px); min-height: 420px }; #map-canvas { position: absolute; inset: 0 }; .map-panel { position: absolute; top: 0; right: 0; bottom: 0; width: 320px; max-width: 90%; background: var(--surface); border-left: 1px solid var(--border); padding: 16px; overflow: auto; transform: translateX(100%); transition: transform .15s ease; z-index: 5 } .map-panel.open { transform: none }; .map-panel h3 {margin: 0 0 8px}; .map-panel .kv-row-like: plain spacing for children (display block, margin 4px 0); .toolbar .legend alignment; .btn.active { background: var(--accent); color: var(--accent-text) }. Under 60 lines.
