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
Create app/static/js/pages/map.js exporting async function render(container, params). Imports: { get, post, patch, del, ApiError } from "../api.js"; { h, clear, toast, typeBadge, statusDot, TYPE_LABELS } from "../util.js".
The library vis-network is vendored at /vendor/vis-network.min.js (classic script, defines the global `vis` with vis.Network and vis.DataSet). Write a helper loadVis(): returns a Promise that resolves immediately when window.vis exists, otherwise injects <script src="vendor/vis-network.min.js"> once and resolves on load (reject on error with a clear message).
Data: GET /api/map returns {"nodes":[{id,label,ip,mac,vendor,type,online(bool),pos_x,pos_y,open_ports,tags[]}], "edges":[{id,from,to,kind,source,confidence,manual(bool)}]}.
Layout of the page inside `container`: a .toolbar with: search input (filters nodes by label/ip/mac/vendor, case-insensitive), <select> type filter (All + TYPE_LABELS), <select> status (All/Online/Offline), buttons "Add link" (toggle, class btn), "Delete link" (btn danger, disabled until an edge is selected), "Reset layout", "Export PNG", and a legend (div.legend with div.legend-item entries, each with a span.legend-swatch coloured like the edge style and a text label: Gateway, Route, Host-of, Manual). Below it a div.map-wrap containing div#map-canvas and an aside.map-panel (gets class "open" when a node is selected).
Network: new vis.Network(canvasEl, {nodes: DataSet, edges: DataSet}, options). Node style: shape "dot", size 18, label = label + "\n" + ip, colour by device type (a palette object: router #2563eb, switch #0891b2, ap #7c3aed, server #475569, pc #059669, phone #db2777, printer #ea580c, iot #ca8a04, camera #dc2626, nas #0d9488, vm #6366f1, unknown #94a3b8); offline nodes are drawn with opacity 0.4 (use the node `opacity` option). Edge style by kind: gateway solid width 1.5 grey; route dashes [8,6] blue; host-of dashes [2,5] purple; manual (edge.manual true) width 3 accent colour solid; edges have arrows "to", smooth {type:"continuous"}, title tooltip as a plain-text string (kind · source · confidence percent). Nodes with both pos_x and pos_y not null are placed at those coordinates; if every node has saved positions disable physics, otherwise enable physics (barnesHut) and call network.setOptions({physics:false}) after the "stabilizationIterationsDone" event so the layout stays still.
Interactions: clicking a node fills the side panel (clear + build with h(): name, typeBadge, statusDot, IP, MAC (mono), vendor, open ports count, tags as .tag chips, and a link <a href="#/device/<id>"> "Open device page"); clicking empty canvas closes the panel. On "dragEnd" with moved nodes (params.nodes non-empty): read network.getPositions(params.nodes) and PATCH /api/devices/<id> {pos_x, pos_y} for each (catch and toast errors). "Reset layout" PATCHes pos_x: null, pos_y: null for every node, then reloads and re-enables physics. "Add link" toggles network.addEdgeMode(); configure options.manipulation = {enabled: false, addEdge: (data, callback) => { POST /api/relations {src_id: data.from, dst_id: data.to}; on success toast "Link added", call callback(null) (so vis does not add its own edge) and reload data; on ApiError toast its message; always network.disableEditMode() and untoggle the button }}. Selecting an edge (network "selectEdge") enables "Delete link"; clicking it DELETEs /api/relations/<edge id>, toasts "Link removed" and reloads. "Export PNG": draw the network canvas (container.querySelector("canvas")) onto a new offscreen canvas of the same size filled with the computed background colour of .map-wrap (getComputedStyle, fallback white), then canvas.toBlob and download as netlens-map.png via a temporary <a download>.
Reloading data (initial load, every 30 s, after changes, and on the "netlens:scan-finished" document event): fetch /api/map and diff into the DataSets (update existing, add new, remove missing) without moving nodes the user is dragging and without resetting positions; apply the search/type/status filters by setting `hidden` on nodes (edges to hidden nodes are hidden automatically). If there are no nodes show div.empty "No devices yet. Run a scan." instead of the canvas wrapper contents. Return a cleanup function that destroys the network, clears the interval and removes the document event listener. Never use innerHTML; node labels come from data so only use textContent/h().
