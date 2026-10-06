# Netlens — Requirements & Design

Working name: **Netlens**. A self-hosted LAN scanner and map, packaged as a Docker container.

## 1. Goals
1. Discover every device on the local network(s) and keep an inventory of them.
2. Identify, per device: hostname(s), IP(s), MAC, vendor, OS guess, open services, device type.
3. Draw a live network map showing devices and the relations between them.
4. Offer a browser-based terminal (SSH/Telnet) to devices that expose a console.
5. Be safe by default: nothing is scanned or exposed beyond what the owner configured.

Non-goals (v1): vulnerability scanning, internet-facing scanning, multi-user accounts, alerting by email/push, IPv6 sweeping.

## 2. Users and deployment
- One owner on a home or lab network. Runs the container on a Docker host inside the LAN.
- Single container, `network_mode: host` (needed for ARP and accurate L2 discovery), capabilities `NET_RAW` and `NET_ADMIN`, one volume `/data` for the database.
- Configured with environment variables only (see section 8).
- NOT deployed by this project until the owner says so. Tests run locally without touching the network.

## 3. Functional requirements

### 3.1 Discovery
- F1 Auto-detect the local subnet(s) from host interfaces. Owner can override or add CIDRs. Refuse ranges larger than /20 unless explicitly allowed.
- F2 Host discovery: ARP sweep for local subnets, plus ICMP/TCP-ping for routed ranges (via nmap `-sn`).
- F3 Passive/name sources, merged into the device record: reverse DNS, mDNS (Bonjour), NetBIOS/LLMNR names, SSDP/UPnP description (friendly name, model), DHCP-given names when readable from the router if configured later.
- F4 MAC vendor lookup from the OUI table shipped with nmap.
- F5 Scheduling: manual "scan now", plus a periodic quick scan (default 15 min) and a deeper scan (default daily). Intervals configurable, scans never overlap.
- F6 Scan progress and history: each scan has status, start/end, devices found.

### 3.2 Identification
- F7 Port/service scan: top 1000 TCP ports by default, service name and version via nmap `-sV` in deep scans only. Quick scans use top 100 ports.
- F8 OS fingerprint via nmap `-O` in deep scans, stored with a confidence value. Also derive hints from TTL, vendor, and service banners (e.g. SSH banner "Ubuntu").
- F9 Device type classification (router, switch/AP, server, PC, phone/tablet, printer, IoT, camera, NAS, VM, unknown) using simple, documented rules over vendor, ports, OS and SSDP/mDNS data. The owner can override type and give a custom name, notes and tags. Overrides are never overwritten by scans.
- F10 Per device, record: first seen, last seen, online/offline state, IP history, hostname history, open ports with service/version, OS, vendor, MAC, type, raw nmap XML of the latest deep scan.
- F11 Detect changes and write them to an event log: new device, device offline/online, IP change, new open port, OS change.

### 3.3 Relations and map
- F12 Network map page: interactive graph, drag/zoom, search, filter by type/online state/tag, click a device for a detail panel.
- F13 Relations drawn (each edge has a `kind`, a `source` of evidence and a confidence):
  - `gateway`: every device to its default gateway of the subnet.
  - `route`: routed devices connected via traceroute hops to the intermediate router.
  - `host-of`: a VM/container device linked to a probable hypervisor (same host MAC prefix pattern, VM vendor OUIs, or user-assigned).
  - `service`: devices that depend on another's service (DNS server in use, SMB share, etc.) only where evidence is cheap to obtain; otherwise skip.
  - `manual`: relations the owner draws or deletes. Manual edges always win.
- F14 Optional LLDP/CDP neighbor and SNMP (v2c community or v3 from env) lookups for managed switches/APs, to draw switch→device links. Behind a config flag, off by default.
- F15 Map layout positions can be dragged and are saved per device.
- F16 Export: inventory as CSV and JSON; map as PNG/SVG.

### 3.4 Web terminal
- F17 A device with port 22 open gets "SSH" button, port 23 gets "Telnet". The terminal opens in a panel in the UI (xterm.js over WebSocket).
- F18 The owner types username/password (or pastes a private key) per session. Credentials are never written to disk or logs. Optionally remembered in browser memory only for the open tab.
- F19 Host key handling: trust-on-first-use, fingerprint stored per device, warn loudly on change.
- F20 Terminal resize, copy/paste, session closes cleanly on disconnect, idle timeout (default 15 min).
- F21 Other consoles (HTTP/HTTPS admin UI, VNC, RDP) get an "Open" link only (new tab). No embedded proxying in v1.

### 3.5 UI
- F22 Pages: Map, Devices (sortable table with search), Device detail, Scans/Events, Settings.
- F23 Plain HTML + JavaScript, no build step, all libraries vendored locally in the image (no CDN at runtime). Works in current Chrome/Firefox/Safari. Dark and light via `prefers-color-scheme`.

## 4. Security requirements
- S1 The UI/API requires an access token (env `NETLENS_TOKEN`). The app refuses to start without one. Login sets an HttpOnly cookie.
- S2 The terminal is the highest risk feature. It can be disabled with `NETLENS_TERMINAL=off`. It can only connect to IPs present in the inventory and inside configured scan ranges, never to arbitrary hosts.
- S3 Scanning only happens against configured/auto-detected private ranges (RFC1918, link-local). Public ranges are rejected.
- S4 The app listens on `0.0.0.0:8080` by default but `NETLENS_BIND` can restrict it. No TLS in the app. Documentation tells the owner to put it behind a reverse proxy for HTTPS.
- S5 No secrets in logs. Input validated. No shell string interpolation: subprocess calls use argument lists.
- S6 Container runs nmap with minimal required capabilities, app process as non-root where possible (nmap raw access via capabilities).

## 5. Technology (decided)
| Concern | Choice | Why |
|---|---|---|
| Backend | Python 3.12, FastAPI, uvicorn | Small, async, WebSockets built in |
| Scanning | nmap binary driven via subprocess + XML parsing | Mature OS/service detection; no reinventing |
| Name discovery | `zeroconf` (mDNS), `python-ssdp`-style raw SSDP via stdlib sockets, `nmblookup`-free NetBIOS via nmap script `nbstat` | Few dependencies |
| SSH | `asyncssh` | Async, supports PTY and host key checks |
| Telnet | stdlib `asyncio` raw socket with minimal IAC handling | Avoids deprecated telnetlib |
| Storage | SQLite via `sqlite3` + small data-access layer | Zero admin, single file in `/data` |
| Scheduler | `asyncio` tasks in-process | Avoids extra services |
| Frontend | Vanilla JS modules, `vis-network` (map), `xterm.js` + fit addon | No build toolchain |
| Packaging | One Dockerfile (python:3.12-slim + nmap), `docker-compose.yml` | Simple to run |
| Tests | `pytest`, nmap XML fixtures, fake network layer | Run without a real LAN |

## 6. Architecture
```
app/
  main.py            FastAPI app, auth, static files, startup tasks
  config.py          env parsing and validation
  db.py              schema, migrations, queries
  models.py          pydantic models
  scanner/
    nmap_runner.py   build args, run nmap, stream progress
    nmap_parser.py   XML -> Device/Port/OS records
    discovery.py     subnet detection, scan orchestration
    names.py         mDNS, SSDP, NetBIOS, reverse DNS
    classify.py      device type rules
    relations.py     edge inference
  terminal/
    ssh.py           asyncssh <-> WebSocket bridge
    telnet.py        telnet <-> WebSocket bridge
  api/               REST routers: devices, scans, events, relations, settings, export
  static/            index.html, js/, css/, vendor/
tests/
Dockerfile
docker-compose.yml
README.md
```
Data model (SQLite): `devices`, `device_ips`, `device_names`, `ports`, `scans`, `events`, `relations`, `settings`, `host_keys`.
Identity: a device is keyed by MAC when known, else by IP. MAC change on same IP creates an event, not a silent merge.

## 7. Non-functional requirements
- Quick scan of a /24 under 60 s on a typical LAN; deep scan runs in the background without blocking the UI.
- Memory under 300 MB at idle with 250 devices.
- Scan traffic is rate-limited (nmap `-T3` default, configurable) to avoid disturbing fragile IoT devices.
- Logs are structured and rotate. No data leaves the host.
- API is documented through FastAPI's OpenAPI page.

## 8. Configuration (env)
`NETLENS_TOKEN` (required), `NETLENS_RANGES`, `NETLENS_QUICK_INTERVAL`, `NETLENS_DEEP_INTERVAL`, `NETLENS_TERMINAL` (on/off), `NETLENS_SNMP_COMMUNITY`, `NETLENS_BIND`, `NETLENS_DATA_DIR`.

## 9. Delivery plan (milestones, each with acceptance checks)
| M | Scope | Done when |
|---|---|---|
| M0 | Project scaffold, config, DB schema, LLM wrapper + token ledger | `pytest` passes, DB initialises |
| M1 | nmap runner + parser + device storage + REST for devices/scans | Parser test on fixture XML yields expected devices; API returns them |
| M2 | Discovery orchestration, scheduling, names, classify, events | Fake-scan integration test shows new/offline/IP-change events |
| M3 | Auth + frontend: Devices table, detail page, scans/events | Manual smoke test in browser against fixture data |
| M4 | Relations inference + network map + manual edges + export | Map renders fixture network with gateway and route edges |
| M5 | Web terminal (SSH, Telnet), host key TOFU, limits | Test against a local SSH server in tests |
| M6 | Dockerfile, compose, README, hardening review | Image builds locally; NOT deployed |

## 10. Working agreement
- All code is written by the local LLM. The project manager (Claude) writes only documents and task briefs, reviews, and runs tests.
- Every LLM call is logged in `ledger/ledger.jsonl` (tokens, task id, outcome, retry count).
- Each task brief states: files to produce, interfaces, acceptance test. Failed tasks are retried with concrete defect feedback, max 3 retries, then split into smaller tasks.
