# Netlens

Self-hosted LAN scanner and network map. Runs as a single Docker container.

## Overview

Netlens scans private network ranges, discovers devices, classifies them, and builds a visual network map. It includes a web-based terminal for SSH and Telnet sessions to discovered devices.

## Features

- Quick and deep network scans using nmap
- Device discovery via ARP, ping, and TCP port scanning
- Service version detection and OS fingerprinting
- Reverse DNS, mDNS, and SSDP name resolution
- MAC vendor lookup from nmap's OUI table
- Device type classification by rules (vendor, OS, ports, hostnames)
- Network map with gateway, route, host-of, and manual edges
- Web terminal (SSH and Telnet) via xterm.js
- CSV and JSON export of devices
- PNG export of the network map
- Event logging (device_new, device_online, device_offline, ip_changed, port_opened, os_changed)

## Quick start

```bash
cp .env.example .env
# Set NETLENS_TOKEN in .env
docker compose up -d --build
```

Open `http://<docker-host>:8080`, log in with the token, and press **"Quick scan"**.

> **Note:** This project was developed but not yet deployed or tested on a real LAN.

## Configuration

| Variable | Default | Description |
|---|---|---|
| `NETLENS_TOKEN` | *(required)* | Access token for login |
| `NETLENS_RANGES` | auto-detect | Private ranges only, prefix >= /20 |
| `NETLENS_QUICK_INTERVAL` | `900` | Quick scan interval in seconds |
| `NETLENS_DEEP_INTERVAL` | `86400` | Deep scan interval in seconds |
| `NETLENS_TERMINAL` | `on` | Enable/disable web terminal |
| `NETLENS_SNMP_COMMUNITY` | *(reserved/unused)* | SNMP community string |
| `NETLENS_BIND` | `0.0.0.0:8080` | Bind address and port |
| `NETLENS_DATA_DIR` | `/data` | Data directory |

## How it works

### Quick scans

- Runs every 15 minutes (`NETLENS_QUICK_INTERVAL`)
- Uses `nmap -T3` with top 100 TCP ports
- Host discovery via ARP and ping

### Deep scans

- Runs daily (`NETLENS_DEEP_INTERVAL`), first scan 10 minutes after start
- Top 1000 ports, `-sV` service versions, `-O` OS detection, `--traceroute`

### Name resolution

- Reverse DNS, mDNS, and SSDP

### MAC vendor

- Lookup from nmap's OUI table

### Device classification

- Rules based on vendor, OS, ports, and hostnames
- Owner can override classification

### Events

- `device_new`, `device_online`, `device_offline`, `ip_changed`, `port_opened`, `os_changed`

### Offline marking

- Devices not seen inside scanned ranges are marked offline

## Map and relations

### Edge kinds

- **gateway** — default route, confidence 1.0 or heuristic 0.5
- **route** — traceroute hops
- **host-of** — VM to a single probable hypervisor, heuristic
- **manual** — drawn or deleted links in the UI; deleted inferred links stay hidden

### Map features

- Node positions saved when dragged
- PNG export
- CSV/JSON export of devices

## Web terminal

- SSH (asyncssh, password or private key) and Telnet in the browser via xterm.js over a WebSocket
- Only to devices in the inventory whose address is private (or inside configured ranges) and whose chosen port is open
- Credentials typed per session, sent once, never stored or logged
- SSH host keys trusted on first use, stored per device; changed key blocks connection with warning; owner can forget key to continue
- Idle timeout: 15 minutes
- Max 5 concurrent sessions
- `NETLENS_TERMINAL=off` disables it
- HTTP/HTTPS admin UIs opened via plain links ("Open" next to ports 80/443/...)

## Security notes

- Access token required (cookie HttpOnly, SameSite=Strict, Secure behind HTTPS)
- Login rate limit: 5 failures/minute per client address
- No TLS built in — put behind a reverse proxy with HTTPS
  - `X-Forwarded-Proto` must be set
  - WebSocket upgrade must be forwarded
- Runs as non-root with file capabilities on nmap
- Only `NET_RAW` and `NET_ADMIN` capabilities
- Host networking
- Read-only root filesystem
- Security headers and CSP
- Never expose to the internet
- Scanning only private ranges
- Treat the token like a root password because the terminal can reach devices

## Not implemented / limitations

- SNMP and LLDP/CDP neighbour discovery (planned)
- Switch-to-device links come only from traceroute/heuristics/manual
- IPv6 hosts are ignored
- No multi-user accounts
- No alerts or notifications
- No vulnerability scanning
- No embedded proxying of device web UIs
- VNC/RDP only as links
- Single container / single network host

## Development

```bash
python3 -m venv .venv
pip install -r requirements-dev.txt
python -m pytest
```

- About 480 tests, no real network or nmap needed
- nmap output tested against XML fixtures in `tests/fixtures`

Run locally:

```bash
NETLENS_TOKEN=dev NETLENS_DATA_DIR=./data python -m app.main
```

> nmap must be installed for real scans.

### Project layout

```
app/scanner
app/terminal
app/api
app/static
tests
```

## Troubleshooting

- **No devices found:** Check ranges, host networking, and that nmap has capabilities. Check `docker logs netlens`; scan errors appear under "Scans & events".
- **OS detection empty:** Needs deep scan and root-capable nmap.
- **Terminal button missing:** Port 22/23 not seen open yet, or `NETLENS_TERMINAL=off`.

## Third-party

- **vis-network** 9.1.9 (MIT) — vendored under `app/static/vendor`
- **xterm.js** 5.5.0 with addon-fit 0.10.0 (MIT) — vendored under `app/static/vendor`
- **Python deps:** FastAPI, uvicorn, asyncssh, zeroconf
- **nmap** is required and installed in the image