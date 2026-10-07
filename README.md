# Netlens

Self-hosted LAN scanner and network map. Runs as a single Docker container.

## Overview

> [!WARNING]
> **Netlens is in active development and is not ready for production use.** Features, configuration and the data format may change without notice, there are known bugs, and it has had limited testing on real networks. It includes a web terminal that can reach your devices, so only run it on a trusted private network, and never expose it to the internet.

Netlens is a self-hosted LAN scanner and network map for home labs and small networks. It periodically scans your private network ranges with nmap, discovers devices, works out what they are (router, server, printer, VM, ...), tracks when they appear, disappear or change, and draws the result as an interactive map. From any discovered device you can open an SSH or Telnet session straight in the browser.

It is a single Docker container (FastAPI backend, SQLite storage, vanilla JavaScript UI) with no external services and no cloud component. Everything stays on your network.

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

## Build and deploy with Docker Compose

### Requirements

- A Linux Docker host on the network you want to scan, with Docker Engine and the Compose plugin (`docker compose version`).
- The container uses **host networking** (needed for ARP/L2 discovery and mDNS/SSDP), so it must run on a host that is directly attached to the LAN. Docker Desktop on macOS/Windows will not work for scanning.

### Option A: standalone (this repository's compose file)

```bash
git clone https://github.com/Gatlarf/netlens.git
cd netlens
cp .env.example .env
# Edit .env:
#   NETLENS_TOKEN  a long random string (generate with: openssl rand -hex 32)
#   DOCKERDIR      base directory for application data, e.g. /home/you/docker
mkdir -p "$DOCKERDIR/appdata/netlens"
sudo chown 10001:10001 "$DOCKERDIR/appdata/netlens"   # the container runs as uid 10001
docker compose up -d --build
```

Open `http://<docker-host>:8080`, log in with the token, and press **Quick scan**.

Application data (the SQLite database) is stored in `$DOCKERDIR/appdata/netlens`, mounted as `/data`, so it survives rebuilds and container removal.

### Option B: add Netlens to an existing compose stack

If you already keep all your services in one `docker-compose.yml` with a shared `.env` (defining `DOCKERDIR`), clone this repository to `$DOCKERDIR/build/netlens` (`git clone https://github.com/Gatlarf/netlens.git $DOCKERDIR/build/netlens`), add `NETLENS_TOKEN` to the shared `.env`, and append this service:

```yaml
  netlens:
    build: ${DOCKERDIR}/build/netlens
    image: netlens:latest
    container_name: netlens
    restart: unless-stopped
    network_mode: host
    cap_drop:
      - ALL
    cap_add:
      - NET_RAW
      - NET_ADMIN
    read_only: true
    tmpfs:
      - /tmp
    volumes:
      - $DOCKERDIR/appdata/netlens:/data
    environment:
      - TZ=${TZ}
      - NETLENS_TOKEN=${NETLENS_TOKEN:?Set NETLENS_TOKEN in .env}
      - NETLENS_BIND=0.0.0.0:8080
```

Create and chown the data directory as in option A, then run `docker compose up -d --build netlens` from the directory that holds your compose file. The other `NETLENS_*` variables in the table below can be added to `environment:` as needed.

### Operating it

```bash
docker compose ps                  # status and health
docker compose logs -f netlens     # logs (scan errors also appear in the UI under "Scans & events")
docker compose up -d --build       # rebuild and restart after pulling new code
docker compose down                # stop and remove the container (data in appdata is kept)
```

Do not use `--no-new-privileges` or remove the `NET_RAW`/`NET_ADMIN` capabilities: nmap runs as a non-root user and relies on file capabilities for raw sockets.

## Updating to a new version

Netlens is built from source, so updating means pulling the new code and rebuilding the image. Your data lives in `$DOCKERDIR/appdata/netlens` and is not touched by a rebuild. Releases and changes are listed at https://github.com/Gatlarf/netlens/commits/main; while the project is in development, check for changes to the data format or configuration before updating.

1. **Back up the data** (recommended before every update):

   ```bash
   docker compose stop netlens
   sudo cp -a "$DOCKERDIR/appdata/netlens" "$DOCKERDIR/appdata/netlens.bak-$(date +%F)"
   ```

2. **Pull the new code.** Option A: run this in your clone. Option B: run it in `$DOCKERDIR/build/netlens`.

   ```bash
   git pull
   ```

   To run a specific release instead of the latest `main`, use `git fetch --tags && git checkout <tag>`.

3. **Rebuild and restart** from the directory that holds your compose file (for option B, `$DOCKERDIR`):

   ```bash
   docker compose up -d --build netlens      # option A: docker compose up -d --build
   ```

   Compose rebuilds the image, recreates the container, and starts it again with the same settings and the same data directory.

4. **Verify:**

   ```bash
   docker compose ps                         # STATUS should show "healthy"
   curl http://<docker-host>:8080/api/health # {"status":"ok","version":"..."}
   docker compose logs --tail 50 netlens
   ```

5. **Clean up** old images once you are happy with the new version:

   ```bash
   docker image prune -f
   ```

### Rolling back

If the new version misbehaves, stop the container, go back to the previous code, restore the data backup, and rebuild:

```bash
docker compose stop netlens
git checkout <previous-tag-or-commit>
sudo rm -rf "$DOCKERDIR/appdata/netlens"
sudo cp -a "$DOCKERDIR/appdata/netlens.bak-<date>" "$DOCKERDIR/appdata/netlens"
docker compose up -d --build netlens
```

Restoring the backup matters because a newer version may have changed the database in a way an older version cannot read. If the update made no data changes you can skip the restore, but you should not count on that.

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

- **Container keeps restarting (running, then restarting):** the app is exiting at startup and `restart: unless-stopped` starts it again. The reason is in the container log:

  ```bash
  docker compose logs --tail 50 netlens      # or: docker logs --tail 50 netlens
  docker inspect netlens --format '{{.State.ExitCode}} {{.State.Error}}'
  ```

  Common causes and what the log shows:

  | Log message | Fix |
  |---|---|
  | `PermissionError: [Errno 13] Permission denied: '/data...'` | The data directory is not writable by the container user. Run `sudo chown 10001:10001 $DOCKERDIR/appdata/netlens` |
  | `NETLENS_TOKEN is required and must be non-empty` | Set `NETLENS_TOKEN` in `.env` |
  | `NETLENS_RANGES contains non-scannable range` | Use private ranges only, no larger than /20 |
  | `NETLENS_BIND must be in format host:port` | Fix the value, e.g. `0.0.0.0:8080` |
  | `address already in use` | Another service on the host already uses port 8080 (the container uses host networking). Change `NETLENS_BIND` |

  If `docker compose up` itself refuses to start, the message names the missing variable (for example `DOCKERDIR` or `NETLENS_TOKEN`). Run `docker compose config` to see the final configuration with all variables filled in.
- **No devices found:** Check ranges, host networking, and that nmap has capabilities. Check `docker logs netlens`; scan errors appear under "Scans & events".
- **OS detection empty:** Needs deep scan and root-capable nmap.
- **Terminal button missing:** Port 22/23 not seen open yet, or `NETLENS_TERMINAL=off`.

## Third-party

- **vis-network** 9.1.9 (MIT) — vendored under `app/static/vendor`
- **xterm.js** 5.5.0 with addon-fit 0.10.0 (MIT) — vendored under `app/static/vendor`
- **Python deps:** FastAPI, uvicorn, asyncssh, zeroconf
- **nmap** is required and installed in the image