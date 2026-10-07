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
- Scan ranges editable in the web UI (Settings), no restart needed
- CSV and JSON export of devices
- PNG export of the network map
- Event logging (device_new, device_online, device_offline, ip_changed, port_opened, os_changed)
- Uptime history like Uptime Kuma: heartbeat bars, 24 h / 7 d / 30 d uptime and response times per device
- E-mail notifications for new and offline devices, with an on/off switch per device
- Proxmox connector: shows which VMs and containers run on which Proxmox host, on the map and on the device pages
- Live scan progress in the header
- Backup and restore of everything from the Settings page
- Every setting you need day to day (ranges, schedule, terminal, mail, Proxmox) is editable in the browser

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
    build:
      context: ${DOCKERDIR}/build/netlens
      args:
        NETLENS_VERSION: ${NETLENS_VERSION:-dev}
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

### Option C: pre-built image (no build, works with Portainer)

A multi-architecture image (amd64 and arm64) is published to GitHub Container Registry on every push to `main` and for every `v*` release tag: `ghcr.io/gatlarf/netlens` (tags: `latest`, a version such as `1.2.3`, and the commit `sha-...`). No source code or Dockerfile is needed on the host, and no registry account is needed to pull it.

```bash
mkdir netlens && cd netlens
curl -O https://raw.githubusercontent.com/Gatlarf/netlens/main/docker-compose.image.yml
printf 'DOCKERDIR=/home/you/docker\nNETLENS_TOKEN=%s\n' "$(openssl rand -hex 32)" > .env
mkdir -p /home/you/docker/appdata/netlens
sudo chown 10001:10001 /home/you/docker/appdata/netlens
docker compose -f docker-compose.image.yml up -d
```

**Portainer:** under **Stacks → Add stack → Web editor**, paste the contents of [`docker-compose.image.yml`](docker-compose.image.yml) and add `DOCKERDIR` and `NETLENS_TOKEN` as environment variables. (The regular `docker-compose.yml` has a `build:` section and fails in the web editor with `failed to read dockerfile: open Dockerfile: no such file or directory`, because there is no source to build from. Use this file, or deploy the stack from the Git repository instead.)

To pin a specific version instead of following `latest`, change the image line, for example `ghcr.io/gatlarf/netlens:1.2.3`.

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

1. **Back up the data** (recommended before every update). The easiest way is **Settings → Backup and restore → Download backup**. From the command line:

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
   # The version number rises with every commit: <VERSION file>.<commit count>
   export NETLENS_VERSION="$(tr -d '[:space:]' < build/netlens/VERSION).$(git -C build/netlens rev-list --count HEAD)"   # option B
   docker compose up -d --build netlens      # option A: run in the clone, and use NETLENS_VERSION="$(tr -d '[:space:]' < VERSION).$(git rev-list --count HEAD)"
   ```

   If you skip the `NETLENS_VERSION` line the app still works, it just reports the version as `dev`.

   Compose rebuilds the image, recreates the container, and starts it again with the same settings and the same data directory.

4. **Verify:**

   ```bash
   docker compose ps                         # STATUS should show "healthy"
   curl http://<docker-host>:8080/api/health # {"status":"ok","version":"..."}
   docker compose logs --tail 50 netlens
   ```

   **If you use the pre-built image (option C),** there is nothing to pull or build from source: run `docker compose -f docker-compose.image.yml pull && docker compose -f docker-compose.image.yml up -d` (in Portainer, recreate the stack with **Pull latest image** enabled). Do the backup and verify steps as above.

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
| `NETLENS_RANGES` | auto-detect | Private ranges only, prefix >= /20. Can also be changed at runtime in the web UI (see below); the web setting takes precedence |
| `NETLENS_QUICK_INTERVAL` | `900` | Quick scan interval in seconds |
| `NETLENS_DEEP_INTERVAL` | `86400` | Deep scan interval in seconds |
| `NETLENS_TERMINAL` | `on` | Enable/disable web terminal |
| `NETLENS_SNMP_COMMUNITY` | *(reserved/unused)* | SNMP community string |
| `NETLENS_BIND` | `0.0.0.0:8080` | Bind address and port |
| `NETLENS_DATA_DIR` | `/data` | Data directory |

### Choosing what to scan

By default Netlens scans the networks it finds on the Docker host's interfaces. You can restrict or change that in two ways:

- **Web UI (recommended):** open **Settings → Scan ranges**, enter one or more ranges separated by commas (for example `192.168.1.0/24, 10.0.0.0/22`) and press **Save**. It takes effect from the next scan, with no restart. It is stored in the data directory, so it survives updates and rebuilds. **Reset to default** removes it.
- **Environment variable:** `NETLENS_RANGES` in `.env`, same format.

Order of precedence: the web setting, then `NETLENS_RANGES`, then auto-detection. Only private IPv4 ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, and link-local) of /20 or smaller are accepted, and a single address such as `192.168.1.10` works too. When ranges are set, the web terminal can only connect to devices inside them.

## Settings in the web interface

Everything below is saved in the data directory, so it survives updates and rebuilds. Values set in the browser take precedence over the matching environment variables; "Reset" returns to the environment value.

| Card | What you can change |
|---|---|
| Scan ranges | which networks are scanned (see "Choosing what to scan") |
| Scan schedule and terminal | how often quick and deep scans run, and the web terminal on/off. Takes effect from the next scheduler cycle, no restart |
| E-mail notifications | SMTP server and recipients (see below) |
| Proxmox connector | Proxmox URL and credentials (see below) |
| Backup and restore | download a snapshot, restore one |

### Version

The header shows the running version. It is `<major.minor from the VERSION file>.<number of commits>`, so it rises with every commit and every published image, for example `0.2.57`. The pre-built image is tagged with it (`ghcr.io/gatlarf/netlens:0.2.57`) as well as `latest`. Builds from source report `dev` unless you pass `NETLENS_VERSION` as shown under "Updating".

### Uptime history

After every scan Netlens records, for each device inside the scanned ranges, whether it answered (and its response time when nmap reports one). The **Uptime** page shows a heartbeat bar per device (green = up, red = down, newest on the right) with 24 hour and 7 day uptime, like Uptime Kuma. Each device page has a larger bar, 24 h / 7 d / 30 d uptime, average response time, how long the current state has lasted, and a response-time graph. History is kept for 90 days. The resolution is your scan interval (15 minutes by default); shorten it under Settings for finer detail.

### E-mail notifications

1. Open **Settings → E-mail notifications**, enter your SMTP server, port and security (STARTTLS, SSL/TLS or none), username and password, the sender and one or more recipients (comma separated).
2. Press **Save**, then **Send test email** to check the settings. A failure is explained in plain words (wrong password, host not found, connection refused, ...).
3. Tick **Send e-mail notifications** and save.

After each scan Netlens sends **one digest mail** listing the devices that appeared ("new devices") and the devices that went offline. Switching notifications on starts from that moment: you never get a mail about the backlog. If the mail server is down, the events are kept and sent after a later scan.

You can switch the offline mails off **per device** with the checkbox "Send an e-mail when this device goes offline" on the device page (useful for phones and laptops that come and go). New-device mails always go out when that option is on.

The SMTP password is stored in the database in plain text (like all settings) and is included in backups, so protect the data directory and the backup files.

### Proxmox connector

The connector asks Proxmox which VMs and containers exist and which host they run on, and matches them to the devices Netlens found (by MAC address, then by IP). The result:

- the map shows a `host-of` link from every guest to its Proxmox host (confidence 100%, replacing the heuristic guess),
- a guest's device page shows "Container (LXC) 105, name, on node X" with a link to the host,
- the host's device page lists all its guests, including stopped ones and guests that are not on the scanned network.

Netlens only reads from Proxmox; it never changes anything. To set it up:

1. **Recommended: create a read-only API token** in Proxmox: *Datacenter → Permissions → API Tokens → Add* (user for example `root@pam`, token ID `netlens`, untick "Privilege Separation" or give the token the role below). Then *Datacenter → Permissions → Add → API Token Permission*: path `/`, the token, role **PVEAuditor**. A username and password work too, but a token limits what a leaked credential can do.
2. In Netlens open **Settings → Proxmox connector**, enter the URL (`https://<proxmox-host>:8006`), the token ID (`user@realm!tokenname`) and its secret, or a username and password.
3. Proxmox uses a self-signed certificate by default: untick **Verify TLS certificate**, or install a trusted certificate on Proxmox and keep it ticked.
4. **Test connection** (nothing is saved by the test), then tick **Enable the connector** and **Save**. It syncs immediately and again after every scan; **Sync now** forces it.

Netlens must be able to see the guests' MAC addresses, so run it on the same network (host networking, as in the compose file). Guests whose MAC never shows up in a scan are listed on the host page as "not seen on the network".

### Backup and restore

**Settings → Backup and restore → Download backup** gives you a consistent snapshot of the whole database (devices, history, settings, saved credentials) while Netlens keeps running. **Restore from file** replaces the current data with a backup; it asks for confirmation, refuses to run during a scan, keeps a safety copy of the previous data next to the database (`netlens.db.pre-restore`), and upgrades a backup made by an older version automatically. A backup from a newer Netlens version is refused. Treat backup files like passwords because they contain the saved SMTP and Proxmox credentials.

### Scan progress

While a scan runs, the header shows what it is doing, for example `Deep scan · Service scan 45% · 12 hosts`, with a progress bar for the current nmap step. Scan failures are explained (for example missing network capabilities) in **Scans & events** and in the logs.

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
- **host-of** — VM or container to its hypervisor: exact when the Proxmox connector is enabled, otherwise a heuristic guess
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
- Notifications are e-mail only (no webhooks, Telegram, ntfy, ...)
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

- About 600 tests (including a static check of the browser modules), no real network or nmap needed
- nmap output tested against XML fixtures in `tests/fixtures`

Run locally:

```bash
NETLENS_TOKEN=dev NETLENS_DATA_DIR=./data python -m app.main
```

> nmap must be installed for real scans.

### Project layout

```
app/scanner      nmap runner, parsing, scheduling, relations
app/notify       e-mail notifications (config, SMTP, digest, service)
app/integrations Proxmox client, matching and sync
app/terminal     SSH/Telnet backends
app/api          REST API routers
app/uptime.py    uptime history, app/backup.py  backup and restore
app/static       web UI (js/pages, js/cards)
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
- **Proxmox sync fails:** the message in Settings says why. `the TLS certificate could not be verified`: untick *Verify TLS certificate* (Proxmox's default certificate is self-signed). `authentication failed`: check the token ID (`user@realm!tokenname`), the secret, or the password. `permission denied (... PVEAuditor)`: give the token or user the PVEAuditor role on `/`. `cannot connect`: wrong URL/port or a firewall.
- **No notification mails:** use **Send test email** first. Check that *Send e-mail notifications* is ticked, that the device has not opted out, and the status line under the card for the last problem. Gmail and most providers need an app password, not your normal password.
- **A guest does not show under its Proxmox host:** the connector matches by MAC address, so Netlens must have scanned that guest at least once on the same network. Run a scan and press *Sync now*.
- **No devices found:** Check ranges, host networking, and that nmap has capabilities. Check `docker logs netlens`; scan errors appear under "Scans & events".
- **OS detection empty:** Needs deep scan and root-capable nmap.
- **Terminal button missing:** Port 22/23 not seen open yet, or `NETLENS_TERMINAL=off`.

## Third-party

- **vis-network** 9.1.9 (MIT) — vendored under `app/static/vendor`
- **xterm.js** 5.5.0 with addon-fit 0.10.0 (MIT) — vendored under `app/static/vendor`
- **Python deps:** FastAPI, uvicorn, asyncssh, zeroconf
- **nmap** is required and installed in the image