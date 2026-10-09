<p align="center"><img src="app/static/img/logo.png" alt="Netlens" width="360"></p>

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
- Plugins for hypervisors and routers, each switchable on and off, with an upload for your own: Proxmox VE and ASUS AiMesh come built in (which VM runs on which host, which device is connected to which mesh node)
- Known and unknown devices, better device identification (router names, mDNS and UPnP details, name hints), Wi-Fi signal history and roaming, service checks (HTTP, TCP, DNS), more notification channels (ntfy, Telegram, Discord, Pushover, webhook) with quiet hours, and Prometheus metrics with a Grafana dashboard
- Statistics page: devices by type/vendor/OS, uptime and reliability, flapping devices, ports and services, scan performance, event history, hierarchy and plugin health, with 24 h to 90 day periods; a compact `/api/stats/summary` for integrations such as Home Assistant
- Network hierarchy: which device depends on which (gateway, then Proxmox host, then its guests), as a tree page, a tree layout on the map, and a parent you can set per device
- Live scan progress in the header
- Light and dark mode, switchable from the top bar
- Delete a device (optionally ignoring it in future scans), and a full scan of a single host from its page
- Backup and restore of everything from the Settings page, with scheduled backups and retention
- Port baselines (alert when a port opens that is not normal for the device), Wake-on-LAN, ping and traceroute from the device page
- Several users (administrator or read-only viewer) with API tokens, and read-only share links for the map or a status page
- Every setting you need day to day (ranges, schedule, terminal, mail, plugins) is editable in the browser

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

Settings has a menu on the left, grouped into General, Notifications, Integrations, Data and System. **Every entry is its own page** with its own address (so you can bookmark it or use Back): `#/settings/ranges`, `nmap`, `schedule`, `map`, `notifications`, `plugins`, `plugin-<id>` (for example `plugin-proxmox`, `plugin-asus`), `plugin-guide`, `ignored`, `backup`, `export`, `about` and `session`, for example `http://<docker-host>:8080/#/settings/plugin-proxmox`. On a narrow screen the menu becomes a row of buttons on top. The older addresses `#/settings/proxmox` and `#/settings/asus` still work.

Everything below is saved in the data directory, so it survives updates and rebuilds. Values set in the browser take precedence over the matching environment variables; "Reset" returns to the environment value.

| Card | What you can change |
|---|---|
| Scan ranges | which networks are scanned (see "Choosing what to scan") |
| Scan performance (nmap) | ports, timing and detection used by quick and deep scans, with presets (see "Making scans faster"). The **Scan settings** button next to the scan buttons jumps straight to it |
| Scan schedule and terminal | how often quick and deep scans run, and the web terminal on/off. Takes effect from the next scheduler cycle, no restart |
| E-mail notifications | SMTP server and recipients (see below) |
| Plugins and one page per plugin | turn plugins on or off, upload your own, and each plugin's own settings (see "Plugins" below) |
| Ignored devices | devices that scans skip, with a button to stop ignoring them |
| Backup and restore | download a snapshot, restore one |

### Making scans faster

Quick scans are normally a few seconds. **Deep scans are the slow part**: they probe the top 1000 ports of every host and run service version detection, OS detection and traceroute. On a network with about 35 devices a default deep scan took 5 to 8 minutes (and occasionally much longer when a device answers slowly). Under **Settings → Scan performance (nmap)** (or the **Scan settings** button in the header) you can trade detail for speed; the page shows how long your last quick and deep scan took so you can see the effect. Changes apply from the next scan.

| Setting | Effect on speed | What you give up |
|---|---|---|
| Timing T4 instead of T3 | faster on a local network | can miss hosts on a flaky or very slow network (T5 even more so) |
| Fewer deep ports (top 200 instead of 1000, or a list such as `22,80,443,8000-8100`) | the biggest win for deep scans | ports outside the list disappear from a device after the next deep scan |
| Version detection light or off | large | `light` is less accurate; `off` clears product and version columns at the next deep scan |
| OS detection off | large | OS names stop updating (the last known one stays) |
| Traceroute off | small | the route links on the map |
| Skip reverse DNS | small to medium | hostnames that come from DNS stop updating (mDNS/SSDP names stay) |
| Host timeout (default 120 s for quick scans, 900 s for deep scans; 0 = no limit) | caps the worst case: one slow or rate-limiting device can otherwise hold a deep scan up for an hour | a host nmap gives up on is skipped for that scan only: it stays online and keeps its known ports, and a "Host timeout" event is logged |
| Quick scan: hosts only (no ports) | fastest quick scan | quick scans no longer refresh ports (deep scans still do) |

### Cancelling a scan

While a scan runs, the strip under the header has a **Cancel scan** button. It stops nmap immediately and marks the scan as `cancelled` in **Scans & events**; nothing from that scan is saved, no notifications are sent and it does not count towards the typical duration. It is only available until the results start being saved (the button is greyed out for the last moment of a scan). The same is available as `POST /api/scans/cancel`.

Three presets set these for you: **Default** (the original behavior), **Fast** (T4, top 200 ports and light version detection in deep scans) and **Fastest** (also no OS or version detection and no reverse DNS, quick scans on the top 50 ports, 2 minute limit per host). The card shows the exact `nmap` command lines that result.

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

### Known and unknown devices

Every device is either **known** (you recognise it) or **unknown**. Devices that exist when you upgrade are all marked known, so nothing changes at first; every device found afterwards starts as unknown, is tagged *unknown* in the Devices list, and its "new device" alert says so. Tick **Known device** on a device's page, or use **Trust all unknown** on the Devices page (it asks first). The Devices page can filter on *Unknown only*, and the Statistics page, the summary API and Home Assistant count them. Netlens also logs an **IP reused** event when an address that another device used in the last day is now used by a different one.

### Device identification

Netlens works out a device's name and type from everything it can see, in this order of trust: reverse DNS, the device's own **UPnP** description (name, make, model, kind of device), **mDNS** names (including the friendly name of casting devices) and service types (printers, AirPlay, Chromecast, HomeKit, cameras...), the **name your router** shows for it (from a topology plugin), and words in the name (`iphone`, `shelly1-...`, `laserjet`, `desktop-...`, `esxi`). Only the first part of a name counts (a domain such as `tv.example.com` says nothing), and an SSDP product token such as "Linux" is never used as a name. Discovery hints are kept per device, so a device keeps its type when a later scan does not hear from it again.

### Wi-Fi details

When a topology plugin reports the signal of Wi-Fi clients (the ASUS plugin does), Netlens stores one sample per scan for 14 days. The device page then shows a **Wi-Fi** card with the signal (excellent / good / fair / weak), node, band, link rate, a 24 hour signal chart and the last moves between nodes. A client that changes node logs a **Wi-Fi move** event. The Statistics page adds a Wi-Fi group (signal quality, weakest clients, moves in 7 days).

### Service checks

**Services** (top bar) watches things a ping cannot: an **HTTP(S) page** (any status 200-399, a chosen status, or text that must appear), a **TCP port**, or a **DNS lookup** against a chosen server (optionally with the address it must return). Pick the interval (15 seconds to a day) and the time-out, optionally attach it to a device, and see a heartbeat bar, 24 hour uptime and response time per check. A state change needs two identical results in a row (one lost packet is not an outage) and logs a **Service down / up** event, which goes to e-mail and the notification channels. A check can be run on demand, paused and edited; HTTPS certificates are not verified (devices on a LAN usually have self-signed ones). Results are kept for 30 days.

### Notification channels and quiet hours

Besides e-mail, **Settings → Channels & quiet hours** sends alerts to **ntfy**, **Telegram**, **Discord**, **Pushover** or any **webhook** (a JSON POST, which works with Home Assistant webhooks, n8n and Node-RED). Each channel chooses the events it wants (new unknown device, device offline or back, service down or recovered, new open port, IP change, IP reused, OS change, Wi-Fi move, scan time-out), has its own *Send test* button, and keeps its own place in the event log: a channel that fails catches up later without disturbing the others, and error messages never contain tokens. **Quiet hours** hold messages back and deliver them afterwards as one digest (a service going down can still break through). Tokens are stored in the database like the SMTP password.

### Prometheus and Grafana

`GET /metrics` (same token as the API, as a Bearer token) exposes Prometheus metrics: device presence and last seen, devices by state, uptime ratio, open ports, scan duration/hosts/last success per kind, events by kind, plugin health, service check state and response time, Wi-Fi signal per client, and a `netlens_problem` flag. `contrib/prometheus/prometheus.yml` has a scrape job and alert rule examples; `contrib/grafana/netlens-dashboard.json` is a dashboard you can import in Grafana.

### Statistics

The **Statistics** page (top bar) shows what Netlens knows, in groups: *History* (devices online per hour or day, devices over time, events per day), *What is on the network* (by type, vendor, operating system, subnet, wired versus Wi-Fi and clients per mesh node when a router plugin is on), *Availability* (network uptime 24 h/7 d/30 d, least and most reliable devices, flapping devices, who has been offline longest, slowest responders), *Ports and services* (counts only: open ports, most common ports and services, devices with the most open ports, newly opened ports), *Network structure* (depth, busiest parents, where the hierarchy comes from, guests per hypervisor host), *Scans* (counts, median/95th percentile/longest duration per kind, hosts found per scan, host timeouts), *Events* and *System* (version, database size, rows, plugin health). The period buttons (24 hours to 90 days) set the window of the history, scan and event groups and are remembered per browser; the page refreshes itself every minute.

The history charts use the uptime checks (kept 90 days) and a **daily snapshot** (devices, online, new devices, open ports, events, scans) that Netlens stores after every scan and keeps for 400 days, so "devices over time" fills in as the days go by. The data comes from `GET /api/stats?range=7d` (24h, 7d, 30d or 90d). `GET /api/stats/summary` is a small, versioned document (`api: 1`) with the headline numbers, scan state, plugin health, a `problem` flag and a compact device list; it is what the Home Assistant integration polls. Both answers are cached for 30 seconds. `GET /api/events?since_id=<id>` returns only events newer than an id.

### Scheduled backups

**Settings → Backup & restore** can make a backup by itself: every 6 hours to every week, keeping the newest 1 to 60 copies in the `backups` folder of the data directory (readable only by Netlens). The page lists them with *Download*, *Restore* and *Delete* and has a *Back up now* button. A failed backup is retried after an hour, shows in the card and raises a **Backup failed** event that the notification channels can send. The copies live on the same disk as the database, so download one now and then as well. A backup holds everything, including saved passwords, users and share links.

### Port baselines

On a device page, **Accept as normal** stores the device's current open ports as its baseline (**Set baselines** on the Devices page does it for all devices without one; devices that have none are never judged). From then on a new port logs **Unexpected port** (instead of *Port opened*), a baseline port that disappears logs **Baseline port gone**, and the device page and Devices list show the difference. Closed ports are noticed by deep scans, which list a port that vanished as **Port closed**. These events go to the notification channels like any other (Unexpected port and Baseline port gone are on for new channels).

### Wake-on-LAN, ping and traceroute

The device page has **Wake** (a Wake-on-LAN magic packet to the device's MAC address, sent to the broadcast address and to the /24 of its IP; the device must have Wake-on-LAN switched on), **Ping** (does it answer now, and how fast) and **Trace** (the hops from Netlens to the device). Ping and trace go through nmap and only accept private addresses.

### Users and API tokens

Without any users, Netlens works as before: the `NETLENS_TOKEN` access token signs you in as administrator. **Settings → Users & tokens** adds named users: an **administrator** can do everything, a **viewer** can look at the map, devices, hierarchy, statistics, uptime and services but cannot change anything, open the terminal, read settings, exports or backups, or see credentials. Sign in with a user name instead of the token from the login dialog. Passwords need at least 8 characters; changing one (Settings → Account, or by an administrator) ends that user's other logins. The access token cannot be locked out, so a forgotten password is fixed by signing in with the token.

An administrator can create **API tokens** for a user (shown once). They are Bearer tokens that act with the role of their user, for scripts, Prometheus (`/metrics`) and the Home Assistant integration; a viewer's token is enough for those because they only read.

### Share links

**Settings → Share links** creates a secret address (`/share/<token>`) that shows the network read-only without a login: either the **map and device list** or only a **status page** (devices online and offline, service states). IP and MAC addresses are left out of the page and the data unless you tick them for that link, and a name that is only an address is shown as "Device N". A link can end after 1 to 90 days and stops working the moment you delete it; the card shows how often each was opened. Netlens itself should not be exposed to the internet without protection; share links are meant for people on your network or behind your own reverse proxy.

### Update notice

When a newer Netlens image has been published, an **Update x.y.z available** badge appears next to the version in the top bar and **Settings → About → Updates** shows what changed and how to update (the steps are under *Updating* above). Netlens only asks the container registry once a day for the list of published version numbers; nothing is installed automatically. The check can be switched off on the same card. `GET /api/update` and the statistics summary report it, and the Home Assistant integration has an update entity.

### Plugins

Netlens learns about your network from other systems through **plugins**. Two kinds exist: **hypervisor** plugins report VMs and containers and the host each runs on, and **topology** plugins report network nodes (router, switch, access point, mesh node) and which node each client is connected to. Netlens matches what a plugin reports to the devices it has scanned (by MAC address, then IP), and shows the result as links on the map and in the hierarchy.

Under **Settings → Integrations** you find:

- **Plugins**: every installed plugin with its type, version, source (built in or uploaded) and last sync, a **Turn on / Turn off** button for each, and an **Upload plugin** box for a `.zip` of your own. A new plugin stays off until you turn it on. Turning one off removes its links from the map and keeps its settings.
- **One page per plugin** with a settings form that Netlens builds from the plugin's manifest, *Test connection* (saves nothing), *Save* and *Sync now*. A plugin syncs when you turn it on and after every scan. A failing plugin never disturbs the others or the scan, and keeps its last good links; a refused login pauses that plugin until you save or sync it again, so a wrong password cannot get an account locked.
- **Plugin guide**: how to write a plugin (package format, `plugin.json`, the two functions, the exact data a plugin must return, security notes). The same text is in the repository at [`app/plugins/PLUGINS.md`](app/plugins/PLUGINS.md), and **Download example plugin** gives a working template.

- **Browse plugins**: the **plugin index** lists plugins from the community with a **review level**: *Verified* (a trusted reviewer read the code of that exact version and tested it on real hardware), *Reviewed* (code read, not tested on hardware) or *Community* (only automatic checks; installing it needs an extra confirmation with a warning). *Install* downloads the plugin, checks it against the SHA-256 pinned in the index and applies the same safety checks as an upload; a new plugin starts switched off. Installed plugins show **update available** (nothing updates by itself), updating keeps the settings, and **Go back to the previous version** restores the last one. The index is a file in this repository (`plugin-index/index.json`, read once every six hours); its address can be changed or switched off under *Plugin index settings*. To publish your own plugin see [`plugin-index/README.md`](plugin-index/README.md) (entry format, review process, templates and a local checker).

**Uploaded and downloaded plugins are Python code that runs inside the Netlens container.** Each runs in its own process with a stripped environment, a time limit and no database path, and everything it returns is validated, but this is not a sandbox: it runs as the same user and could read the data volume. Only install plugins you trust and have read. Uploading needs the Netlens login.

#### ASUS router (AiMesh) plugin

Reads your ASUS router's client list and AiMesh node list and links every online device to the mesh node it is connected to (wired or Wi-Fi), and every mesh node to the router. These links appear in the hierarchy and on the map and rank above traceroute and gateway guesses. It is read-only and uses the router's HTTPS web interface (one login, two reads, a logout per sync; no SSH, so no sessions are left open on the router). Tested on an RT-AX92U with stock firmware.

1. Open **Settings → ASUS router (AiMesh)**, enter the router's address (for example `192.168.0.1`; HTTPS uses port 8443 unless you give another), the admin username and password, and leave *Verify TLS certificate* off (the router's certificate is self-signed).
2. Press *Test connection*, then tick *Enable this plugin* and *Save*.

The password is stored in Netlens' database (inside the data volume and in backups). A dedicated account is a good idea if your firmware allows it.

#### Proxmox VE plugin

The plugin asks Proxmox which VMs and containers exist and which host they run on, and matches them to the devices Netlens found (by MAC address, then by IP). The result:

- the map shows a `host-of` link from every guest to its host (replacing the heuristic guess),
- a guest's device page shows a *Virtualization* box ("Container (LXC) 105, name, on node X") with a link to the host,
- the host's device page lists all its guests, including stopped ones and guests that are not on the scanned network.

Netlens only reads from Proxmox; it never changes anything. To set it up:

1. **Recommended: create a read-only API token** in Proxmox: *Datacenter → Permissions → API Tokens → Add* (user for example `root@pam`, token ID `netlens`, untick "Privilege Separation" or give the token the role below). Then *Datacenter → Permissions → Add → API Token Permission*: path `/`, the token, role **PVEAuditor**. A username and password work too, but a token limits what a leaked credential can do.
2. In Netlens open **Settings → Proxmox VE**, enter the URL (`https://<proxmox-host>:8006`), the token ID (`user@realm!tokenname`) and its secret, or a username and password.
3. Proxmox uses a self-signed certificate by default: untick **Verify TLS certificate**, or install a trusted certificate on Proxmox and keep it ticked.
4. **Test connection**, then tick **Enable this plugin** and **Save**.

Netlens must be able to see the guests' MAC addresses, so run it on the same network (host networking, as in the compose file). Guests whose MAC never shows up in a scan are listed on the host page as "not seen on the network".

### Network hierarchy

Netlens works out which device sits below which, like the topology view of a network controller. Every device gets at most one **parent**, taken from the first source that knows one:

| Priority | Source | Example |
|---|---|---|
| 1 | **Set manually** on the device page | "this camera hangs off the garage switch" |
| 2 | a **hypervisor plugin** (for example Proxmox) | a VM or container sits below its host |
| 3 | an **uplink** from a topology plugin (for example the ASUS router) | a laptop below the mesh node it is connected to |
| 4 | a **guess** for virtual machines when exactly one hypervisor is known | |
| 5 | the next router on the **traceroute** path | |
| 6 | the default **gateway** | everything else |

The result is always a tree: an assignment that would put a device below itself is skipped in favour of the next source. You see it in three places:

- **Hierarchy** page (menu): a tree you can expand and collapse and filter. Each row shows the status, type, IP, how many devices are below it, and where its parent came from (Proxmox, gateway, traceroute, set manually). Devices nothing is known about are listed separately at the bottom.
- **Map**: by default only each device's chosen parent link is drawn, so a Proxmox guest hangs under its host instead of also being linked to the router. *Hierarchy links / All links* switches between that and every inferred link, and *Free / Tree / Horizontal layout* arranges the devices: Tree is a top-down tree, **Horizontal** is a left-to-right topology like Omada's (the router on the left, one column per level, a card per device, right-angle links). In the horizontal layout the client devices of a busy branch (more than 8) start folded into `▸ N more`; double-click a device, or use its details panel, to fold or open its clients, and *Collapse clients*, *Expand all* and *Fit* act on the whole map. The tree layouts arrange themselves, and dragging in them does not overwrite your saved free-layout positions. Clicking a device shows its parent. The layout the map opens with is set under **Settings → Map** (a layout chosen in the map's own menu is remembered per browser and wins; *Forget this browser's choice* in Settings returns to the default).
- **Device page**, card **Network position**: shows what the device sits below and why, lists the devices below it, and lets you choose the parent: *Automatic*, *None (top level)* or a specific device. Devices below the current one are not offered, so a loop is impossible. If a chosen parent is deleted, the device goes back to automatic.

The same data is available as `GET /api/hierarchy`, and `PATCH /api/devices/<id>` accepts `parent_mode` (`auto`, `none`, `device`) and `parent_device_id`.

### Dark mode

The **moon / sun button** at the right end of the top bar switches between light and dark mode. Without a choice Netlens follows your operating system's setting; once you click the button your choice is remembered in that browser (it is not shared between browsers or users). Charts and the map follow the theme too (the map draws brighter device colours and links with outlined dots and haloed labels in dark mode, and offline devices get a dashed outline).

### Deleting a device and ignoring devices

On a device's page, the **Delete device** card removes it together with its ports, names, uptime history and links (past events stay in the log, marked as deleted). A device that is still on the network would simply be found again by the next scan, so the confirmation offers **Also ignore it in future scans** (ticked by default for an online device). Ignored devices are skipped by every scan, are not mailed about, and are listed under **Settings → Ignored devices**, where **Stop ignoring** lets the next scan add one back. Devices are ignored by MAC address, or by IP address when they have no MAC (for example the bridge address of a container network), so a different device that takes over the same IP is not ignored. The same actions exist as `DELETE /api/devices/<id>?ignore=true` and `GET`/`DELETE /api/ignored`.

### Full scan of a single host

The **Full scan** button next to a device's name runs one thorough scan of that host only: all 65535 TCP ports, service versions, OS detection and a traceroute (`nmap -T4 -p- -sV -O --osscan-guess --traceroute`, at most 30 minutes; the aggressive timing is a minimum, and your reverse-DNS preference applies). It is the way to find a service on an unusual port that the top-1000 scan never looks at. The strip under the top bar shows `Full scan of 192.168.0.5` with its progress and the usual elapsed/typical time, you can cancel it like any scan, and the result replaces that device's port list. It does not touch other devices, does not add an uptime heartbeat and does not recalculate the network relations, and it appears in **Scans & events** as `full <ip>`. Only one scan runs at a time. The API is `POST /api/devices/<id>/scan`.

### Backup and restore

**Settings → Backup and restore → Download backup** gives you a consistent snapshot of the whole database (devices, history, settings, saved credentials) while Netlens keeps running. **Restore from file** replaces the current data with a backup; it asks for confirmation, refuses to run during a scan, keeps a safety copy of the previous data next to the database (`netlens.db.pre-restore`), and upgrades a backup made by an older version automatically. A backup from a newer Netlens version is refused. Treat backup files like passwords because they contain the saved SMTP and plugin credentials.

### Scan progress

While a scan runs, the header shows what it is doing, for example `Deep scan · Service scan 45% · 12 hosts`, with a progress bar for the current nmap step, the **time the scan has taken so far and the typical duration of your recent scans of the same type** (the median of the last 20, so one scan that hung does not distort it), for example `1m 16s (typical 7m 26s)`. The strip appears under the header only while a scan runs. Scan failures are explained (for example missing network capabilities) in **Scans & events** and in the logs.

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
- **host-of** — VM or container to its hypervisor: exact when a hypervisor plugin (for example Proxmox) is enabled, otherwise a heuristic guess
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
app/plugins      plugin system: manifest and output contract, runner, registry, service; builtin/ has the Proxmox and ASUS plugins; PLUGINS.md is the plugin guide
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
- **Proxmox sync fails:** the message on the plugin's settings page says why. `the TLS certificate could not be verified`: untick *Verify TLS certificate* (Proxmox's default certificate is self-signed). `authentication failed`: check the token ID (`user@realm!tokenname`), the secret, or the password. `permission denied (... PVEAuditor)`: give the token or user the PVEAuditor role on `/`. `cannot connect`: wrong URL/port or a firewall.
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