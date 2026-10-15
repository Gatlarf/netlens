<p align="center"><img src="app/static/img/logo.png" alt="Netlens" width="360"></p>

# Netlens

Self-hosted LAN scanner and network map. Runs as a single Docker container.

<p align="center"><a href="https://buymeacoffee.com/Gatlarf"><img src="https://img.buymeacoffee.com/button-api/?text=Buy%20me%20a%20coffee&emoji=%E2%98%95&slug=Gatlarf&button_colour=FFDD00&font_colour=000000&font_family=Cookie&outline_colour=000000&coffee_colour=ffffff" alt="Buy me a coffee" height="44"></a></p>

## Contents

- [Overview](#overview)
- [Features](#features)
- [Install](#install)
  - [Docker Compose (any Linux device with Docker)](#docker-compose-any-linux-device-with-docker)
  - [Docker without Compose](#docker-without-compose)
  - [Portainer (for example on DietPi or any other device)](#portainer-for-example-on-dietpi-or-any-other-device)
  - [Synology NAS (DSM 7.2 or newer, Container Manager)](#synology-nas-dsm-72-or-newer-container-manager)
  - [First start](#first-start)
  - [HTTPS](#https)
  - [Advanced: a host folder, building from source, an existing compose stack](#advanced-a-host-folder-building-from-source-an-existing-compose-stack)
  - [Operating it](#operating-it)
- [Updating to a new version](#updating-to-a-new-version)
  - [Rolling back](#rolling-back)
- [Configuration](#configuration)
  - [Choosing what to scan](#choosing-what-to-scan)
- [Settings in the web interface](#settings-in-the-web-interface)
  - [Making scans faster](#making-scans-faster)
  - [Cancelling a scan](#cancelling-a-scan)
  - [Version](#version)
  - [Uptime history](#uptime-history)
  - [E-mail notifications](#e-mail-notifications)
  - [Known and unknown devices](#known-and-unknown-devices)
  - [Device identification](#device-identification)
  - [Installing Netlens as an app](#installing-netlens-as-an-app)
  - [Wi-Fi details](#wi-fi-details)
  - [Service checks](#service-checks)
  - [Performance graphs and health monitoring](#performance-graphs-and-health-monitoring)
  - [Remote sites](#remote-sites)
  - [Maintenance windows](#maintenance-windows)
  - [Notification channels and quiet hours](#notification-channels-and-quiet-hours)
  - [Prometheus and Grafana](#prometheus-and-grafana)
  - [Statistics](#statistics)
  - [Scheduled backups](#scheduled-backups)
  - [Port baselines](#port-baselines)
  - [Wake-on-LAN, ping and traceroute](#wake-on-lan-ping-and-traceroute)
  - [Users and API tokens](#users-and-api-tokens)
  - [Share links](#share-links)
  - [Network checks](#network-checks)
  - [Groups](#groups)
  - [Update notice](#update-notice)
  - [Plugins](#plugins)
  - [Network hierarchy](#network-hierarchy)
  - [Dark mode](#dark-mode)
  - [Deleting a device and ignoring devices](#deleting-a-device-and-ignoring-devices)
  - [Full scan of a single host](#full-scan-of-a-single-host)
  - [Backup and restore](#backup-and-restore)
  - [Scan progress](#scan-progress)
- [How it works](#how-it-works)
  - [Quick scans](#quick-scans)
  - [Deep scans](#deep-scans)
  - [Name resolution](#name-resolution)
  - [MAC vendor](#mac-vendor)
  - [Device classification](#device-classification)
  - [Events](#events)
  - [Offline marking](#offline-marking)
- [Map and relations](#map-and-relations)
  - [Edge kinds](#edge-kinds)
  - [Map features](#map-features)
- [Web terminal](#web-terminal)
- [Remote access](#remote-access)
- [Speed tests](#speed-tests)
- [Demo mode](#demo-mode)
- [Security notes](#security-notes)
- [Not implemented / limitations](#not-implemented--limitations)
- [Development](#development)
  - [Project layout](#project-layout)
- [Troubleshooting](#troubleshooting)
- [License](#license)
- [Support](#support)
- [Third-party](#third-party)

## Overview

> [!WARNING]
> **Netlens is in active development and is not ready for production use.** Features, configuration and the data format may change without notice, there are known bugs, and it has had limited testing on real networks. It includes a web terminal that can reach your devices, so only run it on a trusted private network, and never expose it to the internet.

Netlens is a self-hosted LAN scanner and network map for home labs and small networks. It periodically scans your private network ranges with nmap, discovers devices, works out what they are (router, server, printer, VM, ...), tracks when they appear, disappear or change, and draws the result as an interactive map. From any discovered device you can open an SSH or Telnet session straight in the browser.

Beyond discovery it keeps watch: **performance graphs** of response time and availability up to a year back, **health monitoring** of switches, NAS boxes, printers, UPS units and servers (processor, memory, disks, traffic, temperature, supplies, battery) over SNMP or SSH, certificate and process checks, alerts that name the one cause behind many ("the garden switch is offline, 4 devices behind it cannot be reached"), and **remote sites**: other Netlens installations that report to this one, so a few locations show up in one overview.

It is a single Docker container (FastAPI backend, SQLite storage, vanilla JavaScript UI) with no external services and no cloud component. Everything stays on your network.

## Features

- Quick and deep network scans using nmap
- Device discovery via ARP, ping, and TCP port scanning
- Service version detection and OS fingerprinting
- Reverse DNS, mDNS, and SSDP name resolution
- MAC vendor lookup from nmap's OUI table
- Device type classification by rules (vendor, OS, ports, hostnames)
- Network map with gateway, route, host-of, and manual edges
- Web terminal (SSH and Telnet) via xterm.js, and remote desktop (RDP and VNC) in the browser through an optional helper container (Network → Remote access)
- Scan ranges editable in the web UI (Settings), no restart needed
- CSV and JSON export of devices
- PNG export of the network map
- Event logging (device_new, device_online, device_offline, ip_changed, port_opened, os_changed)
- A **setup guide** that walks a new install through the settings that matter (networks, names, always-on devices, alerts, checks, plugins, backups); reopen it any time under Settings → System → Setup guide
- **Performance graphs** (response time and availability for up to a year) and **health monitoring** of switches, NAS boxes, printers, UPS units, Windows (SNMP) and Linux (SSH): processor, memory, disks, traffic, temperature, supplies and battery, with limits that raise warnings
- **Remote sites**: several locations in one overview; a Netlens at each location reports to a central one (outgoing connection only), with devices, checks, health, graphs and alerts per site
- Uptime history like Uptime Kuma: heartbeat bars with a response-time line, 24 h / 7 d / 30 d, hover details, and **always-on (core) devices** whose availability is shown apart from phones and tablets
- Alerts by e-mail, ntfy, Telegram, Discord, Pushover or webhook, each channel with its own events and an on/off switch per device
- Plugins for hypervisors and routers, each switchable on and off, with an upload for your own: Proxmox VE and ASUS AiMesh come built in (which VM runs on which host, which device is connected to which mesh node); TP-Link Omada and Ubiquiti UniFi are available from the plugin index (community, not yet tested on hardware)
- Known and unknown devices, better device identification (router names, mDNS and UPnP details, name hints), Wi-Fi signal history and roaming, service checks (HTTP, TCP, DNS), more notification channels (ntfy, Telegram, Discord, Pushover, webhook) with quiet hours, and Prometheus metrics with a Grafana dashboard
- Statistics page: devices by type/vendor/OS, uptime and reliability, flapping devices, ports and services, scan performance, event history, hierarchy and plugin health, with 24 h to 90 day periods; a compact `/api/stats/summary` for integrations such as Home Assistant
- Network hierarchy: which device depends on which (gateway, then Proxmox host, then its guests), as a tree page, a tree layout on the map, and a parent you can set per device
- Live scan progress in the header
- Light and dark mode, switchable with the moon / sun button at the top right
- A **dashboard** as the start page: cards for devices online, uptime, unstable devices, services, containers and guests, sites and certificates, plugins, backup and scans, DNS, security, what needs attention, recent events and a small map. **Customize** lets you drag, remove and add cards (also least reliable devices, 14-day trend, device types, Wi-Fi, certificates, available updates, quick scan buttons), make **cards of your own** (any value from your data with colour limits, a device, a group, a service check, notes and links) and add the cards your plugins offer; the layout is saved per user on the server, so every browser and device shows the same dashboard
- A slim one-row top bar with the pages grouped (**Dashboard**, **Network**, **Monitoring**, **Settings**), a **Scan** menu with quick scan, deep scan and scan settings, and an account menu with the version, update notice, a coffee link and log out, plus a moon / sun button for light / dark mode; on iPad and phone the pages fold into one menu, and on a phone the bar slides away while you scroll down. The Settings pages fold into one button on a phone
- Delete a device (optionally ignoring it in future scans), and a full scan of a single host from its page
- Backup and restore of everything from the Settings page, with scheduled backups and retention
- Port baselines (alert when a port opens that is not normal for the device), Wake-on-LAN, ping and traceroute from the device page
- Several users (administrator or read-only viewer) with API tokens, and read-only share links for the map or a status page
- Every setting you need day to day (ranges, schedule, terminal, mail, plugins) is editable in the browser

## Install

Netlens runs as one container. It needs to see your network, so it uses the host's network: install it **on a device that is connected to the
network you want to scan** (a NAS, a mini PC, a Raspberry Pi, a server), not on Docker Desktop for Mac or Windows. It needs **no `.env` file, no
folders to create and no token**. The image is published for 64-bit Intel/AMD (amd64) and 64-bit ARM (arm64, for example a Raspberry Pi 3/4/5
running a 64-bit OS) at `ghcr.io/gatlarf/netlens`; no account is needed to pull it.

### Add it to your existing docker-compose.yml (easiest if you already run other containers)

If you already keep your containers in one `docker-compose.yml`, paste this service under `services:` and add `netlens-data:` under the `volumes:` list at the bottom
of the same file (create a `volumes:` list if there is none). Nothing else is needed: no extra variables, no folders.

```yaml
  netlens:
    image: ghcr.io/gatlarf/netlens:latest
    container_name: netlens
    restart: unless-stopped
    network_mode: host          # required to see the devices on your network (ARP, mDNS, SSDP)
    cap_drop:
      - ALL
    cap_add:
      - NET_RAW
      - NET_ADMIN
    read_only: true
    tmpfs:
      - /tmp
    volumes:
      - netlens-data:/data
    environment:
      - TZ=Europe/Brussels      # your time zone
```

```yaml
volumes:
  netlens-data:
```

Then run `docker compose up -d netlens` and open `http://<this-device>:8080`. To update later: `docker compose pull netlens && docker compose up -d netlens`.
Your own data folder instead of a Docker volume: replace `netlens-data:/data` with `/path/to/netlens:/data` and run `sudo chown 10001:10001 /path/to/netlens` once.

### Portainer (for example on DietPi or any other device)

Netlens needs two things that Portainer does not set by default: the **host network** and two extra **capabilities**, `NET_RAW` and `NET_ADMIN`
(they let it scan the network and listen for devices announcing themselves). Without them the container starts, but scanning does not work.
There are two ways to set this up. A stack is easier because the settings are already in the file.

**Option 1: a stack (recommended)**

1. **Stacks → Add stack**, give it a name (`netlens`), choose **Web editor**.
2. Paste the contents of [`docker-compose.simple.yml`](docker-compose.simple.yml), optionally set `TZ` under *Environment variables*, and press **Deploy the stack**.
3. Open `http://<this-device>:8080`.

The file already contains `network_mode: host` and `cap_add: [NET_RAW, NET_ADMIN]`. (Already have a stack for your other containers? Paste only the
`netlens:` service from above into that stack's editor, add the `netlens-data:` volume, and update the stack.)

To update later: open the stack and press **Update the stack** with **Re-pull image** switched on.

**Option 2: one container by hand (Containers → Add container)**

| Where in Portainer | What to set |
|---|---|
| **Name** | `netlens` |
| **Image** | `ghcr.io/gatlarf/netlens:latest` (no registry login needed) |
| **Advanced container settings → Network → Network** | **host** |
| **Advanced container settings → Runtime & Resources → Capabilities** | switch **NET_RAW** and **NET_ADMIN** to **On**; leave all others as they are |
| **Advanced container settings → Volumes → map additional volume** | container `/data`, a new volume (for example `netlens-data`) |
| **Advanced container settings → Restart policy** | **Unless stopped** |
| **Env** (optional) | `TZ` = your time zone, for example `Europe/Brussels` |

Then press **Deploy the container** and open `http://<this-device>:8080`. Leave **Privileged mode** off. Do not add `no-new-privileges`
under *Security*, because it stops the scanner from using the two capabilities.

**Already running without the capabilities?** Capabilities cannot be changed on a running container. Open the container in Portainer, press
**Duplicate/Edit**, set the network and the two capabilities as in the table (the same volume at `/data` keeps all your data), and **Deploy the container**
again after removing the old one (Portainer asks to replace it).

**How do I know it worked?** Press *Scan* in Netlens: it finds your devices. If it finds nothing, or the passive listening card in *Settings → Scan performance* says "Not running" and mentions `NET_RAW`,
the container is missing the host network or one of the two capabilities.

### Docker Compose with a separate file (any Linux device with Docker)

```bash
mkdir netlens && cd netlens
curl -O https://raw.githubusercontent.com/Gatlarf/netlens/main/docker-compose.simple.yml
docker compose -f docker-compose.simple.yml up -d
```

Open `http://<this-device>:8080` and follow [First start](#first-start). Your data lives in the Docker volume `netlens-data`, which survives updates and
re-creating the container. Set `TZ` (for example `TZ=Europe/Brussels` in the environment or a `.env` file) to have times in your own time zone.

### Docker without Compose

```bash
docker run -d --name netlens --restart unless-stopped --network host \
  --cap-drop ALL --cap-add NET_RAW --cap-add NET_ADMIN --read-only --tmpfs /tmp \
  -e TZ=Europe/Brussels -v netlens-data:/data ghcr.io/gatlarf/netlens:latest
```

### Synology NAS (DSM 7.2 or newer, Container Manager)

1. Open **Container Manager → Project → Create**. Name it `netlens`, choose a path for the project (any shared folder), and as source choose **Create docker-compose.yml**.
2. Paste the contents of [`docker-compose.simple.yml`](docker-compose.simple.yml), press **Next** and finish; the project starts the container.
3. Open `http://<nas-address>:8080`. (DSM itself uses ports 5000 and 5001. If something else on the NAS already uses 8080, add `NETLENS_BIND=0.0.0.0:8081` to the `environment:` list and use that port.)

To update later: **Project → netlens → Action → Build** (it pulls the newest image) and start it again. The data is in a Docker volume, so there are no folder permissions to set up.
(Older DSM versions with the *Docker* package can use the same compose file under *Project* if available, or create the container by hand with: host network, the two capabilities
`NET_RAW` and `NET_ADMIN` added, the image above, and a volume mounted at `/data`.)

### First start

The first time you open Netlens it asks you to **create the administrator account** and to confirm **which networks to scan** (it suggests the ones the device is
connected to), then starts the first scan. After that, everyone signs in with a user name and password; add more users, read-only viewers and API tokens under
**Settings → Users & tokens**.

Until you have created the account, anyone who can open the page can create it, so do this step right after starting the container.

**Forgot the password?** Create a new administrator (or reset a password) from the device that runs Netlens:

```bash
docker exec -it netlens python -m app.cli list-users
docker exec -it netlens python -m app.cli reset-password <user>
docker exec -it netlens python -m app.cli create-admin <user>
```

### HTTPS

Netlens itself speaks plain HTTP on port 8080. Passwords, sessions and (if you use the web terminal) SSH passwords then travel unencrypted, so on a network
where others could listen in, or if you open Netlens from outside, put it behind a **reverse proxy that does HTTPS**. Use a proxy that can keep WebSocket
connections open (the web terminal needs them) and that passes the original `Host` header. When a request arrives over HTTPS (the proxy sends
`X-Forwarded-Proto: https`), Netlens marks its session cookie `Secure` by itself. Do **not** forward Netlens straight to the internet without HTTPS and strong passwords.

If the proxy runs on the same device as Netlens (a Synology's built-in one, Caddy, nginx), add `NETLENS_BIND=127.0.0.1:8080` to the environment so that only the proxy can reach
Netlens. If the proxy runs in its own container (Nginx Proxy Manager, Traefik), leave the default and point the proxy at `http://<device-ip>:8080`.

**Synology (built-in reverse proxy):**
1. *Control Panel → Security → Certificate*: get or import a certificate for the name you will use (for example `netlens.example.com`, or a Let's Encrypt one via your DDNS name).
2. *Control Panel → Login Portal → Advanced → Reverse Proxy → Create*: source `HTTPS`, that host name, port `443`; destination `HTTP`, `localhost`, port `8080`.
3. Edit the rule → *Custom Header → Create → WebSocket* (adds the headers the terminal needs). Then assign the certificate to the rule under *Security → Certificate → Settings*.

**Caddy** (gets and renews the certificate itself): a `Caddyfile` of
```
netlens.example.com {
    reverse_proxy 127.0.0.1:8080
}
```

**nginx:**
```
location / {
    proxy_pass http://127.0.0.1:8080;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_read_timeout 3600s;   # long web terminal sessions
}
```

**Nginx Proxy Manager:** *Proxy Hosts → Add*: scheme `http`, forward host the device's IP, port `8080`, switch **Websockets Support** on, and request a certificate on the *SSL* tab (tick *Force SSL*).

**Traefik:** route the host name to `http://<device-ip>:8080` with TLS on the router; WebSockets work without extra settings.

**For the installable app (see *Installing Netlens as an app*):**
- The certificate must be **trusted by the device** (Let's Encrypt or your own CA installed on it). With a self-signed certificate the browser refuses the service worker, so there is no install option.
- Do **not** switch on the proxy's own caching of static files (Nginx Proxy Manager: *Cache Assets*; Cloudflare: cache rules for the site). Netlens sends `Cache-Control: no-cache` so that an update shows at once, and an extra cache would keep serving the old `sw.js` and interface files.
- If something in front of Netlens asks for a login (Authelia, Authentik, Cloudflare Access, basic auth), it must also let `/manifest.webmanifest`, `/sw.js` and `/img/*` through, or at least accept the same session for them; otherwise the browser cannot read the manifest and silently offers no install. Netlens has its own login, so the simplest setup is no second login in front of it.
- Keep the path as it is: Netlens works under a sub-path (`https://example.com/netlens/`) as long as the proxy strips the prefix.

Things to know: behind a proxy every request comes from the proxy's address, so the login rate limit then counts per user name instead of per address; Home Assistant and Prometheus use
the same HTTPS address (Home Assistant: *Reconfigure*; tick *Verify the TLS certificate* when the certificate is a normal one).

### Advanced: a host folder, a pinned version, building from source

None of this is needed for a normal install. The repository's own [`docker-compose.yml`](docker-compose.yml) (clone the repository and run `docker compose up -d`)
uses the same published image and the same Docker volume as the simple file. Optional settings go in a `.env` file next to it; [`.env.example`](.env.example) lists them.

- **Data in a folder you choose** (for backups with your own tools): set `NETLENS_DATA=/srv/netlens` in `.env`, create the folder and run `sudo chown 10001:10001 /srv/netlens`.
- **A specific version** instead of the newest: set `NETLENS_IMAGE_TAG=0.3.128` in `.env`, or change the image line to `ghcr.io/gatlarf/netlens:0.3.128`.
- **Build from source** (developers): `export NETLENS_VERSION="$(sh contrib/version.sh)"`, then
  `docker compose -f docker-compose.yml -f docker-compose.build.yml up -d --build`. Without `NETLENS_VERSION` the app works but reports the version as `dev`.

#### Existing installations

Nothing changes when you update: a `NETLENS_TOKEN` you already set keeps working as an administrator login, your data is migrated automatically and no
first-start wizard appears. When you want to leave the shared token behind, create an administrator under **Settings → Users & tokens**, sign in with it, and
then remove `NETLENS_TOKEN` from your compose file.

### Operating it

```bash
docker compose ps                  # status and health
docker compose logs -f netlens     # logs (scan errors also appear in the UI under "Scans & events")
docker compose pull && docker compose up -d   # update to the newest published image
docker compose down                # stop and remove the container (the data volume is kept)
```

Do not use `--no-new-privileges` or remove the `NET_RAW`/`NET_ADMIN` capabilities: nmap runs as a non-root user and relies on file capabilities for raw sockets.

## Updating to a new version

Pull the newest image and recreate the container; the data volume is untouched. Take a backup first if you like (**Settings → Backup & restore → Download backup**).

- **Added to your own docker-compose.yml:** `docker compose pull netlens && docker compose up -d netlens`
- **Separate file:** `docker compose -f docker-compose.simple.yml pull && docker compose -f docker-compose.simple.yml up -d`
- **Clone of this repository (`docker-compose.yml`):** `docker compose pull && docker compose up -d`
- **Portainer:** open the stack, press **Update the stack** with **Re-pull image** on.
- **Synology:** **Project → netlens → Action → Build** (it pulls the newest image), then start it again.

Netlens shows an **Update available** badge when a newer image exists. It only tells you; **it cannot update itself from the inside**: the container runs with a read-only file system and without extra rights (that is part of its security), and the application is part of the image. So an update always means pulling the newest image and recreating the container; your data, settings and plugins live in the data volume and stay as they are, and the database upgrades itself on start. The exception is plugins, which you update under **Settings → Plugins → Browse plugins** without a new image. A tool such as Watchtower can pull and restart the container on a schedule, but I would not use it here: the database is upgraded when a new version starts, so a faulty release would be applied to your data without you looking. The same steps are shown under **Settings → About → Updates**. To check: `docker compose ps` should show *healthy*, and `curl http://<docker-host>:8080/api/health` answers `{"status":"ok"}`.
Old images can be removed afterwards with `docker image prune -f`.

**If you build from source** (the build override): pull the new code with `git pull` (a specific release: `git fetch --tags && git checkout <tag>`), set
`NETLENS_VERSION` as shown under *Advanced* and run `docker compose -f docker-compose.yml -f docker-compose.build.yml up -d --build`.

**If you moved from the old `DOCKERDIR` files:** the compose files no longer use `DOCKERDIR`. To keep using your existing data folder, add
`NETLENS_DATA=<your DOCKERDIR>/appdata/netlens` to your `.env` (or use that path as the volume in your own compose file) before the next `docker compose up`;
otherwise Netlens starts empty in a new Docker volume (your old folder is not touched).

### Rolling back

If the new version misbehaves, run the previous version by its tag (for example `NETLENS_IMAGE_TAG=0.3.120`, or `ghcr.io/gatlarf/netlens:0.3.120` in your
compose file) and, if the data was changed, restore the backup you downloaded under **Settings → Backup & restore**:

```bash
docker compose stop netlens
# set the older image tag, then:
docker compose up -d netlens
```

Restoring the backup matters because a newer version may have changed the database in a way an older version cannot read. If the update made no data changes you can skip the restore, but you should not count on that.

## Configuration

| Variable | Default | Description |
|---|---|---|
| `NETLENS_TOKEN` | *(empty)* | Optional shared access token that signs in as administrator (older installs use it; new ones create an account in the first-start wizard). Not needed for Home Assistant or Prometheus: use an API token from Settings → Users & tokens |
| `NETLENS_RANGES` | auto-detect | Private ranges only, prefix >= /20. Can also be changed at runtime in the web UI (see below); the web setting takes precedence |
| `NETLENS_QUICK_INTERVAL` | `900` | Quick scan interval in seconds |
| `NETLENS_DEEP_INTERVAL` | `86400` | Deep scan interval in seconds |
| `NETLENS_TERMINAL` | `on` | Enable/disable web terminal |
| `NETLENS_GUACD` | `127.0.0.1:4822` | Address of the optional guacd helper container for RDP and VNC (`off` disables it) |
| `NETLENS_TERMINAL_REMOTE` | `off` | Where the terminal may be used from: `off` = direct local connections only (not through a reverse proxy / HTTPS address), `lan` = also through a proxy for local clients, `any` = anywhere |
| `NETLENS_TRUSTED_PROXIES` | *(empty)* | Reverse proxies whose `X-Forwarded-For` header is believed, as addresses or networks (`192.168.0.184` or `192.168.0.0/24`, comma separated). **Set this when you reach Netlens through a reverse proxy**: without it every visitor looks like the proxy, so the login throttle (5 wrong attempts a minute) is shared by everybody and a stranger can lock you out |
| `NETLENS_API_DOCS` | `off` | `on` serves the API documentation pages `/docs`, `/redoc` and `/openapi.json`; they are off so a stranger cannot read a map of the API |
| `NETLENS_BIND` | `0.0.0.0:8080` | Bind address and port |
| `NETLENS_DATA_DIR` | `/data` | Data directory |

### Choosing what to scan

By default Netlens scans the networks it finds on the Docker host's interfaces. You can restrict or change that in two ways:

- **Web UI (recommended):** open **Settings → Scan ranges**, enter one or more ranges separated by commas (for example `192.168.1.0/24, 10.0.0.0/22`) and press **Save**. It takes effect from the next scan, with no restart. It is stored in the data directory, so it survives updates and rebuilds. **Reset to default** removes it.
- **Environment variable:** `NETLENS_RANGES` in `.env`, same format.

Order of precedence: the web setting, then `NETLENS_RANGES`, then auto-detection. Only private IPv4 ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, and link-local) of /20 or smaller are accepted, and a single address such as `192.168.1.10` works too. When ranges are set, the web terminal can only connect to devices inside them.

## Settings in the web interface

Settings has a menu on the left, grouped into General, Notifications, Integrations, Data and System. **Every entry is its own page** with its own address (so you can bookmark it or use Back): `#/settings/ranges`, `nmap`, `schedule`, `map`, `channels`, `dns`, `ignored`, `users`, `terminal`, `plugins`, `plugin-browse`, `plugin-<id>` (for example `plugin-proxmox`, `plugin-asus`), `plugin-guide` (linked from the Plugins page), `backup`, `export`, `about` and `session`, for example `http://<docker-host>:8080/#/settings/plugin-proxmox`. On a narrow screen the menu becomes a row of buttons on top. The older addresses `#/settings/proxmox` and `#/settings/asus` still work.

Everything below is saved in the data directory, so it survives updates and rebuilds. Values set in the browser take precedence over the matching environment variables; "Reset" returns to the environment value.

| Card | What you can change |
|---|---|
| Scan ranges | which networks are scanned (see "Choosing what to scan") |
| Scan performance (nmap) | ports, timing and detection used by quick and deep scans, with presets (see "Making scans faster"). The **Scan settings** item in the **Scan** menu of the top bar jumps straight to it |
| Scan schedule | how often quick and deep scans run. Takes effect from the next scheduler cycle, no restart |
| Web terminal | the web terminal on/off (System group) |
| Alert channels & quiet hours | e-mail (SMTP), ntfy, Telegram, Discord, Pushover and webhook channels, each with its own events (see below) |
| Plugins and one page per plugin | turn plugins on or off, upload your own, and each plugin's own settings (see "Plugins" below) |
| Ignored devices | devices that scans skip, with a button to stop ignoring them |
| Backup and restore | download a snapshot, restore one |

### Making scans faster

Quick scans are normally a few seconds. **Deep scans are the slow part**: they probe the top 1000 ports of every host and run service version detection, OS detection and traceroute. On a network with about 35 devices a default deep scan took 5 to 8 minutes (and occasionally much longer when a device answers slowly). Under **Settings → Scan performance (nmap)** (or **Scan → Scan settings** in the top bar) you can trade detail for speed; the page shows how long your last quick and deep scan took so you can see the effect. Changes apply from the next scan.

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

The header shows the running version. It is `<major.minor from the VERSION file>.<commits since that file last changed>`, so it rises with every commit and every published image, for example `0.4.12`. The pre-built image is tagged with it (`ghcr.io/gatlarf/netlens:0.4.12`) as well as `latest`. Builds from source report `dev` unless you pass `NETLENS_VERSION` as shown under "Updating".

### Uptime history

**Sharing cards.** In Customize mode an administrator can press **Share with everyone** on a custom card. It then shows up under *Shared by your administrator* in every user's card pool, so everybody can add it to their own dashboard; changing or deleting it as the administrator changes it for all.

**Always-on devices.** Phones, tablets and laptops that come and go pull the network's availability down. Mark the devices that should be online all the time (router, switches, servers, NAS, cameras) as **always-on**: tick *Always-on device* when you edit a device, or on the Uptime page press **Choose always-on devices** (Netlens suggests the ones that have been up 99% of the last 30 days and are the kind of device that runs all day). The Uptime page then has an **All devices / Always-on** switch, the dashboard Uptime card shows the always-on figure with the all-devices figure beneath it, the Unstable devices card and the attention list count the always-on ones apart from the others, and an always-on device that is not answering is listed as needing attention. Statistics, `/api/stats/summary` (`core`), Prometheus (`netlens_core_*`) and Home Assistant carry the core figures next to the existing ones, which keep meaning all devices.

After every scan Netlens records, for each device inside the scanned ranges, whether it answered (and its response time when nmap reports one). The **Uptime** page shows a heartbeat bar per device (green = up, red = down, newest on the right) with 24 hour and 7 day uptime, like Uptime Kuma. Each device page has a larger bar, 24 h / 7 d / 30 d uptime, average response time, how long the current state has lasted, and a response-time graph. History is kept for 90 days. The resolution is your scan interval (15 minutes by default); shorten it under Settings for finer detail.

### E-mail notifications

E-mail is a notification channel like the others.

1. Open **Settings → Alert channels & quiet hours** and press **Add channel**. The service is **E-mail (SMTP)** by default: enter your SMTP server, the security (STARTTLS, SSL/TLS or none; the port follows from it unless you set one), user name and password, the sender and one or more recipients (comma separated). Tick the events you want mails for.
2. Press **Add channel**, then **Send test** to check the settings. A failure is explained in plain words (wrong password, host not found, connection refused, ...).

After each scan Netlens sends **one digest mail** per channel listing what happened since the last one. A new channel starts from that moment: you never get a mail about the backlog. If the mail server is down, the events are kept and sent later. Quiet hours apply to e-mail too, and you can have several e-mail channels (for example one for the family).

You can switch the offline alerts off **per device** with the checkbox "Alert me when it goes offline" on the device page (useful for phones and laptops that come and go).

An installation that used the former separate **E-mail notifications** page has it converted to an e-mail channel automatically (same server, recipients and events); the old page address redirects to the channels page.

The SMTP password is stored encrypted (see *Stored passwords* below).

### Stored passwords

Passwords and tokens that Netlens has to remember (plugin credentials, the SMTP password, ntfy/Telegram/Discord/Pushover/webhook secrets) are stored **encrypted** (AES-256-GCM). User passwords are stored only as scrypt hashes, and sign-in sessions and API tokens only as SHA-256 hashes.

- The key is created on first start as `secret.key` in the data folder (readable only by the Netlens user). To keep it outside the data volume, set `NETLENS_SECRET_KEY` (64 hex characters, or 43 base64 characters, or any passphrase) and Netlens uses that instead.
- **Backups contain the encrypted values but not the key**, so a backup file that leaks does not leak your passwords. To restore a backup on another machine (or into a new, empty data folder) you need the key: **Settings → Backup & restore → Encryption key** lets an administrator on a direct local connection show it, and set a **recovery passphrase**. With a passphrase set, every backup carries the key wrapped with it (the passphrase itself is not stored; there is no way to get it back), and after a restore you enter the passphrase to unlock the passwords. Without the key or the passphrase Netlens keeps working and the affected passwords are simply empty and must be entered again; the dashboard says so.
- The first start after the update encrypts passwords that were stored in plain text and keeps one copy of the database as `netlens.db.pre-encryption` in the data folder (it still holds the old plain-text values; delete it once you have checked that everything works).
- What this protects against is a copy of the database or a backup falling into the wrong hands. It does not protect against someone who can read both the data folder and the key, or who is signed in as an administrator.

### Known and unknown devices

Every device is either **known** (you recognise it) or **unknown**. Devices that exist when you upgrade are all marked known, so nothing changes at first; every device found afterwards starts as unknown, is tagged *unknown* in the Devices list, and its "new device" alert says so. Tick **Known device** on a device's page, or use **Trust all unknown** on the Devices page (it asks first). The Devices page can filter on *Unknown only*, and the Statistics page, the summary API and Home Assistant count them. Netlens also logs an **IP reused** event when an address that another device used in the last day is now used by a different one.

### Device identification

Netlens works out a device's name and type from everything it can see, in this order of trust: reverse DNS, the device's own **UPnP** description (name, make, model, kind of device), **mDNS** names (including the friendly name of casting devices) and service types (printers, AirPlay, Chromecast, HomeKit, cameras...), the **name your router** shows for it (from a topology plugin), and words in the name (`iphone`, `shelly1-...`, `laserjet`, `desktop-...`, `esxi`). Only the first part of a name counts (a domain such as `tv.example.com` says nothing), and an SSDP product token such as "Linux" is never used as a name. Discovery hints are kept per device, so a device keeps its type when a later scan does not hear from it again.

**Manufacturer.** The vendor comes from nmap, else from the **IEEE registry** (a copy of about 54,000 registrations ships with Netlens and is refreshed from the IEEE website every month; *Settings → Scan performance → Manufacturer database* shows its age and has an *Update now* button), else from a table of virtual-machine and container prefixes (Proxmox, QEMU/KVM, Incus, LXD, Docker, VMware, VirtualBox, Hyper-V). Addresses with the "locally administered" bit are not assigned to any manufacturer: phones use them as **private Wi-Fi addresses**, and the Devices page says *Private address* instead of *Unknown* (the name, the DHCP request and mDNS are the only ways to recognise such a device).

**Type.** Instead of "the first rule that matches wins", Netlens weighs every clue: strong discovery hints (mDNS printer services, UPnP gateway), words in the device's name, nmap's own class of the matched operating system (`webcam`, `printer`, `media device`, `game console`...), product words in nmap's OS name (*Vimtag CP3 PTZ camera*, *Silicondust HDHomeRun*), the manufacturer, open ports and the operating system family. A printer called `hp-laserjet` stays a printer even when nmap guesses Android, and a camera whose OS name says camera is not a server because SSH is open. nmap's product-style guesses (its device class and names like "HP LaserJet") only count when nmap is at least 90 % sure, because below that they are often wrong (TP-Link switches matched as a TV tuner). nmap's class is now remembered between scans, so a quick scan classifies a device the same way as the deep scan did. There are new types besides router, switch, access point, server, computer, phone, printer, IoT, camera, NAS and virtual machine: **tablet, TV / media, speaker, game console and appliance**. A type you set by hand always wins. After an update, Netlens re-applies its rules to the devices it already knows, so the effect shows at once.

**More evidence.** Three optional sources add to the clues above, all shown on the device page under **Why this type?** (every clue with its weight; the strongest decides):

- **Identification scripts** (*Settings → Scan performance*, off by default): a deep scan also runs nmap's read-only `http-title`, `ssl-cert`, `nbstat`, `smb-os-discovery`, `upnp-info` and `banner` scripts with a 15 second limit per script. They give the exact Windows version and computer name, the owner of a certificate (*Synology Inc.*), a web page title and a UPnP model. A deep scan takes longer.
- **Your router or controller.** A topology plugin may report a client's `vendor`, `os`, `model` and `device_type` (see the plugin guide). The ASUS plugin passes the DHCP vendor class that the router has seen (`MSFT 5.0` is Windows, `android-dhcp-13` is Android) and its printer flag. These count less than a clear name or a scan.
- **Passive listening** (*Settings → Scan performance*, on by default when the container has `NET_RAW`, which the compose files give it): Netlens reads DHCP requests, mDNS announcements and UPnP notifications that reach it, and sends nothing. A device asking for an address tells its name and its operating system (by its DHCP vendor class and the order of the options it asks for), so a phone with a private Wi-Fi address, which has no open ports, still gets a name and a type. It only hears its own network segment, and only the interface the container's multicast traffic arrives on.

**Learning from you.** When two or more devices of the same manufacturer were set to the same type by hand (and hardly any to another), Netlens applies that type to the manufacturer's other devices that have no manual type, and says so under *Why this type?*.

### Installing Netlens as an app

Behind HTTPS (see the HTTPS section; plain `http://` only works on `localhost`) your browser offers **Install** (Chrome, Edge) or **Add to Home Screen** (Safari, Chrome on Android). Netlens then opens in its own window with its own icon. Only the public interface files are cached, to open faster and to show the app frame when the server is unreachable: data, share links and metrics are never cached and always need a login. If something looks stale, reload once or clear the site data.

### Wi-Fi details

When a topology plugin reports the signal of Wi-Fi clients (the ASUS plugin does), Netlens stores one sample per scan for 14 days. The device page then shows a **Wi-Fi** card with the signal (excellent / good / fair / weak), node, band, link rate, a 24 hour signal chart and the last moves between nodes. A client that changes node logs a **Wi-Fi move** event. The Statistics page adds a Wi-Fi group (signal quality, weakest clients, moves in 7 days).

### Service checks

**Services** (top bar) watches things a ping cannot: an **HTTP(S) page** (any status 200-399, a chosen status, or text that must appear), a **TCP port**, or a **DNS lookup** against a chosen server (optionally with the address it must return). Pick the interval (15 seconds to a day) and the time-out, optionally attach it to a device, and see a heartbeat bar, 24 hour uptime and response time per check. A **certificate** check reads what a TLS service presents and goes down when fewer than the chosen number of days are left; a **process** check asks a device with health monitoring (below) whether a program or service runs. A state change needs two identical results in a row (one lost packet is not an outage) and logs a **Service down / up** event, which goes to e-mail and the notification channels. A check can be run on demand, paused and edited; HTTPS certificates are not verified (devices on a LAN usually have self-signed ones). Results are kept for 30 days.

### Performance graphs and health monitoring

Netlens keeps a time series of what it measures in its own small database file, `metrics.db`, next to `netlens.db`: the response time and availability of every device (from the scans) and of every service check. Full detail is kept for 7 days, 5-minute values for 90 days and hourly values (lowest, average, highest) for 2 years, so a graph can show anything from 6 hours to a year. A backup carries a trimmed copy of it (the last day in full, 14 days at 5 minutes and all the hourly values), so a restore brings the graphs and the growth trend back; the first start after an update fills it from the uptime history that already exists.

**Health monitoring** adds what a ping cannot tell you. On a device's page choose *Set up health monitoring* and pick how to ask it:

| Method | For | Reads |
| --- | --- | --- |
| **SNMP** v1, v2c and **v3** | switches, routers, NAS boxes, printers, UPS units, Windows with the SNMP service, Linux with `snmpd` | processor, memory, swap, disks (used and free), traffic, load, errors and link state per interface (port), temperatures (net-snmp), uptime, printer supplies, UPS battery and runtime |
| **SSH** | Linux and other systems with `/proc` | processor, load, memory, swap, disks, traffic per interface, temperatures, uptime |
| **SSH to Windows** | Windows 10/11 and Server 2019+ with the OpenSSH server (an optional Windows feature) | processor, memory, swap, disks, traffic per adapter, uptime. Netlens recognises Windows by itself and runs one read-only PowerShell command; nothing is installed |

Nothing is installed on the device and only read requests are sent: SNMP `GET` / `GETNEXT` / `GETBULK`, or one short shell command over SSH that reads `/proc`, `/sys` and `df`. An ordinary (non-root) SSH account is enough. The SSH host key is remembered the first time and shared with the web terminal. The login is stored encrypted (see *Stored passwords*). *Test* shows what the device answers before you save. Windows can be read through the SNMP service or through its OpenSSH server (there is no WinRM or agent). **SNMPv3** uses a user name with authentication (MD5, SHA, SHA-256, SHA-512) and optionally encryption (AES or DES); create a read-only user on the device.

**Warnings**: a reading has to stay past its limit for a few rounds in a row (processor 5, others 2-3) before anything is said, so a short peak is not an alarm. Defaults: processor 90 / 98 %, memory 90 / 97 %, disk 85 / 95 % full, temperature 80 / 90 °C, printer supplies and UPS battery below 15 / 5 % and 50 / 25 %, and a UPS running on battery. Change them on **Monitoring → Health**, or for one device only on its Health tab under *Limits for this device* (a NAS that runs at 90 % by design). Switch ports also get *Port busy* (85 / 95 % of the link speed) and *Port errors* (1 / 10 per second) limits. The events *Health warning*, *Health critical* and *Health normal* go through the notification channels, respect maintenance windows, and show on the dashboard. `/metrics` carries the readings as `netlens_host_*`.

**Ports.** A switch (or any device with three or more interfaces) gets a *Ports* table on its Health tab with the link state, traffic in and out, how full the link is and errors; click a port for its graphs. A cable that is unplugged shows as *down* without an alarm; ports that were switched off on purpose are left out.

**Running out soon.** From the growth of the last weeks Netlens works out when each monitored disk will be full (a steady disk gets no date, one big file is not a trend, and a disk needs three days of history first). The dashboard card *Running out soon* lists them, and a notification (*Disk filling up*, *Disk almost full*) is sent once when a disk is on course to fill within 14 days (3 days for the critical one). The 14 days can be changed with the setting `forecast.alert_days`.

**Dashboard.** The *Health* card shows a heat-map with one tile per monitored device (coloured by its worst level, with bars for processor, memory and the fullest disk); with more than 24 devices the healthy ones shrink to small squares.

### Reports

**Monitoring → Reports** has two things. The **weekly report** is a summary in plain language of the last seven days: what was down and for how long, health readings past a limit, disks that are filling up, new devices and silent remote sites. Switch it on there, choose the day and hour (the time of the server) and tick *Weekly report* on the notification channels that should get it (Settings → Notifications); *Send it now* tries it. The **monthly availability report** lists every device and service for a calendar month with its availability, number of outages, longest outage and time down; print it or download it as a CSV file.

### Remote sites

Netlens can watch more than one network. Run a Netlens at each location (a branch office, a holiday house, a customer) and let them report to one **central** Netlens:

1. On the central Netlens open **Monitoring → Remote sites → Add a remote site**, give the location a name and copy the token (it is shown once; only a hash of it is kept).
2. On the Netlens at that location open **Settings → Report to a central Netlens**, enter the address of the central Netlens and the token, switch it on and press *Send a report now*.

The remote Netlens keeps working on its own (scans, checks, health monitoring, its own alerts) and sends a report every minute: its devices, service checks, health problems and the measurements made since the last report. **The connection always goes out from the remote site**, so nothing there has to be reachable from outside; across the internet the central Netlens should be reachable over `https://` (a plain `http://` address is accepted for a server on your own network, for example through a VPN). The token is the only credential: a new one can be made at any time, which locks the old one out.

The central Netlens keeps the remote devices apart from its own (two sites may use the same address range). Each site shows its devices, service checks and health problems with graphs of their history, and raises alerts through the notification channels: a device offline or new, a service down, a health problem, and **a site that stops reporting** (until it reports again its devices are shown as not watched rather than all offline). Alerts also appear on the dashboard and in Prometheus (`netlens_remote_site_*`).

**Managing a site from the central Netlens.** On the page of a site, *Managed from here* lets you set up service checks and health monitors that run at the remote location (on its own network). The remote Netlens only accepts this when you tick *Accept configuration from the central Netlens* in its **Settings → Report to a central Netlens**; what it receives is marked as managed from the central Netlens and cannot be edited there. The logins are stored encrypted on both sides and travel in the reply to the site's report, so use `https://` or a VPN. What a remote site shows is limited to what it chose to report: names, addresses, MAC addresses, vendors, ports and measurements, never passwords.

### Maintenance windows

**Settings → Maintenance windows** tells Netlens when devices are expected to be unreachable (a mesh node that reboots every night, a planned update). A window covers everything, some groups or chosen devices (optionally the devices behind them, which go down with them) and runs weekly on chosen days between two times (an end before the start runs past midnight) or once, in your time zone. While it is active, the *offline*, *online* and *service down/up* events of covered devices are still recorded, but marked with the window's name and left out of e-mail and notification channels. A device that is still offline when its window ends is reported then. Devices show an *In maintenance* badge, and the **Maintenance…** menu on a device page starts a window for 30 minutes to 24 hours. The events API has a `maintenance` field on held-back events.

### Notification channels and quiet hours

**Settings → Alert channels & quiet hours** sends alerts by **e-mail** and to **ntfy**, **Telegram**, **Discord**, **Pushover** or any **webhook** (a JSON POST, which works with Home Assistant webhooks, n8n and Node-RED). Each channel chooses the events it wants (new unknown device, device offline or back, service down or recovered, new open port, IP change, IP reused, OS change, Wi-Fi move, scan time-out), has its own *Send test* button, and keeps its own place in the event log: a channel that fails catches up later without disturbing the others, and error messages never contain tokens. **Quiet hours** hold messages back and deliver them afterwards as one digest (a service going down can still break through). Tokens are stored in the database like the SMTP password.

### Prometheus and Grafana

`GET /metrics` (an API token from Settings → Users & tokens, as a Bearer token; a viewer's token is enough) exposes Prometheus metrics: device presence and last seen, devices by state, uptime ratio, open ports, scan duration/hosts/last success per kind, events by kind, plugin health, service check state and response time, Wi-Fi signal per client, devices by type and group, how many devices are still unknown or hidden behind a private address, flapping devices, backup result and age, DHCP servers (trusted or not), passive listening activity, reverse proxy sites and the days left on each certificate they use (`netlens_certificate_days_left`), the latest internet speed test (`netlens_speedtest_download_bits_per_second` and friends), containers with a newer image available, database size and a `netlens_problem` flag. `contrib/prometheus/prometheus.yml` has a scrape job and alert rule examples; `contrib/grafana/netlens-dashboard.json` is a dashboard you can import in Grafana.

### Statistics

The **Statistics** page (top bar) shows what Netlens knows, in groups: *History* (devices online per hour or day, devices over time, events per day), *What is on the network* (by type, group, vendor, operating system, subnet, wired versus Wi-Fi and clients per mesh node when a router plugin is on), *How well Netlens knows its devices* (devices of unknown type, with a private address, without manufacturer, name or operating system, set by hand or scanned gently, and what passive listening has heard), *Availability* (network uptime 24 h/7 d/30 d, least and most reliable devices, flapping devices, who has been offline longest, slowest responders), *Ports and services* (counts only: open ports, most common ports and services, devices with the most open ports, newly opened ports), *Network structure* (depth, busiest parents, where the hierarchy comes from, guests per hypervisor host), *Scans* (counts, median/95th percentile/longest duration per kind, hosts found per scan, host timeouts), *Events* and *System* (version, database and schema, manufacturer registry, backups, DHCP servers, plugin health). A row of buttons under the title jumps to every group (it stays in view while you scroll and highlights where you are), and a refresh keeps your place on the page. The period buttons (24 hours to 90 days) set the window of the history, scan and event groups and are remembered per browser; the page refreshes itself every minute.

The history charts use the uptime checks (kept 90 days) and a **daily snapshot** (devices, online, new devices, open ports, events, scans) that Netlens stores after every scan and keeps for 400 days, so "devices over time" fills in as the days go by. The data comes from `GET /api/stats?range=7d` (24h, 7d, 30d or 90d). `GET /api/stats/summary` is a small, versioned document (`api: 1`) with the headline numbers, scan state, plugin health, a `problem` flag and a compact device list; it is what the Home Assistant integration polls (it also carries flapping devices, the identification counts, the backup result, DHCP servers, DNS registration, container health and passive listening). Both answers are cached for 30 seconds. `GET /api/events?since_id=<id>` returns only events newer than an id.

### Scheduled backups

**Settings → Backup & restore** can make a backup by itself: every 6 hours to every week, keeping the newest 1 to 60 copies in the `backups` folder of the data directory (readable only by Netlens). The page lists them with *Download*, *Restore* and *Delete* and has a *Back up now* button. A failed backup is retried after an hour, shows in the card and raises a **Backup failed** event that the notification channels can send. The copies live on the same disk as the database, so download one now and then as well. A backup holds everything, including saved passwords, users, share links and the plugins.

### Port baselines

On a device page, **Accept as normal** stores the device's current open ports as its baseline (**Set baselines** on the Devices page does it for all devices without one; devices that have none are never judged). From then on a new port logs **Unexpected port** (instead of *Port opened*), a baseline port that disappears logs **Baseline port gone**, and the device page and Devices list show the difference. Closed ports are noticed by deep scans, which list a port that vanished as **Port closed**. These events go to the notification channels like any other (Unexpected port and Baseline port gone are on for new channels).

### Wake-on-LAN, ping and traceroute

The device page has **Wake** (a Wake-on-LAN magic packet to the device's MAC address, sent to the broadcast address and to the /24 of its IP; the device must have Wake-on-LAN switched on), **Ping** (does it answer now, and how fast) and **Trace** (the hops from Netlens to the device). Ping and trace go through nmap and only accept private addresses.

### Users and API tokens

New installs have no shared token: you create the first administrator in the [first-start wizard](#first-start). **Settings → Users & tokens** adds more named users: an **administrator** can do everything, a **viewer** can look at the map, devices, hierarchy, statistics, uptime and services but cannot change anything, open the terminal, read settings, exports or backups, or see credentials. Passwords need at least 8 characters; changing one (Settings → Account, or by an administrator) ends that user's other logins. A forgotten password is fixed from the device that runs Netlens with `docker exec -it netlens python -m app.cli reset-password <user>`.

**Access token (older installs):** if `NETLENS_TOKEN` is set in the container's environment, it keeps signing in as administrator (login dialog: "Sign in with the access token instead") and the first-start wizard does not appear. Remove it once you have an administrator account of your own; the Users page reminds you.

An administrator can create **API tokens** for a user (shown once). They are Bearer tokens that act with the role of their user, for scripts, Prometheus (`/metrics`) and the Home Assistant integration; a viewer's token is enough for those because they only read.

### Share links

**Settings → Share links** creates a secret address (`/share/<token>`) that shows the network read-only without a login: either the **map and device list** or only a **status page** (devices online and offline, service states). IP and MAC addresses are left out of the page and the data unless you tick them for that link, and a name that is only an address is shown as "Device N". A link can end after 1 to 90 days and stops working the moment you delete it; the card shows how often each was opened. Netlens itself should not be exposed to the internet without protection; share links are meant for people on your network or behind your own reverse proxy.

### DNS registration

*Settings → Integrations → DNS registration* registers the devices Netlens knows in your DNS server and keeps their addresses right when DHCP hands out a new one. It needs a **DNS plugin** (for example *Technitium DNS*, see `plugins/technitium`). You enter your networks and their zones (`192.168.0.0/24 = home.example.com`, one line per network, several zones are fine), press **Read the DNS server now**, and Netlens shows a preview: what it would add or update, what is a **conflict**, and what is left alone. Nothing is written until you approve it; once the preview is what you want you can switch on *Apply automatically after every scan*. With the Docker plugin you can also tick *Give containers that share their host's address a name*: a running container on a bridge or host network that publishes a port then gets a CNAME to its host (`web.home.example.com`), and a container with its own network address is registered like any other device.

Safety is the point of the design: Netlens only changes records it created itself (marked with a comment, and remembered), and **never changes a record that something else made**. A Windows machine that registers itself leaves a record; Netlens recognises it (also when the name differs from the one Netlens would choose) and leaves it alone, shows *Registers itself*, and does not register Windows machines at all by default. A device without a record waits for a grace period (2 hours by default) before it is registered, only devices you marked as *known* are registered (a stranger cannot claim a name by announcing a hostname), and a name that is already used by a record pointing elsewhere is a conflict that you resolve by hand. Devices without a name get a generated one (`tv-samsung-a1b2`, from a pattern you can change) that stays the same afterwards, and every device has a **DNS registration** setting on its page (*Automatic / Always register / Never register*) and a field for its own DNS name. Removing records of devices that are gone is off by default, and a limit caps how many changes one run may make. DNS events (*registered*, *updated*, *failed*) go to the event log and can go to the notification channels.

### Network checks

**Settings → Network checks** watches for two things that should not change by themselves.

- **Rogue DHCP server:** every 12 hours (changeable, or switched off) Netlens broadcasts one DHCP discover, like a device that has just been plugged in, and lists every server that answers, with the router and DNS servers it hands out. The servers found the first time are taken as normal; a server that appears later is reported as a **Rogue DHCP?** event (e-mail, notification channels and Home Assistant, and it breaks through quiet hours) until you press **Trust** for it. *Check now* listens for about ten seconds. (A rogue DHCP server hands out wrong gateways or DNS servers and is a classic way to redirect traffic.)
- **Gateway MAC changed:** Netlens remembers which MAC address answers for your default gateway. If it changes, a **Gateway changed** event is raised: either you replaced the router or someone pretends to be it (ARP spoofing).

### Groups

**Settings → Groups** creates groups with a name and colour (rooms, floors, owners...). A device is in one group: set it in the *Group* field on its page, or on the **Devices** page, which has a group column and filter and a *Set group of listed…* box that puts all devices currently listed (after your filters) in a group at once. On the **map**, *Colour by group* paints devices by group (ungrouped ones are grey, with a colour key) and the group filter shows one group at a time. The Home Assistant integration uses the group as the suggested area of a tracked device. Deleting a group keeps its devices. The group name is part of the statistics summary (`device_list[].group`).

### Update notice

When a newer Netlens image has been published, an **Update x.y.z available** notice appears in the account menu of the top bar (the menu button shows a small orange dot) and **Settings → About → Updates** shows what changed and how to update (the steps are under *Updating* above). Netlens only asks the container registry once a day for the list of published version numbers; nothing is installed automatically. The check can be switched off on the same card. `GET /api/update` and the statistics summary report it, and the Home Assistant integration has an update entity.

### Plugins

Netlens learns about your network from other systems through **plugins**. Four kinds exist: **hypervisor** plugins report VMs and containers and the host each runs on, **topology** plugins report network nodes (router, switch, access point, mesh node) and which node each client is connected to, **dns** plugins write names to a DNS server, and **proxy** plugins report the sites a reverse proxy publishes. Netlens matches what a plugin reports to the devices it has scanned (by MAC address, then IP), and shows the result as links on the map and in the hierarchy.

Under **Settings → Integrations** you find:

- **Plugins**: every installed plugin with its type, version, source (built in or uploaded) and last sync, a **Turn on / Turn off** button for each, and an **Upload plugin** box for a `.zip` of your own. A new plugin stays off until you turn it on. Turning one off removes its links from the map and keeps its settings.
- **One page per plugin** with a settings form that Netlens builds from the plugin's manifest, *Test connection* (saves nothing), *Save* and *Sync now*. A plugin syncs when you turn it on and after every scan. A failing plugin never disturbs the others or the scan, and keeps its last good links; a refused login pauses that plugin until you save or sync it again, so a wrong password cannot get an account locked.
- **Plugin guide**: how to write a plugin (package format, `plugin.json`, the two functions, the exact data a plugin must return, security notes). The same text is in the repository at [`app/plugins/PLUGINS.md`](app/plugins/PLUGINS.md), and **Download example plugin** gives a working template.

- **Browse plugins**: the **plugin index** lists plugins from the community with a **review level**: *Verified* (a trusted reviewer read the code of that exact version and tested it on real hardware), *Reviewed* (code read, not tested on hardware) or *Community* (only automatic checks; installing it needs an extra confirmation with a warning). *Install* downloads the plugin, checks it against the SHA-256 pinned in the index and applies the same safety checks as an upload; a new plugin starts switched off. Installed plugins show **update available** (nothing updates by itself), updating keeps the settings, and **Go back to the previous version** restores the last one. The index is a file in this repository (`plugin-index/index.json`, read once every six hours); its address can be changed or switched off under *Plugin index settings*. To publish your own plugin see [`plugin-index/README.md`](plugin-index/README.md) (entry format, review process, templates and a local checker).

**Uploaded and downloaded plugins are Python code that runs inside the Netlens container.** Each runs in its own process with a stripped environment, a time limit and no database path, and everything it returns is validated, but this is not a sandbox: it runs as the same user and could read the data volume. Only install plugins you trust and have read. Uploading needs the Netlens login.

#### Nginx Proxy Manager plugin

A **proxy** plugin (`plugins/npm`, install it from *Browse plugins*) that shows what your Nginx Proxy Manager publishes. In Nginx Proxy Manager create a user for Netlens that is not an administrator, has no two-factor login, sees **All Items** and has **View Only** on everything (the plugin's settings show these steps, and warn when the account is wrong); enter the proxy's address (port 81), the e-mail address and the password. Netlens then:

- ties every site (proxy hosts, redirections, streams, 404 hosts) to the device or Docker container its upstream leads to: by a container that publishes the forwarded port on that host, a guest or container with that address, a device with that address or name, or a container name on the proxy's own Docker network. A site it cannot place is listed as *not found*, never guessed;
- shows a *Published through the proxy* card on the device behind a site, *Sites served* on the proxy's own device, and a list of all sites in the plugin's settings with the ones that need attention first;
- raises a *certificate expiring* event 14 days (adjustable), 7, 3 and 1 days before a certificate used by a site ends, and when it has expired;
- keeps one HTTPS check per enabled site under Services (it asks the proxy for the domain, so it does not depend on DNS; a server error such as 502 is *down*; switch it off with *Check every site*);
- can create DNS names for the domains: *Settings → DNS registration → Give the sites of a reverse proxy a name* (off by default, previewed and approved like every DNS change).

Netlens only reads from Nginx Proxy Manager (it logs in and then does `GET` requests).

#### Microsoft Hyper-V plugin

A **hypervisor** plugin (`plugins/hyperv`, install it from *Browse plugins*, needs Netlens 0.3.115 or newer) that lists the virtual machines of a Hyper-V host with their state, processors, memory, start time and network switch, and ties each VM to the device Netlens found by MAC address (then IP). It reads through Windows Remote Management over **HTTPS** by running one fixed `Get-VM` script. Plugins can only use the Python standard library, so it contains its own small WinRM client with NTLMv2 (or Basic) login. The plugin's settings page shows the PowerShell lines to run once on the host: they create a `netlens` user (member of *Remote Management Users* and *Hyper-V Administrators*, not an administrator), switch on an HTTPS listener with a self-signed certificate, drop the plain-HTTP listener and open port 5986 only to the Netlens machine. Windows has no read-only Hyper-V role, so keep that firewall rule and use a long password. Tested against simulated answers and Microsoft's published NTLM test values; not yet on a real host.

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
- **Map**: by default only each device's chosen parent link is drawn, so a Proxmox guest hangs under its host instead of also being linked to the router. *Hierarchy links / All links* switches between that and every inferred link, and *Free / Tree / Horizontal / Vertical / Compact layout* arranges the devices: Tree is a top-down tree, **Horizontal** is a left-to-right topology like Omada's (the router on the left, one column per level, a card per device, right-angle links) and **Vertical** is the same picture top to bottom (the router at the top, one row per level, the devices of a level side by side). **Compact** is the dashboard's mini-map at full size: small dots in columns from left to right with curved links, everything visible at once (nothing folded), click a dot for the details. In the horizontal and vertical layouts the client devices of a busy branch (more than 8) start folded into `▸ N more`; double-click a device, or use its details panel, to fold or open its clients, and *Collapse clients*, *Expand all* and *Fit* act on the whole map. The tree layouts arrange themselves, and dragging in them does not overwrite your saved free-layout positions. Clicking a device shows its parent. The layout the map opens with is set under **Settings → Map** (a layout chosen in the map's own menu is remembered per browser and wins; *Forget this browser's choice* in Settings returns to the default).
- **Device page**, section **Network position** (inside the collapsed **Edit** card): shows what the device sits below and why, lists the devices below it, and lets you choose the parent: *Automatic*, *None (top level)* or a specific device. Devices below the current one are not offered, so a loop is impossible. If a chosen parent is deleted, the device goes back to automatic.

The same data is available as `GET /api/hierarchy`, and `PATCH /api/devices/<id>` accepts `parent_mode` (`auto`, `none`, `device`) and `parent_device_id`.

### Start page

Under **Settings → Account → Start page** each user chooses the page Netlens opens on (the map, Health, Devices, Reports and so on instead of the dashboard). It is kept on the server per user, so it follows you to every browser, and it only applies when you open Netlens without a link to a page: a bookmark, a reload and the back button are left alone.

### Dark mode

The **moon / sun button** at the top right of the bar, left of the account menu, switches between light and dark mode. Without a choice Netlens follows your operating system's setting; once you click the button your choice is remembered in that browser (it is not shared between browsers or users). Charts and the map follow the theme too (the map draws brighter device colours and links with outlined dots and haloed labels in dark mode, and offline devices get a dashed outline).

### Deleting a device and ignoring devices

On a device's page, the **Delete device** card removes it together with its ports, names, uptime history and links (past events stay in the log, marked as deleted). A device that is still on the network would simply be found again by the next scan, so the confirmation offers **Also ignore it in future scans** (ticked by default for an online device). Ignored devices are skipped by every scan, are not mailed about, and are listed under **Settings → Ignored devices**, where **Stop ignoring** lets the next scan add one back. Devices are ignored by MAC address, or by IP address when they have no MAC (for example the bridge address of a container network), so a different device that takes over the same IP is not ignored. The same actions exist as `DELETE /api/devices/<id>?ignore=true` and `GET`/`DELETE /api/ignored`.

### Full scan of a single host

The **Full scan** button next to a device's name runs one thorough scan of that host only: all 65535 TCP ports, service versions, OS detection and a traceroute (`nmap -T4 -p- -sV -O --osscan-guess --traceroute`, at most 30 minutes; the aggressive timing is a minimum, and your reverse-DNS preference applies). It is the way to find a service on an unusual port that the top-1000 scan never looks at. The strip under the top bar shows `Full scan of 192.168.0.5` with its progress and the usual elapsed/typical time, you can cancel it like any scan, and the result replaces that device's port list. It does not touch other devices, does not add an uptime heartbeat and does not recalculate the network relations, and it appears in **Scans & events** as `full <ip>`. Only one scan runs at a time. The API is `POST /api/devices/<id>/scan`.

### Backup and restore

**Settings → Backup and restore → Download backup** gives you a consistent snapshot of the whole database (devices, history, settings, saved credentials) and the installed plugins (their code, not the built-in ones) while Netlens keeps running. A restore into a new container therefore brings everything back as it was, plugins included and switched on as before; the plugin versions of the backup replace the installed ones. Backups made before 0.3.129 have no plugin code: restore them, then install the plugins again from the Plugins page (it lists them, and their settings come back). **Restore from file** replaces the current data with a backup; it asks for confirmation, refuses to run during a scan, keeps a safety copy of the previous data next to the database (`netlens.db.pre-restore`), and upgrades a backup made by an older version automatically. A backup from a newer Netlens version is refused. Treat backup files like passwords because they contain the saved SMTP and plugin credentials.

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

### Investigating a device that keeps going offline

A device that flaps is not always faulty: it may only stop answering Netlens. The **Stability** section of the Uptime card on the device page (administrators; click the arrow to expand it, the page stops refreshing while it is open) has an **Investigate** button that reads the scan history of the last 1-30 days and reports how often and for how long the device is missed, whether the devices behind it stayed online during its gaps (then it is running and merely not answering the probes; this needs the devices behind it to have it as their *Network position* parent), whether other devices were missed at the same moments (a scan problem rather than a device problem), whether it drops at a regular interval or at a certain time of day, and whether it slows down before it drops. **Run live test** then asks the device 8 times by ARP, ping and TCP, runs a real quick scan of just that device, and shows which probe goes unanswered: a device that answers ARP only now and then is the typical cause of a switch or access point that seems to flap while traffic through it is fine. It also checks the **address**: a device that keeps changing its address, or that answers on two addresses with the same MAC at the same time (a fixed address plus a DHCP lease, or a container or VM that shares a MAC), is flagged with the likely cause, because Netlens keeps one entry per MAC and would otherwise show it switching addresses at every scan.

### Offline marking

A device that was online and is not seen by a scan is asked for once more on its own (a short `nmap -sn` with retries) before it is marked offline, because a big sweep gives up on devices that answer late. *Settings → Scan performance → Look again before marking a device offline* switches this off.

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
- **Only on the local network by default.** A request that came through a reverse proxy (it carries `X-Forwarded-*` headers) is treated as coming from outside, so the terminal does not work on your HTTPS address; open `http://<netlens>:8080` on the local network instead. `NETLENS_TERMINAL_REMOTE` widens this: `off` (default), `lan` (also through a proxy when the client address the proxy reports is a local one; the proxy must set `X-Forwarded-For`, which the recipes above do or do by default) or `any`. It is an environment variable on purpose: nobody who reaches the web interface from outside can change it, and the on/off switch for the terminal (Settings) can only be changed from the local network either. The device page's console is in the left column (with a *Wide view* button) and the top bar has an **SSH** button that jumps to it.
- For a guarantee that does not depend on Netlens, also block it in the reverse proxy, for example nginx `location /api/terminal { return 404; }` or Caddy `respond /api/terminal/* 404`. Nginx Proxy Manager: *Custom Locations* with `/api/terminal` and an advanced `return 404;`.
- HTTP/HTTPS admin UIs opened via plain links ("Open" next to ports 80/443/...)

## Remote access

**Network → Remote access** lists the devices that have SSH (22), Telnet (23), RDP (3389) or VNC (5900–5909) open, and opens sessions on the right, in tabs. A device page has an RDP or VNC button when those ports are open.

- **SSH and Telnet** are the web terminal described above, nothing extra is needed.
- **RDP and VNC** need a small helper container, **guacd** from the Apache Guacamole project, which translates the remote desktop protocols for the browser. The page itself shows the three steps (add the service, let Netlens find it, check) with the lines to copy. In short, add this service to the compose file you run Netlens from and run `docker compose up -d`:

  ```yaml
    guacd:
      image: guacamole/guacd:1.5.5
      container_name: netlens-guacd
      restart: unless-stopped
      ports:
        - "127.0.0.1:4822:4822"
  ```

  Netlens runs on the host network in the supplied compose files, so it reaches the helper at `127.0.0.1:4822`, which is the default. Set `NETLENS_GUACD=host:port` if it lives elsewhere (for a Netlens container that is on a normal Docker network, give the helper no published port and use `NETLENS_GUACD=guacd:4822`), or `NETLENS_GUACD=off` to switch it off. Without the helper the page still lists SSH and Telnet and explains what is missing; the same lines are in `docker-compose.yml` as an optional block.
- **Who and where:** administrators only, from a direct connection on the local network, the same rule as the terminal (`NETLENS_TERMINAL`, `NETLENS_TERMINAL_REMOTE`; switched off in the demo). Only inventoried devices with a private address and that port seen open can be reached, and at most 5 sessions (terminal and remote desktop together) run at once; an idle session ends after 15 minutes.
- **Passwords** are typed for each session and sent once. With *Remember this login* they are stored encrypted with the Netlens key (see *Stored passwords*) and can be forgotten again on the same form; the browser never gets a saved password back.
- **Good to know:** the helper has no login of its own, so never publish its port to your network or the internet. RDP certificates are accepted without checking (Windows machines use self-signed ones); network level authentication works. Clipboard text goes both ways; drives, printers and sound are not redirected. The remote screen follows the size of the browser window (RDP) and *Fit* scales it.

## Speed tests

**Network → Speed tests** has four parts, and keeps every result (a year, at most 5000 results).

- **Internet speed** measures delay, jitter, download and upload against Cloudflare's nearest test server (`speed.cloudflare.com`, the same one its public speed test uses; no account, nothing is installed). A test takes about 20 seconds and on a fast line downloads a few hundred megabytes, so the automatic test is **off by default**; switch it on under the chart and pick every 1, 3, 6, 12 or 24 hours. A failed test (no internet) is recorded as a failure. Netlens contacts Cloudflare only when a test runs.
- **iperf3 server**: the image contains `iperf3`. Press **Start server** (default port 5201, changeable) and Netlens listens on all of its addresses (it runs on the host network). The page then shows the line to type on any other computer, for example `iperf3 -c 192.168.0.10`; add `-R` to test the other direction and `-P 4` for four parallel streams. Every test that connects is stored with the client's address. The server stays on after a restart and has no password (iperf3 has none), so switch it off when you are done. If another iperf3 already uses the port, Netlens reports that and stays off; pick another port.
- **iperf3 client**: type an address or choose an online device, and Netlens runs `iperf3 -c` against it (that host must run `iperf3 -s`): both directions, or one, 3 to 60 seconds, 1 to 16 streams.
- **Test from this device** runs in the browser, on any device, with nothing to install. The page downloads and uploads data from and to Netlens over four and three parallel connections for 8 seconds each and measures delay, so it shows the speed between that device and Netlens (a Wi-Fi spot, a cable, a powerline adapter). Open Netlens by its local address to measure only your local network; through a reverse proxy or the internet it measures that whole path. It is a browser test, not iperf: a browser cannot speak the iperf protocol, and a single browser rarely reaches more than a few Gbit/s. Add a label to remember where you tested.

The latest internet test also appears on the dashboard (an *Internet speed* card), in **Statistics → Speed tests**, in the statistics summary (`speed`, used by the Home Assistant integration, which has *Internet download speed*, *upload speed* and *ping* sensors) and in `/metrics` (`netlens_speedtest_*`, with two panels in the Grafana dashboard).

Only one internet or iperf3-client test runs at a time (a test needs the whole line). Administrators run the internet and iperf3 tests; viewers can run the browser test. In demo mode the history is made up and only the browser test works.

## Demo mode

Want to show Netlens to someone, or try it without a network? Start the same image with `NETLENS_DEMO=on`, as its own container next to
the real one (use a different name and port, and no volume). It builds a made-up home network of 46 devices with a month of history:
outages, a flaky smart plug, a switch that takes its cameras down, a power cut, DNS registration, Proxmox / Docker / Hyper-V / TrueNAS
guests, reverse-proxy sites with certificates, service checks and Wi-Fi roaming. A small simulator keeps it moving (devices go offline
and come back), and the map, hierarchy, uptime, statistics and settings pages all work.

```bash
docker compose -f docker-compose.demo.yml up -d      # then open http://<this-machine>:8081, sign in as demo / netlens-demo
```

Or add it to your own compose file: the real image, `NETLENS_DEMO: "on"`, a port and `tmpfs: ["/data:uid=10001,gid=10001"]`.

| Variable | Default | Meaning |
|---|---|---|
| `NETLENS_DEMO` | `off` | `on` switches demo mode on |
| `NETLENS_DEMO_RESET` | `daily` | `off`, `hourly` or `daily`: how often the data starts over |

The demo is read-only for visitors: the demo account sees every page, but every change (scans, settings, plugins, users) is refused
with a message. Nothing is scanned or sent, the web terminal is off, and the sign-in page shows the demo account. The addresses
and names are fictional (`192.168.42.0/24`, `home.example.net`).

## Security notes

- Access token required (cookie HttpOnly, SameSite=Strict, Secure behind HTTPS)
- Login rate limit: 5 wrong attempts a minute per client address and 20 per quarter hour per user name. Behind a reverse proxy set `NETLENS_TRUSTED_PROXIES`, otherwise all visitors share the proxy's address
- The API documentation pages and the version number are hidden from visitors who are not logged in; HSTS is sent over HTTPS
- No TLS built in — put behind a reverse proxy with HTTPS
  - `X-Forwarded-Proto` must be set
  - WebSocket upgrade must be forwarded
- Runs as non-root with file capabilities on nmap
- Only `NET_RAW` and `NET_ADMIN` capabilities
- Host networking
- Read-only root filesystem
- Security headers and CSP
- If you do open it to the internet: HTTPS through the proxy, a long random access token and passwords, `NETLENS_TRUSTED_PROXIES` set, the terminal left on its default (direct local connections only), and ideally an extra layer in front (an access list or VPN in the proxy, or an authenticating proxy)
- Scanning only private ranges
- Treat the token like a root password because the terminal can reach devices

## Not implemented / limitations

- CDP neighbour discovery (planned); SNMP switches and LLDP are covered by the SNMP plugin
- Switch-to-device links come only from traceroute/heuristics/manual
- IPv6 hosts are ignored
- No multi-user accounts
- Notifications are e-mail only (no webhooks, Telegram, ntfy, ...)
- No vulnerability scanning
- No embedded proxying of device web UIs
- VNC/RDP only as links
- Single container / single network host

## Development

Want to help? See [CONTRIBUTING.md](CONTRIBUTING.md) (setup, how to send a change, plugins), the [Code of Conduct](CODE_OF_CONDUCT.md) and the [security policy](SECURITY.md) for private vulnerability reports.

```bash
python3 -m venv .venv
pip install -r requirements-dev.txt
python -m pytest
```

- About 600 tests (including a static check of the browser modules), no real network or nmap needed
- nmap output tested against XML fixtures in `tests/fixtures`

Run locally:

```bash
NETLENS_DATA_DIR=./data python -m app.main   # open http://localhost:8080 and create your account (or set NETLENS_TOKEN=dev to skip the wizard)
```

> nmap must be installed for real scans.

### Project layout

```
app/scanner      nmap runner, parsing, scheduling, relations
app/notify       notification channels (e-mail/SMTP, ntfy, Telegram, ...), quiet hours
app/plugins      plugin system: manifest and output contract, runner, registry, service; builtin/ has the Proxmox and ASUS plugins; PLUGINS.md is the plugin guide
app/terminal     SSH/Telnet backends
app/api          REST API routers
app/uptime.py    uptime history, app/backup.py  backup and restore
app/forecast.py  when will a disk be full (growth trend) and the alert for it
app/reports.py   weekly summary and monthly availability report
app/probe_config.py  checks and monitors that the central Netlens sets up at a remote site
app/tsdb.py      metrics store (metrics.db): raw, 5-minute and hourly tiers behind the performance graphs
app/hostmetrics  health readings: SNMP client, SSH collector, monitors, limits and alerts
app/probes.py    remote sites (central side), app/central.py  reporting to a central Netlens (remote side)
app/rootcause.py groups alerts by the offline device that causes them
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
  | `PermissionError: [Errno 13] Permission denied: '/data...'` | The data directory is not writable by the container user. Only happens with your own data folder: run `sudo chown 10001:10001 <that folder>` |
  | `Is a directory` / the page asks for a token you never set | Old files: the token is optional now. Use `docker-compose.simple.yml`, or leave `NETLENS_TOKEN` empty to get the first-start wizard |
  | `NETLENS_RANGES contains non-scannable range` | Use private ranges only, no larger than /20 |
  | `NETLENS_BIND must be in format host:port` | Fix the value, e.g. `0.0.0.0:8080` |
  | `address already in use` | Another service on the host already uses port 8080 (the container uses host networking). Change `NETLENS_BIND` |

  If `docker compose up` itself refuses to start, the message names the missing variable (none of the shipped compose files require one). Run `docker compose config` to see the final configuration with all variables filled in.
- **Proxmox sync fails:** the message on the plugin's settings page says why. `the TLS certificate could not be verified`: untick *Verify TLS certificate* (Proxmox's default certificate is self-signed). `authentication failed`: check the token ID (`user@realm!tokenname`), the secret, or the password. `permission denied (... PVEAuditor)`: give the token or user the PVEAuditor role on `/`. `cannot connect`: wrong URL/port or a firewall.
- **No notification mails:** use **Send test** on the e-mail channel first. Check that the channel is switched on and has the events you expect, that the device has not opted out, and the status line next to the channel for the last problem. Gmail and most providers need an app password, not your normal password.
- **A guest does not show under its Proxmox host:** the connector matches by MAC address, so Netlens must have scanned that guest at least once on the same network. Run a scan and press *Sync now*.
- **Health monitoring says "cannot be read":** the message on the device's Health monitoring card says why. SNMP: the device does not answer, so check that SNMP is switched on, the community string (many devices use `public`), that the device's access list allows this host, and the port (161). SSH: `the login was refused` means a wrong user name, password or key; `cannot connect` means the port is closed or a firewall is in the way. *Test* in the form shows what the device answers before you save. Windows needs the SNMP feature installed and a community set on it.
- **A remote site shows "Not heard from":** the remote Netlens has stopped reporting. Open its Settings → Report to a central Netlens: the status line says what went wrong (`cannot reach the central Netlens` is a network or address problem, `refused the token` means the token was replaced or the site removed). The remote Netlens only needs to be able to open an outgoing connection to the central one.
- **No devices found:** Check ranges, host networking, and that nmap has capabilities. Check `docker logs netlens`; scan errors appear under "Scans & events".
- **OS detection empty:** Needs deep scan and root-capable nmap.
- **Terminal button missing:** Port 22/23 not seen open yet, `NETLENS_TERMINAL=off`, or you opened Netlens through a reverse proxy (see *Web terminal*).

## License

Netlens is free for **noncommercial use** under the [PolyForm Noncommercial License 1.0.0](LICENSE): you may run it at home, for
a hobby, for study or research, in a school or charity, change it and share it, as long as it is not for commercial purposes.
It is source-available, not "open source" in the OSI sense.

**Commercial use needs a commercial license.** That includes using it in a business, selling it, bundling it in a product, and
offering it as a paid or hosted service. To get one, send a private message through the maintainers' form (only they can see it):
**Security → Report a vulnerability** at <https://github.com/Gatlarf/netlens/security/advisories/new>, start with "Commercial
license" in the first line, and say who you are and what you want to use Netlens for. Exceptions are possible, for example for the
workplace of someone who helps with the project.

Versions **0.3.142 and earlier** were published under the MIT License and stay available under it
([text](licenses/LICENSE-MIT-until-0.3.142.txt), and the git tag `mit-final`); the new license applies from 0.3.143. The
plugins in the plugin index are separate works with their own licenses (the index shows each one). Third-party components keep
their own licenses, see below.

## Support

Netlens is free for noncommercial use and is made in spare time. If it saved you some work, you can
[buy me a coffee](https://buymeacoffee.com/Gatlarf). It is a thank-you, not a license: commercial use still needs the license above.

## Third-party

- **vis-network** 9.1.9 (MIT) — vendored under `app/static/vendor`
- **xterm.js** 5.5.0 with addon-fit 0.10.0 (MIT) — vendored under `app/static/vendor`
- **guacamole-common-js** 1.5.0 (Apache License 2.0, the browser client of Apache Guacamole) — vendored under `app/static/vendor`, licence text in `licenses/`; the optional **guacd** helper is a separate container image from the Apache Guacamole project (Apache License 2.0), not part of Netlens
- **Python deps:** FastAPI, uvicorn, asyncssh, zeroconf
- **nmap** is required and installed in the image