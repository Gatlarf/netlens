# Changelog

The version is `<major.minor from VERSION>.<commit count>`; the list below groups changes by minor version.

## 0.2

### Added
- **Uptime history** (Uptime Kuma style): heartbeat bar per device, 24 h / 7 d / 30 d uptime, response times, an Uptime overview page, and an uptime card on every device page. Kept for 90 days.
- **E-mail notifications** for new and offline devices (one digest per scan), SMTP settings and a test button in Settings, and a per-device switch for offline mails.
- **Proxmox connector**: read-only sync of VMs and containers, matching to devices by MAC/IP, exact `host-of` links on the map, and Proxmox details on the device pages. API token or password login.
- **Plugins**: the Proxmox and ASUS connectors are now plugins of two kinds (`hypervisor`, `topology`) that only fetch data in a fixed, validated format; Netlens does the matching and linking. Each plugin can be turned on or off, has a settings page generated from its `plugin.json`, runs in its own isolated process with a time limit, and a failing or invalid plugin keeps its last good links without disturbing the others. **Upload your own plugins** (zip) under Settings → Plugins; the plugin guide (`app/plugins/PLUGINS.md`, also in the app) documents the package and the exact output, and an example plugin can be downloaded. API: `/api/plugins` (replaces `/api/proxmox` and `/api/asus`). Database schema version 5 migrates the old settings, guests and links automatically; the hierarchy source `proxmox` is now `hypervisor`, and the device page's Proxmox box is *Virtualization*.
- **Settings pages**: every entry of the Settings menu is its own page with its own address, grouped under General / Notifications / Integrations / Data / System (the long single page and its scroll-spy are gone; the old `#/settings/proxmox` and `#/settings/asus` addresses still work).
- **ASUS router / AiMesh connector** (Settings → ASUS router): reads which device is connected to which mesh node and adds `uplink` links, so the hierarchy and the map show the real network position of every wired and Wi-Fi client (and the mesh nodes below the main router). Read-only, over the router's HTTPS web interface: one login, two reads and a logout per sync, never SSH, so no sessions stay open on the router. A refused login pauses automatic syncing so the router does not lock the account.
- **Horizontal map layout** (Omada style): left-to-right columns, a card per device with its name and address, right-angle parent links, and busy branches folded into `▸ N more` (double-click or the details panel to open them, plus Collapse clients / Expand all / Fit). **Settings → Map** chooses the layout the map opens with (`GET/PUT /api/map-settings`); a layout picked in the map itself is remembered per browser and wins.
- **Backup and restore** of the whole database from Settings.
- **Live scan progress** (current nmap step, percentage, hosts found) with elapsed time and the typical (median) duration of recent scans of the same type, shown in a strip under the header while a scan runs.
- **Scan performance settings** (Settings → Scan performance): nmap timing, number of top ports or a custom port list for quick and deep scans, version detection (full/light/off), OS detection, traceroute, reverse DNS and a per-host timeout, with Default/Fast/Fastest presets, the resulting command lines and the duration of the last scans. A **Scan settings** button next to the scan buttons opens it.
- **Dark / light mode** switch at the right of the top bar (remembered per browser, follows the system until you choose); the map canvas follows the theme. Dark mode was tuned for legibility and is verified by measured contrast: links use one themed blue, every text meets 4.5:1, map device colours and link colours meet 3:1 against the canvas, map labels have a halo, offline devices have a dashed outline, and the map legend shows the real colour and line style of each link type.
- **Delete a device** from its page, optionally ignoring it in future scans; **Settings → Ignored devices** lists them and lets you undo. Database schema version 4.
- **Full scan of a single host** (all TCP ports, versions, OS, traceroute) from the device page, with progress, cancel and a `full <ip>` entry in the scan history.
- **Network hierarchy**: every device gets a parent (manual choice, Proxmox host, traceroute, default gateway), shown on a new **Hierarchy** page, as a *Hierarchy links* view and *Tree layout* on the map (Proxmox guests now hang under their host), and editable per device under **Network position**. Loops are impossible. API: `GET /api/hierarchy`, `parent_mode`/`parent_device_id` on devices. Database schema version 3 (migrates automatically).
- **Host timeouts** for scans (default 120 s for quick and 900 s for deep scans, editable under Scan performance): nmap gives up on a host that takes too long, so one slow device can no longer hold a scan up for an hour. A timed-out host stays online, keeps its known ports, and logs a "Host timeout" event.
- **Cancel scan** button in the scan strip (and `POST /api/scans/cancel`): kills nmap, marks the scan `cancelled`, saves nothing.
- **Settings menu**: a sticky index on the left of the Settings page links to every section and follows your scrolling; sections can be deep-linked (`#/settings/proxmox`).
- **Settings in the browser** for scan ranges, quick/deep scan interval and the web terminal switch (no restart needed).
- Friendly scan error messages (missing capabilities, nmap missing, timeout, no ranges).
- Version shown in the UI and API; the version rises with every build. LICENSE (MIT).
- CI runs the test suite before the Docker image is published.
- Static test that every browser module only imports helpers that exist and are imported.

### Changed
- Scan options: the single host timeout became separate quick and deep timeouts (settings saved by earlier builds still load).
- Static files are served with `Cache-Control: no-cache` so an update is picked up immediately.
- The web terminal is switched on and off at runtime instead of at startup.
- Database schema version 2 (migrates automatically; existing data is kept).

### Fixed
- Settings menu and deep links: a section scrolled to the top is no longer hidden behind the sticky top bar (also on narrow screens, where the bar wraps).
- Dragging a node on the map now opens its details panel.
- Device page: duplicated content, repeated "Failed to load device" toasts and a false "Save failed" message.
- Map: error on open/refresh, filters that never worked, and the empty details panel after clicking a device.
- nmap capability mismatch that stopped scans from starting in the container.

## 0.1
First release: scanning, device inventory, classification, network map, web terminal, Docker image.
