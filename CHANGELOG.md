# Changelog

The version is `<major.minor from VERSION>.<commit count>`; the list below groups changes by minor version.

## 0.2

### Added
- **Uptime history** (Uptime Kuma style): heartbeat bar per device, 24 h / 7 d / 30 d uptime, response times, an Uptime overview page, and an uptime card on every device page. Kept for 90 days.
- **E-mail notifications** for new and offline devices (one digest per scan), SMTP settings and a test button in Settings, and a per-device switch for offline mails.
- **Proxmox connector**: read-only sync of VMs and containers, matching to devices by MAC/IP, exact `host-of` links on the map, and Proxmox details on the device pages. API token or password login.
- **Backup and restore** of the whole database from Settings.
- **Live scan progress** (current nmap step, percentage, hosts found) with elapsed time and the typical (median) duration of recent scans of the same type, shown in a strip under the header while a scan runs.
- **Scan performance settings** (Settings → Scan performance): nmap timing, number of top ports or a custom port list for quick and deep scans, version detection (full/light/off), OS detection, traceroute, reverse DNS and a per-host timeout, with Default/Fast/Fastest presets, the resulting command lines and the duration of the last scans. A **Scan settings** button next to the scan buttons opens it.
- **Settings menu**: a sticky index on the left of the Settings page links to every section and follows your scrolling; sections can be deep-linked (`#/settings/proxmox`).
- **Settings in the browser** for scan ranges, quick/deep scan interval and the web terminal switch (no restart needed).
- Friendly scan error messages (missing capabilities, nmap missing, timeout, no ranges).
- Version shown in the UI and API; the version rises with every build. LICENSE (MIT).
- CI runs the test suite before the Docker image is published.
- Static test that every browser module only imports helpers that exist and are imported.

### Changed
- Static files are served with `Cache-Control: no-cache` so an update is picked up immediately.
- The web terminal is switched on and off at runtime instead of at startup.
- Database schema version 2 (migrates automatically; existing data is kept).

### Fixed
- Device page: duplicated content, repeated "Failed to load device" toasts and a false "Save failed" message.
- Map: error on open/refresh, filters that never worked, and the empty details panel after clicking a device.
- nmap capability mismatch that stopped scans from starting in the container.

## 0.1
First release: scanning, device inventory, classification, network map, web terminal, Docker image.
