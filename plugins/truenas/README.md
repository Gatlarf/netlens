# Netlens plugin: TrueNAS

Shows a **TrueNAS** (Community Edition, **25.04 or newer**) as a host in Netlens, with what runs on it as guests, like Proxmox:

- **Containers and virtual machines** of the *Instances / Containers* feature (and classic **VMs**), matched to the devices on your network by IP or MAC address.
  A container with its own IP address on your LAN gets a link to the TrueNAS box on the map and in the hierarchy.
- **Apps** (the Docker apps of TrueNAS) are listed on the host's device page with their version, whether an **update is available**, their image and the **ports they publish** (the host's *Open ports* table names the app behind a port). They use the TrueNAS address, so they do not become devices of their own.
- **Resources** (CPU, memory) and whether it starts at boot are shown for virtual machines and containers. A stopped guest, a started guest and a new app update are events your notification channels can send.
- The TrueNAS box itself is matched by its IP address, so its device page gets a *Virtualization* box listing everything above.

It only reads. It uses the TrueNAS **JSON-RPC WebSocket API** (`wss://<truenas>/api/current`), the supported API of 25.04 and newer (the old REST API is being retired).

## Set-up

1. In TrueNAS create a user for Netlens, for example `netlens`, with a **read-only role** (for example *Readonly Admin*), no shell and no password login.
2. Open that user's menu (top right) → **API Keys → Add**, and copy the key. (TrueNAS shows it only once.)
3. In Netlens: *Settings → Integrations → Browse plugins → TrueNAS → Install* (community plugins ask for an extra confirmation), open its page under *Integrations*,
   enter the address (`https://192.168.0.200`) and paste the key on a line (**+ Add server** for another TrueNAS, **Test** on a line tests that system), leave *Verify TLS certificate* off while TrueNAS uses its self-signed certificate.
4. **Test connection**, **Save**, **Turn on**, **Sync now**.

**Always use https.** TrueNAS **revokes an API key that is used over an unencrypted connection**. The plugin therefore refuses plain connections: an `http://` address is changed to
`https://` on port 443, and the key is only ever sent over TLS.

A refused login (wrong, revoked or expired key) stops automatic syncing until you save the settings or press *Sync now* again.

## If something does not work

Press **Run diagnostic** on the plugin's page (Netlens 0.2.67 or newer, plugin 1.0.1 or newer). It logs in once with the values in the form and shows a report of what TrueNAS answered: which steps worked
(system, interfaces, containers, virtual machines, apps) and the **names and types of the fields**, not their content. Names, addresses, MAC addresses and your settings are removed. **Copy** or **Download** it and send it to whoever maintains the plugin.

## What was tested

Written against and tested on a real **TrueNAS 25.10.6** (a LXC container under *Instances/Containers*, one app) and against a simulated TrueNAS (WebSocket frames, pings, large messages, an old version
without containers, a failing Apps service, a revoked key). **Virtual machines** were tested with simulated data only: if you run VMs, please check that they show up with the right MAC address and
tell us if not. Network cards of a VM only get a MAC address when TrueNAS has assigned one.

## Notes for reviewers

Standard library only. The WebSocket client in `plugin.py` is about 80 lines (RFC 6455: handshake with the `Sec-WebSocket-Accept` check, masked frames, ping/pong, fragmented messages); the static scan
reports a note for `base64`, which is used for the handshake only. The plugin talks only to the configured address.
