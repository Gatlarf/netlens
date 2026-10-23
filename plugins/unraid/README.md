# Netlens plugin: Unraid

Shows an **Unraid** server as a host in Netlens, with what runs on it as guests, like Proxmox and TrueNAS:

- **Docker containers** with their image, state, autostart setting, the ports they publish, and (when a container has its own IP address on your network, for example on `br0`) its MAC and IP, so it is matched to the device Netlens found.
- **Virtual machines** (libvirt) with their state.
- The server itself is matched by its IP address and MAC address, so its device page gets a *Virtualization* box listing everything above.

It only reads, through the **Unraid API** (GraphQL). The API is built into **Unraid 7.2 and newer**; on 7.0 and 7.1 it comes with the *Unraid Connect* plugin.

Combine it with **health monitoring** (SNMP on the server) for processor, memory, array, traffic and temperatures.

## Set-up

1. In Unraid: *Settings → Management Access → API Keys → Create key*: name `netlens`, role **Viewer** (read only). Copy the key. (On the console: `unraid-api apikey --create --name netlens --roles VIEWER`.)
2. In Netlens: *Settings → Integrations → Plugin store → Unraid → Install*, open its page, enter the address (`http://tower` or `https://192.168.0.10`) and the key on a line (**+ Add server** for another server), **Test connection**, **Save**, **Turn on**, **Sync now**.

The key travels in a request header only. If your server redirects http to https the plugin follows that. A refused key stops automatic syncing until you save the settings or press *Sync now* again.

## If something does not work

Press **Run diagnostic** on the plugin's page. It asks the server the plugin's questions once and shows which worked and the **names and types of the fields**, not their content; names, addresses and MAC addresses are removed. **Copy** or **Download** it and send it to whoever maintains the plugin. The plugin tries the current query names and the older ones (`dockerContainers`), and names what the server could not answer.

## What was tested

**Written from the published GraphQL schema** (`unraid/api`, `generated-schema.graphql`) and tested against a **simulated Unraid API only**. Unraid has no free image to run in a lab, so **nothing has been run against a real Unraid server yet**. Please send a diagnostic report when you try it. Things to watch: whether `networkSettings` carries MAC addresses for containers on `br0`, and whether virtual machines can be matched (the API gives them no MAC address, so they are listed under the server but matched by name only).

## Notes for reviewers

Standard library only. The plugin talks only to the configured addresses.
