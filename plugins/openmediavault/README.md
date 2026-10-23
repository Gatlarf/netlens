# Netlens plugin: OpenMediaVault

Shows an **OpenMediaVault** NAS (version 6, 7 and 8) as a host in Netlens, with what runs on it as guests, like Proxmox and Synology:

- **Docker containers** from the *openmediavault-compose* plugin (OMV-Extras): state, health, image, the network and the ports they publish (the host's *Open ports* table names the container behind a port). Podman installs work the same way.
- **Virtual machines and LXC containers** from the *openmediavault-kvm* plugin, matched to the devices on your network by MAC address.
- The NAS itself is matched by its IP address and MAC address, so its device page gets a *Virtualization* box listing everything above.

It only reads. It signs in to OpenMediaVault's web interface API (`/rpc.php`) for a few seconds at each sync and signs out again.

Combine it with **health monitoring** (SNMP on the NAS: *Services → SNMP*) for processor, memory, file systems, traffic and temperatures.

## Set-up

1. In the OMV web page: *Users → Users → Create*: name `netlens`, a long random password, and under **Groups** tick **openmediavault-admin** (the web interface API only answers administrators; there is no read-only role). Do not switch on 2-step verification for this user.
2. In Netlens: *Settings → Integrations → Plugin store → OpenMediaVault → Install*, open its page, enter the address you open OMV with (`http://192.168.0.60`), the user name and the password on a line (**+ Add server** for another NAS), **Test connection**, **Save**, **Turn on**, **Sync now**.

A refused login stops automatic syncing until you save the settings or press *Sync now* again.

## If something does not work

Press **Run diagnostic** on the plugin's page. It signs in once and shows which calls worked and the **names and types of the fields**, not their content; names, addresses and MAC addresses are removed. **Copy** or **Download** it and send it to whoever maintains the plugin.

A NAS without the *compose* or *kvm* plugin is shown with what it has; the test message names what is missing.

## What was tested

Tested on a **real OpenMediaVault 8.5.12** (Debian 13) with the openmediavault-compose plugin 8.2.3: login (right and wrong password), system information, network cards, and the Docker container list (35 real containers, with the real port strings). The container list is read with OMV's own Docker view, so the plugin sees the same containers as the OMV web page.

**Not tested on a real system:** the *openmediavault-kvm* part (virtual machines, LXC and their MAC addresses) was written from that plugin's source code and tested against a simulator only; OpenMediaVault 6 and 7 use the same calls but were not run. A tester with KVM on OMV is welcome.

## Notes for reviewers

Standard library only. The password is sent in the JSON body of the login, never in a URL. The plugin talks only to the configured addresses.
