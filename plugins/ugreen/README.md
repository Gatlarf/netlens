# Netlens plugin: UGREEN

Shows a **UGREEN** NAS (UGOS or UGOS Pro) as a host in Netlens, with its **Docker containers** as guests: state, image and the ports they publish (the host's *Open ports* table names the container behind a port). The NAS is matched by its IP and MAC address, so its device page gets a *Virtualization* box.

It only reads. It signs in for a few seconds per sync.

> **UGREEN has no public API.** The plugin uses the web API that the UGOS web page itself uses (port 9443), as documented by the community (gitlab.com/K-22/nas-monitor-interface, `docs/API.md`; the login follows the Home Assistant integration `home-assistant_ugreen-nas`). A firmware update can change it; the plugin then tells you which part it could not read.

Combine it with **health monitoring** (SNMP on the NAS, where available) for processor, memory, volumes, traffic and temperatures.

## Set-up

1. In UGOS: *Control Panel → Users → Add*: name `netlens`, a long random password, administrator rights (the Docker list needs them), no shared folders, no 2-step verification.
2. In Netlens: *Settings → Integrations → Plugin store → UGREEN → Install*, open its page, enter the address with port 9443 (`https://192.168.0.50:9443`), the user name and the password on a line, leave *Verify TLS certificate* off while the NAS uses its self-signed certificate, **Test connection**, **Save**, **Turn on**, **Sync now**.

The password is encrypted with the NAS' own public key (RSA) before it is sent, as the UGOS web page does. UGOS **locks an account for about three minutes after wrong passwords**, so a refused login stops automatic syncing until you save the settings or press *Sync now* again.

## If something does not work

Press **Run diagnostic** on the plugin's page. It signs in once and shows which calls worked and the **names and types of the fields**, not their content; names, addresses and MAC addresses are removed. **Copy** or **Download** it and send it to whoever maintains the plugin.

## What was tested

**Written from the community's API notes** (confirmed there on a UGREEN DH4300 Plus, firmware 1.13.1.0105) and tested against a **simulated UGOS only**, including the RSA encryption (checked by decrypting with the matching private key). It has **not been run against a real UGREEN NAS**. The shape of the published ports in the container list is not documented, so several forms are accepted. Please send a diagnostic report when you try it.

## Notes for reviewers

Standard library only; the RSA public-key encryption (PKCS#1 v1.5, as the UGOS login requires) is implemented in the plugin. The plugin talks only to the configured addresses.
