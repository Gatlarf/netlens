# Netlens plugin: Rockstor

Shows a **Rockstor** NAS (version 5 and newer) as a host in Netlens, with the Docker containers of its installed **Rock-ons** as guests:

- one guest per container, with the Rock-on's name and version, its state (started or stopped), and the ports it publishes (the host's *Open ports* table names the container behind a port).
- Rock-ons that are only *available* (not installed) are ignored.
- The NAS itself is matched by its IP address and MAC address, so its device page gets a *Virtualization* box listing everything above.

It only reads, through Rockstor's REST API over HTTPS.

Combine it with **health monitoring** (SNMP on the NAS) for processor, memory, pools, traffic and temperatures.

## Set-up

1. In the Rockstor web page: *System → Users → Add a new user*: name `netlens` and a long random password. The plugin only reads.
2. In Netlens: *Settings → Integrations → Plugin store → Rockstor → Install*, open its page, enter the address (`https://192.168.0.30`), the user name and the password on a line (**+ Add server** for another NAS), leave *Verify TLS certificate* off while Rockstor uses its self-signed certificate, **Test connection**, **Save**, **Turn on**, **Sync now**.

A refused login stops automatic syncing until you save the settings or press *Sync now* again.

## If something does not work

Press **Run diagnostic** on the plugin's page. It asks the NAS the plugin's questions once and shows which worked and the **names and types of the fields**, not their content; names, addresses and MAC addresses are removed. **Copy** or **Download** it and send it to whoever maintains the plugin.

## Storage page

Since version 1.1.0 (Netlens 0.4.180 or newer) the plugin also fills the **Storage** page with Btrfs pools with their fill level and health (a missing disk, an unmounted pool or exceeded redundancy is critical), the disks, and the shares. Events: *Storage problem*, *Storage recovered* and *Disk filling up* go through the usual notification channels. Nothing extra is needed on the NAS; the same user and the same read-only calls.

## What was tested

**Written from Rockstor's source code** (`rockstor-core`: the URL routes, models and serializers; HTTP Basic authentication is accepted by every API view) and tested against a **simulated Rockstor only**. Rockstor 5 is an openSUSE-based installer with no container image, so **nothing has been run against a real Rockstor yet**. Please send a diagnostic report when you try it. Things to watch: the paging of the lists (the plugin asks for 1000 per page), and whether a Rock-on's containers show up in the container list.

**Storage page:** Written from Rockstor's published REST serializers (`/api/pools`, `/api/disks`, `/api/shares`) and tested against a simulator only.


## Notes for reviewers

Standard library only. The password is sent in the `Authorization` header over the connection you configure (use https). The plugin talks only to the configured addresses.
