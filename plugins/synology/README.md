# Netlens plugin: Synology

Shows a **Synology NAS** (DiskStation Manager, DSM 7; 6.2 should work too) as a host in Netlens, with what runs on it as guests, like Proxmox and TrueNAS:

- **Containers** of *Container Manager* (Docker on DSM 6), with their image and the ports they publish (the host's *Open ports* table names the container behind a port).
- **Virtual machines** of *Virtual Machine Manager*, matched to the devices on your network by MAC address.
- **Packages** that are installed (Container Manager, Synology Drive and so on) and whether they run.
- The NAS itself is matched by its IP address (and MAC address), so its device page gets a *Virtualization* box listing everything above.

It only reads. It signs in to the **DSM web API** (`https://<nas>:5001`) for a few seconds at each sync and signs out again.

Combine it with **health monitoring** (SNMP on the NAS: Control Panel → Terminal & SNMP) for processor, memory, volumes, traffic and temperatures.

## Set-up

DSM has no read-only role for its web API: the container, virtual machine and package lists need an **administrator**. So give Netlens an account of its own and keep it small:

1. *Control Panel → User & Group → Create*: name `netlens`, a long random password, member of the **administrators** group, and under **Applications** allow **DSM** only (deny File Station, FTP, SMB, and so on).
2. *Control Panel → Security → Firewall*: allow TCP port **5001** only from the machine Netlens runs on.
3. Do **not** switch on two-step verification for this account (a program cannot answer it; the plugin says so when it meets it).
4. In Netlens: *Settings → Integrations → Browse plugins → Synology → Install*, open its page, enter the address (`https://192.168.0.20:5001`), the user name and the password on a line (**+ Add server** for another NAS, **Test** on a line tests that NAS), leave *Verify TLS certificate* off while the NAS uses its self-signed certificate.
5. **Test connection**, **Save**, **Turn on**, **Sync now**.

A refused login stops automatic syncing until you save the settings or press *Sync now* again, so DSM's auto-block does not lock the account out.

## If something does not work

Press **Run diagnostic** on the plugin's page. It signs in once with the values in the form and shows a report of what DSM answered: which APIs exist and which steps worked (DSM info, network, containers, virtual machines, packages), and the **names and types of the fields**, not their content. Names, addresses and MAC addresses are removed. **Copy** or **Download** it and send it to whoever maintains the plugin.

## What was tested

Written from the public DSM web API and tested against a **simulated DSM** only (login, errors, missing features, two systems). It has not yet run on a real Synology: the field names of the Container Manager and Virtual Machine Manager lists are the likeliest to differ between DSM versions, which is what the diagnostic is for. A tester with a **DS923+** is welcome.

## Notes for reviewers

Standard library only. The password is sent in a POST body, never in a URL. The plugin talks only to the configured addresses.
