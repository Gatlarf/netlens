# Netlens plugin: Ceph

Shows a **Ceph** cluster on the **Storage** page and on the device pages. It talks to the Ceph Manager's dashboard REST API, so the *dashboard* module must be enabled (cephadm does that by default). It works with cephadm, Rook, Proxmox VE's Ceph and MicroCeph.

- the cluster **health** (`HEALTH_OK`, `HEALTH_WARN`, `HEALTH_ERR`) and every health check as an alert (muted checks are left out);
- the **hosts** and **monitors**, matched to the devices Netlens found by IP address;
- the **raw capacity** and every **pool** with its fill level (events at 85 and 95 percent), replica count or erasure coding;
- every **OSD** as a disk: *down* or *out* OSDs raise a *Storage problem* event;
- **CephFS** file systems with the hosts that mounted them (linked to their devices) and **RBD** images with their size.

Events (*Storage problem*, *Storage recovered*, *Disk filling up*) go through the usual notification channels.

## Set-up

1. Create a read-only dashboard user on a node with the admin keyring: `echo -n 'a-long-random-password' > /tmp/pw && ceph dashboard ac-user-create netlens -i /tmp/pw read-only && rm /tmp/pw`.
2. In Netlens: *Settings → Integrations → Plugin store → Ceph → Install*, open its page, enter the dashboard address with its port (`https://192.168.0.90:8443`), the user name and password (**+ Add server** for another cluster), **Test connection**, **Save**, **Turn on**, **Sync now**.

A refused login stops automatic syncing until you save the settings or press *Sync now* again. A standby manager redirects to the active one; enter the address of the active manager (or a load balancer in front of the dashboards).

## If something does not work

Press **Run diagnostic**: it shows which API calls worked and the **names and types of the fields**, not their content (cluster ids, names and addresses are removed). Send it to whoever maintains the plugin. A part the cluster does not offer (for example CephFS) is skipped and named in the test message.

## What was tested

Run against a **real Ceph 19.2.7 (squid) cluster** installed with cephadm: login (right password, wrong password, a read-only user), health with real checks, hosts, monitors, three OSDs on loop devices, pools (replicated, RBD and CephFS), a CephFS file system, an RBD image, and the diagnostic. **Not tested on a real cluster:** CephFS clients that really mounted a file system (covered by a unit test built from the real API shape), erasure-coded pools, multi-host clusters, Rook and Proxmox VE.

## Notes for reviewers

Standard library only. The password is sent only in the JSON body of the login to the configured address, never in a URL; the plugin logs out again at the end. Everything but the login is a GET.
