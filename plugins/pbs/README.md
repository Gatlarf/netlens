# Netlens plugin: Proxmox Backup Server

A `backup` plugin (new in Netlens 0.4.x).

Shows what your **Proxmox Backup Server** holds. For every VM, container and host: the newest backup and its age, the number of copies, the size, whether the last backup worked (a failed backup leaves no snapshot, so the plugin reads the backup *tasks*) and whether it was verified. For every datastore: used and free space, the date the server expects it to be full, and the last result of its garbage collection, prune, verify and sync jobs. Recent failed or warning jobs are listed as problems.

Netlens ties each backup to the **guest** it belongs to (the backup id is the Proxmox VM id, and it is matched to the guest of your Proxmox plugin by type and id; the name saved with the backup tells two hypervisors with the same id apart). That gives you:

- a **Backups** page under *Monitoring*, a *Guest backups* card for the dashboard and a *Backup* card on each guest's device page;
- events when a backup **starts failing**, when a guest is **late** (older than 2.5 times its usual interval, or 36 hours when the interval is unknown) and when it is backed up again;
- a warning when a datastore is on course to fill up (30 days, and 3 days as critical);
- the list of **guests that have no backup at all**.

> **Status: tested against the real software in a lab** (Proxmox Backup Server 4.2 with one datastore, 11 backup groups and 113 snapshots from a Proxmox VE node; certificate pinning, a wrong token, a token without rights). Verification jobs, sync jobs and namespaces were not in the lab: they follow the API documentation and simulated answers. Please report what you see; *Run diagnostic* on the plugin's page makes an anonymised report (counts and field names only).

## Set-up

1. In Proxmox Backup Server: *Configuration → Access Control*. Add a user (for example `netlens@pbs`) and an **API token** for it (`netlens@pbs!netlens`); the secret is shown once.
2. *Permissions → Add*: give **both the user and the token** the role **Audit** on path `/` with *Propagate* ticked. A token can never have more rights than its user, so both are needed; without them the server answers empty lists.
3. In Netlens install **Proxmox Backup Server**, add a line with the address (`https://192.168.0.201:8007`), the token id, the secret and, for a self-signed certificate, the certificate **fingerprint** (*Dashboard → Show Fingerprint*). **Test**, enable.

## Good to know

- Netlens only sends GET requests. The Audit role cannot change anything.
- With a fingerprint, exactly that certificate is trusted (a self-signed one is fine); without it the normal certificate check applies.
- A backup of something that no longer exists in Proxmox (an old VM id) is kept in the list but never raises a *late* warning once it is more than two weeks old.
- The *Guests without a backup* list only appears once a backup plugin has reported data, and counts the virtual machines and containers of the hypervisor plugins that this backup server backs up at all (at least one of their guests has a backup). A Hyper-V or TrueNAS guest is not listed as unprotected just because Proxmox Backup Server never backs it up. Docker containers are never counted.
- A datastore that never ran a verify job is pointed out on the Backups page: backups that are never verified can be damaged without anyone noticing.
