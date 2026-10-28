# Netlens plugin: Xen Orchestra backup

A `backup` plugin. It shows what **Xen Orchestra** (Vates VMS) backs up, next to the VMs of the [XCP-ng / XenServer plugin](../xcpng/README.md). Read-only.

For every backed-up VM: the newest backup and its age, the copies kept, the size, and whether the last run worked. For every backup repository: size and free space. Failed runs of the last 7 days are listed as problems. Netlens ties each backup to its VM by the VM's UUID, warns when a backup fails or is late (it knows the usual interval from the job's schedule), predicts a full repository, and lists VMs that have no backup at all (Backups page).

## Set-up

Use the same read-only Xen Orchestra user as for the hypervisor plugin: the built-in role **Read only** also reads the backup jobs, repositories and logs. (Tested.) Enter the address of XO and the login or an authentication token. For a self-signed certificate use the fingerprint.

A pool master has no backups to read: this plugin needs a Xen Orchestra.

## How it reads

- `backup-repositories`, `schedules` and `backup-logs` of the REST API, and for each VM (up to 500) its backup overview (`vms/<id>/dashboard`: runs, archives, protection).
- The interval of a VM is the shortest of the schedules of the jobs that back it up (cron, estimated).
- Only VMs that have an archive or a run are reported as backed up.
- Metadata and mirror jobs are not reported yet.

## Security

The address must be `https://`: a login over plain `http://` would cross the network unencrypted, so it is refused unless you switch on *Allow plain http* (for a lab). A certificate fingerprint pins exactly one certificate. Netlens only reads; nothing is written to the Xen side except the power actions you allow.

## What was tested

Xen Orchestra 6 (REST API 0.41, community Docker image) with a local backup repository, a nightly job, a failed run (a wrongly configured job) and a good run of a VM, also as the read-only user. Not tested: remote repositories (NFS, S3, SMB), replication and mirror jobs, delta backups, large installations.
