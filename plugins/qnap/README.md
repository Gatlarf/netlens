# Netlens plugin: QNAP

Shows a **QNAP** NAS (QTS 5 or QuTS hero with **Container Station 3**) as a host in Netlens, with its containers as guests:

- **Docker containers** with their image, state, compose project, the ports they publish, and the address of a container that has its own IP on your network.
- **LXD containers** of Container Station, as `lxc` guests.
- The NAS is shown under its host name (read from QTS when it answers), and matched by its IP address, so its device page gets a *Virtualization* box listing everything above.

It only reads. It signs in for a few seconds at each sync and signs out again.

Combine it with **health monitoring** (SNMP on the NAS: *Control Panel → Network & File Services → SNMP*) for processor, memory, volumes, traffic and temperatures.

## Set-up

Container Station has no read-only role, so give Netlens an account of its own and keep it small:

1. *Control Panel → Privilege → Users → Create*: name `netlens`, a long random password, member of the **administrators** group, and no shared folder access.
2. Do **not** switch on 2-step verification for this account (a program cannot answer it).
3. *Control Panel → Security → Security Level*: allow access only from the machine Netlens runs on.
4. In Netlens: *Settings → Integrations → Plugin store → QNAP → Install*, open its page, enter the QTS web address (`https://192.168.0.40:443`, or `http://192.168.0.40:8080`), the user name and the password on a line, leave *Verify TLS certificate* off while the NAS uses its self-signed certificate, **Test connection**, **Save**, **Turn on**, **Sync now**.

A refused login stops automatic syncing until you save the settings or press *Sync now* again.

## If something does not work

Press **Run diagnostic** on the plugin's page. It signs in once and shows which calls worked and the **names and types of the fields**, not their content; names, addresses and MAC addresses are removed. **Copy** or **Download** it and send it to whoever maintains the plugin.

## Storage page

Since version 1.1.0 (Netlens 0.4.180 or newer) the plugin also fills the **Storage** page with the volumes with their size and free space, and the disks with their S.M.A.R.T. health. Events: *Storage problem*, *Storage recovered* and *Disk filling up* go through the usual notification channels. Nothing extra is needed on the NAS; the same user and the same read-only calls.

## What was tested

**Written from QNAP's published QTS login documentation and the open-source `qnap-containerstation-mcp` client** (it uses `/container-station/api/v1/login`, `/container`, `/apps`) and tested against a **simulated QNAP only**. QNAP has no free image, so **nothing has been run against a real QNAP yet**. Container Station's container list is not documented: the shape of the published ports (`tcpPort`) and of `externalIP` is a best guess that accepts several forms, and the QTS system information (host name, model, firmware) is optional. A diagnostic report from a real NAS will show what to adjust. Virtual machines of *Virtualization Station* are not read (no documented API).

**Storage page:** The storage part reads QTS' XML tolerantly (volume and disk records are found by their field names), because the exact format differs between QTS versions and could not be checked on a real QNAP. If the Storage page stays empty, press **Run diagnostic** and send the report: it lists the XML tag names that were found.


## Notes for reviewers

Standard library only. The QTS login sends the password base64 encoded, as QNAP's documentation prescribes (this is encoding, not encryption: use https). The plugin talks only to the configured addresses.
