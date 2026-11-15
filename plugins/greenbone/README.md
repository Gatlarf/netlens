# Netlens plugin: Greenbone (OpenVAS)

A `vulnerability` plugin.

Shows what your **Greenbone / OpenVAS** scanner (the free Community Edition or the commercial one) found on the devices of your network: every finding with its severity, CVE numbers, score, the port and the advice of the scanner. Netlens ties each finding to a device by address and gives you:

- a **Vulnerabilities** page under *Analysis*, a *Vulnerabilities* card for the dashboard and a *Vulnerabilities* card on each device's page;
- an event (**New vulnerability**) when a critical vulnerability, or a high one that is known to be exploited, shows up on a device. What was already there when you connect the scanner is not announced;
- critical findings under *Needs attention* on the dashboard.

> **Status: tested against the real software in a lab** (Greenbone Community Containers 22.7, gvmd with a TLS listener, a "Full and fast" scan of one host: 5 real findings read correctly, with severity, score, port, solution and time). Not seen in that scan: results with CVE references (they follow the protocol documentation), several tasks scanning the same host, and very large result sets (paging is tested against a fake server). *Run diagnostic* on the plugin's page makes an anonymised report (counts and field names only).

## Set-up

1. Leave Greenbone's own configuration as it is. Its containers talk over a unix socket (that is what the web interface uses), and gvmd cannot listen on that socket and on the network at the same time. Instead add one small container that passes the socket on to port 9390 with TLS: download [`contrib/greenbone/docker-compose.netlens.yml`](https://github.com/Gatlarf/netlens/blob/main/contrib/greenbone/docker-compose.netlens.yml) next to Greenbone's `docker-compose.yml` and start both: `docker compose -f docker-compose.yml -f docker-compose.netlens.yml up -d` (add `-p <name>` if you started Greenbone with a project name). The port is published to that machine only; if Netlens runs elsewhere set `NETLENS_GMP_BIND` to the machine's address and firewall the port to Netlens (the port has full GMP access for any user that can log in).
2. In Greenbone open *Administration → Users* and make a user for Netlens with the role **Observer** (it reads results and cannot change anything).
3. A user only sees the tasks of other users when they are shared with it. In every task (*Scans → Tasks → Edit task*) put the Netlens user under **Observers** (or create the task with it as observer). Without this Netlens connects fine but sees no results, and the plugin's test says so.
4. In Netlens install **Greenbone (OpenVAS)**, add a line with the address (`192.168.0.190:9390`), the user and the password and the **SHA-256 fingerprint** of the certificate (the bridge makes its own and prints the fingerprint in its log: `docker compose -f docker-compose.yml -f docker-compose.netlens.yml logs netlens-gmp`). **Test**, enable.

## Good to know

- Netlens only reads (`get_version`, `get_tasks`, `get_results`); it never starts or changes a scan.
- A finding's id is made from the host, the vulnerability test and the port, so the same finding keeps its id over many scans and "new" really means new. Where several scans saw the same finding, the newest counts.
- Results from a scan older than *Ignore findings older than* (30 days) are left out, so a fixed host that was not scanned again does not stay red for ever.
- *Minimum quality of detection* (70) is what Greenbone itself shows by default; lower values add guesses.
- Greenbone scores run from 0 to 10; Netlens shows 9 and up as critical, 7 and up as high, 4 and up as medium and above 0 as low.
