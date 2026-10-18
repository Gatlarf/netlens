# Netlens plugin: Greenbone (OpenVAS)

A `vulnerability` plugin.

Shows what your **Greenbone / OpenVAS** scanner (the free Community Edition or the commercial one) found on the devices of your network: every finding with its severity, CVE numbers, score, the port and the advice of the scanner. Netlens ties each finding to a device by address and gives you:

- a **Vulnerabilities** page under *Analysis*, a *Vulnerabilities* card for the dashboard and a *Vulnerabilities* card on each device's page;
- an event (**New vulnerability**) when a critical vulnerability, or a high one that is known to be exploited, shows up on a device. What was already there when you connect the scanner is not announced;
- critical findings under *Needs attention* on the dashboard.

> **Status: being tested against the real software in a lab** (Greenbone Community Containers, gvmd with GMP 22.7 over TLS). The connection and login work; the reading of results is being checked against a real scan. *Run diagnostic* on the plugin's page makes an anonymised report (counts and field names only).

## Set-up

1. Greenbone's Community Containers only let gvmd listen on a Unix socket by default. Make it listen with TLS too: give the `gvmd` service `GVMD_ARGS: "-f --listen-mode=666 --listen=0.0.0.0 --port=9390"` and `GVM_CERTS: "true"` and publish port 9390 **to the machine that runs Netlens only** (the port has full GMP access for any user that can log in).
2. In Greenbone open *Administration → Users* and make a user for Netlens with the role **Observer** (it reads results and cannot change anything).
3. In Netlens install **Greenbone (OpenVAS)**, add a line with the address (`192.168.0.190:9390`), the user and the password and, because gvmd makes its own certificate, its **SHA-256 fingerprint**. **Test**, enable.

## Good to know

- Netlens only reads (`get_version`, `get_tasks`, `get_results`); it never starts or changes a scan.
- A finding's id is made from the host, the vulnerability test and the port, so the same finding keeps its id over many scans and "new" really means new. Where several scans saw the same finding, the newest counts.
- Results from a scan older than *Ignore findings older than* (30 days) are left out, so a fixed host that was not scanned again does not stay red for ever.
- *Minimum quality of detection* (70) is what Greenbone itself shows by default; lower values add guesses.
- Greenbone scores run from 0 to 10; Netlens shows 9 and up as critical, 7 and up as high, 4 and up as medium and above 0 as low.
