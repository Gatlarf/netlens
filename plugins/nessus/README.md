# Netlens plugin: Tenable Nessus

A `vulnerability` plugin.

Shows what your **Tenable Nessus** scanner (Nessus Professional, Expert or Essentials) found on the devices of your network: every finding with its severity, CVE numbers, score, whether it is known to be exploited (the CISA list) and the advice of the scanner. Netlens ties each finding to a device by MAC or address and gives you:

- a **Vulnerabilities** page under *Analysis*, a *Vulnerabilities* card for the dashboard and a *Vulnerabilities* card on each device's page;
- an event (**New vulnerability**) when a critical vulnerability, or a high one that is known to be exploited, shows up on a device. What was already there when you connect the scanner is not announced;
- critical findings under *Needs attention* on the dashboard.

> **Status: written from the Nessus API documentation, not yet tested against a real Nessus.** It was tested against a simulated server only. Please try it and use *Run diagnostic* on the plugin's page: it makes an anonymised report (counts and field names only, no addresses, names or CVE numbers) that helps to correct what a real Nessus does differently.

## Set-up

1. In Nessus open your user (top right) → *My Account* → *API Keys* → *Generate*. Copy the access key and the secret key (the secret is shown once). The keys act as that user, so use a user that can see the scans.
2. In Netlens install **Tenable Nessus**, add a line with the address (`https://192.168.0.50:8834`), the two keys and, because Nessus uses a self-signed certificate, the certificate **fingerprint** (SHA-256, from the certificate details in your browser). **Test**, enable.

## Good to know

- Netlens only sends GET requests and never starts a scan. It reads the **completed** scans; per host and per vulnerability the newest scan counts. Scans that ended longer ago than *Ignore scans older than* (30 days) are left out.
- The scan lists a vulnerability by name and severity. CVE numbers, the score, *known to be exploited* and the solution need one extra request per vulnerability; the most serious are looked up first, up to *Looks at the details of this many vulnerabilities* (300).
- The port is not shown: Nessus gives it per plugin output, which would mean a request per finding and host.
- Nessus only has info, low, medium, high and critical. Info is never reported.
- Not covered: Tenable Vulnerability Management (the cloud service, a different API).
