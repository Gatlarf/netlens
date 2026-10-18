# Netlens plugin: Rapid7 InsightVM

A `vulnerability` plugin.

Shows what your **Rapid7 InsightVM** (Nexpose) security console found on the devices of your network: every vulnerability with its severity, CVE numbers, score, whether exploits exist, the port and the solution. Netlens ties each finding to a device by MAC or address and gives you:

- a **Vulnerabilities** page under *Analysis*, a *Vulnerabilities* card for the dashboard and a *Vulnerabilities* card on each device's page;
- an event (**New vulnerability**) when a critical vulnerability, or a high one that is known to be exploited, shows up on a device. What was already there when you connect the console is not announced;
- critical findings under *Needs attention* on the dashboard.

> **Status: written from the InsightVM API v3 documentation, not yet tested against a real console.** It was tested against a simulated server only. Please try it and use *Run diagnostic* on the plugin's page: it makes an anonymised report (counts and field names only, no addresses, names or CVE numbers) that helps to correct what a real console does differently.

## Set-up

1. In the console (port 3780) open *Administration → Users → Manage → Create*. Give the user a role that can read assets and vulnerabilities (a limited *Security Manager*, or a custom role with only *View Site Asset Data*) and a password.
2. In Netlens install **Rapid7 InsightVM**, add a line with the console address (`https://192.168.0.60:3780`), the user, the password and, because the console uses a self-signed certificate, its **fingerprint**. **Test**, enable.

## Good to know

- Netlens only sends GET requests and never starts a scan. Assets that were not assessed for longer than *Ignore assets not scanned for* (30 days) are left out.
- The console has Critical, Severe and Moderate; Netlens shows them as critical, high and medium. A vulnerability is *known to be exploited* when the console knows exploits or malware kits for it.
- Title, severity, CVE numbers and the solution need extra requests, once per vulnerability, the most widespread first (up to *Looks at the details of this many vulnerabilities*, 300).
- Not covered: the cloud *Insight Platform* (a different API).
