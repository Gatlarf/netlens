# Netlens plugin: Pi-hole

A `dns` plugin.

Registers your devices in Pi-hole's **Local DNS records** (an A record for every device Netlens knows and DNS does not, a CNAME for a container alias, a changed address when a device's IP changes). Pi-hole answers the reverse (PTR) lookup for a Local DNS record by itself, so Netlens writes no reverse records.

> **Status: tested against the real software in a lab** (Pi-hole v6.4.3 (Docker), adding, changing and removing records, a wrong password, and the Pi-hole web server restarting after a settings change.) Please report what you see; *Run diagnostic* on the plugin's page makes an anonymised report (counts and field names, never names or addresses).

## Set-up

1. In Pi-hole: *Settings → Web interface / API → Configure app password*. Use that app password, not the admin password (it also works when two-factor login is on).
2. In Netlens install **Pi-hole**, add a line with the Pi-hole address (`http://192.168.0.2`) and the app password, **Test**, enable.
3. In *Settings → Integrations → DNS registration* enter your network and zone (`192.168.0.0/24 = home.lan`), read the server and approve what you want.

## Good to know

- Pi-hole has no zones: the zone names you give Netlens are reported as writable zones, and a record belongs to the zone its name ends in.
- Pi-hole has no comment field, so Netlens cannot mark its records in Pi-hole. It remembers which records it wrote and only ever changes or removes those; a record you typed in Pi-hole yourself is left alone.
- After a change Pi-hole restarts its web server for a moment; reads are repeated, writes never are.
- Two Pi-holes kept in sync by Gravity Sync or Orbital Sync: list only the one you write to (listing both makes Netlens write the same record twice, which Pi-hole refuses as 'already present').
