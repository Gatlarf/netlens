# Netlens plugin: BIND 9

A `dns` plugin.

Registers your devices in a **BIND 9** (or any RFC 2136 compatible) DNS server: an A record and a reverse (PTR) record for every device Netlens knows and DNS does not, and a changed address when a device's IP changes. Zones are read by zone transfer (AXFR), changes are written by dynamic update, both signed with a TSIG key. The plugin speaks the DNS protocol itself, so it needs nothing installed.

> **Status: tested in a lab** (BIND 9.20 (Docker): zone transfer and dynamic updates signed with an HMAC-SHA256 TSIG key, adding, changing and removing A, AAAA, CNAME and PTR records, a wrong key, an update that is refused.) Please report what you see; *Run diagnostic* on the plugin's page makes an anonymised report (counts and field names, never names or addresses).

## Set-up

1. Make a key (`tsig-keygen netlens-key`), add it to `named.conf`, and allow it to transfer and update your zones (`allow-transfer { key netlens-key; }; allow-update { key netlens-key; };`, see the box at the top of the plugin's page). The zones must be dynamic and BIND's directory writable. `rndc reload`.
2. In Netlens install **BIND 9**, add a line with the server address, the key name and the secret. Name the reverse zones in *Reverse zones* (DNS cannot list zones).
3. In *Settings → Integrations → DNS registration* enter your network and zone, read the server and approve what you want.

## Good to know

- Every change carries a prerequisite that the server checks atomically: an add needs the name to be unused, a change or removal needs the exact old record to exist. So a record that changed meanwhile is never overwritten, and a removal that finds nothing counts as done.
- DNS records have no comment field, so Netlens cannot mark its records on the server. It remembers the records it wrote and only changes or removes those.
- The server's answers are checked for the response code; their TSIG signature is not verified (the request signature protects the server).
- Secondary servers must not be listed: they get the change by zone transfer.
