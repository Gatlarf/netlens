# Netlens plugin: PowerDNS Authoritative

A `dns` plugin.

Registers your devices in **PowerDNS Authoritative Server 4.x**: an A record and a reverse (PTR) record for every device Netlens knows and DNS does not, and a changed address when a device's IP changes.

> **Status: tested in a lab** (PowerDNS Authoritative 4.9.17 (Docker, sqlite backend): reading, adding, changing and removing record sets, a foreign record set, a wrong key.) Please report what you see; *Run diagnostic* on the plugin's page makes an anonymised report (counts and field names, never names or addresses).

## Set-up

1. Switch the API on in `pdns.conf` (`api=yes`, `api-key=...`, `webserver=yes`, `webserver-allow-from=<Netlens>`) and restart. The key can change every zone: keep the port closed to everything but Netlens.
2. In Netlens install **PowerDNS Authoritative**, add a line with the API address (`http://192.168.0.2:8081`) and the key.
3. In *Settings → Integrations → DNS registration* enter your network and zone, read the server and approve what you want.

## Good to know

- PowerDNS keeps comments on a whole record set, so Netlens marks every set it writes with a comment and only changes or removes a set that has the marker **and** holds exactly the record Netlens wrote. A name that already has records of any other origin is never taken over.
- PowerDNS needs a TTL on every record set: the setting *TTL for new records* (default 3600) is used for new sets, an existing set keeps its own.
- Secondary zones (kind Slave/Secondary) are shown as read-only.
