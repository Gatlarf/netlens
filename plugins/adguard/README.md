# Netlens plugin: AdGuard Home

A `dns` plugin.

Registers your devices in AdGuard Home as **DNS rewrites** (*Filters → DNS rewrites*): an A record for every device Netlens knows and DNS does not, a CNAME for a container alias, and a changed address when a device's IP changes. AdGuard Home makes no reverse (PTR) answers for rewrites, so none are written.

> **Status: verified on a real installation** (reported by the maintainer, 2026-10-16), after lab tests on AdGuard Home v0.107.79 (Docker): adding, changing and removing rewrites, duplicates, a wrong password. Please report what you see; *Run diagnostic* on the plugin's page makes an anonymised report (counts and field names, never names or addresses).

## Set-up

1. AdGuard Home has one kind of login. Add a user of its own under `users:` in `AdGuardHome.yaml` (a bcrypt hash: `htpasswd -nbB netlens 'password'`), restart AdGuard Home.
2. In Netlens install **AdGuard Home**, add a line with the address (`http://192.168.0.2:3000`), user name and password, **Test**, enable.
3. In *Settings → Integrations → DNS registration* enter your network and zone, read the server and approve what you want.

## Good to know

- AdGuard Home answers 200 to everything: a duplicate add and a delete of something that is not there both 'succeed'. The plugin therefore reads the list before and after each write.
- The update call of v0.107.79 keeps the old rewrite, so a changed address is made with add + delete.
- No zones and no comment field: same behaviour as the Pi-hole plugin (Netlens only changes what it remembers writing).
- Disabled rewrites, wildcard rewrites and the special answers `A` / `AAAA` are ignored.
