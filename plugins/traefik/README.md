# Netlens plugin: Traefik

A `proxy` plugin.

Shows the sites a **Traefik v2/v3** reverse proxy publishes: domains from the router rules (`Host()`, `HostSNI()`), upstream address and port, TLS, redirects, TCP routers as streams. Netlens ties every site to the device or container behind it, can keep an HTTPS check per site and can register the domains in DNS.

> **Status: tested against the real software in a lab** (Traefik v3.7.15 (Docker provider, one router); TCP routers, redirect middlewares, TLS routers and basic authentication follow the documentation and are covered by simulated answers only.) Please report what you see; *Run diagnostic* on the plugin's page makes an anonymised report (counts and field names, never names or addresses).

## Set-up

1. Traefik's API must be reachable: `api.insecure=true` (port 8080) on a trusted network, or your own router for `api@internal` protected by basic authentication.
2. In Netlens install **Traefik**, add a line with the API address (`http://192.168.0.4:8080`), the optional user name and password, and the address of the machine Traefik runs on.
3. Test, enable.

## Good to know

- Traefik's Docker provider gives the container's address on its Docker network (`172.18.0.7`), not a LAN address, so Netlens often cannot tie such a site to a device. A file provider with real addresses or names works better.
- Traefik does not list the certificates it holds (ACME keeps them in `acme.json`), so no certificate information is reported; Netlens' own HTTPS check watches the expiry.
- Routers of the `internal` provider (the dashboard and API) are skipped. `HostRegexp` rules give no names.
