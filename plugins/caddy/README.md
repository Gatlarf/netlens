# Netlens plugin: Caddy

A `proxy` plugin.

Shows the sites a **Caddy 2** web server serves as a reverse proxy: domains, upstream address and port, redirects, and whether Caddy makes the HTTPS certificate itself. Netlens ties every site to the device or container behind it, can keep an HTTPS check per site and register the domains in DNS.

> **Status: tested against the real software in a lab** (Caddy v2.11.7 (Docker, a Caddyfile with two reverse proxies and a redirect); HTTPS-upstream and automatic-HTTPS details follow the Caddy documentation.) Please report what you see; *Run diagnostic* on the plugin's page makes an anonymised report (counts and field names, never names or addresses).

## Set-up

1. Caddy's admin API listens on `localhost:2019` only. To let Netlens read it, put `admin 0.0.0.0:2019` (or the LAN address) in the global options of the Caddyfile, and close that port to everything but Netlens: **the admin API has no password and can change the configuration**.
2. In Netlens install **Caddy**, add a line with the address (`http://192.168.0.4:2019`) and the address of the machine Caddy runs on.
3. Test, enable.

## Good to know

- Routes without a host match and routes that only serve files are not sites.
- A container name as upstream (`whoami:80`) is matched by Netlens to a container on the proxy's Docker network.
- Caddy's API gives neither the version nor the certificate expiry; Netlens' own HTTPS check watches the expiry.
