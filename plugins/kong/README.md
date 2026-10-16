# Netlens plugin: Kong Gateway

A `proxy` plugin.

Shows the **routes a Kong Gateway publishes**: host names, the upstream service address and port, protocols and whether the service is enabled. Netlens ties every route to the device or container behind it, can keep an HTTPS check per site and can register the host names in DNS.

> **Status: tested in a lab** (Kong 3.9.4 in DB-less mode (three services/routes, one without a route). TCP routes, Enterprise RBAC tokens and a database-backed Kong follow the Kong documentation and are covered by simulated answers only.) Please report what you see; *Run diagnostic* on the plugin's page makes an anonymised report (counts and field names, never names or addresses).

## Set-up

1. Let the Admin API listen on a private address only (`KONG_ADMIN_LISTEN=192.168.0.4:8001`) and allow only Netlens to connect: the open-source Admin API has no login and can change everything. Kong Enterprise: make an RBAC user with a read-only role and use its token.
2. In Netlens install **Kong Gateway**, add a line with the Admin API address and the address of the machine Kong runs on. Test, enable.

## Good to know

- gRPC routes are skipped; routes with only TCP/TLS protocols become `stream` sites with the destination port.
- Kong keeps its certificates as PEM text that the Admin API does not decode, so no certificate expiry is reported; Netlens' own HTTPS check watches it.
- A route whose service has no host is shown as a site without upstream.
