# Netlens plugin: Envoy

A `proxy` plugin.

Shows the **sites an Envoy proxy publishes**: every virtual host of its HTTP listeners (domains, the upstream cluster and its first endpoint, redirects) and every TCP proxy listener (port and upstream). Netlens ties each site to the device or container behind it, can keep an HTTPS check per site and can register the host names in DNS.

> **Status: tested against the real software in a lab** (Envoy 1.32.13 in Docker, configured by a file: two virtual hosts, a TCP proxy, clusters with several endpoints). Envoy configured through xDS (Istio, Contour, Envoy Gateway), TLS listeners and route configurations sent over RDS follow the Envoy documentation and are covered by simulated answers only. Please report what you see; *Run diagnostic* on the plugin's page makes an anonymised report (counts and section names, never names or addresses).

## Set-up

1. Let Envoy's **admin interface** listen on a private address only and allow only Netlens to connect: it has no login and can stop the proxy.
   ```yaml
   admin:
     address:
       socket_address: { address: 192.168.0.4, port_value: 9901 }
   ```
2. In Netlens install **Envoy**, add a line with the admin address (`http://192.168.0.4:9901`) and the address of the machine Envoy runs on. Test, enable.

## Good to know

- Netlens only sends `GET /server_info`, `/config_dump?include_eds` and `/clusters`.
- A virtual host is one site; its upstream is the first route that has a cluster (a cluster with several endpoints lists all their addresses as `forward_ips`). A virtual host that only redirects is a *redirect* site, one with only direct responses a *dead* site. The domain `*` is not a domain.
- Envoy has no certificate expiry in its configuration (it only names the files), so no expiry is reported; Netlens' own HTTPS check watches it.
- Endpoints that Envoy's health checking marks as unhealthy show as a warning on the proxy.
