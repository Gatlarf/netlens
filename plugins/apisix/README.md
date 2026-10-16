# Netlens plugin: Apache APISIX

A `proxy` plugin.

Shows the **routes an Apache APISIX gateway publishes**: host names, the upstream (the route's own, a shared upstream, or the one of its service), redirects, routes that are switched off, and the TLS **certificates with their expiry date**. Netlens ties each route to the device or container behind it, can keep an HTTPS check per site and can register the host names in DNS.

> **Status: tested against the real software in a lab** (APISIX 3.11.0 with etcd in Docker: routes with several hosts, shared and inline upstreams, a service, a redirect, a disabled route, a wildcard certificate, the viewer role and a wrong key). The stream proxy (`stream_routes`) was not enabled in the lab and follows the documentation. Please report what you see; *Run diagnostic* on the plugin's page makes an anonymised report (counts and field names only).

## Set-up

1. Keep a key with the **viewer** role in APISIX's `config.yaml` and let the Admin API listen on a private address only:
   ```yaml
   deployment:
     admin:
       allow_admin: [192.168.0.0/24]
       admin_key:
         - name: viewer
           key: <a long random key>
           role: viewer
   ```
2. In Netlens install **Apache APISIX**, add a line with the Admin API address (`http://192.168.0.4:9180`), the viewer key and the address of the machine APISIX runs on. Test, enable.

## Good to know

- Netlens only sends GET requests. The viewer role cannot change anything.
- The expiry of a certificate is read from the public certificate that the Admin API returns (private keys are never read: APISIX encrypts them).
- A route gets a certificate when one of the certificate's SNIs matches a domain of the route (wildcards such as `*.home.lan` work).
- A route with the `redirect` plugin and no upstream is a *redirect* site; a route with neither is a *dead* site.
- Routes use `hosts` or `host`; a route without any host is shown by its name without a domain.
