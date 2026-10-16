# Netlens plugin: HAProxy

A `proxy` plugin.

Shows the **backends of an HAProxy load balancer as sites**: the first healthy server of each backend as the upstream (address and port) and whether the backend is in maintenance. Netlens ties every backend to the device or container behind it. HAProxy's statistics do not contain host names, so you can list them per backend yourself.

> **Status: tested in a lab** (HAProxy 3.4.7 (Docker): statistics CSV with `stats show-legends`, two backends, a disabled server. The relation between host names and backends is not in HAProxy's statistics, so it is a setting.) Please report what you see; *Run diagnostic* on the plugin's page makes an anonymised report (counts and field names, never names or addresses).

## Set-up

1. Add a statistics listener to `haproxy.cfg` (see the box at the top of the plugin's page): `stats enable`, `stats uri /stats`, **`stats show-legends`** (needed for the server addresses) and `stats auth user:password`, on a private address.
2. In Netlens install **HAProxy**, add a line with the address of the statistics page (`http://192.168.0.4:8404/stats`), the optional login and the address of the machine HAProxy runs on. Optionally fill in *Host names per backend* (`be_files=files.example.com`).
3. Test, enable.

## Good to know

- The `;csv` export is read. Frontends, the statistics listener itself and backends without servers are not sites.
- Without host names a site shows without a domain; sites still link the proxy to the devices behind it.
