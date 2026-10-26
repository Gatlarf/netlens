# Netlens plugin: TP-Link Omada

Reads an **Omada controller** (software controller, OC200 / OC300 or other hardware controller, **version 5.1 or newer**) and tells
Netlens which switch or access point every device is connected to and which device hangs below which. Netlens then shows the real
network position in the hierarchy and on the map, and the Wi-Fi signal, band and link rate of wireless clients.

> **Status: not yet tested on real hardware** (the application statistics of 1.2.0 least of all: they follow the Open API as used by the Home Assistant Omada integration). It is written from the API the Omada web page itself uses (the same one the open-source
> `tplink-omada-client` library uses) and tested against a simulated controller. Please test it and report back, see *Testing* below.

## What it does (read-only)

One login, a handful of reads and a logout per sync (Netlens syncs after every scan). It never changes anything on the controller.
The session is closed again afterwards, so no sessions pile up.

| Step | Request |
|---|---|
| version and id | `GET /api/info` (no login) |
| login | `POST /<id>/api/v2/login` (cookie + `Csrf-Token`) |
| sites | `GET .../users/current` |
| devices | `GET .../sites/<site>/devices`, then per switch `.../switches/<mac>` and per access point `.../eaps/<mac>` (their uplink; for a switch also its ports: link, speed, duplex, byte counters) |
| health | (from the device list above, no extra request) processor `cpuUtil`, memory `memUtil`, uptime (`uptimeLong`, or the text of `uptime`), firmware `firmwareVersion` and whether `needUpgrade`. The controller gives no temperature. Netlens records them like a monitored device (1.4.0; written from the controller's documented fields, not yet tested on real hardware) |
| clients | `GET .../sites/<site>/clients?currentPage=&currentPageSize=` (paged) |
| logout | `POST .../logout` (best effort) |
| application statistics (only with an Open API client, see below) | `POST /openapi/authorize/token?grant_type=client_credentials`, `GET /openapi/v1/<id>/sites`, then per client `GET /openapi/v1/<id>/sites/<site>/dashboard/specificClientInfo/<mac>?start=&end=` |

## Set-up

1. In Omada create an account with the **Viewer** role (Settings → Admin → Add) so the plugin can never change anything.
2. In Netlens: *Settings → Integrations → Plugin store → TP-Link Omada → Install* (community plugins ask for an extra confirmation), then open
   its page under *Integrations*, enter the address (`https://<controller>:8043` for the software controller, `https://<controller>` for an
   OC200/OC300), the account, the site name (empty = all sites) and leave *Verify TLS certificate* off unless you installed a real certificate.
3. **Test connection**, **Save**, **Turn on**, **Sync now**.

### Application statistics (optional, version 1.2.0)

Statistics > Network > Applications shows which applications and which devices used the traffic. Omada only hands out these DPI figures
through its **Open API**, which has its own login, so this part needs one extra step:

1. On the gateway, switch on **DPI** (Omada: Settings > Network Settings > Application Traffic/Deep Packet Inspection, the wording differs per version). Without a gateway
   that does DPI (an Omada router/ER-series gateway) there is nothing to read.
2. In Omada: *Settings > Platform Integration > Open API > Add New App*. Choose access mode **Client Credentials**, the role **Viewer**, and the site(s) to read.
   Copy the **Client ID** and **Client Secret**.
3. In Netlens, enter both in the plugin's settings (*Open API client ID* and *Open API client secret*; the secret is stored encrypted), then **Test connection**.
   The message ends with *Application statistics: working* when the login, the site and the DPI read all succeeded.

Besides the Open API client, **Settings > Traffic statistics in Netlens must be switched on** (it is off by default: in some countries this kind of data may not be collected; switching it off deletes what was stored, and while it is off nothing is asked from the controller).
Since 1.3.0 the applications are also kept per device and shown on the device's **Network** tab.

Leave the two fields empty to skip the statistics; everything else works as before. The figures are today's totals so far (from midnight on the Netlens server),
per application and per device. The controller has no list for the whole site, so Netlens asks once **per client** and adds the figures up: with many clients one
sync takes longer (the busiest clients are read first, and the reads stop after 60 seconds). A failing statistics read never fails the topology sync; the reason is
shown in the connection test and in *Run diagnostic*.

A refused login stops automatic syncing until you save the settings or press *Sync now* again, so a wrong password cannot lock the account.

## Testing (what we would like to know)

Please check after a sync, and tell us what is wrong:

- [ ] *Test connection* says how many devices and clients it found, and the numbers are right.
- [ ] *Hierarchy*: the gateway is at the top, switches below it, access points below the switch they are plugged into.
- [ ] A wired client is shown below the right switch, on the right **port** (device page → *Connected to*), and the switch's page lists its ports with link state, speed and traffic graphs (new in 1.1.0; the speed and duplex codes are the part we are least sure about).
- [ ] A Wi-Fi client is shown below the right access point; its device page has a *Wi-Fi* card with signal, band and link rate (values plausible? the **link rate** unit is the part we are least sure about).
- [ ] Access points connected **wirelessly (mesh)** and devices behind a router that is not Omada.
- [ ] Several sites, if you have them.
- [ ] With an Open API client entered: *Test connection* says *Application statistics: working*, and after a sync Statistics > Network > Applications lists applications and devices.
  Are the **bytes** right (compare a big download with Omada's own client page; if the numbers are 8 times too big or too small the unit is the question), does *upload* mean what the
  client sent, and does the list cover every client or only some?

If something is off, press **Run diagnostic** on the plugin's page in Netlens (needs a Netlens version with the button, 0.2.67 or newer; update the image if you do not see it). It logs in once like a normal sync with the values in the form, and shows a report of what the controller
answered: the controller version, which steps worked, and the **names and types of the fields** (not their content). Names, MAC and IP addresses and your settings are removed. Press **Copy** or **Download**, read it, and send it to whoever maintains the plugin.

## Troubleshooting

- **"... (error -1)" / "General error"**: the controller rejected one request. Since 1.0.1 the message starts with the step that failed (for example `sites/<site>/clients: General error. (error -1)`).
  1.0.1 also retries the client list with the other filter variants controllers expect. If it still fails, press **Run diagnostic** (see above) and send us the report: it records which step fails and what the controller answers.
- **"login refused"**: wrong user name or password, or the account may not log in to the web interface (use an account of the *Viewer* role). The plugin stops retrying until you save the settings again.
- **"cannot reach the controller"**: wrong address or port (8043 for the software controller), or a firewall.

## Known limits

- **Application statistics** need DPI on the gateway and an Open API client (see above). They are read per client, so a network with hundreds of clients is read partly each sync (the busiest first).
  Only today is read; the day changes at midnight of the Netlens server's clock, not the controller's.
- **Application statistics stay empty although the connection test says "working"?** The Open API login and the site match, but the controller returns no application rows. Four things to check, in this order:
  1. **Settings > Network Security > Application Control > Deep Packet Inspection**: DPI must be on *and* **Logging Traffic** must be on there too. TP-Link: without *Logging Traffic* the application statistics are not recorded at all (DPI alone only "activates the inspection capability"). Look at *Statistics > Application Analytics* in Omada: if that page is empty, Netlens cannot get anything either. It takes about five minutes before the first figures arrive, and a local controller needs TCP port 29815 reachable from the gateway.
  2. Version 1.3.2 asks for each client's applications with the MAC address written the way the Open API wants it (it tries `AA-BB-...` and `AA:BB:...` and keeps the one that returns rows); earlier versions only tried the first.
  3. If *Statistics > Application Analytics* does not exist in your Omada, or is empty, the controller does not record application traffic for this gateway and **no program can read it from Omada**; Netlens then simply has no application statistics for this site (everything else keeps working). Not every gateway model records them.
  4. Press *Run diagnostic*: since 1.3.3 its *gateway_dpi* step shows the gateway model, its firmware and every setting of the gateway whose name mentions DPI, applications, statistics or logging, with its yes/no or number value (never texts or addresses), so it is visible whether the gateway supports and has switched on the recording. The *application_traffic* step shows what the controller answered for the three busiest clients, in both MAC notations and three time windows (today in seconds, the last 24 hours in seconds and in milliseconds), whether its application list is known (`application_catalogue`), and which combination returned rows. Send that report.
- **Run diagnostic** also has a *dpi_web_api* step (1.4.1): it asks the web interface's own site-wide statistics (`stat/dpi/overview` and `stat/dpi/category/categoryCards`, the ones behind Statistics > Application Analytics) and shows their field names, sizes and the application and category names (never addresses). It needs no Open API client. Those two may allow site-wide application statistics without one.
- **Run diagnostic** has an *application_traffic* step that shows the field names the Open API answered with (never names or addresses) and whether the Open API's site ids match the ones the web interface uses.
- Controllers older than 5.1 are refused with a clear message.
- The uplink of a **mesh** access point (connected by radio) may not be reported; such a device then hangs below the gateway.
- A client connected to a switch that is not an Omada device is shown below the gateway.
