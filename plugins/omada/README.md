# Netlens plugin: TP-Link Omada

Reads an **Omada controller** (software controller, OC200 / OC300 or other hardware controller, **version 5.1 or newer**) and tells
Netlens which switch or access point every device is connected to and which device hangs below which. Netlens then shows the real
network position in the hierarchy and on the map, and the Wi-Fi signal, band and link rate of wireless clients.

> **Status: not yet tested on real hardware.** It is written from the API the Omada web page itself uses (the same one the open-source
> `tplink-omada-client` library uses) and tested against a simulated controller. Please test it and report back, see *Testing* below.

## What it does (read-only)

One login, a handful of reads and a logout per sync (Netlens syncs after every scan). It never changes anything on the controller.
The session is closed again afterwards, so no sessions pile up.

| Step | Request |
|---|---|
| version and id | `GET /api/info` (no login) |
| login | `POST /<id>/api/v2/login` (cookie + `Csrf-Token`) |
| sites | `GET .../users/current` |
| devices | `GET .../sites/<site>/devices`, then per switch `.../switches/<mac>` and per access point `.../eaps/<mac>` (their uplink) |
| clients | `GET .../sites/<site>/clients?currentPage=&currentPageSize=` (paged) |
| logout | `POST .../logout` (best effort) |

## Set-up

1. In Omada create an account with the **Viewer** role (Settings → Admin → Add) so the plugin can never change anything.
2. In Netlens: *Settings → Integrations → Browse plugins → TP-Link Omada → Install* (community plugins ask for an extra confirmation), then open
   its page under *Integrations*, enter the address (`https://<controller>:8043` for the software controller, `https://<controller>` for an
   OC200/OC300), the account, the site name (empty = all sites) and leave *Verify TLS certificate* off unless you installed a real certificate.
3. **Test connection**, **Save**, **Turn on**, **Sync now**.

A refused login stops automatic syncing until you save the settings or press *Sync now* again, so a wrong password cannot lock the account.

## Testing (what we would like to know)

Please check after a sync, and tell us what is wrong:

- [ ] *Test connection* says how many devices and clients it found, and the numbers are right.
- [ ] *Hierarchy*: the gateway is at the top, switches below it, access points below the switch they are plugged into.
- [ ] A wired client is shown below the right switch (device page → *Network position*).
- [ ] A Wi-Fi client is shown below the right access point; its device page has a *Wi-Fi* card with signal, band and link rate (values plausible? the **link rate** unit is the part we are least sure about).
- [ ] Access points connected **wirelessly (mesh)** and devices behind a router that is not Omada.
- [ ] Several sites, if you have them.

If something is off, press **Run diagnostic** on the plugin's page in Netlens (needs a Netlens version with the button, 0.2.65 or newer; update the image if you do not see it). It logs in once like a normal sync with the values in the form, and shows a report of what the controller
answered: the controller version, which steps worked, and the **names and types of the fields** (not their content). Names, MAC and IP addresses and your settings are removed. Press **Copy** or **Download**, read it, and send it to whoever maintains the plugin.

(From a terminal the same report is written by `python diagnose.py --url https://<controller>:8043 --username <viewer account>`; Python 3.9 or newer, nothing to install.)

## Troubleshooting

- **"... (error -1)" / "General error"**: the controller rejected one request. Since 1.0.1 the message starts with the step that failed (for example `sites/<site>/clients: General error. (error -1)`).
  1.0.1 also retries the client list with the other filter variants controllers expect. If it still fails, press **Run diagnostic** (see above) and send us the report: it records which step fails and what the controller answers.
- **"login refused"**: wrong user name or password, or the account may not log in to the web interface (use an account of the *Viewer* role). The plugin stops retrying until you save the settings again.
- **"cannot reach the controller"**: wrong address or port (8043 for the software controller), or a firewall.

## Known limits

- Controllers older than 5.1 are refused with a clear message.
- The uplink of a **mesh** access point (connected by radio) may not be reported; such a device then hangs below the gateway.
- A client connected to a switch that is not an Omada device is shown below the gateway.
