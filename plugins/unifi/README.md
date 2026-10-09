# Netlens plugin: Ubiquiti UniFi

Reads the **UniFi Network application** and tells Netlens which switch or access point every device is connected to and which device hangs
below which. Works with a **UniFi OS console** (Dream Machine / Pro / SE, Dream Router, Cloud Gateway, Cloud Key Gen2+, ...) and with a
**classic self-hosted controller** (port 8443). Netlens then shows the real network position in the hierarchy and on the map, and the Wi-Fi
signal, band and link rate of wireless clients.

> **Status: not yet tested on real hardware.** It is written from the controller API that the UniFi web interface uses (documented by the
> community) and tested against simulated controllers. Please test it and report back, see *Testing* below.

## What it does (read-only)

One login, three reads per site and a logout per sync (Netlens syncs after every scan). It never changes anything on the controller.

| Step | UniFi OS console | Classic controller |
|---|---|---|
| login | `POST /api/auth/login` | `POST /api/login` |
| sites | `GET /proxy/network/api/self/sites` | `GET /api/self/sites` |
| devices | `GET /proxy/network/api/s/<site>/stat/device` | `GET /api/s/<site>/stat/device` |
| clients | `GET /proxy/network/api/s/<site>/stat/sta` | `GET /api/s/<site>/stat/sta` |
| logout | `POST /api/auth/logout` | `POST /api/logout` |

*Type of controller = Detect automatically* tries the UniFi OS login first and falls back to the classic one.

## Set-up

1. In UniFi create a **local** account with read-only access (UniFi OS: *Admins & Users → Create new*, role *Limited Admin* / read-only for Network; classic:
   *Settings → Admins*, *Read Only*). It must be a local account **without two-factor authentication**; a Ubiquiti cloud (SSO) account does not work.
2. In Netlens: *Settings → Integrations → Browse plugins → Ubiquiti UniFi → Install* (community plugins ask for an extra confirmation), then open its
   page under *Integrations*, enter the address (`https://<console>` or `https://<server>:8443`), the account, the site (empty = all sites) and leave
   *Verify TLS certificate* off unless you installed a real certificate.
3. **Test connection**, **Save**, **Turn on**, **Sync now**.

A refused login stops automatic syncing until you save the settings or press *Sync now* again, so a wrong password cannot lock the account.

## Testing (what we would like to know)

Please check after a sync, and tell us what is wrong:

- [ ] *Test connection* says how many devices and clients it found, and the numbers are right.
- [ ] *Hierarchy*: the gateway is at the top, switches below it, access points below the switch (or the access point, for a meshed one) they are connected to.
- [ ] A wired client is shown below the right switch (device page → *Network position*); one plugged straight into the gateway below the gateway.
- [ ] A Wi-Fi client is shown below the right access point; its device page has a *Wi-Fi* card with signal (dBm), band and link rate (plausible?).
- [ ] Both a UniFi OS console and a classic controller, if you have access to both.
- [ ] Several sites, if you have them.

If something is off, run the diagnostic and send us the file:

```
python diagnose.py --url https://<console> --username <read-only account> --site default
```

It asks for the password (not stored), logs in once and writes `unifi-diagnostic.json` with the **names and types of the fields** the controller
returned and a summary of what the plugin made of them. Names, MAC and IP addresses and all other text are replaced by placeholders. Read the file
before sending it. (Python 3.9 or newer, nothing to install.)

## Known limits

- Ubiquiti SSO / two-factor accounts and API keys are not supported (the classic read-only pages are used).
- Link rates are read as kilobits per second, which is what UniFi reports.
- A client whose uplink is not a known device is shown below the gateway.
