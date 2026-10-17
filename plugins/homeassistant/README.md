# Netlens plugin: Home Assistant

An `inventory` plugin (new in Netlens 0.4.x).

Reads the **device registry** of Home Assistant and brings into Netlens what the network scan cannot see:

- manufacturer, model, **area**, firmware and protocol (Zigbee, Bluetooth, MQTT, the integration that owns the device);
- whether a device is **available** (not every one of its entities is `unavailable`), its **battery** level and whether an **update** is waiting;
- for Zigbee devices the device they are **paired through** (the coordinator or a router).

Devices with a MAC address (Wi-Fi and Ethernet devices that Home Assistant knows by MAC), or with an address in their configuration link, are matched to the device Netlens found by scanning: its page then has a **Smart home** card. All devices are listed on the **Smart home** page under *Monitoring* (filter by area, unavailable, low battery). Netlens raises events when a device **becomes unavailable** or comes back and when a **battery runs low**, adds them to the dashboard's attention list and shows the numbers in Prometheus.

> **Status: tested against a real Home Assistant 2026.7.1** (129 registry entries, Zigbee, MQTT, Shelly, ASUS router and mobile-app devices; sign-in with a token and with a user name and password). Please report what you see; *Run diagnostic* makes an anonymised report (counts only: no names, areas, addresses or MAC addresses).

## Set-up

1. In Home Assistant create a **long-lived access token** (profile → Security → Long-lived access tokens). Use a dedicated user; the plugin only reads. The registry is read through the template API, which needs an **administrator** user.
2. In Netlens install **Home Assistant**, fill in the address (`https://ha.example.com` or `http://192.168.0.20:8123`) and the token. **Test**, enable.

Without a token the plugin can sign in with a user name and password (the normal sign-in flow; the password is kept encrypted in Netlens). A user with two-factor sign-in needs a token.

## Good to know

- Read only: the plugin sends GET requests and one template request that renders the registry; it changes nothing.
- *Services and add-ons* (the Supervisor, integrations such as Uptime Kuma) live in the same registry as devices; they are left out unless you tick *Also list services and add-ons*.
- Disabled devices are left out. A device counts as unavailable only when **all** its entities are unavailable.
- Devices that exist only in Home Assistant (a Zigbee sensor) are not added to the Netlens device list: they are not on the network.
