# Netlens plugin: ASUS router (AiMesh)

A `topology` plugin. Until Netlens 0.4.43 it was built in; since then it is installed from the **Plugin store**. If you used it before, Netlens installs it again by itself after the upgrade, with your settings, and keeps it switched on.

Shows which device is connected to which AiMesh node, with Wi-Fi signal and roaming. Stock ASUSWRT, read-only, no SSH (it signs in to the router's web interface the way a browser does). Tested on an ASUS RT-AX92U.

## Set-up

Enter the address of the router's web interface (`https://192.168.50.1:8443` or `http://router.asus.com`), a user name and password (a separate admin user is best), **Test**, enable.

## Traffic Analyzer (applications and devices)

Since 1.2.0 the plugin also reads the router's **Traffic Analyzer** when it is on (router: *Adaptive QoS > Traffic Analyzer > Statistic*, switch it on; the first figures appear after about an hour). Per day it takes the traffic of every application (the router's own application recognition) and of every device, up and down, and Netlens shows them in **Statistics > Network > Applications**: the top applications, the top devices and the traffic per day. **Per device** (1.3.0): for the 25 busiest devices of today it also asks the router which applications that device used, shown on the device's **Network** tab (one extra request per device, within 40 seconds). Only today and yesterday are read on each sync, and the day ends at the router's own midnight (its clock is read from the router). The figures are the router's: Netlens does not measure anything itself.

Models without Trend Micro's traffic analysis do not have these pages; the plugin then just skips this part. Untick *Read the Traffic Analyzer statistics* to turn it off. **Netlens' own switch also has to be on: Settings > Traffic statistics** (off by default, because in some countries this kind of data may not be collected; switching it off deletes what was stored, and while it is off the plugin does not even ask the router). **Run diagnostic** reports whether the pages answered and the shape of one row (never names or addresses).


## The health of the router and of every AiMesh node (1.5.0)

Every sync also reads, from the main router **and from each node that is online**: the **processor** (the growth of the processor time between two syncs, as a percentage), the **memory** (the router's figure includes its cache, so it is graphed but never raises an alert), the **temperature**, the **uptime**, the **physical ports** (WAN and LAN 1-4: is a cable in, and at what speed: 100 Mbit/s, gigabit ...) and the **speed of the interfaces** (the main router's internet connection, the wired LAN and the Wi-Fi radios; a node has no WAN). The **firmware** of each node comes from the router's list, with the newer version when one is waiting: Netlens tells it once as a *Firmware update waiting* event.

The devices then show up like monitored devices: graphs on their pages, the **Health** page, the usual limits (processor and temperature raise warnings). Nothing to set up per node: the nodes accept the main router's user name and password, and each sync asks every node at the address **the router lists for it right now**, so a node that got another address is still found. A node that refuses the login is skipped (the others still count); the *Test* message says how many answered. A device that already has a health monitor of its own (SNMP or SSH) keeps that and is left alone.

Switches in the plugin settings: *Record the health of the routers* (everything above) and *Read the AiMesh nodes too* (one extra login per node per sync). Everything is read-only, with the endpoints the router's own web page uses (`appGet.cgi`: `netdev`, `cpu_usage`, `memory_usage`, `get_cpu_temperature`, `get_wan_lan_status`, `uptime`).
